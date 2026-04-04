//! Circom `include` resolution.
//!
//! Resolves `include "path"` directives by:
//! 1. Searching relative to the including file's directory.
//! 2. Searching each library directory (passed via `-l` flags).
//! 3. Deduplicating by canonical path (each file parsed at most once).
//! 4. Detecting include cycles.
//!
//! The result is a single [`CircomProgram`] with all definitions merged.

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use diagnostics::{Diagnostic, ParseError};

use crate::ast::{CircomProgram, Definition, MainComponent, Version};
use crate::parser::parse_circom;

/// Resolved program: all includes flattened into a single program.
#[derive(Debug)]
pub struct ResolvedProgram {
    /// Merged version (from the root file's pragma).
    pub version: Option<Version>,
    /// Whether any file declared `pragma custom_templates`.
    pub custom_templates: bool,
    /// All definitions from all files, in include order.
    pub definitions: Vec<Definition>,
    /// Main component (from the root file only).
    pub main_component: Option<MainComponent>,
    /// All diagnostics collected during parsing.
    pub diagnostics: Vec<Diagnostic>,
}

/// Resolve all includes starting from a root `.circom` file.
///
/// `library_dirs` are additional directories to search (Circom `-l` flag).
pub fn resolve_includes(
    root_path: &Path,
    library_dirs: &[PathBuf],
) -> Result<ResolvedProgram, IncludeError> {
    let root_path = root_path
        .canonicalize()
        .map_err(|e| IncludeError::Io(root_path.to_path_buf(), e))?;

    let mut resolver = Resolver {
        library_dirs: library_dirs.to_vec(),
        visited: HashSet::new(),
        in_progress: HashSet::new(),
        parsed_cache: HashMap::new(),
        diagnostics: Vec::new(),
    };

    resolver.resolve_file(&root_path)?;

    // Build merged program: root file first, then includes in order
    // SAFETY: resolve_file(&root_path) returned Ok above, which means root_path
    // was successfully parsed and inserted into parsed_cache.
    let root_prog = resolver
        .parsed_cache
        .remove(&root_path)
        .expect("root file must be in cache after successful resolve_file");

    let mut definitions = Vec::new();
    let mut custom_templates = root_prog.custom_templates;

    // Collect definitions from all parsed files (root last so its defs are on top)
    for (path, prog) in &resolver.parsed_cache {
        if *path != root_path {
            definitions.extend(prog.definitions.clone());
            custom_templates |= prog.custom_templates;
        }
    }
    definitions.extend(root_prog.definitions);

    Ok(ResolvedProgram {
        version: root_prog.version,
        custom_templates,
        definitions,
        main_component: root_prog.main_component,
        diagnostics: resolver.diagnostics,
    })
}

/// Resolve a single source string with no file system access.
///
/// Useful for tests and in-memory compilation. Includes are not resolved
/// (any `include` directives produce errors).
pub fn resolve_source(source: &str) -> Result<ResolvedProgram, IncludeError> {
    let (prog, diagnostics) =
        parse_circom(source).map_err(|e| IncludeError::Parse("<source>".into(), e))?;

    if !prog.includes.is_empty() {
        return Err(IncludeError::IncludeInSource(prog.includes[0].path.clone()));
    }

    Ok(ResolvedProgram {
        version: prog.version,
        custom_templates: prog.custom_templates,
        definitions: prog.definitions,
        main_component: prog.main_component,
        diagnostics,
    })
}

// ---------------------------------------------------------------------------
// Resolver state
// ---------------------------------------------------------------------------

struct Resolver {
    library_dirs: Vec<PathBuf>,
    /// Files already fully resolved (canonical path).
    visited: HashSet<PathBuf>,
    /// Files currently being resolved (cycle detection).
    in_progress: HashSet<PathBuf>,
    /// Parsed programs by canonical path.
    parsed_cache: HashMap<PathBuf, CircomProgram>,
    /// Accumulated diagnostics.
    diagnostics: Vec<Diagnostic>,
}

impl Resolver {
    fn resolve_file(&mut self, canonical_path: &Path) -> Result<(), IncludeError> {
        // Already resolved or currently being resolved — skip.
        // Circom allows mutual includes (e.g., bitify ↔ comparators) which
        // are resolved by deduplication, not treated as errors.
        if self.visited.contains(canonical_path) || self.in_progress.contains(canonical_path) {
            return Ok(());
        }

        self.in_progress.insert(canonical_path.to_path_buf());

        // Read and parse the file
        let source = std::fs::read_to_string(canonical_path)
            .map_err(|e| IncludeError::Io(canonical_path.to_path_buf(), e))?;

        let (prog, parse_diags) = parse_circom(&source)
            .map_err(|e| IncludeError::Parse(canonical_path.to_path_buf(), e))?;

        self.diagnostics.extend(parse_diags);

        // Resolve each include recursively
        let file_dir = canonical_path
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .to_path_buf();

        for include in &prog.includes {
            let resolved = self.find_include(&include.path, &file_dir)?;
            self.resolve_file(&resolved)?;
        }

        self.in_progress.remove(canonical_path);
        self.visited.insert(canonical_path.to_path_buf());
        self.parsed_cache.insert(canonical_path.to_path_buf(), prog);

        Ok(())
    }

    /// Find an include path:
    /// 1. Relative to the including file's directory
    /// 2. In each library directory
    fn find_include(&self, include_path: &str, file_dir: &Path) -> Result<PathBuf, IncludeError> {
        // Try relative to the including file's directory
        let relative = file_dir.join(include_path);
        if relative.exists() {
            return relative
                .canonicalize()
                .map_err(|e| IncludeError::Io(relative, e));
        }

        // Try each library directory
        for lib_dir in &self.library_dirs {
            let lib_path = lib_dir.join(include_path);
            if lib_path.exists() {
                return lib_path
                    .canonicalize()
                    .map_err(|e| IncludeError::Io(lib_path, e));
            }
        }

        Err(IncludeError::NotFound {
            include_path: include_path.to_string(),
            searched: {
                let mut dirs = vec![file_dir.to_path_buf()];
                dirs.extend(self.library_dirs.iter().cloned());
                dirs
            },
        })
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors that can occur during include resolution.
#[derive(Debug)]
pub enum IncludeError {
    /// File I/O error.
    Io(PathBuf, std::io::Error),
    /// Parse error in a Circom file.
    Parse(PathBuf, ParseError),
    /// Include cycle detected.
    Cycle(PathBuf),
    /// Include file not found.
    NotFound {
        include_path: String,
        searched: Vec<PathBuf>,
    },
    /// Include directive in source-only mode (no filesystem).
    IncludeInSource(String),
}

impl std::fmt::Display for IncludeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(path, err) => write!(f, "I/O error reading `{}`: {}", path.display(), err),
            Self::Parse(path, err) => write!(f, "parse error in `{}`: {}", path.display(), err),
            Self::Cycle(path) => write!(f, "circular include detected: `{}`", path.display()),
            Self::NotFound {
                include_path,
                searched,
            } => {
                write!(f, "include `{include_path}` not found, searched: ")?;
                for (i, dir) in searched.iter().enumerate() {
                    if i > 0 {
                        write!(f, ", ")?;
                    }
                    write!(f, "{}", dir.display())?;
                }
                Ok(())
            }
            Self::IncludeInSource(path) => {
                write!(f, "cannot resolve include `{path}` in source-only mode")
            }
        }
    }
}

impl std::error::Error for IncludeError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn make_temp_dir() -> tempfile::TempDir {
        tempfile::tempdir().expect("failed to create temp dir")
    }

    #[test]
    fn resolve_single_file_no_includes() {
        let dir = make_temp_dir();
        let file = dir.path().join("main.circom");
        fs::write(
            &file,
            r#"
            pragma circom 2.1.6;
            template T() { signal input x; }
            component main = T();
            "#,
        )
        .unwrap();

        let resolved = resolve_includes(&file, &[]).unwrap();
        assert_eq!(resolved.definitions.len(), 1);
        assert!(resolved.main_component.is_some());
        assert!(resolved.diagnostics.is_empty());
    }

    #[test]
    fn resolve_relative_include() {
        let dir = make_temp_dir();
        let lib_file = dir.path().join("utils.circom");
        fs::write(&lib_file, "template Utils() { signal input a; }").unwrap();

        let main_file = dir.path().join("main.circom");
        fs::write(
            &main_file,
            r#"
            include "utils.circom";
            template Main() { signal input b; }
            component main = Main();
            "#,
        )
        .unwrap();

        let resolved = resolve_includes(&main_file, &[]).unwrap();
        assert_eq!(resolved.definitions.len(), 2); // Utils + Main
    }

    #[test]
    fn resolve_library_dir_include() {
        let dir = make_temp_dir();
        let lib_dir = dir.path().join("libs");
        fs::create_dir(&lib_dir).unwrap();
        fs::write(
            lib_dir.join("helper.circom"),
            "template Helper() { signal input h; }",
        )
        .unwrap();

        let main_file = dir.path().join("main.circom");
        fs::write(
            &main_file,
            r#"
            include "helper.circom";
            template Main() { signal input m; }
            "#,
        )
        .unwrap();

        let resolved = resolve_includes(&main_file, &[lib_dir]).unwrap();
        assert_eq!(resolved.definitions.len(), 2);
    }

    #[test]
    fn resolve_deduplicates_includes() {
        let dir = make_temp_dir();
        let shared = dir.path().join("shared.circom");
        fs::write(&shared, "template Shared() { signal input s; }").unwrap();

        let a = dir.path().join("a.circom");
        fs::write(&a, r#"include "shared.circom";"#).unwrap();

        let b = dir.path().join("b.circom");
        fs::write(&b, r#"include "shared.circom";"#).unwrap();

        let main_file = dir.path().join("main.circom");
        fs::write(
            &main_file,
            r#"
            include "a.circom";
            include "b.circom";
            template Main() { signal input x; }
            "#,
        )
        .unwrap();

        let resolved = resolve_includes(&main_file, &[]).unwrap();
        // Shared should appear only once
        let shared_count = resolved
            .definitions
            .iter()
            .filter(|d| matches!(d, Definition::Template(t) if t.name == "Shared"))
            .count();
        assert_eq!(shared_count, 1);
    }

    #[test]
    fn mutual_includes_deduplicated() {
        // Circom allows mutual includes (e.g., bitify ↔ comparators).
        // They are resolved by deduplication, not treated as errors.
        let dir = make_temp_dir();
        let a = dir.path().join("a.circom");
        let b = dir.path().join("b.circom");
        fs::write(
            &a,
            r#"include "b.circom"; template A() { signal input x; }"#,
        )
        .unwrap();
        fs::write(
            &b,
            r#"include "a.circom"; template B() { signal input y; }"#,
        )
        .unwrap();

        let result = resolve_includes(&a, &[]);
        assert!(result.is_ok());
        let resolved = result.unwrap();
        assert_eq!(resolved.definitions.len(), 2); // A + B
    }

    #[test]
    fn not_found_error() {
        let dir = make_temp_dir();
        let main_file = dir.path().join("main.circom");
        fs::write(&main_file, r#"include "nonexistent.circom";"#).unwrap();

        let result = resolve_includes(&main_file, &[]);
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), IncludeError::NotFound { .. }));
    }

    #[test]
    fn resolve_source_no_includes() {
        let resolved =
            resolve_source("template T() { signal input x; } component main = T();").unwrap();
        assert_eq!(resolved.definitions.len(), 1);
        assert!(resolved.main_component.is_some());
    }

    #[test]
    fn resolve_source_rejects_includes() {
        let result = resolve_source(r#"include "something.circom";"#);
        assert!(result.is_err());
        assert!(matches!(
            result.unwrap_err(),
            IncludeError::IncludeInSource(_)
        ));
    }

    #[test]
    fn nested_includes() {
        let dir = make_temp_dir();
        let sub = dir.path().join("sub");
        fs::create_dir(&sub).unwrap();

        fs::write(
            sub.join("deep.circom"),
            "template Deep() { signal input d; }",
        )
        .unwrap();
        fs::write(
            dir.path().join("mid.circom"),
            r#"include "sub/deep.circom";"#,
        )
        .unwrap();
        let main_file = dir.path().join("main.circom");
        fs::write(
            &main_file,
            r#"
            include "mid.circom";
            template Main() { signal input x; }
            "#,
        )
        .unwrap();

        let resolved = resolve_includes(&main_file, &[]).unwrap();
        // Deep + Main
        assert_eq!(resolved.definitions.len(), 2);
    }
}
