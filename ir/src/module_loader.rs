use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use achronyme_parser::ast::{Program, Stmt};

use crate::suggest::find_similar_ir;

/// Tracks which names a module exports, along with the parsed AST.
pub struct ModuleExports {
    pub exported_names: Vec<String>,
    pub program: Program,
}

/// Loads, caches, and deduplicates module files. Detects circular imports.
pub struct ModuleLoader {
    cache: HashMap<PathBuf, ModuleExports>,
}

impl Default for ModuleLoader {
    fn default() -> Self {
        Self::new()
    }
}

impl ModuleLoader {
    pub fn new() -> Self {
        Self {
            cache: HashMap::new(),
        }
    }

    /// Load a module from the given canonical path.
    /// Returns the exported names and the parsed AST.
    /// Caches results for deduplication.
    pub fn load(&mut self, canonical_path: &Path) -> Result<&ModuleExports, String> {
        if self.cache.contains_key(canonical_path) {
            return Ok(&self.cache[canonical_path]);
        }

        let source = std::fs::read_to_string(canonical_path)
            .map_err(|e| format!("cannot read {}: {}", canonical_path.display(), e))?;

        let (program, parse_errors) = achronyme_parser::parse_program(&source);
        if let Some(err) = parse_errors
            .iter()
            .find(|d| d.severity == diagnostics::Severity::Error)
        {
            return Err(format!(
                "parse error in {}: {}",
                canonical_path.display(),
                err.message
            ));
        }

        let exported_names = collect_exports(&program)?;

        let key = canonical_path.to_path_buf();
        self.cache.insert(
            key.clone(),
            ModuleExports {
                exported_names,
                program,
            },
        );

        Ok(&self.cache[&key])
    }
}

/// Collect all top-level defined names (fn and let declarations) in a program.
fn collect_defined_names(program: &Program) -> HashSet<String> {
    let mut defined = HashSet::new();
    for stmt in &program.stmts {
        match stmt {
            Stmt::FnDecl { name, .. } | Stmt::LetDecl { name, .. } => {
                defined.insert(name.clone());
            }
            Stmt::Export { inner, .. } => match inner.as_ref() {
                Stmt::FnDecl { name, .. } | Stmt::LetDecl { name, .. } => {
                    defined.insert(name.clone());
                }
                _ => {}
            },
            _ => {}
        }
    }
    defined
}

/// Collect the names of all exported declarations in a program.
/// Returns an error if a name is exported more than once or if an export list
/// references undefined names.
fn collect_exports(program: &Program) -> Result<Vec<String>, String> {
    let defined = collect_defined_names(program);
    let mut names = Vec::new();
    let mut seen = HashSet::new();
    for stmt in &program.stmts {
        match stmt {
            Stmt::Export { inner, .. } => {
                let name = match inner.as_ref() {
                    Stmt::FnDecl { name, .. } => Some(name.clone()),
                    Stmt::LetDecl { name, .. } => Some(name.clone()),
                    _ => None,
                };
                if let Some(name) = name {
                    if !seen.insert(name.clone()) {
                        return Err(format!("`{name}` is exported more than once"));
                    }
                    names.push(name);
                }
            }
            Stmt::ExportList {
                names: export_names,
                ..
            } => {
                for name in export_names {
                    if !defined.contains(name) {
                        let suggestion = find_similar_ir(name, defined.iter().map(|s| s.as_str()));
                        let mut msg = format!("cannot export `{name}`: not defined in this module");
                        if let Some(s) = suggestion {
                            msg.push_str(&format!(". Did you mean `{s}`?"));
                        }
                        return Err(msg);
                    }
                    if !seen.insert(name.clone()) {
                        return Err(format!("`{name}` is exported more than once"));
                    }
                    names.push(name.clone());
                }
            }
            _ => {}
        }
    }
    Ok(names)
}
