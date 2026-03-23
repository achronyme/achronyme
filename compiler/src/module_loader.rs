use std::collections::HashMap;
use std::path::{Path, PathBuf};

use achronyme_parser::ast::{Program, Stmt};

use crate::error::CompilerError;

/// Tracks which names a module exports.
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
    pub fn load(&mut self, canonical_path: &Path) -> Result<&ModuleExports, CompilerError> {
        if self.cache.contains_key(canonical_path) {
            return Ok(&self.cache[canonical_path]);
        }

        let source = std::fs::read_to_string(canonical_path).map_err(|e| {
            CompilerError::ModuleLoadError(format!(
                "cannot read {}: {}",
                canonical_path.display(),
                e
            ))
        })?;

        let (program, parse_errors) = achronyme_parser::parse_program(&source);
        if let Some(err) = parse_errors
            .iter()
            .find(|d| d.severity == achronyme_parser::Severity::Error)
        {
            return Err(CompilerError::ModuleLoadError(format!(
                "parse error in {}: {}",
                canonical_path.display(),
                err.message
            )));
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
fn collect_defined_names(program: &Program) -> std::collections::HashSet<String> {
    let mut defined = std::collections::HashSet::new();
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
fn collect_exports(program: &Program) -> Result<Vec<String>, CompilerError> {
    let defined = collect_defined_names(program);
    let mut names = Vec::new();
    let mut seen = std::collections::HashSet::new();
    for stmt in &program.stmts {
        match stmt {
            Stmt::Export { inner, span, .. } => {
                let name = match inner.as_ref() {
                    Stmt::FnDecl { name, .. } => Some(name.clone()),
                    Stmt::LetDecl { name, .. } => Some(name.clone()),
                    _ => None,
                };
                if let Some(name) = name {
                    if !seen.insert(name.clone()) {
                        return Err(CompilerError::CompileError(
                            format!("`{name}` is exported more than once"),
                            crate::error::span_box(span),
                        ));
                    }
                    names.push(name);
                }
            }
            Stmt::ExportList {
                names: export_names,
                span,
            } => {
                for name in export_names {
                    if !defined.contains(name) {
                        let suggestion = crate::suggest::find_similar(
                            name,
                            defined.iter().map(|s| s.as_str()),
                            2,
                        );
                        let mut msg = format!("cannot export `{name}`: not defined in this module");
                        if let Some(s) = suggestion {
                            msg.push_str(&format!(". Did you mean `{s}`?"));
                        }
                        return Err(CompilerError::CompileError(
                            msg,
                            crate::error::span_box(span),
                        ));
                    }
                    if !seen.insert(name.clone()) {
                        return Err(CompilerError::CompileError(
                            format!("`{name}` is exported more than once"),
                            crate::error::span_box(span),
                        ));
                    }
                    names.push(name.clone());
                }
            }
            _ => {}
        }
    }
    Ok(names)
}
