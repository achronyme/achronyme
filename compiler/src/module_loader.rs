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

        let program = achronyme_parser::parse_program(&source).map_err(|e| {
            CompilerError::ModuleLoadError(format!(
                "parse error in {}: {}",
                canonical_path.display(),
                e
            ))
        })?;

        let exported_names = collect_exports(&program);

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

/// Collect the names of all exported declarations in a program.
fn collect_exports(program: &Program) -> Vec<String> {
    let mut names = Vec::new();
    for stmt in &program.stmts {
        if let Stmt::Export { inner, .. } = stmt {
            match inner.as_ref() {
                Stmt::FnDecl { name, .. } => names.push(name.clone()),
                Stmt::LetDecl { name, .. } => names.push(name.clone()),
                _ => {}
            }
        }
    }
    names
}
