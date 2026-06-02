use achronyme_parser::ast::*;
use memory::FieldBackend;

use super::super::{FnDef, ProveIrCompiler};
use crate::error::ProveIrError;

impl<F: FieldBackend> ProveIrCompiler<F> {
    /// Resolve a relative import path against the source directory.
    pub(in crate::ast_lower) fn resolve_import_path(
        &self,
        path: &str,
        _span: &Span,
    ) -> Result<std::path::PathBuf, ProveIrError> {
        let base = self.source_dir.as_ref().ok_or_else(|| {
            ProveIrError::ModuleLoadError(
                "imports require a file path context (not available in inline prove blocks)".into(),
            )
        })?;
        let full_path = base.join(path);
        if !full_path.exists() {
            return Err(ProveIrError::ModuleNotFound(format!(
                "{} (resolved from {})",
                full_path.display(),
                path
            )));
        }
        full_path.canonicalize().map_err(|e| {
            ProveIrError::ModuleLoadError(format!("cannot resolve {}: {}", full_path.display(), e))
        })
    }

    /// Register exported functions from a module into fn_table with alias prefix.
    pub(in crate::ast_lower) fn register_module_exports(
        &mut self,
        alias: &str,
        module: &crate::module_loader::ModuleExports,
    ) {
        for stmt in &module.program.stmts {
            let inner = match stmt {
                Stmt::Export { inner, .. } => inner.as_ref(),
                other => other,
            };
            if let Stmt::FnDecl {
                name,
                params,
                body,
                return_type,
                ..
            } = inner
            {
                if module.exported_names.contains(name) {
                    let qualified = format!("{alias}::{name}");
                    self.fn_table.insert(
                        qualified,
                        FnDef {
                            params: params.clone(),
                            body: body.clone(),
                            return_type: return_type.clone(),
                            owner_module: None,
                            availability: None,
                        },
                    );
                }
            }
        }
    }

    /// `import "./module.ach" as alias`
    pub(in crate::ast_lower) fn compile_import(
        &mut self,
        path: &str,
        alias: &str,
        span: &Span,
    ) -> Result<(), ProveIrError> {
        let canonical = self.resolve_import_path(path, span)?;
        if self.compiling_modules.contains(&canonical) {
            return Err(ProveIrError::CircularImport(path.to_string()));
        }
        self.compiling_modules.insert(canonical.clone());
        let module = self
            .module_loader
            .load(&canonical)
            .map_err(ProveIrError::ModuleLoadError)?;
        // Clone what we need before releasing the borrow on module_loader.
        let exported_names = module.exported_names.clone();
        let stmts = module.program.stmts.clone();
        let exports = crate::module_loader::ModuleExports {
            exported_names,
            program: achronyme_parser::ast::Program { stmts },
        };
        self.register_module_exports(alias, &exports);
        Ok(())
    }

    /// `import { fn1, fn2 } from "./module.ach"`
    pub(in crate::ast_lower) fn compile_selective_import(
        &mut self,
        names: &[String],
        path: &str,
        span: &Span,
    ) -> Result<(), ProveIrError> {
        let canonical = self.resolve_import_path(path, span)?;
        if self.compiling_modules.contains(&canonical) {
            return Err(ProveIrError::CircularImport(path.to_string()));
        }
        self.compiling_modules.insert(canonical.clone());
        let module = self
            .module_loader
            .load(&canonical)
            .map_err(ProveIrError::ModuleLoadError)?;
        let exported_names = module.exported_names.clone();
        let stmts = module.program.stmts.clone();

        // Validate requested names are actually exported
        for name in names {
            if !exported_names.contains(name) {
                return Err(ProveIrError::ModuleLoadError(format!(
                    "`{name}` is not exported from `{path}`"
                )));
            }
        }

        // Register each requested function directly (no alias prefix)
        for stmt in &stmts {
            let inner = match stmt {
                Stmt::Export { inner, .. } => inner.as_ref(),
                other => other,
            };
            if let Stmt::FnDecl {
                name,
                params,
                body,
                return_type,
                ..
            } = inner
            {
                if names.contains(name) {
                    self.fn_table.insert(
                        name.clone(),
                        FnDef {
                            params: params.clone(),
                            body: body.clone(),
                            return_type: return_type.clone(),
                            owner_module: None,
                            availability: None,
                        },
                    );
                }
            }
        }
        Ok(())
    }
}
