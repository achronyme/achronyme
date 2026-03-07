use std::path::Path;

use achronyme_parser::ast::*;
use achronyme_parser::parse_program as ast_parse_program;

use crate::error::IrError;

use super::{EnvValue, FnDef, IrLowering};

impl IrLowering {
    /// Re-register all fn_table and env entries from `original` alias under `new_alias`.
    pub(super) fn alias_module_entries(&mut self, original: &str, new_alias: &str) {
        let prefix = format!("{original}::");
        let fn_copies: Vec<(String, FnDef)> = self
            .fn_table
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(k, v)| {
                let suffix = &k[prefix.len()..];
                (format!("{new_alias}::{suffix}"), v.clone())
            })
            .collect();
        for (k, v) in fn_copies {
            self.fn_table.insert(k, v);
        }

        let env_copies: Vec<(String, EnvValue)> = self
            .env
            .iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .map(|(k, v)| {
                let suffix = &k[prefix.len()..];
                (format!("{new_alias}::{suffix}"), v.clone())
            })
            .collect();
        for (k, v) in env_copies {
            self.env.insert(k, v);
        }
    }

    pub(super) fn load_module(
        &mut self,
        path: &str,
        alias: &str,
        _span: &Span,
    ) -> Result<(), IrError> {
        let base = self
            .base_path
            .clone()
            .unwrap_or_else(|| Path::new(".").to_path_buf());
        let resolved = base.join(path);
        let canonical = resolved.canonicalize().map_err(|_| {
            IrError::ModuleNotFound(format!("{} (resolved from {})", path, base.display()))
        })?;

        if self.loading_modules.contains(&canonical) {
            return Err(IrError::CircularImport(canonical.display().to_string()));
        }

        if let Some(original_alias) = self.loaded_modules.get(&canonical).cloned() {
            if original_alias != alias {
                // Same file, different alias: re-register entries under new alias
                self.alias_module_entries(&original_alias, alias);
            }
            return Ok(());
        }

        self.loading_modules.insert(canonical.clone());

        let source = std::fs::read_to_string(&canonical)
            .map_err(|e| IrError::ModuleLoadError(format!("{}: {}", canonical.display(), e)))?;

        let (program, parse_errors) = ast_parse_program(&source);
        if let Some(err) = parse_errors.into_iter().next() {
            return Err(IrError::ModuleLoadError(format!(
                "parse error in {}: {}",
                canonical.display(),
                err.message
            )));
        }

        // Save and set base_path for nested imports
        let old_base = self.base_path.take();
        self.base_path = canonical.parent().map(|p| p.to_path_buf());

        for stmt in &program.stmts {
            match stmt {
                Stmt::Export { inner, .. } => match inner.as_ref() {
                    Stmt::FnDecl {
                        name,
                        params,
                        return_type,
                        body,
                        ..
                    } => {
                        let qualified = format!("{alias}::{name}");
                        self.fn_table.insert(
                            qualified,
                            FnDef {
                                params: params.clone(),
                                body: body.clone(),
                                return_type: return_type.clone(),
                            },
                        );
                    }
                    Stmt::LetDecl {
                        name,
                        value,
                        span: _,
                        ..
                    } => {
                        let qualified = format!("{alias}::{name}");
                        let v = self.lower_expr(value)?;
                        self.env.insert(qualified, EnvValue::Scalar(v));
                    }
                    _ => {}
                },
                Stmt::FnDecl {
                    name,
                    params,
                    return_type,
                    body,
                    ..
                } => {
                    // Internal (non-exported) functions: register with module prefix
                    // so exported functions can call them via fn_call_prefix
                    let qualified = format!("{alias}::{name}");
                    self.fn_table.insert(
                        qualified,
                        FnDef {
                            params: params.clone(),
                            body: body.clone(),
                            return_type: return_type.clone(),
                        },
                    );
                }
                Stmt::LetDecl { name, value, .. } => {
                    // Internal (non-exported) let bindings: register in env so
                    // exported functions that reference them can resolve
                    let qualified = format!("{alias}::{name}");
                    let v = self.lower_expr(value)?;
                    self.env.insert(qualified, EnvValue::Scalar(v));
                }
                Stmt::Import {
                    path: sub_path,
                    alias: sub_alias,
                    span: sub_span,
                    ..
                } => {
                    // Handle nested imports
                    self.load_module(sub_path, sub_alias, sub_span)?;
                }
                Stmt::PublicDecl { .. } | Stmt::WitnessDecl { .. } => {
                    // Ignored: public/witness in imported modules don't affect the circuit
                }
                _ => {
                    // Other statements (let without export, etc.) are ignored
                }
            }
        }

        self.base_path = old_base;
        self.loading_modules.remove(&canonical);
        self.loaded_modules.insert(canonical, alias.to_string());

        Ok(())
    }
}
