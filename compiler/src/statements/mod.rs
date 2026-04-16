use std::path::Path;

use crate::codegen::Compiler;
use crate::control_flow::ControlFlowCompiler;
use crate::declarations::DeclarationCompiler;
use crate::error::{span_box, CompilerError};
use crate::expressions::ExpressionCompiler;
use crate::functions::FunctionDefinitionCompiler;
use achronyme_parser::ast::*;
use memory::Value;
use vm::opcode::OpCode;

pub mod circom_imports;
pub mod declarations;

/// File kind routed by an `import` / `import circuit` directive, determined
/// from the path's extension. Used to dispatch between the native `.ach`
/// module loader and the `.circom` frontend (library-mode compilation).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ImportFileKind {
    /// Native Achronyme module — `.ach` suffix or no suffix at all.
    Ach,
    /// Circom source file — `.circom` suffix.
    Circom,
}

/// Classify an import path by its file extension.
///
/// Paths ending in `.circom` (case-insensitive) resolve to [`ImportFileKind::Circom`];
/// anything else — including extensionless paths — resolves to
/// [`ImportFileKind::Ach`]. The path is **not** validated here: that stays
/// in the caller so the resulting error message can include the import span.
pub(crate) fn detect_import_kind(path: &str) -> ImportFileKind {
    match Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .as_deref()
    {
        Some("circom") => ImportFileKind::Circom,
        _ => ImportFileKind::Ach,
    }
}

#[cfg(test)]
mod circom_import_dispatch_tests {
    use super::*;
    use crate::codegen::Compiler;

    /// Owns a `tempfile::TempDir` + the path of a `.circom` file
    /// inside it. On drop, the directory and its contents are
    /// deleted — even if the test panics — so stray
    /// `/tmp/ach_import_dispatch_*.circom` files don't accumulate
    /// across failing runs.
    struct TempCircom {
        _dir: tempfile::TempDir,
        path: std::path::PathBuf,
    }

    impl TempCircom {
        fn dir(&self) -> std::path::PathBuf {
            self.path.parent().unwrap().to_path_buf()
        }
        fn filename(&self) -> String {
            self.path.file_name().unwrap().to_str().unwrap().to_string()
        }
    }

    fn temp_circom(src: &str) -> TempCircom {
        let dir = tempfile::tempdir().expect("create temp dir");
        let path = dir.path().join("module.circom");
        std::fs::write(&path, src).expect("write temp circom");
        TempCircom { _dir: dir, path }
    }

    #[test]
    fn import_circom_namespace_registers_library() {
        let tc = temp_circom(
            r#"
            pragma circom 2.0.0;
            template Square() {
                signal input x;
                signal output y;
                y <== x * x;
            }
            "#,
        );
        let tmp_dir = tc.dir();
        let rel = tc.filename();
        let ach_src = format!("import \"./{}\" as P\n", rel);

        let mut compiler = Compiler::new();
        compiler.base_path = Some(tmp_dir);
        compiler.compile(&ach_src).expect("compile should succeed");

        let ns = compiler
            .circom_namespaces
            .get("P")
            .expect("P namespace registered");
        assert!(ns.template("Square").is_some());
        // Namespace imports must NOT register a runtime global.
        assert!(
            !compiler.global_symbols.contains_key("P"),
            "P should not leak into global_symbols"
        );
    }

    #[test]
    fn import_circom_missing_file_errors() {
        let mut compiler = Compiler::new();
        compiler.base_path = Some(std::env::temp_dir());
        let result = compiler.compile("import \"./does-not-exist.circom\" as P\n");
        match result {
            Err(CompilerError::ModuleNotFound(msg, _)) => {
                assert!(
                    msg.contains("circom file not found"),
                    "unexpected error message: {msg}"
                );
            }
            other => panic!("expected ModuleNotFound, got {other:?}"),
        }
    }

    #[test]
    fn selective_import_circom_registers_aliases() {
        let tc = temp_circom(
            r#"
            pragma circom 2.0.0;
            template Square() {
                signal input x;
                signal output y;
                y <== x * x;
            }
            template Cube() {
                signal input x;
                signal output y;
                signal tmp;
                tmp <== x * x;
                y <== tmp * x;
            }
            "#,
        );
        let tmp_dir = tc.dir();
        let rel = tc.filename();
        let ach_src = format!("import {{ Square, Cube }} from \"./{rel}\"\n");

        let mut compiler = Compiler::new();
        compiler.base_path = Some(tmp_dir);
        compiler
            .compile(&ach_src)
            .expect("selective import should succeed");

        assert!(compiler.circom_template_aliases.contains_key("Square"));
        assert!(compiler.circom_template_aliases.contains_key("Cube"));
        // Neither name should leak into the runtime global table.
        assert!(!compiler.global_symbols.contains_key("Square"));
        assert!(!compiler.global_symbols.contains_key("Cube"));
    }

    #[test]
    fn selective_import_circom_unknown_name_with_suggestion() {
        let tc = temp_circom(
            r#"
            pragma circom 2.0.0;
            template Square() {
                signal input x;
                signal output y;
                y <== x * x;
            }
            "#,
        );
        let tmp_dir = tc.dir();
        let rel = tc.filename();
        // `Squar` is a typo for `Square` — distance 1.
        let ach_src = format!("import {{ Squar }} from \"./{rel}\"\n");

        let mut compiler = Compiler::new();
        compiler.base_path = Some(tmp_dir);
        let err = compiler
            .compile(&ach_src)
            .expect_err("selective import should fail on unknown template");
        match err {
            CompilerError::CompileError(msg, _) => {
                assert!(msg.contains("does not declare template"), "msg: {msg}");
                assert!(msg.contains("Did you mean `Square`"), "msg: {msg}");
            }
            other => panic!("expected CompileError, got {other:?}"),
        }
    }

    #[test]
    fn selective_import_circom_shares_library_with_namespace() {
        // Same physical file imported twice (once as namespace, once
        // selectively) should reuse the same Arc<CircomLibrary> under
        // the hood — not trigger a second compile_template_library call.
        // We can't inspect Arc refcount without racing, but we can at
        // least verify both imports succeed and the alias tables agree.
        let tc = temp_circom(
            r#"
            pragma circom 2.0.0;
            template Square() {
                signal input x;
                signal output y;
                y <== x * x;
            }
            "#,
        );
        let tmp_dir = tc.dir();
        let rel = tc.filename();
        let ach_src = format!("import \"./{rel}\" as P\nimport {{ Square }} from \"./{rel}\"\n");
        let mut compiler = Compiler::new();
        compiler.base_path = Some(tmp_dir);
        compiler
            .compile(&ach_src)
            .expect("namespace + selective on same file should work");

        let ns = compiler.circom_namespaces.get("P").unwrap();
        let sel_lib = compiler.circom_template_aliases.get("Square").unwrap();
        assert_eq!(ns.source_path, sel_lib.source_path);
    }

    #[test]
    fn import_circuit_circom_with_main_component_registers_global() {
        let tc = temp_circom(
            r#"
            pragma circom 2.0.0;
            template Square() {
                signal input x;
                signal output y;
                y <== x * x;
            }
            component main = Square();
            "#,
        );
        let tmp_dir = tc.dir();
        let rel = tc.filename();
        let ach_src = format!("import circuit \"./{rel}\" as SquareCircuit\n");

        let mut compiler = Compiler::new();
        compiler.base_path = Some(tmp_dir);
        compiler
            .compile(&ach_src)
            .expect("import circuit should compile a full circom circuit");

        // Unlike namespace/selective imports, `import circuit` binds a
        // runtime global (the serialized ProveIR blob).
        let entry = compiler
            .global_symbols
            .get("SquareCircuit")
            .expect("SquareCircuit global registered");
        let params = entry.param_names.as_ref().expect("param_names present");
        assert!(params.iter().any(|p| p == "x"));
        assert!(params.iter().any(|p| p == "y"));

        // It must NOT be registered on the circom_* tables — those are
        // for library-mode imports only.
        assert!(!compiler.circom_namespaces.contains_key("SquareCircuit"));
        assert!(!compiler
            .circom_template_aliases
            .contains_key("SquareCircuit"));
    }

    #[test]
    fn import_circuit_circom_without_main_errors() {
        let tc = temp_circom(
            r#"
            pragma circom 2.0.0;
            template Square() {
                signal input x;
                signal output y;
                y <== x * x;
            }
            "#,
        );
        let tmp_dir = tc.dir();
        let rel = tc.filename();
        let ach_src = format!("import circuit \"./{rel}\" as C\n");

        let mut compiler = Compiler::new();
        compiler.base_path = Some(tmp_dir);
        let err = compiler
            .compile(&ach_src)
            .expect_err("import circuit without component main should fail");
        match err {
            CompilerError::CircomImport { diagnostics, .. } => {
                assert!(
                    diagnostics
                        .iter()
                        .any(|d| d.message.contains("component main")),
                    "expected missing main diagnostic, got: {diagnostics:?}"
                );
            }
            other => panic!("expected CircomImport, got {other:?}"),
        }
    }

    #[test]
    fn import_circuit_circom_alias_collides_with_existing_global() {
        // B2 from the refactor review: full_circuit was silently
        // overwriting existing global_symbols entries. Now the
        // check_alias_conflict helper rejects the collision with
        // DuplicateModuleAlias before any bytecode is emitted.
        let tc = temp_circom(
            r#"
            pragma circom 2.0.0;
            template Square() {
                signal input x;
                signal output y;
                y <== x * x;
            }
            component main = Square();
            "#,
        );
        let tmp_dir = tc.dir();
        let rel = tc.filename();
        // `poseidon` is a native global registered at compiler
        // construction — importing as `poseidon` must collide.
        let ach_src = format!("import circuit \"./{rel}\" as poseidon\n");

        let mut compiler = Compiler::new();
        compiler.base_path = Some(tmp_dir);
        let err = compiler
            .compile(&ach_src)
            .expect_err("alias collision with `poseidon` native should fail");
        assert!(
            matches!(err, CompilerError::DuplicateModuleAlias(ref name, _) if name == "poseidon"),
            "expected DuplicateModuleAlias(poseidon), got {err:?}"
        );
    }

    #[test]
    fn import_circuit_circom_alias_collides_with_circom_namespace() {
        // B3: imports were inconsistent about checking the circom
        // namespace table. After R12 all three dispatch paths share
        // check_alias_conflict, so an import_circuit that shadows a
        // previously-registered circom namespace is rejected.
        let tc = temp_circom(
            r#"
            pragma circom 2.0.0;
            template Square() {
                signal input x;
                signal output y;
                y <== x * x;
            }
            component main = Square();
            "#,
        );
        let tmp_dir = tc.dir();
        let rel = tc.filename();
        let ach_src = format!("import \"./{rel}\" as C\nimport circuit \"./{rel}\" as C\n");

        let mut compiler = Compiler::new();
        compiler.base_path = Some(tmp_dir);
        let err = compiler
            .compile(&ach_src)
            .expect_err("alias collision with circom namespace should fail");
        assert!(
            matches!(err, CompilerError::DuplicateModuleAlias(ref name, _) if name == "C"),
            "expected DuplicateModuleAlias(C), got {err:?}"
        );
    }

    #[test]
    fn import_circom_parse_error_returns_structured_diagnostic() {
        // D2: instead of flattening circom diagnostics into a plain
        // string, the compiler now raises CompilerError::CircomImport
        // carrying the inner Diagnostic list. to_diagnostic() folds
        // them into notes on the outer diagnostic so the
        // DiagnosticRenderer can show both together.
        let tc = temp_circom("this is not circom at all @#$%");
        let tmp_dir = tc.dir();
        let rel = tc.filename();
        let ach_src = format!("import \"./{rel}\" as P\n");

        let mut compiler = Compiler::new();
        compiler.base_path = Some(tmp_dir);
        let err = compiler
            .compile(&ach_src)
            .expect_err("bad circom should fail");
        let diag = err.to_diagnostic();
        assert_eq!(diag.severity, achronyme_parser::Severity::Error);
        assert!(
            diag.message.contains("failed to load circom file"),
            "unexpected primary message: {}",
            diag.message
        );
        assert!(
            !diag.notes.is_empty(),
            "expected at least one note carrying inner circom diagnostics"
        );
    }

    #[test]
    fn import_circom_duplicate_alias_conflicts() {
        let tc = temp_circom(
            r#"
            pragma circom 2.0.0;
            template T() {
                signal input x;
                signal output y;
                y <== x;
            }
            "#,
        );
        let tmp_dir = tc.dir();
        let rel = tc.filename();
        // Same alias, same path → idempotent.
        let ach_src = format!("import \"./{rel}\" as P\nimport \"./{rel}\" as P\n");
        let mut compiler = Compiler::new();
        compiler.base_path = Some(tmp_dir);
        compiler
            .compile(&ach_src)
            .expect("duplicate same-path import is idempotent");
    }

    // --- Phase 3.2: build_circom_imports_for_outer_scope ---

    #[test]
    fn build_circom_imports_flattens_namespace_templates_to_colon_keys() {
        let tc = temp_circom(
            r#"
            pragma circom 2.0.0;
            template Square() {
                signal input x;
                signal output y;
                y <== x * x;
            }
            template Cube() {
                signal input x;
                signal output y;
                signal tmp;
                tmp <== x * x;
                y <== tmp * x;
            }
            "#,
        );
        let tmp_dir = tc.dir();
        let rel = tc.filename();
        let ach_src = format!("import \"./{rel}\" as P\n");
        let mut compiler = Compiler::new();
        compiler.base_path = Some(tmp_dir);
        compiler.compile(&ach_src).expect("namespace import");

        let imports = circom_imports::build_circom_imports_for_outer_scope(&compiler);
        // Two templates → two "P::T" keys.
        assert!(imports.contains_key("P::Square"), "missing P::Square");
        assert!(imports.contains_key("P::Cube"), "missing P::Cube");
        assert_eq!(imports.get("P::Square").unwrap().template_name, "Square");
        assert_eq!(imports.get("P::Cube").unwrap().template_name, "Cube");
        // Bare names must NOT be present for namespace imports —
        // namespaces do not pollute the unqualified key space.
        assert!(!imports.contains_key("Square"));
        assert!(!imports.contains_key("Cube"));
    }

    #[test]
    fn build_circom_imports_carries_selective_aliases_under_bare_names() {
        let tc = temp_circom(
            r#"
            pragma circom 2.0.0;
            template Square() {
                signal input x;
                signal output y;
                y <== x * x;
            }
            template Cube() {
                signal input x;
                signal output y;
                signal tmp;
                tmp <== x * x;
                y <== tmp * x;
            }
            "#,
        );
        let tmp_dir = tc.dir();
        let rel = tc.filename();
        // Selective import pulls only Square, leaves Cube un-imported.
        let ach_src = format!("import {{ Square }} from \"./{rel}\"\n");
        let mut compiler = Compiler::new();
        compiler.base_path = Some(tmp_dir);
        compiler.compile(&ach_src).expect("selective import");

        let imports = circom_imports::build_circom_imports_for_outer_scope(&compiler);
        assert!(imports.contains_key("Square"));
        assert_eq!(imports.get("Square").unwrap().template_name, "Square");
        // Cube was not imported — must not appear.
        assert!(!imports.contains_key("Cube"));
        // And there is no namespace, so no "_::_" key either.
        assert!(imports.keys().all(|k| !k.contains("::")));
    }

    #[test]
    fn build_circom_imports_handles_namespace_and_selective_together() {
        // Mirrors the real-world case: one file namespaced as P, a
        // different import selects some templates by bare name.
        let tc = temp_circom(
            r#"
            pragma circom 2.0.0;
            template Square() {
                signal input x;
                signal output y;
                y <== x * x;
            }
            template Cube() {
                signal input x;
                signal output y;
                signal tmp;
                tmp <== x * x;
                y <== tmp * x;
            }
            "#,
        );
        let tmp_dir = tc.dir();
        let rel = tc.filename();
        // Same physical file gets namespaced + selectively-imported.
        let ach_src = format!("import \"./{rel}\" as P\nimport {{ Square }} from \"./{rel}\"\n");
        let mut compiler = Compiler::new();
        compiler.base_path = Some(tmp_dir);
        compiler
            .compile(&ach_src)
            .expect("namespace + selective must coexist");

        let imports = circom_imports::build_circom_imports_for_outer_scope(&compiler);
        assert!(imports.contains_key("P::Square"));
        assert!(imports.contains_key("P::Cube"));
        assert!(imports.contains_key("Square"));
        assert!(!imports.contains_key("Cube"));
        assert_eq!(imports.len(), 3);
    }

    #[test]
    fn build_circom_imports_is_empty_when_no_circom_imports() {
        let compiler = Compiler::new();
        let imports = circom_imports::build_circom_imports_for_outer_scope(&compiler);
        assert!(imports.is_empty());
    }
}

#[cfg(test)]
mod import_kind_tests {
    use super::{detect_import_kind, ImportFileKind};

    #[test]
    fn plain_ach_file_is_ach() {
        assert_eq!(detect_import_kind("./lib.ach"), ImportFileKind::Ach);
    }

    #[test]
    fn no_extension_is_ach() {
        assert_eq!(detect_import_kind("lib"), ImportFileKind::Ach);
    }

    #[test]
    fn circom_extension_is_circom() {
        assert_eq!(
            detect_import_kind("./poseidon.circom"),
            ImportFileKind::Circom
        );
    }

    #[test]
    fn circom_extension_case_insensitive() {
        assert_eq!(
            detect_import_kind("./POSEIDON.CIRCOM"),
            ImportFileKind::Circom
        );
    }

    #[test]
    fn circom_in_directory_name_not_in_suffix_is_ach() {
        // Only the final extension matters — a `circom/` directory in the
        // middle of the path should still dispatch as `.ach`.
        assert_eq!(detect_import_kind("circom/lib.ach"), ImportFileKind::Ach);
    }
}

pub trait StatementCompiler {
    fn compile_stmt(&mut self, stmt: &Stmt) -> Result<(), CompilerError>;
    fn compile_import(&mut self, path: &str, alias: &str, span: &Span)
        -> Result<(), CompilerError>;
    fn compile_selective_import(
        &mut self,
        names: &[String],
        path: &str,
        span: &Span,
    ) -> Result<(), CompilerError>;
    fn compile_circuit_decl(
        &mut self,
        name: &str,
        params: &[TypedParam],
        body: &Block,
        span: &Span,
    ) -> Result<(), CompilerError>;
    fn compile_import_circuit(
        &mut self,
        path: &str,
        alias: &str,
        span: &Span,
    ) -> Result<(), CompilerError>;
}

/// Extract the source line number from a statement (1-based), or 0 if unavailable.
fn stmt_line(stmt: &Stmt) -> u32 {
    stmt_span(stmt).map_or(0, |s| s.line_start as u32)
}

/// Extract the span from a statement, if available.
pub(crate) fn stmt_span(stmt: &Stmt) -> Option<&Span> {
    match stmt {
        Stmt::LetDecl { span, .. }
        | Stmt::MutDecl { span, .. }
        | Stmt::Assignment { span, .. }
        | Stmt::Print { span, .. }
        | Stmt::Return { span, .. }
        | Stmt::FnDecl { span, .. }
        | Stmt::PublicDecl { span, .. }
        | Stmt::WitnessDecl { span, .. }
        | Stmt::Break { span }
        | Stmt::Continue { span }
        | Stmt::Import { span, .. }
        | Stmt::Export { span, .. }
        | Stmt::SelectiveImport { span, .. }
        | Stmt::ExportList { span, .. }
        | Stmt::CircuitDecl { span, .. }
        | Stmt::ImportCircuit { span, .. }
        | Stmt::Error { span } => Some(span),
        Stmt::Expr(expr) => Some(expr.span()),
    }
}

impl StatementCompiler for Compiler {
    fn compile_stmt(&mut self, stmt: &Stmt) -> Result<(), CompilerError> {
        // Track source line for error reporting
        self.current()?.current_line = stmt_line(stmt);
        // Track span for error diagnostics
        self.current_span = stmt_span(stmt).cloned();

        match stmt {
            Stmt::LetDecl {
                name,
                type_ann,
                value,
                ..
            } => self.compile_let_decl(name, type_ann.as_ref(), value),
            Stmt::MutDecl {
                name,
                type_ann,
                value,
                ..
            } => self.compile_mut_decl(name, type_ann.as_ref(), value),
            Stmt::Assignment { target, value, .. } => self.compile_assignment(target, value),
            Stmt::Print { value, .. } => {
                // 1. Prepare Call Frame: Func Reg, Arg Reg
                let func_reg = self.alloc_reg()?;
                let arg_reg = self.alloc_reg()?; // Must be func_reg + 1

                // 2. Load "print" (Pre-defined)
                let print_idx = self
                    .global_symbols
                    .get("print")
                    .ok_or_else(|| {
                        CompilerError::InternalError(
                            "native function 'print' not registered".into(),
                        )
                    })?
                    .index;
                self.emit_abx(OpCode::GetGlobal, func_reg, print_idx)?;

                // 3. Compile Argument
                self.compile_expr_into(value, arg_reg)?;

                // 4. Call
                self.emit_abc(OpCode::Call, func_reg, func_reg, 1)?;

                self.free_reg(arg_reg)?;
                self.free_reg(func_reg)?;
                Ok(())
            }
            Stmt::Break { .. } => self.compile_break(),
            Stmt::Continue { .. } => self.compile_continue(),
            Stmt::Return { value, .. } => {
                if let Some(expr) = value {
                    let reg = self.compile_expr(expr)?;
                    self.emit_abc(OpCode::Return, reg, 1, 0)?;
                    self.free_reg(reg)?;
                } else {
                    // Void return (0 values), do NOT load Nil
                    self.emit_abc(OpCode::Return, 0, 0, 0)?;
                }
                Ok(())
            }
            Stmt::FnDecl {
                name, params, body, ..
            } => {
                // Store the AST for ProveIR (prove/circuit blocks inline outer functions).
                // Only capture top-level functions (depth 1 = main script scope).
                //
                // When we're inside a namespace-imported module
                // (`module_prefix = Some(alias)`), tag the stored FnDecl
                // with its qualified name `alias::name` so prove blocks
                // that dispatch via the `::` path find it in their
                // `fn_table`. Without this, `h::commitment(...)` inside a
                // prove block would silently miss because the module's
                // functions land in the outer scope's fn_decl_asts with
                // their bare name and the ProveIR compiler keys
                // `fn_table` by the literal FnDecl name.
                if self.compilers.len() == 1 {
                    if let Some(prefix) = self.module_prefix.clone() {
                        let qualified = format!("{prefix}::{name}");
                        // Rebuild the stmt with the qualified name. Only
                        // `FnDecl.name` changes; params, body,
                        // return_type, span all stay put.
                        let tagged = if let Stmt::FnDecl {
                            params,
                            body,
                            return_type,
                            span,
                            ..
                        } = stmt
                        {
                            Stmt::FnDecl {
                                name: qualified,
                                params: params.clone(),
                                body: body.clone(),
                                return_type: return_type.clone(),
                                span: span.clone(),
                            }
                        } else {
                            unreachable!("outer match arm guarantees Stmt::FnDecl")
                        };
                        self.fn_decl_asts.push(tagged);
                    } else {
                        self.fn_decl_asts.push(stmt.clone());
                    }
                }
                // Phase 4: skip VM bytecode for ProveIr-only functions.
                // Their AST is already captured in fn_decl_asts above
                // for ProveIR inlining; the VM compiler has no use for them.
                let fn_key = match &self.module_prefix {
                    Some(prefix) => format!("{prefix}::{name}"),
                    None => name.clone(),
                };
                if let Some(map) = &self.resolver_availability_map {
                    if let Some(avail) = map.get(&fn_key) {
                        if !avail.includes_vm() {
                            return Ok(());
                        }
                    }
                }

                let reg = self.compile_fn_core(Some(name), params, body)?;
                self.free_reg(reg)?;
                Ok(())
            }
            Stmt::PublicDecl { span, .. } | Stmt::WitnessDecl { span, .. } => {
                Err(CompilerError::CompileError(
                    "top-level `public`/`witness` declarations are not supported; \
                     use `circuit name(param: Public, ...) { body }` instead"
                        .into(),
                    span_box(span),
                ))
            }
            Stmt::Import {
                path, alias, span, ..
            } => self.compile_import(path, alias, span),
            Stmt::SelectiveImport {
                names, path, span, ..
            } => self.compile_selective_import(names, path, span),
            Stmt::Export { inner, .. } => self.compile_stmt(inner),
            Stmt::ExportList { .. } => {
                // Export lists are metadata — handled by collect_exports, no bytecode to emit
                Ok(())
            }
            Stmt::CircuitDecl {
                name,
                params,
                body,
                span,
            } => self.compile_circuit_decl(name, params, body, span),
            Stmt::ImportCircuit {
                path, alias, span, ..
            } => self.compile_import_circuit(path, alias, span),
            Stmt::Error { .. } => Ok(()),
            Stmt::Expr(expr) => {
                let reg = self.compile_expr(expr)?;
                self.free_reg(reg)?;
                Ok(())
            }
        }
    }

    fn compile_circuit_decl(
        &mut self,
        name: &str,
        params: &[TypedParam],
        body: &Block,
        span: &Span,
    ) -> Result<(), CompilerError> {
        use achronyme_parser::ast::Visibility;
        // 1. Synthesize public/witness declarations from circuit params
        let mut stmts = Vec::new();
        for param in params {
            let ta = param.type_ann.as_ref().ok_or_else(|| {
                CompilerError::CompileError(
                    format!("circuit parameter `{}` has no type annotation", param.name),
                    span_box(span),
                )
            })?;
            let vis = ta.visibility.ok_or_else(|| {
                CompilerError::CompileError(
                    format!(
                        "circuit parameter `{}` requires Public or Witness visibility",
                        param.name
                    ),
                    span_box(span),
                )
            })?;
            let decl = InputDecl {
                name: param.name.clone(),
                array_size: ta.array_size,
                type_ann: Some(ta.clone()),
            };
            match vis {
                Visibility::Public => stmts.push(Stmt::PublicDecl {
                    names: vec![decl],
                    span: span.clone(),
                }),
                Visibility::Witness => stmts.push(Stmt::WitnessDecl {
                    names: vec![decl],
                    span: span.clone(),
                }),
            }
        }
        stmts.extend(body.stmts.clone());
        let circuit_body = Block {
            stmts,
            span: body.span.clone(),
        };

        // 2. Compile to ProveIR — pass outer functions so the circuit can
        //    inline user-defined helpers from the enclosing scope, plus
        //    any circom template imports so the ProveIR compiler can
        //    resolve `Poseidon(...)(...)` / `P.Poseidon(...)(...)` calls.
        let functions = self
            .resolver_outer_functions
            .clone()
            .unwrap_or_else(|| self.fn_decl_asts.clone());
        let outer_scope = ir::prove_ir::OuterScope {
            functions,
            circom_imports: crate::statements::circom_imports::build_circom_imports_for_outer_scope(
                self,
            ),
            ..Default::default()
        };
        let mut prove_ir =
            ir::prove_ir::ProveIrCompiler::<memory::Bn254Fr>::compile(&circuit_body, &outer_scope)
                .map_err(|e| CompilerError::CompileError(format!("{e}"), span_box(span)))?;
        prove_ir.name = Some(name.to_string());

        // 3. Serialize to bytes
        let ir_bytes = prove_ir.to_bytes(self.prime_id).map_err(|e| {
            CompilerError::CompileError(format!("ProveIR serialization: {e}"), span_box(span))
        })?;

        // 4. Store bytes in constant pool and bind as global
        let handle = self.intern_bytes(ir_bytes);
        let val = Value::bytes(handle);
        let idx = self.add_constant(val)?;
        if idx > 0xFFFF {
            return Err(CompilerError::TooManyConstants(span_box(span)));
        }

        // Bind the circuit name as a global pointing to the bytes constant
        if self.next_global_idx == u16::MAX {
            return Err(CompilerError::TooManyConstants(span_box(span)));
        }
        let global_idx = self.next_global_idx;
        self.next_global_idx += 1;
        self.global_symbols.insert(
            name.to_string(),
            crate::types::GlobalEntry {
                index: global_idx,
                type_ann: None,
                is_mutable: false,
                param_names: Some(params.iter().map(|p| p.name.clone()).collect()),
            },
        );

        // Emit: load the bytes constant into a register, then define as global
        let reg = self.alloc_reg()?;
        self.emit_abx(vm::opcode::OpCode::LoadConst, reg, idx as u16)?;
        self.emit_abx(vm::opcode::OpCode::DefGlobalLet, reg, global_idx)?;
        self.free_reg(reg)?;

        Ok(())
    }

    fn compile_import_circuit(
        &mut self,
        path: &str,
        alias: &str,
        span: &Span,
    ) -> Result<(), CompilerError> {
        if detect_import_kind(path) == ImportFileKind::Circom {
            return circom_imports::full_circuit(self, path, alias, span);
        }

        // 1. Resolve path relative to base_path
        let base = self
            .base_path
            .clone()
            .unwrap_or_else(|| std::path::PathBuf::from("."));
        let full_path = base.join(path);

        if !full_path.exists() {
            return Err(CompilerError::CompileError(
                format!("circuit file not found: {}", full_path.display()),
                span_box(span),
            ));
        }

        // 2. Read circuit source
        let source = std::fs::read_to_string(&full_path).map_err(|e| {
            CompilerError::CompileError(
                format!("cannot read circuit file {}: {e}", full_path.display()),
                span_box(span),
            )
        })?;

        // 3. Compile to ProveIR via compile_circuit (self-contained)
        let mut prove_ir = ir::prove_ir::ProveIrCompiler::<memory::Bn254Fr>::compile_circuit(
            &source,
            Some(&full_path),
        )
        .map_err(|e| CompilerError::CompileError(format!("{e}"), span_box(span)))?;
        prove_ir.name = Some(alias.to_string());

        // 4. Serialize to bytes
        let ir_bytes = prove_ir.to_bytes(self.prime_id).map_err(|e| {
            CompilerError::CompileError(format!("ProveIR serialization: {e}"), span_box(span))
        })?;

        // 5. Store bytes in constant pool and bind alias as global
        let handle = self.intern_bytes(ir_bytes);
        let val = Value::bytes(handle);
        let idx = self.add_constant(val)?;
        if idx > 0xFFFF {
            return Err(CompilerError::TooManyConstants(span_box(span)));
        }

        if self.next_global_idx == u16::MAX {
            return Err(CompilerError::TooManyConstants(span_box(span)));
        }
        let global_idx = self.next_global_idx;
        self.next_global_idx += 1;
        let circuit_param_names: Vec<String> = prove_ir
            .public_inputs
            .iter()
            .chain(prove_ir.witness_inputs.iter())
            .map(|input| input.name.clone())
            .collect();
        self.global_symbols.insert(
            alias.to_string(),
            crate::types::GlobalEntry {
                index: global_idx,
                type_ann: None,
                is_mutable: false,
                param_names: Some(circuit_param_names),
            },
        );

        let reg = self.alloc_reg()?;
        self.emit_abx(vm::opcode::OpCode::LoadConst, reg, idx as u16)?;
        self.emit_abx(vm::opcode::OpCode::DefGlobalLet, reg, global_idx)?;
        self.free_reg(reg)?;

        Ok(())
    }

    fn compile_import(
        &mut self,
        path: &str,
        alias: &str,
        span: &Span,
    ) -> Result<(), CompilerError> {
        if detect_import_kind(path) == ImportFileKind::Circom {
            return circom_imports::namespace(self, path, alias, span);
        }

        // 1. Resolve path relative to base_path
        let base = self
            .base_path
            .clone()
            .unwrap_or_else(|| Path::new(".").to_path_buf());
        let resolved = base.join(path);
        let canonical = resolved.canonicalize().map_err(|_| {
            CompilerError::ModuleNotFound(
                format!(
                    "module not found: {} (resolved from {})",
                    path,
                    base.display()
                ),
                span_box(span),
            )
        })?;

        // 2. Check for duplicate alias
        if let Some(existing) = self.imported_aliases.get(alias) {
            if *existing != canonical {
                return Err(CompilerError::DuplicateModuleAlias(
                    alias.to_string(),
                    span_box(span),
                ));
            }
            // Same path, same alias → already imported, skip
            return Ok(());
        }
        self.imported_aliases
            .insert(alias.to_string(), canonical.clone());

        // 3. Check for circular imports
        if self.compiling_modules.contains(&canonical) {
            return Err(CompilerError::CircularImport(
                canonical.display().to_string(),
                span_box(span),
            ));
        }

        // 4. Load and parse the module
        let module = self
            .module_loader
            .load(&canonical)
            .map_err(CompilerError::ModuleLoadError)?;
        let module_stmts = module.program.stmts.clone();
        let exported_names = module.exported_names.clone();

        // 5. Mark as compiling (for cycle detection during stmt compilation)
        self.compiling_modules.insert(canonical.clone());

        // 6. Save and set module_prefix + base_path for name mangling
        let old_prefix = self.module_prefix.take();
        let old_base = self.base_path.take();
        self.module_prefix = Some(alias.to_string());
        self.base_path = canonical.parent().map(|p| p.to_path_buf());

        // 7. Compile the module's statements (globals get mangled as alias::name)
        for stmt in &module_stmts {
            self.compile_stmt(stmt)?;
        }

        // 8. Restore prefix and base_path, remove from compiling set
        self.module_prefix = old_prefix;
        self.base_path = old_base;
        self.compiling_modules.remove(&canonical);

        // 9. Build a Map { export_name: value } and bind it to the alias
        let count = exported_names.len();

        // Allocate target register first (LIFO register hygiene)
        let map_reg = self.alloc_reg()?;

        let start_reg = if count > 0 {
            self.alloc_contiguous((count * 2) as u8)?
        } else {
            self.current()?.reg_top
        };

        for (i, name) in exported_names.iter().enumerate() {
            let key_reg = start_reg + (i as u8 * 2);
            let val_reg = key_reg + 1;

            // Key: the export name as a string constant
            let key_handle = self.intern_string(name);
            let key_val = Value::string(key_handle);
            let const_idx = self.add_constant(key_val)?;
            if const_idx > 0xFFFF {
                return Err(CompilerError::TooManyConstants(span_box(span)));
            }
            self.emit_abx(OpCode::LoadConst, key_reg, const_idx as u16)?;

            // Value: load from the mangled global
            let mangled = format!("{}::{}", alias, name);
            let global_idx = self
                .global_symbols
                .get(&mangled)
                .ok_or_else(|| {
                    CompilerError::CompileError(
                        format!(
                        "internal error: mangled global `{}` not found after module compilation",
                        mangled
                    ),
                        span_box(span),
                    )
                })?
                .index;
            self.emit_abx(OpCode::GetGlobal, val_reg, global_idx)?;
        }

        self.emit_abc(OpCode::BuildMap, map_reg, start_reg, count as u8)?;

        // Free pair registers (LIFO: last allocated = first freed)
        if count > 0 {
            for _ in 0..(count * 2) {
                let top = self.current()?.reg_top - 1;
                self.free_reg(top)?;
            }
        }

        // Bind the map to the alias as a global
        if self.next_global_idx == u16::MAX {
            return Err(CompilerError::TooManyConstants(span_box(span)));
        }
        let idx = self.next_global_idx;
        self.next_global_idx += 1;
        self.global_symbols.insert(
            alias.to_string(),
            crate::types::GlobalEntry {
                index: idx,
                type_ann: None,
                is_mutable: false,
                param_names: None,
            },
        );
        self.emit_abx(OpCode::DefGlobalLet, map_reg, idx)?;
        self.free_reg(map_reg)?;

        Ok(())
    }

    fn compile_selective_import(
        &mut self,
        names: &[String],
        path: &str,
        span: &Span,
    ) -> Result<(), CompilerError> {
        if detect_import_kind(path) == ImportFileKind::Circom {
            return circom_imports::selective(self, names, path, span);
        }

        // 1. Resolve path relative to base_path
        let base = self
            .base_path
            .clone()
            .unwrap_or_else(|| Path::new(".").to_path_buf());
        let resolved = base.join(path);
        let canonical = resolved.canonicalize().map_err(|_| {
            CompilerError::ModuleNotFound(
                format!(
                    "module not found: {} (resolved from {})",
                    path,
                    base.display()
                ),
                span_box(span),
            )
        })?;

        // 2. Check for circular imports
        if self.compiling_modules.contains(&canonical) {
            return Err(CompilerError::CircularImport(
                canonical.display().to_string(),
                span_box(span),
            ));
        }

        // 3. Load and parse the module
        let module = self
            .module_loader
            .load(&canonical)
            .map_err(CompilerError::ModuleLoadError)?;
        let module_stmts = module.program.stmts.clone();
        let exported_names = module.exported_names.clone();

        // 4. Validate that all requested names are exported
        for name in names {
            if !exported_names.contains(name) {
                let suggestion = crate::suggest::find_similar(
                    name,
                    exported_names.iter().map(|s| s.as_str()),
                    2,
                );
                let mut msg = format!("module \"{}\" does not export `{}`", path, name);
                if let Some(s) = suggestion {
                    msg.push_str(&format!(". Did you mean `{s}`?"));
                }
                return Err(CompilerError::CompileError(msg, span_box(span)));
            }
        }

        // 5. Check for conflicts with existing names
        for name in names {
            if let Some((existing_path, _)) = self.imported_names.get(name) {
                if *existing_path != canonical {
                    return Err(CompilerError::CompileError(
                        format!(
                            "`{}` already imported from \"{}\"",
                            name,
                            existing_path.display()
                        ),
                        span_box(span),
                    ));
                }
                // Same name from same module — already imported, skip
                continue;
            }
            if self.global_symbols.contains_key(name) {
                return Err(CompilerError::CompileError(
                    format!(
                        "cannot import `{}`: a global with this name already exists",
                        name
                    ),
                    span_box(span),
                ));
            }
        }

        // 6. Generate internal module prefix
        let internal_prefix = format!("__sel_{}", self.imported_aliases.len());

        // 7. Mark as compiling (for cycle detection)
        self.compiling_modules.insert(canonical.clone());

        // 8. Save and set module_prefix + base_path for name mangling
        let old_prefix = self.module_prefix.take();
        let old_base = self.base_path.take();
        self.module_prefix = Some(internal_prefix.clone());
        self.base_path = canonical.parent().map(|p| p.to_path_buf());

        // 9. Compile the module's statements
        for stmt in &module_stmts {
            self.compile_stmt(stmt)?;
        }

        // 10. Restore prefix and base_path, remove from compiling set
        self.module_prefix = old_prefix;
        self.base_path = old_base;
        self.compiling_modules.remove(&canonical);

        // 11. Copy only the requested names from mangled globals to user-visible globals
        for name in names {
            if self.imported_names.contains_key(name) {
                // Already imported from same module — skip
                continue;
            }

            let mangled = format!("{}::{}", internal_prefix, name);
            let mangled_entry = self.global_symbols.get(&mangled).ok_or_else(|| {
                CompilerError::CompileError(
                    format!(
                        "internal error: mangled global `{}` not found after module compilation",
                        mangled
                    ),
                    span_box(span),
                )
            })?;
            let global_idx = mangled_entry.index;
            let source_type_ann = mangled_entry.type_ann.clone();
            let source_is_mutable = mangled_entry.is_mutable;

            // Emit GetGlobal + DefGlobalLet to copy value to a new global slot
            let tmp_reg = self.alloc_reg()?;
            self.emit_abx(OpCode::GetGlobal, tmp_reg, global_idx)?;

            if self.next_global_idx == u16::MAX {
                self.free_reg(tmp_reg)?;
                return Err(CompilerError::TooManyConstants(span_box(span)));
            }
            let new_idx = self.next_global_idx;
            self.next_global_idx += 1;
            self.global_symbols.insert(
                name.clone(),
                crate::types::GlobalEntry {
                    index: new_idx,
                    type_ann: source_type_ann,
                    is_mutable: source_is_mutable,
                    param_names: None,
                },
            );
            self.emit_abx(OpCode::DefGlobalLet, tmp_reg, new_idx)?;
            self.free_reg(tmp_reg)?;

            self.imported_names
                .insert(name.clone(), (canonical.clone(), span.clone()));
        }

        Ok(())
    }
}
