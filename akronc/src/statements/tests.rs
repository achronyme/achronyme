//! Integration tests for the statements dispatch layer.
//!
//! These tests construct a full `Compiler` and exercise the whole
//! import pipeline (namespace + selective + circuit), not individual
//! submodules in isolation. They live here rather than inside any
//! single submodule because they straddle `imports.rs`, `circuit.rs`,
//! and `circom_imports.rs`.

use super::circom_imports;
use crate::codegen::Compiler;
use crate::error::CompilerError;

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

// --- build_circom_imports_for_outer_scope ---

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
