use cli::commands::ErrorFormat;
use memory::field::PrimeId;
use std::path::Path;

const EF: ErrorFormat = ErrorFormat::Human;

/// Resolve the path to a test fixture under test/modules/.
fn fixture(name: &str) -> String {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let workspace = Path::new(manifest_dir).parent().unwrap();
    workspace
        .join("test/modules")
        .join(name)
        .to_str()
        .unwrap()
        .to_string()
}

// ======================================================================
// VM (run) tests
// ======================================================================

#[test]
fn import_basic_function_call() {
    // utils.ach exports add(a,b) and PI=3; main_vm.ach imports and calls utils.add(1,2)
    let result = cli::commands::run::run_file(
        &fixture("main_vm.ach"),
        false,
        None,
        "r1cs",
        PrimeId::Bn254,
        None,
        false,
        false,
        EF,
    );
    assert!(result.is_ok(), "run_file failed: {:?}", result.err());
}

#[test]
fn import_constants_access() {
    let result = cli::commands::run::run_file(
        &fixture("test_constants.ach"),
        false,
        None,
        "r1cs",
        PrimeId::Bn254,
        None,
        false,
        false,
        EF,
    );
    assert!(result.is_ok(), "run_file failed: {:?}", result.err());
}

#[test]
fn import_internal_helper_function() {
    // internal_helper.ach: helper() is not exported, pub_fn() is and calls helper()
    let result = cli::commands::run::run_file(
        &fixture("test_internal.ach"),
        false,
        None,
        "r1cs",
        PrimeId::Bn254,
        None,
        false,
        false,
        EF,
    );
    assert!(result.is_ok(), "run_file failed: {:?}", result.err());
}

#[test]
fn import_transitive() {
    // c.ach → b.ach → a.ach (transitive chain)
    let result = cli::commands::run::run_file(
        &fixture("transitive/c.ach"),
        false,
        None,
        "r1cs",
        PrimeId::Bn254,
        None,
        false,
        false,
        EF,
    );
    assert!(result.is_ok(), "run_file failed: {:?}", result.err());
}

#[test]
fn import_circular_detected() {
    let result = cli::commands::run::run_file(
        &fixture("circular_a.ach"),
        false,
        None,
        "r1cs",
        PrimeId::Bn254,
        None,
        false,
        false,
        EF,
    );
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("circular import"),
        "expected circular import error, got: {err}"
    );
}

#[test]
fn import_module_not_found() {
    let result = cli::commands::run::run_file(
        &fixture("test_not_found.ach"),
        false,
        None,
        "r1cs",
        PrimeId::Bn254,
        None,
        false,
        false,
        EF,
    );
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("module not found"),
        "expected module not found error, got: {err}"
    );
}

#[test]
fn import_no_exports_module() {
    // Importing a module with no exports should work (empty namespace)
    let result = cli::commands::run::run_file(
        &fixture("test_no_exports.ach"),
        false,
        None,
        "r1cs",
        PrimeId::Bn254,
        None,
        false,
        false,
        EF,
    );
    assert!(result.is_ok(), "run_file failed: {:?}", result.err());
}

// ======================================================================
// Selective imports (beta.6)
// ======================================================================

#[test]
fn selective_import_basic() {
    let result = cli::commands::run::run_file(
        &fixture("test_selective_import.ach"),
        false,
        None,
        "r1cs",
        PrimeId::Bn254,
        None,
        false,
        false,
        EF,
    );
    assert!(result.is_ok(), "run_file failed: {:?}", result.err());
}

#[test]
fn export_list_via_namespace() {
    let result = cli::commands::run::run_file(
        &fixture("test_export_list.ach"),
        false,
        None,
        "r1cs",
        PrimeId::Bn254,
        None,
        false,
        false,
        EF,
    );
    assert!(result.is_ok(), "run_file failed: {:?}", result.err());
}

#[test]
fn mixed_selective_and_namespace_import() {
    let result = cli::commands::run::run_file(
        &fixture("test_mixed_imports.ach"),
        false,
        None,
        "r1cs",
        PrimeId::Bn254,
        None,
        false,
        false,
        EF,
    );
    assert!(result.is_ok(), "run_file failed: {:?}", result.err());
}

#[test]
fn selective_import_nonexistent_name() {
    let result = cli::commands::run::run_file(
        &fixture("test_selective_not_exported.ach"),
        false,
        None,
        "r1cs",
        PrimeId::Bn254,
        None,
        false,
        false,
        EF,
    );
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("does not export"),
        "expected 'does not export' error, got: {err}"
    );
}

#[test]
fn duplicate_export_detected() {
    let result = cli::commands::run::run_file(
        &fixture("test_duplicate_export.ach"),
        false,
        None,
        "r1cs",
        PrimeId::Bn254,
        None,
        false,
        false,
        EF,
    );
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("exported more than once"),
        "expected 'exported more than once' error, got: {err}"
    );
}

#[test]
fn export_list_undefined_name() {
    let result = cli::commands::run::run_file(
        &fixture("test_bad_export_list.ach"),
        false,
        None,
        "r1cs",
        PrimeId::Bn254,
        None,
        false,
        false,
        EF,
    );
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("not defined in this module"),
        "expected 'not defined in this module' error, got: {err}"
    );
}

// ======================================================================
// W005: Unused selective imports
// ======================================================================

/// Helper: compile a fixture file and return warning messages as strings.
fn compile_fixture_warning_messages(name: &str) -> Vec<String> {
    let path = fixture(name);
    let content = std::fs::read_to_string(&path).unwrap();
    let mut compiler = compiler::Compiler::new();
    let source_path = Path::new(&path);
    compiler.base_path = Some(source_path.parent().unwrap_or(Path::new(".")).to_path_buf());
    let _ = compiler.compile(&content);
    compiler
        .take_warnings()
        .into_iter()
        .map(|w| w.message)
        .collect()
}

#[test]
fn w005_unused_selective_import() {
    // imports { add, PI } but only uses add → PI should trigger W005
    let ws = compile_fixture_warning_messages("test_w005_unused.ach");
    assert!(
        ws.iter()
            .any(|m| m.contains("imported name `PI` is never used")),
        "expected W005 for unused `PI`, got: {:?}",
        ws
    );
    // add IS used, so no warning for it
    assert!(
        !ws.iter().any(|m| m.contains("imported name `add`")),
        "should NOT warn about `add` which is used"
    );
}

#[test]
fn w005_all_used_no_warning() {
    // imports { add, PI } and uses both → no W005
    let ws = compile_fixture_warning_messages("test_w005_all_used.ach");
    let w005s: Vec<_> = ws.iter().filter(|m| m.contains("imported name")).collect();
    assert!(
        w005s.is_empty(),
        "expected no W005 warnings, got: {:?}",
        w005s
    );
}

#[test]
fn w005_underscore_suppresses_warning() {
    // imports { add, _PI } but only uses add → _PI should NOT trigger W005
    let ws = compile_fixture_warning_messages("test_w005_underscore.ach");
    assert!(
        !ws.iter().any(|m| m.contains("_PI")),
        "underscore-prefixed import should suppress W005, got: {:?}",
        ws
    );
}

// ======================================================================
// Circuit (IR) tests
// ======================================================================

#[test]
fn circuit_import_with_poseidon() {
    let path = fixture("main_circuit.ach");
    let tmpdir = tempfile::tempdir().unwrap();
    let r1cs = tmpdir.path().join("test.r1cs");
    let wtns = tmpdir.path().join("test.wtns");

    let result = cli::commands::circuit::circuit_command(
        &path,
        r1cs.to_str().unwrap(),
        wtns.to_str().unwrap(),
        None,
        None,
        false,
        "r1cs",
        PrimeId::Bn254,
        false,
        None,
        None,
        false,
        false,
        EF,
    );
    assert!(result.is_ok(), "circuit_command failed: {:?}", result.err());
    assert!(r1cs.exists(), "R1CS file was not created");
}

#[test]
fn circuit_import_not_found() {
    use std::io::Write;
    let tmpdir = tempfile::tempdir().unwrap();
    let main_path = tmpdir.path().join("main.ach");
    std::fs::write(
        &main_path,
        "import \"./nonexistent.ach\" as m\n\
         circuit test(x: Public) { assert_eq(x, x) }\n",
    )
    .unwrap();

    let r1cs = tmpdir.path().join("out.r1cs");
    let wtns = tmpdir.path().join("out.wtns");
    let result = cli::commands::circuit::circuit_command(
        main_path.to_str().unwrap(),
        r1cs.to_str().unwrap(),
        wtns.to_str().unwrap(),
        None,
        None,
        false,
        "r1cs",
        PrimeId::Bn254,
        false,
        None,
        None,
        false,
        false,
        EF,
    );
    assert!(result.is_err(), "should fail for missing module");
}

#[test]
fn circuit_import_self_circular_detected() {
    let tmpdir = tempfile::tempdir().unwrap();

    // a.ach imports itself — triggers circular detection
    std::fs::write(
        tmpdir.path().join("a.ach"),
        "import \"./a.ach\" as self_ref\n\
         circuit test(x: Public) { assert_eq(x, x) }\n",
    )
    .unwrap();

    let main_path = tmpdir.path().join("a.ach");
    let r1cs = tmpdir.path().join("out.r1cs");
    let wtns = tmpdir.path().join("out.wtns");
    let result = cli::commands::circuit::circuit_command(
        main_path.to_str().unwrap(),
        r1cs.to_str().unwrap(),
        wtns.to_str().unwrap(),
        None,
        None,
        false,
        "r1cs",
        PrimeId::Bn254,
        false,
        None,
        None,
        false,
        false,
        EF,
    );
    assert!(result.is_err(), "should detect circular import");
    let err_msg = format!("{:?}", result.unwrap_err());
    assert!(
        err_msg.contains("circular") || err_msg.contains("Circular"),
        "error should mention circular import, got: {err_msg}"
    );
}
