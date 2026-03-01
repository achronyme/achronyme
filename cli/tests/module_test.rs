use std::path::Path;

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
    let result = cli::commands::run::run_file(&fixture("main_vm.ach"), false, None, "r1cs");
    assert!(result.is_ok(), "run_file failed: {:?}", result.err());
}

#[test]
fn import_constants_access() {
    let result = cli::commands::run::run_file(&fixture("test_constants.ach"), false, None, "r1cs");
    assert!(result.is_ok(), "run_file failed: {:?}", result.err());
}

#[test]
fn import_internal_helper_function() {
    // internal_helper.ach: helper() is not exported, pub_fn() is and calls helper()
    let result = cli::commands::run::run_file(&fixture("test_internal.ach"), false, None, "r1cs");
    assert!(result.is_ok(), "run_file failed: {:?}", result.err());
}

#[test]
fn import_transitive() {
    // c.ach → b.ach → a.ach (transitive chain)
    let result = cli::commands::run::run_file(&fixture("transitive/c.ach"), false, None, "r1cs");
    assert!(result.is_ok(), "run_file failed: {:?}", result.err());
}

#[test]
fn import_circular_detected() {
    let result = cli::commands::run::run_file(&fixture("circular_a.ach"), false, None, "r1cs");
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("CircularImport"),
        "expected CircularImport error, got: {err}"
    );
}

#[test]
fn import_module_not_found() {
    let result = cli::commands::run::run_file(&fixture("test_not_found.ach"), false, None, "r1cs");
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("ModuleNotFound"),
        "expected ModuleNotFound error, got: {err}"
    );
}

#[test]
fn import_no_exports_module() {
    // Importing a module with no exports should work (empty namespace)
    let result = cli::commands::run::run_file(&fixture("test_no_exports.ach"), false, None, "r1cs");
    assert!(result.is_ok(), "run_file failed: {:?}", result.err());
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
        &[],
        &[],
        None,
        false,
        "r1cs",
        false,
        None,
    );
    assert!(result.is_ok(), "circuit_command failed: {:?}", result.err());
    assert!(r1cs.exists(), "R1CS file was not created");
}
