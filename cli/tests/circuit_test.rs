use std::io::Write;

use cli::commands::ErrorFormat;
use tempfile::NamedTempFile;

const EF: ErrorFormat = ErrorFormat::Human;

fn fixture(name: &str) -> String {
    format!(
        "{}/test/circuit/{name}",
        env!("CARGO_MANIFEST_DIR").trim_end_matches("/cli")
    )
}

fn write_temp_source(content: &str) -> NamedTempFile {
    let mut f = NamedTempFile::with_suffix(".ach").unwrap();
    f.write_all(content.as_bytes()).unwrap();
    f.flush().unwrap();
    f
}

// ======================================================================
// T14: Basic circuit compilation (no inputs)
// ======================================================================

#[test]
fn circuit_r1cs_basic_compilation() {
    let tmpdir = tempfile::tempdir().unwrap();
    let r1cs = tmpdir.path().join("out.r1cs");
    let wtns = tmpdir.path().join("out.wtns");

    let result = cli::commands::circuit::circuit_command(
        &fixture("basic_arithmetic.ach"),
        r1cs.to_str().unwrap(),
        wtns.to_str().unwrap(),
        None,
        false,
        "r1cs",
        false,
        None,
        None,
        false,
        false,
        EF,
    );
    assert!(result.is_ok(), "circuit r1cs failed: {:?}", result.err());
    assert!(r1cs.exists(), "R1CS file was not created");
    // Without --inputs, no .wtns should be created
    assert!(!wtns.exists(), "wtns should not be created without inputs");
}

#[test]
fn circuit_plonkish_basic_compilation() {
    let tmpdir = tempfile::tempdir().unwrap();
    let r1cs = tmpdir.path().join("out.r1cs");
    let wtns = tmpdir.path().join("out.wtns");

    let result = cli::commands::circuit::circuit_command(
        &fixture("basic_arithmetic.ach"),
        r1cs.to_str().unwrap(),
        wtns.to_str().unwrap(),
        None,
        false,
        "plonkish",
        false,
        None,
        None,
        false,
        false,
        EF,
    );
    assert!(
        result.is_ok(),
        "circuit plonkish failed: {:?}",
        result.err()
    );
}

#[test]
fn circuit_nonexistent_file_error() {
    let tmpdir = tempfile::tempdir().unwrap();
    let result = cli::commands::circuit::circuit_command(
        "/tmp/nonexistent_achronyme_test.ach",
        tmpdir.path().join("out.r1cs").to_str().unwrap(),
        tmpdir.path().join("out.wtns").to_str().unwrap(),
        None,
        false,
        "r1cs",
        false,
        None,
        None,
        false,
        false,
        EF,
    );
    assert!(result.is_err(), "nonexistent file should error");
}

#[test]
fn circuit_invalid_source_error() {
    let src = write_temp_source("let = ???");

    let tmpdir = tempfile::tempdir().unwrap();
    let result = cli::commands::circuit::circuit_command(
        src.path().to_str().unwrap(),
        tmpdir.path().join("out.r1cs").to_str().unwrap(),
        tmpdir.path().join("out.wtns").to_str().unwrap(),
        None,
        false,
        "r1cs",
        false,
        None,
        None,
        false,
        false,
        EF,
    );
    assert!(result.is_err(), "invalid source should error");
}

// ======================================================================
// T14: Circuit with witness generation and verification
// ======================================================================

#[test]
fn circuit_r1cs_with_witness() {
    let tmpdir = tempfile::tempdir().unwrap();
    let r1cs = tmpdir.path().join("out.r1cs");
    let wtns = tmpdir.path().join("out.wtns");

    let result = cli::commands::circuit::circuit_command(
        &fixture("basic_arithmetic.ach"),
        r1cs.to_str().unwrap(),
        wtns.to_str().unwrap(),
        Some("out=42,a=6,b=7"),
        false,
        "r1cs",
        false,
        None,
        None,
        false,
        false,
        EF,
    );
    assert!(
        result.is_ok(),
        "circuit with witness failed: {:?}",
        result.err()
    );
    assert!(r1cs.exists(), "R1CS file was not created");
    assert!(wtns.exists(), "wtns file was not created");

    // Verify file sizes are non-trivial
    let r1cs_size = std::fs::metadata(&r1cs).unwrap().len();
    let wtns_size = std::fs::metadata(&wtns).unwrap().len();
    assert!(r1cs_size > 0, "R1CS file is empty");
    assert!(wtns_size > 0, "wtns file is empty");
}

#[test]
fn circuit_plonkish_with_witness() {
    let tmpdir = tempfile::tempdir().unwrap();
    let r1cs = tmpdir.path().join("out.r1cs");
    let wtns = tmpdir.path().join("out.wtns");

    let result = cli::commands::circuit::circuit_command(
        &fixture("basic_arithmetic.ach"),
        r1cs.to_str().unwrap(),
        wtns.to_str().unwrap(),
        Some("out=42,a=6,b=7"),
        false,
        "plonkish",
        false,
        None,
        None,
        false,
        false,
        EF,
    );
    assert!(
        result.is_ok(),
        "plonkish with witness failed: {:?}",
        result.err()
    );
}

#[test]
fn circuit_r1cs_wrong_witness_rejected() {
    let tmpdir = tempfile::tempdir().unwrap();
    let r1cs = tmpdir.path().join("out.r1cs");
    let wtns = tmpdir.path().join("out.wtns");

    // out=99 but a*b=42, constraint violation
    let result = cli::commands::circuit::circuit_command(
        &fixture("basic_arithmetic.ach"),
        r1cs.to_str().unwrap(),
        wtns.to_str().unwrap(),
        Some("out=99,a=6,b=7"),
        false,
        "r1cs",
        false,
        None,
        None,
        false,
        false,
        EF,
    );
    assert!(result.is_err(), "wrong witness should fail verification");
}

// ======================================================================
// T14: Circuit with specific fixtures
// ======================================================================

#[test]
fn circuit_r1cs_poseidon() {
    use constraints::poseidon::{poseidon_hash, PoseidonParams};

    let params = PoseidonParams::bn254_t3();
    let expected = poseidon_hash(
        &params,
        memory::FieldElement::from_u64(1),
        memory::FieldElement::from_u64(2),
    );
    let expected_dec = format!("{}", expected);

    let tmpdir = tempfile::tempdir().unwrap();
    let r1cs = tmpdir.path().join("out.r1cs");
    let wtns = tmpdir.path().join("out.wtns");

    let inputs = format!("expected={expected_dec},a=1,b=2,c=3");
    let result = cli::commands::circuit::circuit_command(
        &fixture("poseidon.ach"),
        r1cs.to_str().unwrap(),
        wtns.to_str().unwrap(),
        Some(&inputs),
        false,
        "r1cs",
        false,
        None,
        None,
        false,
        false,
        EF,
    );
    assert!(
        result.is_ok(),
        "poseidon circuit failed: {:?}",
        result.err()
    );
}

#[test]
fn circuit_r1cs_range_check() {
    let tmpdir = tempfile::tempdir().unwrap();
    let r1cs = tmpdir.path().join("out.r1cs");
    let wtns = tmpdir.path().join("out.wtns");

    let result = cli::commands::circuit::circuit_command(
        &fixture("range_check.ach"),
        r1cs.to_str().unwrap(),
        wtns.to_str().unwrap(),
        Some("x=200,y=60000"),
        false,
        "r1cs",
        false,
        None,
        None,
        false,
        false,
        EF,
    );
    assert!(
        result.is_ok(),
        "range_check circuit failed: {:?}",
        result.err()
    );
}

#[test]
fn circuit_r1cs_mux() {
    let tmpdir = tempfile::tempdir().unwrap();
    let r1cs = tmpdir.path().join("out.r1cs");
    let wtns = tmpdir.path().join("out.wtns");

    // mux(1, 42, 99) = 42
    let result = cli::commands::circuit::circuit_command(
        &fixture("mux.ach"),
        r1cs.to_str().unwrap(),
        wtns.to_str().unwrap(),
        Some("out=42,cond=1,a=42,b=99"),
        false,
        "r1cs",
        false,
        None,
        None,
        false,
        false,
        EF,
    );
    assert!(result.is_ok(), "mux circuit failed: {:?}", result.err());
}

// ======================================================================
// T14: CLI flags
// ======================================================================

#[test]
fn circuit_no_optimize_flag() {
    let tmpdir = tempfile::tempdir().unwrap();
    let r1cs = tmpdir.path().join("out.r1cs");
    let wtns = tmpdir.path().join("out.wtns");

    let result = cli::commands::circuit::circuit_command(
        &fixture("basic_arithmetic.ach"),
        r1cs.to_str().unwrap(),
        wtns.to_str().unwrap(),
        None,
        true, // --no-optimize
        "r1cs",
        false,
        None,
        None,
        false,
        false,
        EF,
    );
    assert!(
        result.is_ok(),
        "circuit with --no-optimize failed: {:?}",
        result.err()
    );
    assert!(r1cs.exists());
}

#[test]
fn circuit_unknown_backend_error() {
    let tmpdir = tempfile::tempdir().unwrap();
    let result = cli::commands::circuit::circuit_command(
        &fixture("basic_arithmetic.ach"),
        tmpdir.path().join("out.r1cs").to_str().unwrap(),
        tmpdir.path().join("out.wtns").to_str().unwrap(),
        None,
        false,
        "unknown_backend",
        false,
        None,
        None,
        false,
        false,
        EF,
    );
    assert!(result.is_err(), "unknown backend should error");
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("unknown backend"),
        "error should mention unknown backend, got: {err}"
    );
}

#[test]
fn circuit_solidity_with_plonkish_rejected() {
    let tmpdir = tempfile::tempdir().unwrap();
    let result = cli::commands::circuit::circuit_command(
        &fixture("basic_arithmetic.ach"),
        tmpdir.path().join("out.r1cs").to_str().unwrap(),
        tmpdir.path().join("out.wtns").to_str().unwrap(),
        None,
        false,
        "plonkish",
        false,
        Some("verifier.sol"),
        None,
        false,
        false,
        EF,
    );
    assert!(
        result.is_err(),
        "--solidity with plonkish should be rejected"
    );
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("r1cs"),
        "error should mention r1cs requirement, got: {err}"
    );
}

#[test]
fn circuit_prove_without_inputs_rejected() {
    let tmpdir = tempfile::tempdir().unwrap();
    let result = cli::commands::circuit::circuit_command(
        &fixture("basic_arithmetic.ach"),
        tmpdir.path().join("out.r1cs").to_str().unwrap(),
        tmpdir.path().join("out.wtns").to_str().unwrap(),
        None,
        false,
        "plonkish",
        true, // --prove
        None,
        None,
        false,
        false,
        EF,
    );
    assert!(
        result.is_err(),
        "--prove without --inputs should be rejected"
    );
}

// ======================================================================
// W5: --plonkish-json integration tests
// ======================================================================

#[test]
fn circuit_plonkish_json_with_inputs() {
    let tmpdir = tempfile::tempdir().unwrap();
    let r1cs = tmpdir.path().join("out.r1cs");
    let wtns = tmpdir.path().join("out.wtns");
    let json_path = tmpdir.path().join("circuit.json");

    let result = cli::commands::circuit::circuit_command(
        &fixture("basic_arithmetic.ach"),
        r1cs.to_str().unwrap(),
        wtns.to_str().unwrap(),
        Some("out=42,a=6,b=7"),
        false,
        "plonkish",
        false,
        None,
        Some(json_path.to_str().unwrap()),
        false,
        false,
        EF,
    );
    assert!(
        result.is_ok(),
        "plonkish --plonkish-json with inputs failed: {:?}",
        result.err()
    );
    assert!(json_path.exists(), "JSON file was not created");

    let contents = std::fs::read_to_string(&json_path).unwrap();
    constraints::validate_plonkish_json(&contents).expect("exported JSON failed validation");
}

#[test]
fn circuit_plonkish_json_without_inputs() {
    let tmpdir = tempfile::tempdir().unwrap();
    let r1cs = tmpdir.path().join("out.r1cs");
    let wtns = tmpdir.path().join("out.wtns");
    let json_path = tmpdir.path().join("circuit.json");

    let result = cli::commands::circuit::circuit_command(
        &fixture("basic_arithmetic.ach"),
        r1cs.to_str().unwrap(),
        wtns.to_str().unwrap(),
        None,
        false,
        "plonkish",
        false,
        None,
        Some(json_path.to_str().unwrap()),
        false,
        false,
        EF,
    );
    assert!(
        result.is_ok(),
        "plonkish --plonkish-json without inputs failed: {:?}",
        result.err()
    );
    assert!(json_path.exists(), "JSON file was not created");

    let contents = std::fs::read_to_string(&json_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&contents).unwrap();
    assert_eq!(parsed["format"], "achronyme-plonkish-v1");
}

#[test]
fn circuit_plonkish_json_with_r1cs_rejected() {
    let tmpdir = tempfile::tempdir().unwrap();
    let json_path = tmpdir.path().join("circuit.json");

    let result = cli::commands::circuit::circuit_command(
        &fixture("basic_arithmetic.ach"),
        tmpdir.path().join("out.r1cs").to_str().unwrap(),
        tmpdir.path().join("out.wtns").to_str().unwrap(),
        None,
        false,
        "r1cs",
        false,
        None,
        Some(json_path.to_str().unwrap()),
        false,
        false,
        EF,
    );
    assert!(
        result.is_err(),
        "--plonkish-json with r1cs backend should be rejected"
    );
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("plonkish"),
        "error should mention plonkish requirement, got: {err}"
    );
}

// ======================================================================
// T14: Error format tests for circuit command
// ======================================================================

#[test]
fn circuit_json_error_format() {
    let src = write_temp_source("let = ???");

    let tmpdir = tempfile::tempdir().unwrap();
    let result = cli::commands::circuit::circuit_command(
        src.path().to_str().unwrap(),
        tmpdir.path().join("out.r1cs").to_str().unwrap(),
        tmpdir.path().join("out.wtns").to_str().unwrap(),
        None,
        false,
        "r1cs",
        false,
        None,
        None,
        false,
        false,
        ErrorFormat::Json,
    );
    assert!(result.is_err());
}

#[test]
fn circuit_short_error_format() {
    let src = write_temp_source("let = ???");

    let tmpdir = tempfile::tempdir().unwrap();
    let result = cli::commands::circuit::circuit_command(
        src.path().to_str().unwrap(),
        tmpdir.path().join("out.r1cs").to_str().unwrap(),
        tmpdir.path().join("out.wtns").to_str().unwrap(),
        None,
        false,
        "r1cs",
        false,
        None,
        None,
        false,
        false,
        ErrorFormat::Short,
    );
    assert!(result.is_err());
}

// ======================================================================
// assert_eq with custom message
// ======================================================================

#[test]
fn circuit_assert_eq_with_message_compiles() {
    let tmpdir = tempfile::tempdir().unwrap();
    let r1cs = tmpdir.path().join("out.r1cs");
    let wtns = tmpdir.path().join("out.wtns");

    let result = cli::commands::circuit::circuit_command(
        &fixture("assert_message.ach"),
        r1cs.to_str().unwrap(),
        wtns.to_str().unwrap(),
        None,
        false,
        "r1cs",
        false,
        None,
        None,
        false,
        false,
        EF,
    );
    assert!(
        result.is_ok(),
        "assert_eq with message should compile: {:?}",
        result.err()
    );
}

#[test]
fn circuit_assert_eq_message_shown_on_failure() {
    let src = write_temp_source(
        "circuit test_msg(x: Public, y: Witness) {\n\
         assert_eq(x, y, \"values must be equal\")\n\
         }",
    );
    let tmpdir = tempfile::tempdir().unwrap();
    let r1cs = tmpdir.path().join("out.r1cs");
    let wtns = tmpdir.path().join("out.wtns");

    let result = cli::commands::circuit::circuit_command(
        src.path().to_str().unwrap(),
        r1cs.to_str().unwrap(),
        wtns.to_str().unwrap(),
        Some("x=1,y=2"),
        false,
        "r1cs",
        false,
        None,
        None,
        false,
        false,
        EF,
    );
    let err = result.unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("values must be equal"),
        "expected custom message in error, got: {msg}"
    );
}
