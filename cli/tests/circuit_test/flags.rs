use super::*;

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
        None,
        true, // --no-optimize
        "r1cs",
        PrimeId::Bn254,
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
        None,
        false,
        "unknown_backend",
        PrimeId::Bn254,
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
        None,
        false,
        "plonkish",
        PrimeId::Bn254,
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
        None,
        false,
        "plonkish",
        PrimeId::Bn254,
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
