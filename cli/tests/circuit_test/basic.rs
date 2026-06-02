use super::*;

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
        None,
        false,
        "plonkish",
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
    assert!(result.is_err(), "invalid source should error");
}
