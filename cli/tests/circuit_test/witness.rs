use super::*;

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
    assert!(result.is_err(), "wrong witness should fail verification");
}
