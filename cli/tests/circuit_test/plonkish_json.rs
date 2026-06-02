use super::*;

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
        None,
        false,
        "plonkish",
        PrimeId::Bn254,
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
        None,
        false,
        "plonkish",
        PrimeId::Bn254,
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
        None,
        false,
        "r1cs",
        PrimeId::Bn254,
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
