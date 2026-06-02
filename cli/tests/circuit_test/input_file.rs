use super::*;

#[test]
fn circuit_input_file_toml() {
    let tmpdir = tempfile::tempdir().unwrap();
    let r1cs = tmpdir.path().join("out.r1cs");
    let wtns = tmpdir.path().join("out.wtns");
    let toml_path = tmpdir.path().join("inputs.toml");
    std::fs::write(&toml_path, "out = \"42\"\na = \"6\"\nb = \"7\"\n").unwrap();

    let result = cli::commands::circuit::circuit_command(
        &fixture("basic_arithmetic.ach"),
        r1cs.to_str().unwrap(),
        wtns.to_str().unwrap(),
        None,
        Some(toml_path.to_str().unwrap()),
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
    assert!(result.is_ok(), "input-file failed: {:?}", result.err());
    assert!(wtns.exists(), "wtns should be created with input-file");
}

#[test]
fn circuit_inputs_and_input_file_mutually_exclusive() {
    let tmpdir = tempfile::tempdir().unwrap();
    let toml_path = tmpdir.path().join("inputs.toml");
    std::fs::write(&toml_path, "x = \"1\"\n").unwrap();

    let result = cli::commands::circuit::circuit_command(
        &fixture("basic_arithmetic.ach"),
        tmpdir.path().join("out.r1cs").to_str().unwrap(),
        tmpdir.path().join("out.wtns").to_str().unwrap(),
        Some("out=42,a=6,b=7"),
        Some(toml_path.to_str().unwrap()),
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
        result.is_err(),
        "should reject both --inputs and --input-file"
    );
    let msg = format!("{:?}", result.unwrap_err());
    assert!(msg.contains("mutually exclusive"), "got: {msg}");
}
