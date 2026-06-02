use super::*;

#[test]
fn circuit_json_error_format() {
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
        None,
        false,
        "r1cs",
        PrimeId::Bn254,
        false,
        None,
        None,
        false,
        false,
        ErrorFormat::Short,
    );
    assert!(result.is_err());
}
