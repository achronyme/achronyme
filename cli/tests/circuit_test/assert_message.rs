use super::*;

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
    let err = result.unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("values must be equal"),
        "expected custom message in error, got: {msg}"
    );
}
