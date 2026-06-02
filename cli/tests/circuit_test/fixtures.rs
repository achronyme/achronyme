use super::*;

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
    assert!(result.is_ok(), "mux circuit failed: {:?}", result.err());
}
