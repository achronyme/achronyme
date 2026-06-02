use constraints::poseidon::{poseidon_hash, PoseidonParams};
use ir::IrLowering;
use memory::FieldElement;
use zkc::plonkish_backend::{PlonkishCompiler, PlonkishWitnessGenerator};
use zkc::r1cs_backend::R1CSCompiler;
use zkc::witness::WitnessGenerator;

use super::helpers::{
    build_merkle_tree, fe, inputs, merkle_inputs, merkle_proof, merkle_source, merkle_wit_names,
};

#[test]
fn negative_wrong_poseidon_preimage() {
    let params = PoseidonParams::bn254_t3();
    let expected = poseidon_hash(&params, fe(1), fe(2));

    let source = "let h = poseidon(a, b)\nassert_eq(h, expected)";
    let inp = inputs(&[("expected", expected), ("a", fe(99)), ("b", fe(88))]);

    let mut program = IrLowering::lower_circuit(source, &["expected"], &["a", "b"]).unwrap();
    ir::passes::optimize(&mut program);
    let mut rc = R1CSCompiler::new();
    rc.compile_ir(&program).unwrap();
    let wg = WitnessGenerator::from_compiler(&rc);
    let w = wg.generate(&inp).unwrap();
    assert!(
        rc.cs.verify(&w).is_err(),
        "wrong Poseidon preimage should fail"
    );

    // Also verify Plonkish rejects wrong preimage
    let program_p = IrLowering::lower_circuit(source, &["expected"], &["a", "b"]).unwrap();
    let mut pc = PlonkishCompiler::new();
    pc.compile_ir(&program_p).expect("compilation failed");
    let wg_p = PlonkishWitnessGenerator::from_compiler(&pc);
    wg_p.generate(&inp, &mut pc.system.assignments)
        .expect("witness gen failed");
    assert!(
        pc.system.verify().is_err(),
        "wrong Poseidon preimage should fail Plonkish verification"
    );
}

#[test]
fn negative_assert_false() {
    let source = "assert(flag)";
    let inp = inputs(&[("flag", fe(0))]);

    let mut program = IrLowering::lower_circuit(source, &[], &["flag"]).unwrap();
    ir::passes::optimize(&mut program);
    let mut rc = R1CSCompiler::new();
    let err = rc.compile_ir_with_witness(&program, &inp);
    assert!(err.is_err(), "assert(0) should fail");

    // Also verify Plonkish rejects assert(0)
    let program_p = IrLowering::lower_circuit(source, &[], &["flag"]).unwrap();
    let mut pc = PlonkishCompiler::new();
    let err = pc.compile_ir_with_witness(&program_p, &inp);
    assert!(err.is_err(), "assert(0) should fail in Plonkish");
}

#[test]
fn negative_comparison_wrong() {
    let source = "let r = a >= b\nassert(r)";
    let inp = inputs(&[("a", fe(3)), ("b", fe(7))]);

    let mut program = IrLowering::lower_circuit(source, &[], &["a", "b"]).unwrap();
    ir::passes::optimize(&mut program);
    let mut rc = R1CSCompiler::new();
    let err = rc.compile_ir_with_witness(&program, &inp);
    assert!(err.is_err(), "3 >= 7 should fail assertion");

    // Also verify Plonkish rejects wrong comparison
    let program_p = IrLowering::lower_circuit(source, &[], &["a", "b"]).unwrap();
    let mut pc = PlonkishCompiler::new();
    let err = pc.compile_ir_with_witness(&program_p, &inp);
    assert!(err.is_err(), "3 >= 7 should fail Plonkish assertion");
}

#[test]
fn negative_recursion_rejected() {
    let source = r#"
fn f(x) { f(x) }
assert_eq(f(a), out)
"#;
    let result = IrLowering::<memory::Bn254Fr>::lower_circuit(source, &["out"], &["a"]);
    assert!(result.is_err(), "recursion should be rejected at lowering");
}

#[test]
fn negative_merkle_wrong_sibling() {
    let params = PoseidonParams::bn254_t3();
    let leaves: Vec<FieldElement> = (0..8).map(|i| fe(i + 100)).collect();
    let root = build_merkle_tree(&params, &leaves);

    let index = 2;
    let (mut siblings, directions) = merkle_proof(&params, &leaves, index);
    siblings[0] = fe(99999); // corrupt sibling
    let inp = merkle_inputs(root, leaves[index], &siblings, &directions);

    let source = merkle_source(3);
    let wit_names = merkle_wit_names(3);
    let wit_refs: Vec<&str> = wit_names.iter().map(|s| s.as_str()).collect();

    let mut program = IrLowering::lower_circuit(&source, &["root"], &wit_refs).unwrap();
    ir::passes::optimize(&mut program);
    let mut rc = R1CSCompiler::new();
    rc.compile_ir(&program).unwrap();
    let wg = WitnessGenerator::from_compiler(&rc);
    let w = wg.generate(&inp).unwrap();
    assert!(
        rc.cs.verify(&w).is_err(),
        "wrong sibling should fail verification"
    );

    // Also verify Plonkish rejects wrong sibling
    let program_p = IrLowering::lower_circuit(&source, &["root"], &wit_refs).unwrap();
    let mut pc = PlonkishCompiler::new();
    pc.compile_ir(&program_p).expect("compilation failed");
    let wg_p = PlonkishWitnessGenerator::from_compiler(&pc);
    wg_p.generate(&inp, &mut pc.system.assignments)
        .expect("witness gen failed");
    assert!(
        pc.system.verify().is_err(),
        "wrong sibling should fail Plonkish verification"
    );
}

#[test]
fn negative_division_by_zero() {
    let source = "let r = x / y\nassert_eq(r, out)";
    let inp = inputs(&[("x", fe(42)), ("y", fe(0)), ("out", fe(0))]);

    let mut program = IrLowering::lower_circuit(source, &["out"], &["x", "y"]).unwrap();
    ir::passes::optimize(&mut program);
    let mut rc = R1CSCompiler::new();
    let err = rc.compile_ir_with_witness(&program, &inp);
    assert!(err.is_err(), "division by zero should fail");

    // Also verify Plonkish rejects division by zero
    let program_p = IrLowering::lower_circuit(source, &["out"], &["x", "y"]).unwrap();
    let mut pc = PlonkishCompiler::new();
    let err = pc.compile_ir_with_witness(&program_p, &inp);
    assert!(err.is_err(), "division by zero should fail in Plonkish");
}
