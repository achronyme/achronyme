use constraints::poseidon::PoseidonParams;
use ir::IrLowering;
use memory::FieldElement;
use zkc::plonkish_backend::{PlonkishCompiler, PlonkishWitnessGenerator};
use zkc::r1cs_backend::R1CSCompiler;
use zkc::witness::WitnessGenerator;

use super::helpers::{
    build_merkle_tree, fe, merkle_inputs, merkle_proof, merkle_source, merkle_wit_names,
    plonkish_verify, r1cs_verify,
};

#[test]
fn merkle_depth8_256_leaves() {
    let params = PoseidonParams::bn254_t3();
    let leaves: Vec<FieldElement> = (0..256).map(|i| fe(i + 1000)).collect();
    let root = build_merkle_tree(&params, &leaves);

    let index = 137;
    let (siblings, directions) = merkle_proof(&params, &leaves, index);
    let inp = merkle_inputs(root, leaves[index], &siblings, &directions);

    let source = merkle_source(8);
    let wit_names = merkle_wit_names(8);
    let wit_refs: Vec<&str> = wit_names.iter().map(|s| s.as_str()).collect();

    let rc = r1cs_verify(&source, &["root"], &wit_refs, &inp);
    // 8 levels × (2 mux + 1 poseidon) + 1 assert_eq ≈ 8×(4+361) + 1 = 5793
    assert!(
        rc.cs.num_constraints() > 2900,
        "expected >2900 constraints for depth-8 Merkle, got {}",
        rc.cs.num_constraints()
    );
    plonkish_verify(&source, &["root"], &wit_refs, &inp);
}

#[test]
fn merkle_depth8_wrong_leaf_fails() {
    let params = PoseidonParams::bn254_t3();
    let leaves: Vec<FieldElement> = (0..256).map(|i| fe(i + 1000)).collect();
    let root = build_merkle_tree(&params, &leaves);

    let index = 137;
    let (siblings, directions) = merkle_proof(&params, &leaves, index);
    let wrong_leaf = fe(99999);
    let inp = merkle_inputs(root, wrong_leaf, &siblings, &directions);

    let source = merkle_source(8);
    let wit_names = merkle_wit_names(8);
    let wit_refs: Vec<&str> = wit_names.iter().map(|s| s.as_str()).collect();

    let mut program = IrLowering::lower_circuit(&source, &["root"], &wit_refs).unwrap();
    ir::passes::optimize(&mut program);
    let mut rc = R1CSCompiler::new();
    rc.compile_ir(&program).unwrap();
    let wg = WitnessGenerator::from_compiler(&rc);
    let w = wg.generate(&inp).unwrap();
    assert!(
        rc.cs.verify(&w).is_err(),
        "wrong leaf should fail verification"
    );

    // Also verify Plonkish rejects wrong leaf
    let program_p = IrLowering::lower_circuit(&source, &["root"], &wit_refs).unwrap();
    let mut pc = PlonkishCompiler::new();
    pc.compile_ir(&program_p).expect("compilation failed");
    let wg_p = PlonkishWitnessGenerator::from_compiler(&pc);
    wg_p.generate(&inp, &mut pc.system.assignments)
        .expect("witness gen failed");
    assert!(
        pc.system.verify().is_err(),
        "wrong leaf should fail Plonkish verification"
    );
}

#[test]
fn merkle_depth8_corner_positions() {
    let params = PoseidonParams::bn254_t3();
    let leaves: Vec<FieldElement> = (0..256).map(|i| fe(i + 500)).collect();
    let root = build_merkle_tree(&params, &leaves);

    let source = merkle_source(8);
    let wit_names = merkle_wit_names(8);
    let wit_refs: Vec<&str> = wit_names.iter().map(|s| s.as_str()).collect();

    for &index in &[0, 127, 128, 255] {
        let (siblings, directions) = merkle_proof(&params, &leaves, index);
        let inp = merkle_inputs(root, leaves[index], &siblings, &directions);
        r1cs_verify(&source, &["root"], &wit_refs, &inp);
        plonkish_verify(&source, &["root"], &wit_refs, &inp);
    }
}

#[test]
#[ignore]
fn merkle_depth16_65536_leaves() {
    let params = PoseidonParams::bn254_t3();
    let leaves: Vec<FieldElement> = (0..65536).map(|i| fe(i as u64)).collect();
    let root = build_merkle_tree(&params, &leaves);

    let index = 31337;
    let (siblings, directions) = merkle_proof(&params, &leaves, index);
    let inp = merkle_inputs(root, leaves[index], &siblings, &directions);

    let source = merkle_source(16);
    let wit_names = merkle_wit_names(16);
    let wit_refs: Vec<&str> = wit_names.iter().map(|s| s.as_str()).collect();

    let rc = r1cs_verify(&source, &["root"], &wit_refs, &inp);
    assert!(
        rc.cs.num_constraints() > 5800,
        "expected >5800 constraints for depth-16 Merkle, got {}",
        rc.cs.num_constraints()
    );
}

// ============================================================================
