use constraints::{write_r1cs, write_wtns};
use ir::passes::bool_prop::compute_proven_boolean;
use ir::IrLowering;
use memory::field::PrimeId;
use zkc::r1cs_backend::R1CSCompiler;

use super::helpers::*;

#[test]
fn merkle_depth2_export_roundtrip() {
    let p = params();
    let leaves = make_leaves(2, 500);
    let root = build_merkle_tree(&p, &leaves);
    let (sibs, dirs) = merkle_proof(&p, &leaves, 0);
    let inputs = merkle_inputs(root, leaves[0], &sibs, &dirs);

    let source = merkle_source(2);
    let (_, _, mut program) =
        IrLowering::lower_self_contained(&source).expect("IR lowering failed");
    ir::passes::optimize(&mut program);
    let proven = compute_proven_boolean(&program);

    let mut compiler = R1CSCompiler::new();
    compiler.set_proven_boolean(proven);
    let witness = compiler
        .compile_ir_with_witness(&program, &inputs)
        .expect("R1CS compilation failed");
    compiler.cs.verify(&witness).expect("verification failed");

    // Export and validate magic bytes
    let r1cs_data = write_r1cs(&compiler.cs, PrimeId::Bn254);
    assert_eq!(&r1cs_data[0..4], b"r1cs", "R1CS magic mismatch");

    let wtns_data = write_wtns(&witness, PrimeId::Bn254);
    assert_eq!(&wtns_data[0..4], b"wtns", "WTNS magic mismatch");

    // Wire counts must match
    let n_wires = u32::from_le_bytes(r1cs_data[60..64].try_into().unwrap());
    let n_witness = u32::from_le_bytes(wtns_data[60..64].try_into().unwrap());
    assert_eq!(
        n_wires, n_witness,
        "wire count mismatch between R1CS and WTNS"
    );
}

#[test]
fn merkle_depth4_export_roundtrip() {
    let p = params();
    let leaves = make_leaves(4, 700);
    let root = build_merkle_tree(&p, &leaves);
    let (sibs, dirs) = merkle_proof(&p, &leaves, 7);
    let inputs = merkle_inputs(root, leaves[7], &sibs, &dirs);

    let source = merkle_source(4);
    let (_, _, mut program) =
        IrLowering::lower_self_contained(&source).expect("IR lowering failed");
    ir::passes::optimize(&mut program);
    let proven = compute_proven_boolean(&program);

    let mut compiler = R1CSCompiler::new();
    compiler.set_proven_boolean(proven);
    let witness = compiler
        .compile_ir_with_witness(&program, &inputs)
        .expect("R1CS compilation failed");
    compiler.cs.verify(&witness).expect("verification failed");

    let r1cs_data = write_r1cs(&compiler.cs, PrimeId::Bn254);
    assert_eq!(&r1cs_data[0..4], b"r1cs");

    let wtns_data = write_wtns(&witness, PrimeId::Bn254);
    assert_eq!(&wtns_data[0..4], b"wtns");

    let n_wires = u32::from_le_bytes(r1cs_data[60..64].try_into().unwrap());
    let n_witness = u32::from_le_bytes(wtns_data[60..64].try_into().unwrap());
    assert_eq!(n_wires, n_witness);
}
