use std::collections::HashMap;

use ir::passes::bool_prop::compute_proven_boolean;
use ir::IrLowering;
use memory::FieldElement;
use zkc::r1cs_backend::R1CSCompiler;

/// p - 1: largest element in the field (equivalent to -1)
pub(crate) const P_MINUS_1: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495616";
/// p - 2: second-largest element
pub(crate) const P_MINUS_2: &str =
    "21888242871839275222246405745257275088548364400416034343698204186575808495615";

pub(crate) fn fe(val: u64) -> FieldElement {
    FieldElement::from_u64(val)
}

pub(crate) fn fe_str(s: &str) -> FieldElement {
    FieldElement::from_decimal_str(s).unwrap()
}

pub(crate) fn compile_and_verify(source: &str, inputs: &[(&str, FieldElement)]) -> usize {
    let (_, _, mut program) = IrLowering::lower_self_contained(source).expect("IR lowering failed");
    ir::passes::optimize(&mut program);
    let proven = compute_proven_boolean(&program);
    let mut compiler = R1CSCompiler::new();
    compiler.set_proven_boolean(proven);
    let input_map: HashMap<String, FieldElement> =
        inputs.iter().map(|(k, v)| (k.to_string(), *v)).collect();
    let witness = compiler
        .compile_ir_with_witness(&program, &input_map)
        .expect("R1CS compilation failed");
    compiler
        .cs
        .verify(&witness)
        .expect("R1CS witness verification failed");
    compiler.cs.num_constraints()
}

pub(crate) fn compile_expect_fail(source: &str, inputs: &[(&str, FieldElement)]) {
    let (_, _, mut program) = IrLowering::lower_self_contained(source).expect("IR lowering failed");
    ir::passes::optimize(&mut program);
    let proven = compute_proven_boolean(&program);
    let mut compiler = R1CSCompiler::new();
    compiler.set_proven_boolean(proven);
    let input_map: HashMap<String, FieldElement> =
        inputs.iter().map(|(k, v)| (k.to_string(), *v)).collect();
    let result = compiler.compile_ir_with_witness(&program, &input_map);
    if let Ok(witness) = result {
        let verify = compiler.cs.verify(&witness);
        assert!(
            verify.is_err(),
            "expected verification failure but it passed"
        );
    }
}
