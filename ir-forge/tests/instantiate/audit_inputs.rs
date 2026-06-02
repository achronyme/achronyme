use super::helpers::*;

#[test]
fn audit_bool_input_gets_range_check() {
    let prove_ir = ProveIR {
        name: None,
        public_inputs: vec![ProveInputDecl {
            name: "flag".into(),
            array_size: None,
            ir_type: IrType::Bool,
        }],
        witness_inputs: vec![],
        captures: vec![],
        body: vec![],
        capture_arrays: vec![],
        component_bodies: Default::default(),
    };
    let ir = prove_ir
        .instantiate_lysis::<Bn254Fr>(&HashMap::new())
        .unwrap();
    let range_checks = ir
        .instructions
        .iter()
        .filter(|i| matches!(i, Instruction::RangeCheck { bits: 1, .. }))
        .count();
    assert_eq!(
        range_checks, 1,
        "Bool input must have RangeCheck(1), got {range_checks}"
    );
}

#[test]
fn audit_bool_array_input_gets_range_checks() {
    let prove_ir = ProveIR {
        name: None,
        public_inputs: vec![ProveInputDecl {
            name: "flags".into(),
            array_size: Some(ArraySize::Literal(3)),
            ir_type: IrType::Bool,
        }],
        witness_inputs: vec![],
        captures: vec![],
        body: vec![],
        capture_arrays: vec![],
        component_bodies: Default::default(),
    };
    let ir = prove_ir
        .instantiate_lysis::<Bn254Fr>(&HashMap::new())
        .unwrap();
    let range_checks = ir
        .instructions
        .iter()
        .filter(|i| matches!(i, Instruction::RangeCheck { bits: 1, .. }))
        .count();
    assert_eq!(range_checks, 3, "3 Bool array elements need 3 RangeChecks");
}

// E1: PoseidonMany with 2 args
#[test]
fn audit_type_propagation() {
    let ir = compile_and_instantiate("public a\npublic b\nlet sum = a + b\nassert(a == b)");
    // sum (Add result) should have type Field
    // a == b (IsEq result) should have type Bool
    let has_field = ir
        .instructions
        .iter()
        .any(|i| matches!(i, Instruction::Add { result, .. } if ir.get_type(*result) == Some(IrType::Field)));
    let has_bool = ir
        .instructions
        .iter()
        .any(|i| matches!(i, Instruction::IsEq { result, .. } if ir.get_type(*result) == Some(IrType::Bool)));
    assert!(has_field, "Add result should have IrType::Field");
    assert!(has_bool, "IsEq result should have IrType::Bool");
}

// ===================================================================
// Phase D audit: hardening tests
// ===================================================================
