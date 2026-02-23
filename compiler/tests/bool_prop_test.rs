use std::collections::HashMap;

use compiler::r1cs_backend::R1CSCompiler;
use compiler::witness_gen::WitnessGenerator;
use ir::passes::bool_prop::compute_proven_boolean;
use ir::types::{Instruction, IrProgram, Visibility};
use memory::FieldElement;

// ============================================================================
// Unit tests for compute_proven_boolean
// ============================================================================

#[test]
fn bool_prop_const_0_1_are_boolean() {
    let mut p = IrProgram::new();
    let c0 = p.fresh_var();
    p.push(Instruction::Const {
        result: c0,
        value: FieldElement::ZERO,
    });
    let c1 = p.fresh_var();
    p.push(Instruction::Const {
        result: c1,
        value: FieldElement::ONE,
    });
    let c42 = p.fresh_var();
    p.push(Instruction::Const {
        result: c42,
        value: FieldElement::from_u64(42),
    });

    let set = compute_proven_boolean(&p);
    assert!(set.contains(&c0));
    assert!(set.contains(&c1));
    assert!(!set.contains(&c42));
}

#[test]
fn bool_prop_is_eq_result_boolean() {
    let mut p = IrProgram::new();
    let a = p.fresh_var();
    p.push(Instruction::Input {
        result: a,
        name: "a".into(),
        visibility: Visibility::Witness,
    });
    let b = p.fresh_var();
    p.push(Instruction::Input {
        result: b,
        name: "b".into(),
        visibility: Visibility::Witness,
    });
    let eq = p.fresh_var();
    p.push(Instruction::IsEq {
        result: eq,
        lhs: a,
        rhs: b,
    });

    let set = compute_proven_boolean(&p);
    assert!(set.contains(&eq));
    assert!(!set.contains(&a));
    assert!(!set.contains(&b));
}

#[test]
fn bool_prop_not_of_boolean() {
    let mut p = IrProgram::new();
    let a = p.fresh_var();
    p.push(Instruction::Input {
        result: a,
        name: "a".into(),
        visibility: Visibility::Witness,
    });
    let b = p.fresh_var();
    p.push(Instruction::Input {
        result: b,
        name: "b".into(),
        visibility: Visibility::Witness,
    });
    let eq = p.fresh_var();
    p.push(Instruction::IsEq {
        result: eq,
        lhs: a,
        rhs: b,
    });
    // Not(boolean) → boolean
    let not_eq = p.fresh_var();
    p.push(Instruction::Not {
        result: not_eq,
        operand: eq,
    });

    let set = compute_proven_boolean(&p);
    assert!(set.contains(&not_eq));

    // Not(witness) → NOT boolean
    let not_a = p.fresh_var();
    p.push(Instruction::Not {
        result: not_a,
        operand: a,
    });
    let set2 = compute_proven_boolean(&p);
    assert!(!set2.contains(&not_a));
}

#[test]
fn bool_prop_and_of_booleans() {
    let mut p = IrProgram::new();
    let a = p.fresh_var();
    p.push(Instruction::Input {
        result: a,
        name: "a".into(),
        visibility: Visibility::Witness,
    });
    let b = p.fresh_var();
    p.push(Instruction::Input {
        result: b,
        name: "b".into(),
        visibility: Visibility::Witness,
    });
    let c = p.fresh_var();
    p.push(Instruction::Input {
        result: c,
        name: "c".into(),
        visibility: Visibility::Witness,
    });
    let eq = p.fresh_var();
    p.push(Instruction::IsEq {
        result: eq,
        lhs: a,
        rhs: b,
    });
    let lt = p.fresh_var();
    p.push(Instruction::IsLt {
        result: lt,
        lhs: a,
        rhs: c,
    });

    // And(boolean, boolean) → boolean
    let and_bool = p.fresh_var();
    p.push(Instruction::And {
        result: and_bool,
        lhs: eq,
        rhs: lt,
    });
    let set = compute_proven_boolean(&p);
    assert!(set.contains(&and_bool));

    // And(boolean, witness) → NOT boolean
    let and_mixed = p.fresh_var();
    p.push(Instruction::And {
        result: and_mixed,
        lhs: eq,
        rhs: a,
    });
    let set2 = compute_proven_boolean(&p);
    assert!(!set2.contains(&and_mixed));
}

// ============================================================================
// Integration: constraint count reduction
// ============================================================================

/// Helper: compile source via IR with and without bool_prop, return constraint counts.
fn constraint_counts_with_without(
    pub_decls: &[&str],
    wit_decls: &[&str],
    source: &str,
    inputs: &[(&str, u64)],
) -> (usize, usize) {
    let program = ir::IrLowering::lower_circuit(source, pub_decls, wit_decls).unwrap();

    // Without bool_prop
    let mut compiler_no = R1CSCompiler::new();
    compiler_no.compile_ir(&program).unwrap();
    let count_without = compiler_no.cs.num_constraints();

    // With bool_prop
    let proven = compute_proven_boolean(&program);
    let mut compiler_yes = R1CSCompiler::new();
    compiler_yes.set_proven_boolean(proven);
    compiler_yes.compile_ir(&program).unwrap();
    let count_with = compiler_yes.cs.num_constraints();

    // Verify the optimized circuit still passes
    let input_map: HashMap<String, FieldElement> = inputs
        .iter()
        .map(|(n, v)| (n.to_string(), FieldElement::from_u64(*v)))
        .collect();
    let wg = WitnessGenerator::from_compiler(&compiler_yes);
    let witness = wg.generate(&input_map).unwrap();
    compiler_yes.cs.verify(&witness).unwrap();

    (count_without, count_with)
}

#[test]
fn bool_prop_reduces_not_constraints() {
    // assert(!(x == y)): without bool_prop = 2 (IsEq) + 1 (Not bool) + 2 (Assert) = 5
    // with bool_prop: IsEq result is proven boolean, Not skips check = 4
    let source = r#"
let eq = x == y
let neg = !eq
assert(neg)
"#;
    let (without, with) =
        constraint_counts_with_without(&[], &["x", "y"], source, &[("x", 3), ("y", 5)]);
    assert!(
        with < without,
        "bool_prop should reduce constraints: without={without}, with={with}"
    );
    // Verify: the Not(IsEq) result is also boolean, so Assert skips its check too
    // Expected savings: Not skips 1 boolean check + Assert skips 1 boolean check = 2 saved
    assert_eq!(without - with, 2, "expected 2 fewer constraints");
}

#[test]
fn bool_prop_reduces_and_constraints() {
    // assert((x == y) && (a == b)):
    // Without: 2 (IsEq) + 2 (IsEq) + 2 (And bool checks) + 1 (And mul) + 2 (Assert) = 9
    // With: both operands of And are proven boolean → skip 2 checks = 7
    // Also Assert operand is proven boolean → skip 1 more = 6? No, And result is also
    // proven boolean since both inputs are, so Assert skips its check = saved 3
    let source = r#"
let eq1 = x == y
let eq2 = a == b
let both = eq1 && eq2
assert(both)
"#;
    let (without, with) = constraint_counts_with_without(
        &[],
        &["x", "y", "a", "b"],
        source,
        &[("x", 3), ("y", 3), ("a", 7), ("b", 7)],
    );
    assert!(
        with < without,
        "bool_prop should reduce constraints: without={without}, with={with}"
    );
    // And skips 2 bool checks + Assert skips 1 = 3 saved
    assert_eq!(without - with, 3, "expected 3 fewer constraints");
}

#[test]
fn bool_prop_plonkish_reduces_rows() {
    use compiler::plonkish_backend::{PlonkishCompiler, PlonkishWitnessGenerator};

    let source = r#"
let eq = x == y
let neg = !eq
assert(neg)
"#;
    let program = ir::IrLowering::lower_circuit(source, &[], &["x", "y"]).unwrap();

    // Without bool_prop
    let mut compiler_no = PlonkishCompiler::new();
    compiler_no.compile_ir(&program).unwrap();
    let rows_without = compiler_no.num_circuit_rows();

    // With bool_prop
    let proven = compute_proven_boolean(&program);
    let mut compiler_yes = PlonkishCompiler::new();
    compiler_yes.set_proven_boolean(proven);
    compiler_yes.compile_ir(&program).unwrap();
    let rows_with = compiler_yes.num_circuit_rows();

    assert!(
        rows_with < rows_without,
        "bool_prop should reduce plonkish rows: without={rows_without}, with={rows_with}"
    );

    // Verify optimized circuit still passes
    let mut inputs = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::from_u64(3));
    inputs.insert("y".to_string(), FieldElement::from_u64(5));
    let wg = PlonkishWitnessGenerator::from_compiler(&compiler_yes);
    wg.generate(&inputs, &mut compiler_yes.system.assignments)
        .unwrap();
    compiler_yes.system.verify().unwrap();
}
