use crate::passes::dense::DenseVarSet;

use memory::FieldElement;

use crate::types::{Instruction, IrProgram, Visibility};

use super::super::detect_bit_patterns;
use super::builders::make_num2bits_program;

#[test]
fn num2bits_3_detects_3bit_bound() {
    let (program, input) = make_num2bits_program(3);
    let booleans = DenseVarSet::new();
    let result = detect_bit_patterns(&program, &booleans);

    assert_eq!(result.booleans_detected, 3);
    assert_eq!(result.bounds.get(&input), Some(&3));
}

#[test]
fn num2bits_8_detects_8bit_bound() {
    let (program, input) = make_num2bits_program(8);
    let booleans = DenseVarSet::new();
    let result = detect_bit_patterns(&program, &booleans);

    assert_eq!(result.booleans_detected, 8);
    assert_eq!(result.bounds.get(&input), Some(&8));
}
#[test]
fn commuted_mul_operands() {
    // Mul(Sub(v, 1), v) instead of Mul(v, Sub(v, 1))
    let mut p: IrProgram = IrProgram::new();

    let input = p.fresh_var();
    p.push(Instruction::Input {
        result: input,
        name: "input".into(),
        visibility: Visibility::Witness,
    });

    let const_one = p.fresh_var();
    p.push(Instruction::Const {
        result: const_one,
        value: FieldElement::one(),
    });
    let const_zero = p.fresh_var();
    p.push(Instruction::Const {
        result: const_zero,
        value: FieldElement::zero(),
    });

    let bit = p.fresh_var();
    p.push(Instruction::Input {
        result: bit,
        name: "bit".into(),
        visibility: Visibility::Witness,
    });

    // Sub(bit, 1)
    let sub_r = p.fresh_var();
    p.push(Instruction::Sub {
        result: sub_r,
        lhs: bit,
        rhs: const_one,
    });

    // COMMUTED: Mul(sub_r, bit) instead of Mul(bit, sub_r)
    let mul_r = p.fresh_var();
    p.push(Instruction::Mul {
        result: mul_r,
        lhs: sub_r,
        rhs: bit,
    });

    // AssertEq(mul_r, 0)
    let assert_r = p.fresh_var();
    p.push(Instruction::AssertEq {
        result: assert_r,
        lhs: mul_r,
        rhs: const_zero,
        message: None,
    });

    // Weighted sum: bit * 1 = input
    let c1 = p.fresh_var();
    p.push(Instruction::Const {
        result: c1,
        value: FieldElement::from_u64(1),
    });
    let term = p.fresh_var();
    p.push(Instruction::Mul {
        result: term,
        lhs: bit,
        rhs: c1,
    });
    let assert_sum = p.fresh_var();
    p.push(Instruction::AssertEq {
        result: assert_sum,
        lhs: term,
        rhs: input,
        message: None,
    });

    let booleans = DenseVarSet::new();
    let result = detect_bit_patterns(&p, &booleans);
    assert_eq!(result.booleans_detected, 1);
    assert_eq!(result.bounds.get(&input), Some(&1));
}

#[test]
fn symmetric_assert_eq() {
    // AssertEq(0, mul_result) instead of AssertEq(mul_result, 0)
    let mut p: IrProgram = IrProgram::new();

    let input = p.fresh_var();
    p.push(Instruction::Input {
        result: input,
        name: "input".into(),
        visibility: Visibility::Witness,
    });

    let const_one = p.fresh_var();
    p.push(Instruction::Const {
        result: const_one,
        value: FieldElement::one(),
    });
    let const_zero = p.fresh_var();
    p.push(Instruction::Const {
        result: const_zero,
        value: FieldElement::zero(),
    });

    let bit = p.fresh_var();
    p.push(Instruction::Input {
        result: bit,
        name: "bit".into(),
        visibility: Visibility::Witness,
    });
    let sub_r = p.fresh_var();
    p.push(Instruction::Sub {
        result: sub_r,
        lhs: bit,
        rhs: const_one,
    });
    let mul_r = p.fresh_var();
    p.push(Instruction::Mul {
        result: mul_r,
        lhs: bit,
        rhs: sub_r,
    });

    // SWAPPED: AssertEq(0, mul_result) — zero on the left
    let assert_r = p.fresh_var();
    p.push(Instruction::AssertEq {
        result: assert_r,
        lhs: const_zero,
        rhs: mul_r,
        message: None,
    });

    // Weighted sum: bit * 1 = input (also swapped: AssertEq(input, sum))
    let c1 = p.fresh_var();
    p.push(Instruction::Const {
        result: c1,
        value: FieldElement::from_u64(1),
    });
    let term = p.fresh_var();
    p.push(Instruction::Mul {
        result: term,
        lhs: bit,
        rhs: c1,
    });
    let assert_sum = p.fresh_var();
    p.push(Instruction::AssertEq {
        result: assert_sum,
        lhs: input,
        rhs: term,
        message: None,
    });

    let booleans = DenseVarSet::new();
    let result = detect_bit_patterns(&p, &booleans);
    assert_eq!(result.booleans_detected, 1);
    assert_eq!(result.bounds.get(&input), Some(&1));
}

#[test]
fn single_bit_pattern() {
    // Num2Bits(1): single boolean with coefficient 2^0 = 1
    let (program, input) = make_num2bits_program(1);
    let booleans = DenseVarSet::new();
    let result = detect_bit_patterns(&program, &booleans);

    assert_eq!(result.booleans_detected, 1);
    assert_eq!(result.bounds.get(&input), Some(&1));
}

#[test]
fn integration_with_bool_prop_booleans() {
    // Use pre-proven booleans from bool_prop (e.g., comparison results)
    // instead of v*(v-1)=0 enforcement
    let mut p: IrProgram = IrProgram::new();

    let input = p.fresh_var();
    p.push(Instruction::Input {
        result: input,
        name: "input".into(),
        visibility: Visibility::Witness,
    });

    // Two bits that are results of comparisons (proven boolean by bool_prop)
    let bit0 = p.fresh_var();
    let dummy0 = p.fresh_var();
    let dummy1 = p.fresh_var();
    p.push(Instruction::Input {
        result: dummy0,
        name: "d0".into(),
        visibility: Visibility::Witness,
    });
    p.push(Instruction::Input {
        result: dummy1,
        name: "d1".into(),
        visibility: Visibility::Witness,
    });
    p.push(Instruction::IsEq {
        result: bit0,
        lhs: dummy0,
        rhs: dummy1,
    });

    let bit1 = p.fresh_var();
    p.push(Instruction::IsEq {
        result: bit1,
        lhs: dummy0,
        rhs: dummy1,
    });

    // Weighted sum: bit0 * 1 + bit1 * 2 = input
    let c1 = p.fresh_var();
    p.push(Instruction::Const {
        result: c1,
        value: FieldElement::from_u64(1),
    });
    let c2 = p.fresh_var();
    p.push(Instruction::Const {
        result: c2,
        value: FieldElement::from_u64(2),
    });

    let t0 = p.fresh_var();
    p.push(Instruction::Mul {
        result: t0,
        lhs: bit0,
        rhs: c1,
    });
    let t1 = p.fresh_var();
    p.push(Instruction::Mul {
        result: t1,
        lhs: bit1,
        rhs: c2,
    });
    let sum = p.fresh_var();
    p.push(Instruction::Add {
        result: sum,
        lhs: t0,
        rhs: t1,
    });
    let assert_r = p.fresh_var();
    p.push(Instruction::AssertEq {
        result: assert_r,
        lhs: sum,
        rhs: input,
        message: None,
    });

    // Pre-proven booleans from bool_prop
    let mut proven = DenseVarSet::new();
    proven.insert(bit0);
    proven.insert(bit1);

    let result = detect_bit_patterns(&p, &proven);
    assert_eq!(result.booleans_detected, 0); // no NEW booleans detected
    assert_eq!(result.bounds.get(&input), Some(&2));
}
