use crate::passes::dense::DenseVarSet;

use memory::FieldElement;

use crate::types::{Instruction, IrProgram, Visibility};

use super::super::detect_bit_patterns;

#[test]
fn no_false_positive_without_boolean_enforcement() {
    // Weighted sum without boolean enforcement → should not infer bounds
    let mut p: IrProgram = IrProgram::new();
    let input = p.fresh_var();
    p.push(Instruction::Input {
        result: input,
        name: "input".into(),
        visibility: Visibility::Witness,
    });

    let bit0 = p.fresh_var();
    p.push(Instruction::Input {
        result: bit0,
        name: "b0".into(),
        visibility: Visibility::Witness,
    });
    let bit1 = p.fresh_var();
    p.push(Instruction::Input {
        result: bit1,
        name: "b1".into(),
        visibility: Visibility::Witness,
    });

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

    let booleans = DenseVarSet::new();
    let result = detect_bit_patterns(&p, &booleans);
    assert!(result.bounds.is_empty());
}

#[test]
fn no_false_positive_non_power_of_2_coefficients() {
    // Boolean-enforced vars but coefficient 3 (not power of 2)
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

    // bit0: boolean enforced
    let bit0 = p.fresh_var();
    p.push(Instruction::Input {
        result: bit0,
        name: "b0".into(),
        visibility: Visibility::Witness,
    });
    let sub0 = p.fresh_var();
    p.push(Instruction::Sub {
        result: sub0,
        lhs: bit0,
        rhs: const_one,
    });
    let mul0 = p.fresh_var();
    p.push(Instruction::Mul {
        result: mul0,
        lhs: bit0,
        rhs: sub0,
    });
    let a0 = p.fresh_var();
    p.push(Instruction::AssertEq {
        result: a0,
        lhs: mul0,
        rhs: const_zero,
        message: None,
    });

    // bit0 * 3 (not a power of 2!)
    let c3 = p.fresh_var();
    p.push(Instruction::Const {
        result: c3,
        value: FieldElement::from_u64(3),
    });
    let term = p.fresh_var();
    p.push(Instruction::Mul {
        result: term,
        lhs: bit0,
        rhs: c3,
    });
    let assert_r = p.fresh_var();
    p.push(Instruction::AssertEq {
        result: assert_r,
        lhs: term,
        rhs: input,
        message: None,
    });

    let booleans = DenseVarSet::new();
    let result = detect_bit_patterns(&p, &booleans);
    // Should not infer a bound (coeff 3 is not power of 2 → decomposition fails)
    assert!(result.bounds.is_empty());
}
#[test]
fn non_contiguous_bits_rejected() {
    // Bits at positions 0 and 2 (missing 1) → should not infer bound
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

    // Two boolean-enforced bits
    let mut bits = Vec::new();
    for _ in 0..2 {
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
        let assert_r = p.fresh_var();
        p.push(Instruction::AssertEq {
            result: assert_r,
            lhs: mul_r,
            rhs: const_zero,
            message: None,
        });
        bits.push(bit);
    }

    // bit0 * 1 + bit1 * 4  (positions 0 and 2 — gap at 1!)
    let c1 = p.fresh_var();
    p.push(Instruction::Const {
        result: c1,
        value: FieldElement::from_u64(1),
    });
    let c4 = p.fresh_var();
    p.push(Instruction::Const {
        result: c4,
        value: FieldElement::from_u64(4),
    });

    let t0 = p.fresh_var();
    p.push(Instruction::Mul {
        result: t0,
        lhs: bits[0],
        rhs: c1,
    });
    let t1 = p.fresh_var();
    p.push(Instruction::Mul {
        result: t1,
        lhs: bits[1],
        rhs: c4,
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

    let booleans = DenseVarSet::new();
    let result = detect_bit_patterns(&p, &booleans);
    assert!(
        result.bounds.is_empty(),
        "non-contiguous bits should be rejected"
    );
}
