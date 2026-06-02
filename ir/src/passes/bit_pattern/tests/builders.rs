use memory::FieldElement;

use crate::types::{Instruction, IrProgram, SsaVar, Visibility};

/// Helper: build a Num2Bits(n) pattern in IR.
///
/// Creates n boolean-enforced bits and a weighted sum asserting:
///   bit_0 * 1 + bit_1 * 2 + ... + bit_{n-1} * 2^{n-1} = input
pub(super) fn make_num2bits_program(n: u32) -> (IrProgram, SsaVar) {
    let mut p: IrProgram = IrProgram::new();

    // Input signal
    let input = p.fresh_var();
    p.push(Instruction::Input {
        result: input,
        name: "input".into(),
        visibility: Visibility::Witness,
    });

    // Constant 1 (for Sub(bit, 1))
    let const_one = p.fresh_var();
    p.push(Instruction::Const {
        result: const_one,
        value: FieldElement::one(),
    });

    // Constant 0 (for AssertEq(..., 0))
    let const_zero = p.fresh_var();
    p.push(Instruction::Const {
        result: const_zero,
        value: FieldElement::zero(),
    });

    let mut bit_vars = Vec::new();

    // For each bit: create boolean enforcement v*(v-1)=0
    for _ in 0..n {
        let bit = p.fresh_var(); // the bit variable (witness)
        p.push(Instruction::Input {
            result: bit,
            name: "bit".into(),
            visibility: Visibility::Witness,
        });

        // Sub(bit, 1)
        let sub_result = p.fresh_var();
        p.push(Instruction::Sub {
            result: sub_result,
            lhs: bit,
            rhs: const_one,
        });

        // Mul(bit, sub_result) = bit * (bit - 1)
        let mul_result = p.fresh_var();
        p.push(Instruction::Mul {
            result: mul_result,
            lhs: bit,
            rhs: sub_result,
        });

        // AssertEq(mul_result, 0)
        let assert_result = p.fresh_var();
        p.push(Instruction::AssertEq {
            result: assert_result,
            lhs: mul_result,
            rhs: const_zero,
            message: None,
        });

        bit_vars.push(bit);
    }

    // Build weighted sum: bit_0 * 2^0 + bit_1 * 2^1 + ... + bit_{n-1} * 2^{n-1}
    // Start with bit_0 * 1 (= bit_0 * 2^0)
    let coeff_0 = p.fresh_var();
    p.push(Instruction::Const {
        result: coeff_0,
        value: FieldElement::from_u64(1),
    });
    let mut sum = p.fresh_var();
    p.push(Instruction::Mul {
        result: sum,
        lhs: bit_vars[0],
        rhs: coeff_0,
    });

    for i in 1..n {
        let coeff = p.fresh_var();
        p.push(Instruction::Const {
            result: coeff,
            value: FieldElement::from_u64(1u64 << i),
        });
        let term = p.fresh_var();
        p.push(Instruction::Mul {
            result: term,
            lhs: bit_vars[i as usize],
            rhs: coeff,
        });
        let new_sum = p.fresh_var();
        p.push(Instruction::Add {
            result: new_sum,
            lhs: sum,
            rhs: term,
        });
        sum = new_sum;
    }

    // AssertEq(sum, input)
    let assert_sum = p.fresh_var();
    p.push(Instruction::AssertEq {
        result: assert_sum,
        lhs: sum,
        rhs: input,
        message: None,
    });

    (p, input)
}
