use std::collections::HashSet;

use ir_core::{Instruction, IrProgram, SsaVar, Visibility};
use memory::FieldElement;

use super::constant_fold;

/// Regression for issue #86: the SHA-256(64) Lysis pipeline emits
/// many "alias-style" Decomposes — `Decompose { result, operand,
/// .. }` with `result == operand` (RangeCheck-shaped, used to
/// constrain that an existing var fits in N bits while exposing
/// the bit_results as new SSA wires). The pre-fix expansion logic
/// keyed by `result_var()`; with hundreds of alias-Decomposes
/// all reporting `result_var == %390`, only the first entry's
/// bit_results were emitted, and every later Decompose's
/// bit_results dangled. This test materialises that pattern with
/// two alias-Decomposes sharing a result var and asserts both
/// bit_var-Consts come out alive.
#[test]
fn alias_decompose_with_shared_result_emits_all_bit_consts() {
    let mut p: IrProgram = IrProgram::new();
    let v_const = SsaVar(0);
    let bit_a = SsaVar(1);
    let bit_b = SsaVar(2);
    // %0 = Const(1) — the "alias" var that two Decomposes share as result.
    p.push(Instruction::Const {
        result: v_const,
        value: FieldElement::from_u64(1),
    });
    // First alias-Decompose: result == operand == %0, bit_results = [%1].
    p.push(Instruction::Decompose {
        result: v_const,
        bit_results: vec![bit_a],
        operand: v_const,
        num_bits: 1,
    });
    // Second alias-Decompose with the same result var. Pre-fix this
    // entry's bit_results were dropped because the first entry's
    // expansion shadowed it.
    p.push(Instruction::Decompose {
        result: v_const,
        bit_results: vec![bit_b],
        operand: v_const,
        num_bits: 1,
    });
    p.next_var = 3;

    constant_fold(&mut p);

    // Both bit_vars must end up defined as Const{1}.
    let const_results: HashSet<SsaVar> = p
        .iter()
        .filter_map(|i| match i {
            Instruction::Const { result, value } if *value == FieldElement::one() => Some(*result),
            _ => None,
        })
        .collect();
    assert!(
        const_results.contains(&bit_a),
        "bit_a (first alias Decompose) should be folded to Const(1)"
    );
    assert!(
        const_results.contains(&bit_b),
        "bit_b (second alias Decompose) should be folded to Const(1) — \
         pre-fix this was dropped because expansion was keyed by result_var",
    );
}

/// Three alias-Decomposes — exercise that expansion handles >2
/// entries with the same result var without offset drift.
#[test]
fn alias_decompose_chain_emits_each_bit_distinctly() {
    let mut p: IrProgram = IrProgram::new();
    let v = SsaVar(0);
    let bits = [SsaVar(1), SsaVar(2), SsaVar(3)];
    p.push(Instruction::Const {
        result: v,
        value: FieldElement::from_u64(5), // 0b101 — bits 0 and 2 are 1, bit 1 is 0
    });
    for &b in &bits {
        p.push(Instruction::Decompose {
            result: v,
            bit_results: vec![b],
            operand: v,
            num_bits: 1,
        });
    }
    p.next_var = 4;

    constant_fold(&mut p);

    // Each Decompose has num_bits=1, so each bit_var is the LSB
    // of `5` from that Decompose's perspective. With num_bits=1
    // the expansion only ever computes bit[0], regardless of the
    // chain position. So all three bit_vars should be Const(1).
    for &b in &bits {
        let defined = p.iter().any(|i| {
            matches!(i, Instruction::Const { result, value }
                if *result == b && *value == FieldElement::one())
        });
        assert!(defined, "{b} should be Const(1)");
    }
}

/// Sanity: a single non-alias Decompose still folds correctly
/// (the original happy path the pre-fix code handled).
#[test]
fn non_alias_decompose_still_folds() {
    let mut p: IrProgram = IrProgram::new();
    let v_in = SsaVar(0);
    let v_alias = SsaVar(1);
    let bit_0 = SsaVar(2);
    let bit_1 = SsaVar(3);
    p.push(Instruction::Const {
        result: v_in,
        value: FieldElement::from_u64(2), // binary 10
    });
    p.push(Instruction::Input {
        result: v_alias,
        name: "y".into(),
        visibility: Visibility::Witness,
    });
    // Non-alias Decompose: result != operand.
    p.push(Instruction::Decompose {
        result: v_alias,
        bit_results: vec![bit_0, bit_1],
        operand: v_in,
        num_bits: 2,
    });
    p.next_var = 4;

    constant_fold(&mut p);

    // bit_0 = LSB(2) = 0; bit_1 = next bit = 1
    let bit_0_val = p.iter().find_map(|i| match i {
        Instruction::Const { result, value } if *result == bit_0 => Some(*value),
        _ => None,
    });
    let bit_1_val = p.iter().find_map(|i| match i {
        Instruction::Const { result, value } if *result == bit_1 => Some(*value),
        _ => None,
    });
    assert_eq!(bit_0_val, Some(FieldElement::zero()));
    assert_eq!(bit_1_val, Some(FieldElement::one()));
}
