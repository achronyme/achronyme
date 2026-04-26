use std::collections::HashMap;

use memory::{FieldBackend, FieldElement};

use crate::types::{Instruction, IrProgram, SsaVar};

/// Constant folding pass.
///
/// Forward pass O(n). Tracks which SSA variables have known constant values.
/// If all operands of an arithmetic instruction are constants, replaces the
/// instruction with a `Const`.
pub fn constant_fold<F: FieldBackend>(program: &mut IrProgram<F>) {
    let mut constants: HashMap<SsaVar, FieldElement<F>> = HashMap::new();
    // Decompose(Const(k), N) can't be replaced in-place (1 → N+1 instructions).
    // Collect them keyed by the *instruction index* so the expansion in
    // Loop 2 can re-match them positionally. Keying by `result_var` was
    // wrong: alias-style Decomposes (`Decompose { result, operand, .. }`
    // with `result == operand`) all share the same result var across
    // the program, so a result-keyed lookup ambiguously points at the
    // first entry only — every subsequent Decompose's bit_results are
    // dropped.
    let mut decompose_expansions: Vec<(usize, FieldElement<F>, Vec<SsaVar>)> = Vec::new();

    for (idx, inst) in program.instructions.iter_mut().enumerate() {
        match inst {
            Instruction::Const { result, value } => {
                constants.insert(*result, *value);
            }
            Instruction::Neg { result, operand } => {
                if let Some(v) = constants.get(operand) {
                    let folded = v.neg();
                    constants.insert(*result, folded);
                    *inst = Instruction::Const {
                        result: *result,
                        value: folded,
                    };
                }
            }
            Instruction::Add { result, lhs, rhs } => {
                let lhs_val = constants.get(lhs).copied();
                let rhs_val = constants.get(rhs).copied();
                // x + 0 → x, 0 + x → x
                if lhs_val.is_some_and(|v| v.is_zero()) {
                    if let Some(val) = rhs_val {
                        constants.insert(*result, val);
                        *inst = Instruction::Const {
                            result: *result,
                            value: val,
                        };
                    }
                } else if rhs_val.is_some_and(|v| v.is_zero()) {
                    if let Some(val) = lhs_val {
                        constants.insert(*result, val);
                        *inst = Instruction::Const {
                            result: *result,
                            value: val,
                        };
                    }
                } else if let (Some(a), Some(b)) = (lhs_val, rhs_val) {
                    let folded = a.add(&b);
                    constants.insert(*result, folded);
                    *inst = Instruction::Const {
                        result: *result,
                        value: folded,
                    };
                }
            }
            Instruction::Sub { result, lhs, rhs } => {
                if lhs == rhs {
                    // x - x → 0 regardless of whether x is constant
                    let r = *result;
                    constants.insert(r, FieldElement::<F>::zero());
                    *inst = Instruction::Const {
                        result: r,
                        value: FieldElement::<F>::zero(),
                    };
                } else {
                    let lhs_val = constants.get(lhs).copied();
                    let rhs_val = constants.get(rhs).copied();
                    // x - 0 → x
                    if rhs_val.is_some_and(|v| v.is_zero()) {
                        if let Some(val) = lhs_val {
                            constants.insert(*result, val);
                            *inst = Instruction::Const {
                                result: *result,
                                value: val,
                            };
                        }
                    } else if let (Some(a), Some(b)) = (lhs_val, rhs_val) {
                        let folded = a.sub(&b);
                        constants.insert(*result, folded);
                        *inst = Instruction::Const {
                            result: *result,
                            value: folded,
                        };
                    }
                }
            }
            Instruction::Mul { result, lhs, rhs } => {
                let lhs_val = constants.get(lhs).copied();
                let rhs_val = constants.get(rhs).copied();
                // x * 0 → 0, 0 * x → 0
                let lhs_zero = lhs_val.is_some_and(|v| v.is_zero());
                let rhs_zero = rhs_val.is_some_and(|v| v.is_zero());
                if lhs_zero || rhs_zero {
                    constants.insert(*result, FieldElement::<F>::zero());
                    *inst = Instruction::Const {
                        result: *result,
                        value: FieldElement::<F>::zero(),
                    };
                // x * 1 → x, 1 * x → x
                } else if lhs_val == Some(FieldElement::<F>::one()) {
                    if let Some(val) = rhs_val {
                        constants.insert(*result, val);
                        *inst = Instruction::Const {
                            result: *result,
                            value: val,
                        };
                    }
                } else if rhs_val == Some(FieldElement::<F>::one()) {
                    if let Some(val) = lhs_val {
                        constants.insert(*result, val);
                        *inst = Instruction::Const {
                            result: *result,
                            value: val,
                        };
                    }
                } else if let (Some(a), Some(b)) = (lhs_val, rhs_val) {
                    let folded = a.mul(&b);
                    constants.insert(*result, folded);
                    *inst = Instruction::Const {
                        result: *result,
                        value: folded,
                    };
                }
            }
            Instruction::Div { result, lhs, rhs } => {
                let r = *result;
                let l = *lhs;
                let rh = *rhs;
                // x / x → 1, but only when x is a known non-zero constant.
                // If x is a witness, we must keep the constraint (implicit w != 0 check).
                let mut folded_self = false;
                if l == rh {
                    if let Some(val) = constants.get(&l).copied() {
                        if !val.is_zero() {
                            constants.insert(r, FieldElement::<F>::one());
                            *inst = Instruction::Const {
                                result: r,
                                value: FieldElement::<F>::one(),
                            };
                            folded_self = true;
                        }
                    }
                }
                if !folded_self {
                    let lhs_val = constants.get(&l).copied();
                    let rhs_val = constants.get(&rh).copied();
                    // 0 / x → 0 (for any non-zero x)
                    let lhs_zero = lhs_val.is_some_and(|v| v.is_zero());
                    let rhs_zero = rhs_val.is_some_and(|v| v.is_zero());
                    if lhs_zero && !rhs_zero {
                        constants.insert(r, FieldElement::<F>::zero());
                        *inst = Instruction::Const {
                            result: r,
                            value: FieldElement::<F>::zero(),
                        };
                    // x / 1 → x
                    } else if rhs_val == Some(FieldElement::<F>::one()) {
                        if let Some(val) = lhs_val {
                            constants.insert(r, val);
                            *inst = Instruction::Const {
                                result: r,
                                value: val,
                            };
                        }
                    } else if let (Some(a), Some(b)) = (lhs_val, rhs_val) {
                        if let Some(inv) = b.inv() {
                            let folded = a.mul(&inv);
                            constants.insert(r, folded);
                            *inst = Instruction::Const {
                                result: r,
                                value: folded,
                            };
                        }
                    }
                }
            }
            // Mux with constant condition or equal branches
            Instruction::Mux {
                result,
                cond,
                if_true,
                if_false,
            } => {
                let cond_val = constants.get(cond).copied();
                let true_val = constants.get(if_true).copied();
                let false_val = constants.get(if_false).copied();
                // Equal branches: mux(c, x, x) → x
                if let (Some(t), Some(f)) = (true_val, false_val) {
                    if t == f {
                        constants.insert(*result, t);
                        *inst = Instruction::Const {
                            result: *result,
                            value: t,
                        };
                    } else if let Some(c) = cond_val {
                        let val = if c.is_zero() { f } else { t };
                        constants.insert(*result, val);
                        *inst = Instruction::Const {
                            result: *result,
                            value: val,
                        };
                    }
                } else if let Some(c) = cond_val {
                    if c.is_zero() {
                        if let Some(val) = false_val {
                            constants.insert(*result, val);
                            *inst = Instruction::Const {
                                result: *result,
                                value: val,
                            };
                        }
                    } else if c == FieldElement::<F>::one() {
                        if let Some(val) = true_val {
                            constants.insert(*result, val);
                            *inst = Instruction::Const {
                                result: *result,
                                value: val,
                            };
                        }
                    }
                }
            }
            // RangeCheck: if operand is constant and fits in bits, propagate constant
            Instruction::RangeCheck {
                result,
                operand,
                bits,
            } => {
                if let Some(val) = constants.get(operand) {
                    let limbs = val.to_canonical();
                    let fits = if *bits >= 64 {
                        // For ≥64 bits, check upper limbs cover the value
                        let full_limbs_needed = (*bits / 64) as usize;
                        let remaining_bits = *bits % 64;
                        let mut ok = true;
                        for limb in limbs.iter().skip(full_limbs_needed + 1) {
                            if *limb != 0 {
                                ok = false;
                            }
                        }
                        if ok && full_limbs_needed < 4 && remaining_bits > 0 {
                            ok = limbs[full_limbs_needed] < (1u64 << remaining_bits);
                        }
                        ok
                    } else {
                        limbs[0] < (1u64 << *bits)
                            && limbs[1] == 0
                            && limbs[2] == 0
                            && limbs[3] == 0
                    };
                    if fits {
                        constants.insert(*result, *val);
                    }
                }
            }
            Instruction::Not { result, operand } => {
                if let Some(v) = constants.get(operand) {
                    // Only fold if operand is actually boolean (0 or 1).
                    // Non-boolean values must keep the instruction so the
                    // boolean enforcement constraint is emitted in the circuit.
                    if v.is_zero() || *v == FieldElement::<F>::one() {
                        let folded = if v.is_zero() {
                            FieldElement::<F>::one()
                        } else {
                            FieldElement::<F>::zero()
                        };
                        constants.insert(*result, folded);
                        *inst = Instruction::Const {
                            result: *result,
                            value: folded,
                        };
                    }
                }
            }
            Instruction::And { result, lhs, rhs } => {
                let lhs_val = constants.get(lhs).copied();
                let rhs_val = constants.get(rhs).copied();
                let is_bool = |v: FieldElement<F>| v.is_zero() || v == FieldElement::<F>::one();
                // Short-circuit: 0 && x = 0 (safe: 0 is boolean)
                if lhs_val.is_some_and(|v| v.is_zero()) || rhs_val.is_some_and(|v| v.is_zero()) {
                    constants.insert(*result, FieldElement::<F>::zero());
                    *inst = Instruction::Const {
                        result: *result,
                        value: FieldElement::<F>::zero(),
                    };
                } else if let (Some(a), Some(b)) = (lhs_val, rhs_val) {
                    // Only fold if both operands are actually boolean.
                    // Non-boolean constants must keep the instruction so
                    // boolean enforcement constraints are emitted.
                    if is_bool(a) && is_bool(b) {
                        let folded = a.mul(&b);
                        constants.insert(*result, folded);
                        *inst = Instruction::Const {
                            result: *result,
                            value: folded,
                        };
                    }
                }
            }
            Instruction::Or { result, lhs, rhs } => {
                let lhs_val = constants.get(lhs).copied();
                let rhs_val = constants.get(rhs).copied();
                let is_bool = |v: FieldElement<F>| v.is_zero() || v == FieldElement::<F>::one();
                // Short-circuit: 1 || x = 1 (safe: 1 is boolean)
                if lhs_val == Some(FieldElement::<F>::one())
                    || rhs_val == Some(FieldElement::<F>::one())
                {
                    constants.insert(*result, FieldElement::<F>::one());
                    *inst = Instruction::Const {
                        result: *result,
                        value: FieldElement::<F>::one(),
                    };
                } else if let (Some(a), Some(b)) = (lhs_val, rhs_val) {
                    // Only fold if both operands are actually boolean.
                    if is_bool(a) && is_bool(b) {
                        // a + b - a*b
                        let folded = a.add(&b).sub(&a.mul(&b));
                        constants.insert(*result, folded);
                        *inst = Instruction::Const {
                            result: *result,
                            value: folded,
                        };
                    }
                }
            }
            Instruction::IsEq { result, lhs, rhs } => {
                if let (Some(a), Some(b)) = (constants.get(lhs), constants.get(rhs)) {
                    let folded = if a == b {
                        FieldElement::<F>::one()
                    } else {
                        FieldElement::<F>::zero()
                    };
                    constants.insert(*result, folded);
                    *inst = Instruction::Const {
                        result: *result,
                        value: folded,
                    };
                }
            }
            Instruction::IsNeq { result, lhs, rhs } => {
                if let (Some(a), Some(b)) = (constants.get(lhs), constants.get(rhs)) {
                    let folded = if a != b {
                        FieldElement::<F>::one()
                    } else {
                        FieldElement::<F>::zero()
                    };
                    constants.insert(*result, folded);
                    *inst = Instruction::Const {
                        result: *result,
                        value: folded,
                    };
                }
            }
            Instruction::IsLt { result, lhs, rhs }
            | Instruction::IsLtBounded {
                result, lhs, rhs, ..
            } => {
                if let (Some(a), Some(b)) = (constants.get(lhs), constants.get(rhs)) {
                    // Compare canonical representations (little-endian limbs)
                    let la = a.to_canonical();
                    let lb = b.to_canonical();
                    let less = (la[3], la[2], la[1], la[0]) < (lb[3], lb[2], lb[1], lb[0]);
                    let folded = if less {
                        FieldElement::<F>::one()
                    } else {
                        FieldElement::<F>::zero()
                    };
                    constants.insert(*result, folded);
                    *inst = Instruction::Const {
                        result: *result,
                        value: folded,
                    };
                }
            }
            Instruction::IsLe { result, lhs, rhs }
            | Instruction::IsLeBounded {
                result, lhs, rhs, ..
            } => {
                if let (Some(a), Some(b)) = (constants.get(lhs), constants.get(rhs)) {
                    let la = a.to_canonical();
                    let lb = b.to_canonical();
                    let le = (la[3], la[2], la[1], la[0]) <= (lb[3], lb[2], lb[1], lb[0]);
                    let folded = if le {
                        FieldElement::<F>::one()
                    } else {
                        FieldElement::<F>::zero()
                    };
                    constants.insert(*result, folded);
                    *inst = Instruction::Const {
                        result: *result,
                        value: folded,
                    };
                }
            }
            // Decompose(Const(k), N): fold to N constant bits.
            // Can't replace in-place (1 instruction → N), so mark for expansion.
            Instruction::Decompose {
                result,
                bit_results,
                operand,
                ..
            } => {
                if let Some(val) = constants.get(operand).copied() {
                    let limbs = val.to_canonical();
                    for (i, bit_var) in bit_results.iter().enumerate() {
                        let limb_idx = i / 64;
                        let bit_idx = i % 64;
                        let bit = if limb_idx < 4 {
                            (limbs[limb_idx] >> bit_idx) & 1
                        } else {
                            0
                        };
                        let bit_val = if bit == 1 {
                            FieldElement::<F>::one()
                        } else {
                            FieldElement::<F>::zero()
                        };
                        constants.insert(*bit_var, bit_val);
                    }
                    constants.insert(*result, val);
                    let bits: Vec<SsaVar> = bit_results.clone();
                    *inst = Instruction::Const {
                        result: *result,
                        value: val,
                    };
                    decompose_expansions.push((idx, val, bits));
                }
            }
            // Input, AssertEq, Assert, PoseidonHash — no folding
            _ => {}
        }
    }

    // Expand constant Decompose: insert Const instructions for each bit
    // immediately after the Decompose's original position. The
    // decompose_expansions vec is naturally sorted by `idx` because we
    // pushed in walk order; we sweep it in lockstep with the drain.
    if !decompose_expansions.is_empty() {
        let total_extra: usize = decompose_expansions.iter().map(|(_, _, b)| b.len()).sum();
        let mut new_instructions = Vec::with_capacity(program.len() + total_extra);
        let mut next_exp = 0usize;

        for (idx, inst) in program.drain_instructions().enumerate() {
            new_instructions.push(inst);
            if next_exp < decompose_expansions.len() && decompose_expansions[next_exp].0 == idx {
                let (_, val, bits) = &decompose_expansions[next_exp];
                let limbs = val.to_canonical();
                for (i, bit_var) in bits.iter().enumerate() {
                    let limb_idx = i / 64;
                    let bit_idx = i % 64;
                    let bit = if limb_idx < 4 {
                        (limbs[limb_idx] >> bit_idx) & 1
                    } else {
                        0
                    };
                    let bit_val = if bit == 1 {
                        FieldElement::<F>::one()
                    } else {
                        FieldElement::<F>::zero()
                    };
                    new_instructions.push(Instruction::Const {
                        result: *bit_var,
                        value: bit_val,
                    });
                }
                next_exp += 1;
            }
        }
        program.instructions = new_instructions;
    }
}

#[cfg(test)]
mod tests {
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
                Instruction::Const { result, value } if *value == FieldElement::one() => {
                    Some(*result)
                }
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
}
