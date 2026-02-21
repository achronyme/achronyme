use std::collections::HashMap;
use std::fmt;

use constraints::poseidon::{poseidon_hash, PoseidonParams};
use memory::FieldElement;

use crate::types::{Instruction, IrProgram, SsaVar};

/// Errors that can occur during IR evaluation.
#[derive(Debug)]
pub enum EvalError {
    MissingInput(String),
    DivisionByZero { var: SsaVar },
    AssertionFailed { var: SsaVar },
    AssertEqFailed { lhs: SsaVar, rhs: SsaVar },
    RangeCheckFailed { var: SsaVar, bits: u32 },
    UndefinedVar(SsaVar),
}

impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvalError::MissingInput(name) => write!(f, "missing input: `{name}`"),
            EvalError::DivisionByZero { var } => {
                write!(f, "division by zero at SSA var {:?}", var.0)
            }
            EvalError::AssertionFailed { var } => {
                write!(f, "assertion failed at SSA var {:?}", var.0)
            }
            EvalError::AssertEqFailed { lhs, rhs } => {
                write!(
                    f,
                    "assert_eq failed: SSA vars {:?} and {:?} are not equal",
                    lhs.0, rhs.0
                )
            }
            EvalError::RangeCheckFailed { var, bits } => {
                write!(
                    f,
                    "range check failed: SSA var {:?} does not fit in {bits} bits",
                    var.0
                )
            }
            EvalError::UndefinedVar(var) => write!(f, "undefined SSA var {:?}", var.0),
        }
    }
}

impl std::error::Error for EvalError {}

/// Evaluate an IR program with concrete inputs, returning all SSA variable values.
///
/// This is a pure evaluator: it computes every SSA variable's value by walking
/// the instruction list forward. Assertions (`AssertEq`, `Assert`, `RangeCheck`)
/// are checked eagerly and return errors immediately on failure.
pub fn evaluate(
    program: &IrProgram,
    inputs: &HashMap<String, FieldElement>,
) -> Result<HashMap<SsaVar, FieldElement>, EvalError> {
    let mut values: HashMap<SsaVar, FieldElement> = HashMap::new();
    let mut poseidon_params: Option<PoseidonParams> = None;

    let get = |values: &HashMap<SsaVar, FieldElement>, var: &SsaVar| -> Result<FieldElement, EvalError> {
        values.get(var).copied().ok_or(EvalError::UndefinedVar(*var))
    };

    for inst in &program.instructions {
        match inst {
            Instruction::Const { result, value } => {
                values.insert(*result, *value);
            }
            Instruction::Input { result, name, .. } => {
                let val = inputs
                    .get(name)
                    .copied()
                    .ok_or_else(|| EvalError::MissingInput(name.clone()))?;
                values.insert(*result, val);
            }
            Instruction::Add { result, lhs, rhs } => {
                let a = get(&values, lhs)?;
                let b = get(&values, rhs)?;
                values.insert(*result, a.add(&b));
            }
            Instruction::Sub { result, lhs, rhs } => {
                let a = get(&values, lhs)?;
                let b = get(&values, rhs)?;
                values.insert(*result, a.sub(&b));
            }
            Instruction::Mul { result, lhs, rhs } => {
                let a = get(&values, lhs)?;
                let b = get(&values, rhs)?;
                values.insert(*result, a.mul(&b));
            }
            Instruction::Div { result, lhs, rhs } => {
                let a = get(&values, lhs)?;
                let b = get(&values, rhs)?;
                let inv = b.inv().ok_or(EvalError::DivisionByZero { var: *result })?;
                values.insert(*result, a.mul(&inv));
            }
            Instruction::Neg { result, operand } => {
                let v = get(&values, operand)?;
                values.insert(*result, v.neg());
            }
            Instruction::Mux {
                result,
                cond,
                if_true,
                if_false,
            } => {
                let c = get(&values, cond)?;
                let t = get(&values, if_true)?;
                let f = get(&values, if_false)?;
                let val = if c == FieldElement::ONE { t } else { f };
                values.insert(*result, val);
            }
            Instruction::PoseidonHash {
                result,
                left,
                right,
            } => {
                let l = get(&values, left)?;
                let r = get(&values, right)?;
                let params = poseidon_params
                    .get_or_insert_with(PoseidonParams::bn254_t3);
                let hash = poseidon_hash(params, l, r);
                values.insert(*result, hash);
            }
            Instruction::AssertEq { result, lhs, rhs } => {
                let a = get(&values, lhs)?;
                let b = get(&values, rhs)?;
                if a != b {
                    return Err(EvalError::AssertEqFailed {
                        lhs: *lhs,
                        rhs: *rhs,
                    });
                }
                values.insert(*result, a);
            }
            Instruction::Assert { result, operand } => {
                let v = get(&values, operand)?;
                if v != FieldElement::ONE {
                    return Err(EvalError::AssertionFailed { var: *operand });
                }
                values.insert(*result, v);
            }
            Instruction::RangeCheck {
                result,
                operand,
                bits,
            } => {
                let v = get(&values, operand)?;
                if !fits_in_bits(&v, *bits) {
                    return Err(EvalError::RangeCheckFailed {
                        var: *operand,
                        bits: *bits,
                    });
                }
                values.insert(*result, v);
            }
            Instruction::Not { result, operand } => {
                let v = get(&values, operand)?;
                values.insert(*result, FieldElement::ONE.sub(&v));
            }
            Instruction::And { result, lhs, rhs } => {
                let a = get(&values, lhs)?;
                let b = get(&values, rhs)?;
                values.insert(*result, a.mul(&b));
            }
            Instruction::Or { result, lhs, rhs } => {
                let a = get(&values, lhs)?;
                let b = get(&values, rhs)?;
                // a + b - a*b
                values.insert(*result, a.add(&b).sub(&a.mul(&b)));
            }
            Instruction::IsEq { result, lhs, rhs } => {
                let a = get(&values, lhs)?;
                let b = get(&values, rhs)?;
                let eq = if a == b {
                    FieldElement::ONE
                } else {
                    FieldElement::ZERO
                };
                values.insert(*result, eq);
            }
            Instruction::IsNeq { result, lhs, rhs } => {
                let a = get(&values, lhs)?;
                let b = get(&values, rhs)?;
                let neq = if a != b {
                    FieldElement::ONE
                } else {
                    FieldElement::ZERO
                };
                values.insert(*result, neq);
            }
            Instruction::IsLt { result, lhs, rhs } => {
                let a = get(&values, lhs)?;
                let b = get(&values, rhs)?;
                let la = a.to_canonical();
                let lb = b.to_canonical();
                let less = (la[3], la[2], la[1], la[0]) < (lb[3], lb[2], lb[1], lb[0]);
                values.insert(
                    *result,
                    if less {
                        FieldElement::ONE
                    } else {
                        FieldElement::ZERO
                    },
                );
            }
            Instruction::IsLe { result, lhs, rhs } => {
                let a = get(&values, lhs)?;
                let b = get(&values, rhs)?;
                let la = a.to_canonical();
                let lb = b.to_canonical();
                let le = (la[3], la[2], la[1], la[0]) <= (lb[3], lb[2], lb[1], lb[0]);
                values.insert(
                    *result,
                    if le {
                        FieldElement::ONE
                    } else {
                        FieldElement::ZERO
                    },
                );
            }
        }
    }

    Ok(values)
}

/// Check whether a field element fits in `bits` bits.
fn fits_in_bits(v: &FieldElement, bits: u32) -> bool {
    if bits >= 256 {
        return true;
    }
    let limbs = v.to_canonical();
    // Check each 64-bit limb
    for (i, &limb) in limbs.iter().enumerate() {
        let limb_start = (i as u32) * 64;
        if limb_start >= bits {
            // This entire limb must be zero
            if limb != 0 {
                return false;
            }
        } else {
            let remaining_bits = bits - limb_start;
            if remaining_bits < 64 {
                // Only lower `remaining_bits` bits allowed
                if limb >= (1u64 << remaining_bits) {
                    return false;
                }
            }
            // If remaining_bits >= 64, the whole limb is fine
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{IrProgram, Instruction, SsaVar, Visibility};

    fn empty_inputs() -> HashMap<String, FieldElement> {
        HashMap::new()
    }

    fn fe(n: u64) -> FieldElement {
        FieldElement::from_u64(n)
    }

    #[test]
    fn eval_const() {
        let mut p = IrProgram::new();
        let v = p.fresh_var();
        p.push(Instruction::Const { result: v, value: fe(42) });
        let vals = evaluate(&p, &empty_inputs()).unwrap();
        assert_eq!(vals[&v], fe(42));
    }

    #[test]
    fn eval_input() {
        let mut p = IrProgram::new();
        let v = p.fresh_var();
        p.push(Instruction::Input {
            result: v,
            name: "x".into(),
            visibility: Visibility::Public,
        });
        let mut inputs = HashMap::new();
        inputs.insert("x".into(), fe(7));
        let vals = evaluate(&p, &inputs).unwrap();
        assert_eq!(vals[&v], fe(7));
    }

    #[test]
    fn eval_missing_input_error() {
        let mut p = IrProgram::new();
        let v = p.fresh_var();
        p.push(Instruction::Input {
            result: v,
            name: "x".into(),
            visibility: Visibility::Witness,
        });
        let err = evaluate(&p, &empty_inputs()).unwrap_err();
        assert!(matches!(err, EvalError::MissingInput(ref n) if n == "x"));
    }

    #[test]
    fn eval_add() {
        let mut p = IrProgram::new();
        let a = p.fresh_var();
        let b = p.fresh_var();
        let c = p.fresh_var();
        p.push(Instruction::Const { result: a, value: fe(3) });
        p.push(Instruction::Const { result: b, value: fe(4) });
        p.push(Instruction::Add { result: c, lhs: a, rhs: b });
        let vals = evaluate(&p, &empty_inputs()).unwrap();
        assert_eq!(vals[&c], fe(7));
    }

    #[test]
    fn eval_sub() {
        let mut p = IrProgram::new();
        let a = p.fresh_var();
        let b = p.fresh_var();
        let c = p.fresh_var();
        p.push(Instruction::Const { result: a, value: fe(10) });
        p.push(Instruction::Const { result: b, value: fe(3) });
        p.push(Instruction::Sub { result: c, lhs: a, rhs: b });
        let vals = evaluate(&p, &empty_inputs()).unwrap();
        assert_eq!(vals[&c], fe(7));
    }

    #[test]
    fn eval_mul() {
        let mut p = IrProgram::new();
        let a = p.fresh_var();
        let b = p.fresh_var();
        let c = p.fresh_var();
        p.push(Instruction::Const { result: a, value: fe(6) });
        p.push(Instruction::Const { result: b, value: fe(7) });
        p.push(Instruction::Mul { result: c, lhs: a, rhs: b });
        let vals = evaluate(&p, &empty_inputs()).unwrap();
        assert_eq!(vals[&c], fe(42));
    }

    #[test]
    fn eval_div() {
        let mut p = IrProgram::new();
        let a = p.fresh_var();
        let b = p.fresh_var();
        let c = p.fresh_var();
        p.push(Instruction::Const { result: a, value: fe(42) });
        p.push(Instruction::Const { result: b, value: fe(6) });
        p.push(Instruction::Div { result: c, lhs: a, rhs: b });
        let vals = evaluate(&p, &empty_inputs()).unwrap();
        assert_eq!(vals[&c], fe(7));
    }

    #[test]
    fn eval_neg() {
        let mut p = IrProgram::new();
        let a = p.fresh_var();
        let b = p.fresh_var();
        p.push(Instruction::Const { result: a, value: fe(5) });
        p.push(Instruction::Neg { result: b, operand: a });
        let vals = evaluate(&p, &empty_inputs()).unwrap();
        assert_eq!(vals[&b], fe(5).neg());
    }

    #[test]
    fn eval_div_by_zero_error() {
        let mut p = IrProgram::new();
        let a = p.fresh_var();
        let b = p.fresh_var();
        let c = p.fresh_var();
        p.push(Instruction::Const { result: a, value: fe(1) });
        p.push(Instruction::Const { result: b, value: FieldElement::ZERO });
        p.push(Instruction::Div { result: c, lhs: a, rhs: b });
        let err = evaluate(&p, &empty_inputs()).unwrap_err();
        assert!(matches!(err, EvalError::DivisionByZero { .. }));
    }

    #[test]
    fn eval_mux_true() {
        let mut p = IrProgram::new();
        let c = p.fresh_var();
        let t = p.fresh_var();
        let f = p.fresh_var();
        let r = p.fresh_var();
        p.push(Instruction::Const { result: c, value: FieldElement::ONE });
        p.push(Instruction::Const { result: t, value: fe(10) });
        p.push(Instruction::Const { result: f, value: fe(20) });
        p.push(Instruction::Mux {
            result: r,
            cond: c,
            if_true: t,
            if_false: f,
        });
        let vals = evaluate(&p, &empty_inputs()).unwrap();
        assert_eq!(vals[&r], fe(10));
    }

    #[test]
    fn eval_mux_false() {
        let mut p = IrProgram::new();
        let c = p.fresh_var();
        let t = p.fresh_var();
        let f = p.fresh_var();
        let r = p.fresh_var();
        p.push(Instruction::Const { result: c, value: FieldElement::ZERO });
        p.push(Instruction::Const { result: t, value: fe(10) });
        p.push(Instruction::Const { result: f, value: fe(20) });
        p.push(Instruction::Mux {
            result: r,
            cond: c,
            if_true: t,
            if_false: f,
        });
        let vals = evaluate(&p, &empty_inputs()).unwrap();
        assert_eq!(vals[&r], fe(20));
    }

    #[test]
    fn eval_poseidon_matches_native() {
        let params = PoseidonParams::bn254_t3();
        let l = fe(1);
        let r = fe(2);
        let expected = poseidon_hash(&params, l, r);

        let mut p = IrProgram::new();
        let lv = p.fresh_var();
        let rv = p.fresh_var();
        let hv = p.fresh_var();
        p.push(Instruction::Const { result: lv, value: l });
        p.push(Instruction::Const { result: rv, value: r });
        p.push(Instruction::PoseidonHash {
            result: hv,
            left: lv,
            right: rv,
        });
        let vals = evaluate(&p, &empty_inputs()).unwrap();
        assert_eq!(vals[&hv], expected);
    }

    #[test]
    fn eval_not() {
        let mut p = IrProgram::new();
        let a = p.fresh_var();
        let b = p.fresh_var();
        p.push(Instruction::Const { result: a, value: FieldElement::ONE });
        p.push(Instruction::Not { result: b, operand: a });
        let vals = evaluate(&p, &empty_inputs()).unwrap();
        assert_eq!(vals[&b], FieldElement::ZERO);
    }

    #[test]
    fn eval_and() {
        let mut p = IrProgram::new();
        let a = p.fresh_var();
        let b = p.fresh_var();
        let c = p.fresh_var();
        p.push(Instruction::Const { result: a, value: FieldElement::ONE });
        p.push(Instruction::Const { result: b, value: FieldElement::ZERO });
        p.push(Instruction::And { result: c, lhs: a, rhs: b });
        let vals = evaluate(&p, &empty_inputs()).unwrap();
        assert_eq!(vals[&c], FieldElement::ZERO);
    }

    #[test]
    fn eval_or() {
        let mut p = IrProgram::new();
        let a = p.fresh_var();
        let b = p.fresh_var();
        let c = p.fresh_var();
        p.push(Instruction::Const { result: a, value: FieldElement::ONE });
        p.push(Instruction::Const { result: b, value: FieldElement::ZERO });
        p.push(Instruction::Or { result: c, lhs: a, rhs: b });
        let vals = evaluate(&p, &empty_inputs()).unwrap();
        assert_eq!(vals[&c], FieldElement::ONE);
    }

    #[test]
    fn eval_is_eq() {
        let mut p = IrProgram::new();
        let a = p.fresh_var();
        let b = p.fresh_var();
        let c = p.fresh_var();
        p.push(Instruction::Const { result: a, value: fe(5) });
        p.push(Instruction::Const { result: b, value: fe(5) });
        p.push(Instruction::IsEq { result: c, lhs: a, rhs: b });
        let vals = evaluate(&p, &empty_inputs()).unwrap();
        assert_eq!(vals[&c], FieldElement::ONE);
    }

    #[test]
    fn eval_is_neq() {
        let mut p = IrProgram::new();
        let a = p.fresh_var();
        let b = p.fresh_var();
        let c = p.fresh_var();
        p.push(Instruction::Const { result: a, value: fe(3) });
        p.push(Instruction::Const { result: b, value: fe(5) });
        p.push(Instruction::IsNeq { result: c, lhs: a, rhs: b });
        let vals = evaluate(&p, &empty_inputs()).unwrap();
        assert_eq!(vals[&c], FieldElement::ONE);
    }

    #[test]
    fn eval_is_lt() {
        let mut p = IrProgram::new();
        let a = p.fresh_var();
        let b = p.fresh_var();
        let c = p.fresh_var();
        p.push(Instruction::Const { result: a, value: fe(3) });
        p.push(Instruction::Const { result: b, value: fe(5) });
        p.push(Instruction::IsLt { result: c, lhs: a, rhs: b });
        let vals = evaluate(&p, &empty_inputs()).unwrap();
        assert_eq!(vals[&c], FieldElement::ONE);

        // Not less
        let mut p2 = IrProgram::new();
        let a2 = p2.fresh_var();
        let b2 = p2.fresh_var();
        let c2 = p2.fresh_var();
        p2.push(Instruction::Const { result: a2, value: fe(5) });
        p2.push(Instruction::Const { result: b2, value: fe(3) });
        p2.push(Instruction::IsLt { result: c2, lhs: a2, rhs: b2 });
        let vals2 = evaluate(&p2, &empty_inputs()).unwrap();
        assert_eq!(vals2[&c2], FieldElement::ZERO);
    }

    #[test]
    fn eval_is_le() {
        let mut p = IrProgram::new();
        let a = p.fresh_var();
        let b = p.fresh_var();
        let c = p.fresh_var();
        p.push(Instruction::Const { result: a, value: fe(5) });
        p.push(Instruction::Const { result: b, value: fe(5) });
        p.push(Instruction::IsLe { result: c, lhs: a, rhs: b });
        let vals = evaluate(&p, &empty_inputs()).unwrap();
        assert_eq!(vals[&c], FieldElement::ONE);
    }

    #[test]
    fn eval_assert_ok() {
        let mut p = IrProgram::new();
        let a = p.fresh_var();
        let r = p.fresh_var();
        p.push(Instruction::Const { result: a, value: FieldElement::ONE });
        p.push(Instruction::Assert { result: r, operand: a });
        assert!(evaluate(&p, &empty_inputs()).is_ok());
    }

    #[test]
    fn eval_assert_fail() {
        let mut p = IrProgram::new();
        let a = p.fresh_var();
        let r = p.fresh_var();
        p.push(Instruction::Const { result: a, value: FieldElement::ZERO });
        p.push(Instruction::Assert { result: r, operand: a });
        let err = evaluate(&p, &empty_inputs()).unwrap_err();
        assert!(matches!(err, EvalError::AssertionFailed { .. }));
    }

    #[test]
    fn eval_assert_eq_fail() {
        let mut p = IrProgram::new();
        let a = p.fresh_var();
        let b = p.fresh_var();
        let r = p.fresh_var();
        p.push(Instruction::Const { result: a, value: fe(1) });
        p.push(Instruction::Const { result: b, value: fe(2) });
        p.push(Instruction::AssertEq { result: r, lhs: a, rhs: b });
        let err = evaluate(&p, &empty_inputs()).unwrap_err();
        assert!(matches!(err, EvalError::AssertEqFailed { .. }));
    }

    #[test]
    fn eval_range_check_ok() {
        let mut p = IrProgram::new();
        let a = p.fresh_var();
        let r = p.fresh_var();
        p.push(Instruction::Const { result: a, value: fe(255) });
        p.push(Instruction::RangeCheck { result: r, operand: a, bits: 8 });
        assert!(evaluate(&p, &empty_inputs()).is_ok());
    }

    #[test]
    fn eval_range_check_fail() {
        let mut p = IrProgram::new();
        let a = p.fresh_var();
        let r = p.fresh_var();
        p.push(Instruction::Const { result: a, value: fe(256) });
        p.push(Instruction::RangeCheck { result: r, operand: a, bits: 8 });
        let err = evaluate(&p, &empty_inputs()).unwrap_err();
        assert!(matches!(err, EvalError::RangeCheckFailed { .. }));
    }

    #[test]
    fn fits_in_bits_edge_cases() {
        assert!(fits_in_bits(&fe(0), 1));
        assert!(fits_in_bits(&fe(1), 1));
        assert!(!fits_in_bits(&fe(2), 1));
        assert!(fits_in_bits(&fe(255), 8));
        assert!(!fits_in_bits(&fe(256), 8));
        assert!(fits_in_bits(&fe(u64::MAX), 64));
        assert!(!fits_in_bits(&fe(u64::MAX), 63));
    }
}
