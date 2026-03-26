use std::collections::HashMap;
use std::fmt;

use constraints::poseidon::{poseidon_hash, PoseidonParams};
use memory::FieldElement;

use crate::types::{Instruction, IrProgram, SsaVar};

/// Errors that can occur during IR evaluation.
#[derive(Debug)]
pub enum EvalError {
    MissingInput(String),
    DivisionByZero {
        var: SsaVar,
        dividend_name: Option<String>,
        divisor_name: Option<String>,
    },
    AssertionFailed {
        var: SsaVar,
        name: Option<String>,
        value: Option<FieldElement>,
        message: Option<String>,
    },
    AssertEqFailed {
        lhs: SsaVar,
        rhs: SsaVar,
        lhs_name: Option<String>,
        rhs_name: Option<String>,
        lhs_value: Option<FieldElement>,
        rhs_value: Option<FieldElement>,
        message: Option<String>,
    },
    RangeCheckFailed {
        var: SsaVar,
        bits: u32,
        name: Option<String>,
        value: Option<FieldElement>,
    },
    NonBooleanMuxCondition {
        var: SsaVar,
        name: Option<String>,
        value: Option<FieldElement>,
    },
    UndefinedVar(SsaVar),
}

/// Look up the source-level name for an SSA variable.
fn resolve_name(program: &IrProgram, var: SsaVar) -> Option<String> {
    program.get_name(var).map(|s| s.to_string())
}

impl fmt::Display for EvalError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvalError::MissingInput(name) => write!(f, "missing input: `{name}`"),
            EvalError::DivisionByZero {
                dividend_name,
                divisor_name,
                ..
            } => match (dividend_name, divisor_name) {
                (Some(a), Some(b)) => {
                    write!(
                        f,
                        "division by zero when dividing '{a}' by '{b}' (which is 0)"
                    )
                }
                _ => write!(f, "division by zero"),
            },
            EvalError::AssertionFailed {
                name,
                value,
                message,
                ..
            } => {
                if let Some(msg) = message {
                    write!(f, "assertion failed: {msg}")
                } else {
                    match (name, value) {
                        (Some(n), Some(v)) => write!(
                            f,
                            "assertion failed at '{n}' (value is {}, expected non-zero)",
                            v.to_decimal_string()
                        ),
                        (Some(n), None) => {
                            write!(f, "assertion failed at '{n}' (expected non-zero)")
                        }
                        _ => write!(f, "assertion failed (expected non-zero)"),
                    }
                }
            }
            EvalError::AssertEqFailed {
                lhs_name,
                rhs_name,
                lhs_value,
                rhs_value,
                message,
                ..
            } => {
                if let Some(msg) = message {
                    write!(f, "assert_eq failed: {msg}")
                } else {
                    match (lhs_name, rhs_name, lhs_value, rhs_value) {
                        (Some(a), Some(b), Some(av), Some(bv)) => write!(
                            f,
                            "assert_eq failed: '{a}' (value {}) != '{b}' (value {})",
                            av.to_decimal_string(),
                            bv.to_decimal_string()
                        ),
                        _ => write!(f, "assert_eq failed: values are not equal"),
                    }
                }
            }
            EvalError::RangeCheckFailed {
                bits, name, value, ..
            } => match (name, value) {
                (Some(n), Some(v)) => {
                    let max_str = if *bits < 64 {
                        format!("{}", (1u64 << bits) - 1)
                    } else {
                        format!("2^{bits}-1")
                    };
                    write!(
                        f,
                        "range check failed: '{n}' (value {}) does not fit in {bits} bits (max {max_str})",
                        v.to_decimal_string()
                    )
                }
                _ => write!(f, "range check failed: value does not fit in {bits} bits"),
            },
            EvalError::NonBooleanMuxCondition { name, value, .. } => match (name, value) {
                (Some(n), Some(v)) => write!(
                    f,
                    "if/else condition must be boolean: '{n}' has value {} (expected 0 or 1)",
                    v.to_decimal_string()
                ),
                _ => write!(f, "if/else condition must be boolean (expected 0 or 1)"),
            },
            EvalError::UndefinedVar(var) => write!(f, "undefined variable #{}", var.0),
        }
    }
}

impl std::error::Error for EvalError {}

/// Evaluate an IR program with concrete inputs, returning all SSA variable values.
///
/// This is a pure evaluator: it computes every SSA variable's value by walking
/// the instruction list forward. Assertions (`AssertEq`, `Assert`, `RangeCheck`)
/// are checked eagerly and return errors immediately on failure.
///
/// ```
/// use std::collections::HashMap;
/// use ir::IrLowering;
/// use ir::eval::evaluate;
/// use memory::FieldElement;
///
/// let prog = IrLowering::lower_circuit("assert_eq(x, y)", &["x"], &["y"]).unwrap();
/// let mut inputs = HashMap::new();
/// inputs.insert("x".to_string(), FieldElement::from_u64(42));
/// inputs.insert("y".to_string(), FieldElement::from_u64(42));
/// assert!(evaluate(&prog, &inputs).is_ok());
/// ```
pub fn evaluate(
    program: &IrProgram,
    inputs: &HashMap<String, FieldElement>,
) -> Result<HashMap<SsaVar, FieldElement>, Box<EvalError>> {
    let mut values: HashMap<SsaVar, FieldElement> = HashMap::new();
    let mut poseidon_params: Option<PoseidonParams> = None;

    let get = |values: &HashMap<SsaVar, FieldElement>,
               var: &SsaVar|
     -> Result<FieldElement, Box<EvalError>> {
        values
            .get(var)
            .copied()
            .ok_or_else(|| Box::new(EvalError::UndefinedVar(*var)))
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
                    .ok_or_else(|| Box::new(EvalError::MissingInput(name.clone())))?;
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
                let inv = b.inv().ok_or_else(|| {
                    Box::new(EvalError::DivisionByZero {
                        var: *result,
                        dividend_name: resolve_name(program, *lhs),
                        divisor_name: resolve_name(program, *rhs),
                    })
                })?;
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
                if c != FieldElement::ZERO && c != FieldElement::ONE {
                    return Err(Box::new(EvalError::NonBooleanMuxCondition {
                        var: *cond,
                        name: resolve_name(program, *cond),
                        value: Some(c),
                    }));
                }
                let val = if !c.is_zero() { t } else { f };
                values.insert(*result, val);
            }
            Instruction::PoseidonHash {
                result,
                left,
                right,
            } => {
                let l = get(&values, left)?;
                let r = get(&values, right)?;
                let params = poseidon_params.get_or_insert_with(PoseidonParams::bn254_t3);
                let hash = poseidon_hash(params, l, r);
                values.insert(*result, hash);
            }
            Instruction::AssertEq {
                result,
                lhs,
                rhs,
                message,
            } => {
                let a = get(&values, lhs)?;
                let b = get(&values, rhs)?;
                if a != b {
                    return Err(Box::new(EvalError::AssertEqFailed {
                        lhs: *lhs,
                        rhs: *rhs,
                        lhs_name: resolve_name(program, *lhs),
                        rhs_name: resolve_name(program, *rhs),
                        lhs_value: Some(a),
                        rhs_value: Some(b),
                        message: message.clone(),
                    }));
                }
                values.insert(*result, a);
            }
            Instruction::Assert {
                result,
                operand,
                message,
            } => {
                let v = get(&values, operand)?;
                if v != FieldElement::ONE {
                    return Err(Box::new(EvalError::AssertionFailed {
                        var: *operand,
                        name: resolve_name(program, *operand),
                        value: Some(v),
                        message: message.clone(),
                    }));
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
                    return Err(Box::new(EvalError::RangeCheckFailed {
                        var: *operand,
                        bits: *bits,
                        name: resolve_name(program, *operand),
                        value: Some(v),
                    }));
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
            Instruction::IsLt { result, lhs, rhs }
            | Instruction::IsLtBounded {
                result, lhs, rhs, ..
            } => {
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
            Instruction::IsLe { result, lhs, rhs }
            | Instruction::IsLeBounded {
                result, lhs, rhs, ..
            } => {
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
mod tests;
