use std::collections::HashMap;

use constraints::poseidon::{poseidon_hash, PoseidonParams};
use constraints::PoseidonParamsProvider;
use memory::{FieldBackend, FieldElement};

use crate::types::{Instruction, IrProgram, SsaVar};

use super::error::resolve_name;
use super::int::{fits_in_bits, int_divmod_field};
use super::witness::dispatch_witness_call;
use super::EvalError;

/// ```
/// use std::collections::HashMap;
/// use ir::IrLowering;
/// use ir::eval::evaluate;
/// use memory::FieldElement;
///
/// let prog: ir::types::IrProgram =
///     IrLowering::lower_circuit("assert_eq(x, y)", &["x"], &["y"]).unwrap();
/// let mut inputs = HashMap::new();
/// inputs.insert("x".to_string(), FieldElement::from_u64(42));
/// inputs.insert("y".to_string(), FieldElement::from_u64(42));
/// assert!(evaluate(&prog, &inputs).is_ok());
/// ```
pub fn evaluate<F: FieldBackend + PoseidonParamsProvider>(
    program: &IrProgram<F>,
    inputs: &HashMap<String, FieldElement<F>>,
) -> Result<HashMap<SsaVar, FieldElement<F>>, Box<EvalError<F>>> {
    let mut values: HashMap<SsaVar, FieldElement<F>> = HashMap::new();
    let mut poseidon_params: Option<PoseidonParams<F>> = None;

    let get = |values: &HashMap<SsaVar, FieldElement<F>>,
               var: &SsaVar|
     -> Result<FieldElement<F>, Box<EvalError<F>>> {
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
                if c != FieldElement::<F>::zero() && c != FieldElement::<F>::one() {
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
                let params = poseidon_params.get_or_insert_with(F::default_poseidon_t3);
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
                if v != FieldElement::<F>::one() {
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
                values.insert(*result, FieldElement::<F>::one().sub(&v));
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
                    FieldElement::<F>::one()
                } else {
                    FieldElement::<F>::zero()
                };
                values.insert(*result, eq);
            }
            Instruction::IsNeq { result, lhs, rhs } => {
                let a = get(&values, lhs)?;
                let b = get(&values, rhs)?;
                let neq = if a != b {
                    FieldElement::<F>::one()
                } else {
                    FieldElement::<F>::zero()
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
                        FieldElement::<F>::one()
                    } else {
                        FieldElement::<F>::zero()
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
                        FieldElement::<F>::one()
                    } else {
                        FieldElement::<F>::zero()
                    },
                );
            }
            Instruction::Decompose {
                result,
                bit_results,
                operand,
                num_bits,
            } => {
                let v = get(&values, operand)?;
                if !fits_in_bits(&v, *num_bits) {
                    return Err(Box::new(EvalError::RangeCheckFailed {
                        var: *operand,
                        bits: *num_bits,
                        name: resolve_name(program, *operand),
                        value: Some(v),
                    }));
                }
                let limbs = v.to_canonical();
                for (i, bit_var) in bit_results.iter().enumerate() {
                    let limb_idx = i / 64;
                    let bit_pos = i % 64;
                    let bit = if limb_idx < 4 {
                        (limbs[limb_idx] >> bit_pos) & 1
                    } else {
                        0
                    };
                    values.insert(*bit_var, FieldElement::<F>::from_u64(bit));
                }
                values.insert(*result, v);
            }
            Instruction::IntDiv {
                result, lhs, rhs, ..
            } => {
                let a = get(&values, lhs)?;
                let b = get(&values, rhs)?;
                let (q, _) = int_divmod_field(&a, &b);
                values.insert(*result, q);
            }
            Instruction::IntMod {
                result, lhs, rhs, ..
            } => {
                let a = get(&values, lhs)?;
                let b = get(&values, rhs)?;
                let (_, r) = int_divmod_field(&a, &b);
                values.insert(*result, r);
            }
            Instruction::WitnessCall(call) => {
                dispatch_witness_call(
                    &call.inputs,
                    &call.outputs,
                    &call.program_bytes,
                    &mut values,
                )?;
            }
        }
    }

    Ok(values)
}
