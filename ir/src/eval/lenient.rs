use std::collections::HashMap;

use constraints::poseidon::{poseidon_hash, PoseidonParams};
use constraints::PoseidonParamsProvider;
use memory::{FieldBackend, FieldElement};

use crate::types::{Instruction, IrProgram, SsaVar};

use super::int::int_divmod_field;
use super::witness::dispatch_witness_call;

pub fn evaluate_lenient<F: FieldBackend + PoseidonParamsProvider>(
    program: &IrProgram<F>,
    inputs: &HashMap<String, FieldElement<F>>,
) -> (HashMap<SsaVar, FieldElement<F>>, Vec<usize>) {
    let mut values: HashMap<SsaVar, FieldElement<F>> = HashMap::new();
    let mut poseidon_params: Option<PoseidonParams<F>> = None;
    let mut failures: Vec<usize> = Vec::new();

    let get = |values: &HashMap<SsaVar, FieldElement<F>>,
               var: &SsaVar|
     -> Option<FieldElement<F>> { values.get(var).copied() };

    for (idx, inst) in program.iter().enumerate() {
        match inst {
            Instruction::Const { result, value } => {
                values.insert(*result, *value);
            }
            Instruction::Input { result, name, .. } => {
                if let Some(val) = inputs.get(name) {
                    values.insert(*result, *val);
                }
            }
            Instruction::Add { result, lhs, rhs } => {
                if let (Some(a), Some(b)) = (get(&values, lhs), get(&values, rhs)) {
                    values.insert(*result, a.add(&b));
                }
            }
            Instruction::Sub { result, lhs, rhs } => {
                if let (Some(a), Some(b)) = (get(&values, lhs), get(&values, rhs)) {
                    values.insert(*result, a.sub(&b));
                }
            }
            Instruction::Mul { result, lhs, rhs } => {
                if let (Some(a), Some(b)) = (get(&values, lhs), get(&values, rhs)) {
                    values.insert(*result, a.mul(&b));
                }
            }
            Instruction::Div { result, lhs, rhs } => {
                if let (Some(a), Some(b)) = (get(&values, lhs), get(&values, rhs)) {
                    if let Some(inv) = b.inv() {
                        values.insert(*result, a.mul(&inv));
                    }
                }
            }
            Instruction::Neg { result, operand } => {
                if let Some(v) = get(&values, operand) {
                    values.insert(*result, v.neg());
                }
            }
            Instruction::Mux {
                result,
                cond,
                if_true,
                if_false,
            } => {
                if let (Some(c), Some(t), Some(f)) = (
                    get(&values, cond),
                    get(&values, if_true),
                    get(&values, if_false),
                ) {
                    values.insert(*result, if !c.is_zero() { t } else { f });
                }
            }
            Instruction::PoseidonHash {
                result,
                left,
                right,
            } => {
                if let (Some(l), Some(r)) = (get(&values, left), get(&values, right)) {
                    let params = poseidon_params.get_or_insert_with(F::default_poseidon_t3);
                    values.insert(*result, poseidon_hash(params, l, r));
                }
            }
            Instruction::AssertEq {
                result, lhs, rhs, ..
            } => {
                if let (Some(a), Some(b)) = (get(&values, lhs), get(&values, rhs)) {
                    if a != b {
                        failures.push(idx);
                    }
                    values.insert(*result, a);
                }
            }
            Instruction::Assert {
                result, operand, ..
            } => {
                if let Some(v) = get(&values, operand) {
                    if v != FieldElement::<F>::one() {
                        failures.push(idx);
                    }
                    values.insert(*result, v);
                }
            }
            Instruction::RangeCheck {
                result, operand, ..
            } => {
                if let Some(v) = get(&values, operand) {
                    values.insert(*result, v);
                }
            }
            Instruction::Not { result, operand } => {
                if let Some(v) = get(&values, operand) {
                    values.insert(*result, FieldElement::<F>::one().sub(&v));
                }
            }
            Instruction::And { result, lhs, rhs } => {
                if let (Some(a), Some(b)) = (get(&values, lhs), get(&values, rhs)) {
                    values.insert(*result, a.mul(&b));
                }
            }
            Instruction::Or { result, lhs, rhs } => {
                if let (Some(a), Some(b)) = (get(&values, lhs), get(&values, rhs)) {
                    values.insert(*result, a.add(&b).sub(&a.mul(&b)));
                }
            }
            Instruction::IsEq { result, lhs, rhs } => {
                if let (Some(a), Some(b)) = (get(&values, lhs), get(&values, rhs)) {
                    values.insert(
                        *result,
                        if a == b {
                            FieldElement::<F>::one()
                        } else {
                            FieldElement::<F>::zero()
                        },
                    );
                }
            }
            Instruction::IsNeq { result, lhs, rhs } => {
                if let (Some(a), Some(b)) = (get(&values, lhs), get(&values, rhs)) {
                    values.insert(
                        *result,
                        if a != b {
                            FieldElement::<F>::one()
                        } else {
                            FieldElement::<F>::zero()
                        },
                    );
                }
            }
            Instruction::IsLt {
                result, lhs, rhs, ..
            }
            | Instruction::IsLtBounded {
                result, lhs, rhs, ..
            } => {
                if let (Some(a), Some(b)) = (get(&values, lhs), get(&values, rhs)) {
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
            }
            Instruction::IsLe {
                result, lhs, rhs, ..
            }
            | Instruction::IsLeBounded {
                result, lhs, rhs, ..
            } => {
                if let (Some(a), Some(b)) = (get(&values, lhs), get(&values, rhs)) {
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
            }
            Instruction::Decompose {
                result,
                bit_results,
                operand,
                ..
            } => {
                if let Some(v) = get(&values, operand) {
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
            }
            Instruction::IntDiv {
                result, lhs, rhs, ..
            } => {
                if let (Some(a), Some(b)) = (get(&values, lhs), get(&values, rhs)) {
                    let (q, _) = int_divmod_field(&a, &b);
                    values.insert(*result, q);
                }
            }
            Instruction::IntMod {
                result, lhs, rhs, ..
            } => {
                if let (Some(a), Some(b)) = (get(&values, lhs), get(&values, rhs)) {
                    let (_, r) = int_divmod_field(&a, &b);
                    values.insert(*result, r);
                }
            }
            Instruction::WitnessCall(call) => {
                // Lenient eval tolerates missing inputs (leaves values
                // absent); the Artik dispatch needs all inputs, so
                // bail silently and record the failure index if any
                // are unresolved. This matches the behaviour of other
                // lenient arms that skip incomplete computations.
                let all_resolved = call.inputs.iter().all(|v| values.contains_key(v));
                if !all_resolved {
                    failures.push(idx);
                    continue;
                }
                if dispatch_witness_call(
                    &call.inputs,
                    &call.outputs,
                    &call.program_bytes,
                    &mut values,
                )
                .is_err()
                {
                    failures.push(idx);
                }
            }
        }
    }

    (values, failures)
}
