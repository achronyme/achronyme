//! Bridge from Lysis's mirror [`InstructionKind<F>`] back to
//! the canonical [`Instruction<F>`].
//!
//! ## Why the mirror exists
//!
//! The Lysis VM deliberately keeps a mirror [`InstructionKind<F>`]
//! in the `lysis-types` leaf crate so new emitters can come online
//! without depending on `ir` (which transitively pulls the full
//! parser / diagnostics / resolve / compile tree). That decision
//! left open how the bytecode-driven emission path would eventually
//! feed the R1CS backend, whose signature is
//! `compile_ir(&IrProgram<F>) where IrProgram<F>: uses Instruction<F>`.
//!
//! ## Why the bridge lives in `ir`
//!
//! Rust's orphan rule requires `impl<..> From<A> for B` to be
//! defined in the crate that owns `A` or `B`. Since `Instruction<F>`
//! lives in `ir`, the `From` direction goes here. `ir` depends on
//! `lysis-types` for the mirror surface — a cheap leaf dep. `lysis`
//! is not needed just for the types anymore, though `ir` still pulls
//! in the full `lysis` crate because the walker (P7a's job) lives
//! here and uses the Lysis runtime (Program, ProgramBuilder,
//! executor, bytecode codec).
//!
//! ## Conversion shape
//!
//! Every `InstructionKind<F>` variant has a 1:1 counterpart in
//! `Instruction<F>` by name and field layout — that was the point
//! of the mirror. The only non-trivial bit is [`NodeId`] →
//! [`SsaVar`]: `NodeId` is a `NonZeroU32` one-based handle with a
//! zero-based `index()` accessor, while `SsaVar` is a plain
//! `u32` newtype. Converting via `SsaVar(id.index() as u32)` maps
//! the interner's insertion order directly onto the SSA var
//! numbering the backend expects.
//!
//! [`InstructionKind<F>`]: lysis_types::InstructionKind
//! [`NodeId`]: lysis_types::NodeId

use lysis_types::{InstructionKind, NodeId, Visibility as LysisVisibility};
use memory::FieldBackend;

use crate::types::{Instruction, SsaVar, Visibility as IrVisibility};

/// Convert a Lysis `NodeId` into the SSA var numbering the IR uses.
#[inline]
pub fn ssa_var_from_node_id(id: NodeId) -> SsaVar {
    SsaVar(id.index() as u32)
}

#[inline]
fn map_visibility(v: LysisVisibility) -> IrVisibility {
    match v {
        LysisVisibility::Public => IrVisibility::Public,
        LysisVisibility::Witness => IrVisibility::Witness,
    }
}

#[inline]
fn map_vec_ids(ids: &[NodeId]) -> Vec<SsaVar> {
    ids.iter().copied().map(ssa_var_from_node_id).collect()
}

/// Convert a Lysis [`InstructionKind<F>`] reference into the
/// canonical `ir::Instruction<F>` the R1CS backend consumes.
pub fn instruction_from_kind<F: FieldBackend>(kind: &InstructionKind<F>) -> Instruction<F> {
    use InstructionKind as K;
    match kind {
        K::Const { result, value } => Instruction::Const {
            result: ssa_var_from_node_id(*result),
            value: *value,
        },
        K::Input {
            result,
            name,
            visibility,
        } => Instruction::Input {
            result: ssa_var_from_node_id(*result),
            name: name.clone(),
            visibility: map_visibility(*visibility),
        },
        K::Add { result, lhs, rhs } => Instruction::Add {
            result: ssa_var_from_node_id(*result),
            lhs: ssa_var_from_node_id(*lhs),
            rhs: ssa_var_from_node_id(*rhs),
        },
        K::Sub { result, lhs, rhs } => Instruction::Sub {
            result: ssa_var_from_node_id(*result),
            lhs: ssa_var_from_node_id(*lhs),
            rhs: ssa_var_from_node_id(*rhs),
        },
        K::Mul { result, lhs, rhs } => Instruction::Mul {
            result: ssa_var_from_node_id(*result),
            lhs: ssa_var_from_node_id(*lhs),
            rhs: ssa_var_from_node_id(*rhs),
        },
        K::Div { result, lhs, rhs } => Instruction::Div {
            result: ssa_var_from_node_id(*result),
            lhs: ssa_var_from_node_id(*lhs),
            rhs: ssa_var_from_node_id(*rhs),
        },
        K::Neg { result, operand } => Instruction::Neg {
            result: ssa_var_from_node_id(*result),
            operand: ssa_var_from_node_id(*operand),
        },
        K::Mux {
            result,
            cond,
            if_true,
            if_false,
        } => Instruction::Mux {
            result: ssa_var_from_node_id(*result),
            cond: ssa_var_from_node_id(*cond),
            if_true: ssa_var_from_node_id(*if_true),
            if_false: ssa_var_from_node_id(*if_false),
        },
        K::AssertEq {
            result,
            lhs,
            rhs,
            message,
        } => Instruction::AssertEq {
            result: ssa_var_from_node_id(*result),
            lhs: ssa_var_from_node_id(*lhs),
            rhs: ssa_var_from_node_id(*rhs),
            message: message.clone(),
        },
        K::PoseidonHash {
            result,
            left,
            right,
        } => Instruction::PoseidonHash {
            result: ssa_var_from_node_id(*result),
            left: ssa_var_from_node_id(*left),
            right: ssa_var_from_node_id(*right),
        },
        K::RangeCheck {
            result,
            operand,
            bits,
        } => Instruction::RangeCheck {
            result: ssa_var_from_node_id(*result),
            operand: ssa_var_from_node_id(*operand),
            bits: *bits,
        },
        K::Not { result, operand } => Instruction::Not {
            result: ssa_var_from_node_id(*result),
            operand: ssa_var_from_node_id(*operand),
        },
        K::And { result, lhs, rhs } => Instruction::And {
            result: ssa_var_from_node_id(*result),
            lhs: ssa_var_from_node_id(*lhs),
            rhs: ssa_var_from_node_id(*rhs),
        },
        K::Or { result, lhs, rhs } => Instruction::Or {
            result: ssa_var_from_node_id(*result),
            lhs: ssa_var_from_node_id(*lhs),
            rhs: ssa_var_from_node_id(*rhs),
        },
        K::IsEq { result, lhs, rhs } => Instruction::IsEq {
            result: ssa_var_from_node_id(*result),
            lhs: ssa_var_from_node_id(*lhs),
            rhs: ssa_var_from_node_id(*rhs),
        },
        K::IsNeq { result, lhs, rhs } => Instruction::IsNeq {
            result: ssa_var_from_node_id(*result),
            lhs: ssa_var_from_node_id(*lhs),
            rhs: ssa_var_from_node_id(*rhs),
        },
        K::IsLt { result, lhs, rhs } => Instruction::IsLt {
            result: ssa_var_from_node_id(*result),
            lhs: ssa_var_from_node_id(*lhs),
            rhs: ssa_var_from_node_id(*rhs),
        },
        K::IsLe { result, lhs, rhs } => Instruction::IsLe {
            result: ssa_var_from_node_id(*result),
            lhs: ssa_var_from_node_id(*lhs),
            rhs: ssa_var_from_node_id(*rhs),
        },
        K::IsLtBounded {
            result,
            lhs,
            rhs,
            bitwidth,
        } => Instruction::IsLtBounded {
            result: ssa_var_from_node_id(*result),
            lhs: ssa_var_from_node_id(*lhs),
            rhs: ssa_var_from_node_id(*rhs),
            bitwidth: *bitwidth,
        },
        K::IsLeBounded {
            result,
            lhs,
            rhs,
            bitwidth,
        } => Instruction::IsLeBounded {
            result: ssa_var_from_node_id(*result),
            lhs: ssa_var_from_node_id(*lhs),
            rhs: ssa_var_from_node_id(*rhs),
            bitwidth: *bitwidth,
        },
        K::Assert {
            result,
            operand,
            message,
        } => Instruction::Assert {
            result: ssa_var_from_node_id(*result),
            operand: ssa_var_from_node_id(*operand),
            message: message.clone(),
        },
        K::Decompose {
            result,
            bit_results,
            operand,
            num_bits,
        } => Instruction::Decompose {
            result: ssa_var_from_node_id(*result),
            bit_results: map_vec_ids(bit_results),
            operand: ssa_var_from_node_id(*operand),
            num_bits: *num_bits,
        },
        K::IntDiv {
            result,
            lhs,
            rhs,
            max_bits,
        } => Instruction::IntDiv {
            result: ssa_var_from_node_id(*result),
            lhs: ssa_var_from_node_id(*lhs),
            rhs: ssa_var_from_node_id(*rhs),
            max_bits: *max_bits,
        },
        K::IntMod {
            result,
            lhs,
            rhs,
            max_bits,
        } => Instruction::IntMod {
            result: ssa_var_from_node_id(*result),
            lhs: ssa_var_from_node_id(*lhs),
            rhs: ssa_var_from_node_id(*rhs),
            max_bits: *max_bits,
        },
        K::WitnessCall {
            outputs,
            inputs,
            program_bytes,
        } => Instruction::WitnessCall {
            outputs: map_vec_ids(outputs),
            inputs: map_vec_ids(inputs),
            program_bytes: program_bytes.clone(),
        },
    }
}

#[cfg(test)]
mod tests {
    use memory::{Bn254Fr, FieldElement};

    use super::*;

    fn node(i: usize) -> lysis_types::NodeId {
        lysis_types::NodeId::from_zero_based(i)
    }

    fn fe(n: u64) -> FieldElement<Bn254Fr> {
        FieldElement::from_canonical([n, 0, 0, 0])
    }

    #[test]
    fn node_id_to_ssa_var_preserves_zero_based_index() {
        assert_eq!(ssa_var_from_node_id(node(0)), SsaVar(0));
        assert_eq!(ssa_var_from_node_id(node(5)), SsaVar(5));
        assert_eq!(ssa_var_from_node_id(node(42)), SsaVar(42));
    }

    #[test]
    fn const_variant_round_trips() {
        let k = lysis_types::InstructionKind::<Bn254Fr>::Const {
            result: node(3),
            value: fe(7),
        };
        let ir = instruction_from_kind(&k);
        match ir {
            Instruction::Const { result, value } => {
                assert_eq!(result, SsaVar(3));
                assert_eq!(value, fe(7));
            }
            _ => panic!("expected Const"),
        }
    }

    #[test]
    fn add_variant_maps_operands() {
        let k = lysis_types::InstructionKind::<Bn254Fr>::Add {
            result: node(10),
            lhs: node(1),
            rhs: node(2),
        };
        let ir = instruction_from_kind(&k);
        match ir {
            Instruction::Add { result, lhs, rhs } => {
                assert_eq!(result, SsaVar(10));
                assert_eq!(lhs, SsaVar(1));
                assert_eq!(rhs, SsaVar(2));
            }
            _ => panic!("expected Add"),
        }
    }

    #[test]
    fn input_variant_preserves_name_and_visibility() {
        let k = lysis_types::InstructionKind::<Bn254Fr>::Input {
            result: node(0),
            name: "x".into(),
            visibility: lysis_types::Visibility::Witness,
        };
        let ir = instruction_from_kind(&k);
        match ir {
            Instruction::Input {
                result,
                name,
                visibility,
            } => {
                assert_eq!(result, SsaVar(0));
                assert_eq!(name, "x");
                assert_eq!(visibility, IrVisibility::Witness);
            }
            _ => panic!("expected Input"),
        }
    }

    #[test]
    fn decompose_maps_bit_results_vec() {
        let k = lysis_types::InstructionKind::<Bn254Fr>::Decompose {
            result: node(0),
            bit_results: vec![node(1), node(2), node(3), node(4)],
            operand: node(0),
            num_bits: 4,
        };
        let ir = instruction_from_kind(&k);
        match ir {
            Instruction::Decompose {
                result,
                bit_results,
                operand,
                num_bits,
            } => {
                assert_eq!(result, SsaVar(0));
                assert_eq!(operand, SsaVar(0));
                assert_eq!(num_bits, 4);
                assert_eq!(
                    bit_results,
                    vec![SsaVar(1), SsaVar(2), SsaVar(3), SsaVar(4)]
                );
            }
            _ => panic!("expected Decompose"),
        }
    }

    #[test]
    fn witness_call_maps_outputs_inputs_and_bytes() {
        let k = lysis_types::InstructionKind::<Bn254Fr>::WitnessCall {
            outputs: vec![node(7), node(8)],
            inputs: vec![node(1), node(2), node(3)],
            program_bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
        };
        let ir = instruction_from_kind(&k);
        match ir {
            Instruction::WitnessCall {
                outputs,
                inputs,
                program_bytes,
            } => {
                assert_eq!(outputs, vec![SsaVar(7), SsaVar(8)]);
                assert_eq!(inputs, vec![SsaVar(1), SsaVar(2), SsaVar(3)]);
                assert_eq!(program_bytes, vec![0xDE, 0xAD, 0xBE, 0xEF]);
            }
            _ => panic!("expected WitnessCall"),
        }
    }

    #[test]
    fn bounded_variants_carry_bitwidth() {
        let k = lysis_types::InstructionKind::<Bn254Fr>::IsLtBounded {
            result: node(0),
            lhs: node(1),
            rhs: node(2),
            bitwidth: 8,
        };
        let ir = instruction_from_kind(&k);
        match ir {
            Instruction::IsLtBounded {
                result,
                lhs,
                rhs,
                bitwidth,
            } => {
                assert_eq!(result, SsaVar(0));
                assert_eq!(lhs, SsaVar(1));
                assert_eq!(rhs, SsaVar(2));
                assert_eq!(bitwidth, 8);
            }
            _ => panic!("expected IsLtBounded"),
        }
    }

    #[test]
    fn intmod_carries_max_bits() {
        let k = lysis_types::InstructionKind::<Bn254Fr>::IntMod {
            result: node(0),
            lhs: node(1),
            rhs: node(2),
            max_bits: 32,
        };
        let ir = instruction_from_kind(&k);
        match ir {
            Instruction::IntMod {
                result,
                lhs,
                rhs,
                max_bits,
            } => {
                assert_eq!(result, SsaVar(0));
                assert_eq!(lhs, SsaVar(1));
                assert_eq!(rhs, SsaVar(2));
                assert_eq!(max_bits, 32);
            }
            _ => panic!("expected IntMod"),
        }
    }

    #[test]
    fn visibility_round_trip() {
        let pk = lysis_types::InstructionKind::<Bn254Fr>::Input {
            result: node(0),
            name: "p".into(),
            visibility: lysis_types::Visibility::Public,
        };
        let wk = lysis_types::InstructionKind::<Bn254Fr>::Input {
            result: node(0),
            name: "w".into(),
            visibility: lysis_types::Visibility::Witness,
        };
        match instruction_from_kind(&pk) {
            Instruction::Input { visibility, .. } => {
                assert_eq!(visibility, IrVisibility::Public);
            }
            _ => panic!(),
        }
        match instruction_from_kind(&wk) {
            Instruction::Input { visibility, .. } => {
                assert_eq!(visibility, IrVisibility::Witness);
            }
            _ => panic!(),
        }
    }
}
