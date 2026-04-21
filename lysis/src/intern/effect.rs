//! `SideEffect<F>` — the channel for instructions that **must not**
//! be hash-consed (RFC §5.3).
//!
//! Side-effects stay on a separate `Vec<SideEffect<F>>` inside the
//! interner, ordered by emission. Two textually-identical `AssertEq`
//! instructions keep both entries because they may guard different
//! witness paths, and two `Input` instructions with the same name
//! still define two distinct wires — dedup on this channel would be
//! a soundness bug.
//!
//! Keeping this enum disjoint from [`crate::intern::NodeKey`] is the
//! type-level form of the side-effect wall the RFC argues for: the
//! interner's pure-path API only accepts `NodeKey`, the effect-path
//! API only accepts `SideEffect`, so the language itself makes it
//! impossible to accidentally intern an assert or a witness call.

use std::num::NonZeroU32;

use memory::field::FieldBackend;

use crate::intern::kind::{InstructionKind, Visibility};
use crate::intern::node::NodeId;

/// Opaque handle for a side-effect slot. `NonZeroU32` so
/// `Option<EffectId>` stays pointer-sized.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct EffectId(NonZeroU32);

impl EffectId {
    #[inline]
    pub fn from_zero_based(idx: usize) -> Self {
        let one_based = u32::try_from(idx)
            .expect("effect index overflows u32")
            .checked_add(1)
            .expect("effect index + 1 overflows u32");
        EffectId(NonZeroU32::new(one_based).expect("one-based idx is non-zero"))
    }

    #[inline]
    pub fn index(self) -> usize {
        (self.0.get() - 1) as usize
    }
}

/// Side-effecting IR instruction. Never interned, never deduplicated.
/// One-to-one with the side-effecting variants of [`InstructionKind`].
///
/// `SideEffect` is **not** generic over the field backend: none of its
/// variants carry a `FieldElement`, so parameterizing over `F` would
/// leave it `PhantomData`-only. Conversion to/from
/// [`InstructionKind<F>`] happens per-call in the methods below, where
/// `F` is injected from the caller's context (normally a
/// [`crate::intern::NodeInterner<F>`]).
#[derive(Debug, Clone)]
pub enum SideEffect {
    Input {
        output: NodeId,
        name: String,
        visibility: Visibility,
    },
    AssertEq {
        result: NodeId,
        lhs: NodeId,
        rhs: NodeId,
        message: Option<String>,
    },
    Assert {
        result: NodeId,
        operand: NodeId,
        message: Option<String>,
    },
    RangeCheck {
        result: NodeId,
        operand: NodeId,
        bits: u32,
    },
    /// `result` aliases `operand` (mirror of `ir::Instruction::Decompose`).
    Decompose {
        result: NodeId,
        operand: NodeId,
        bit_results: Vec<NodeId>,
        num_bits: u32,
    },
    WitnessCall {
        outputs: Vec<NodeId>,
        inputs: Vec<NodeId>,
        program_bytes: Vec<u8>,
    },
}

impl SideEffect {
    /// Move an `InstructionKind` into a `SideEffect`. Returns `None`
    /// if the instruction is a pure variant (belongs on the
    /// [`crate::intern::NodeKey`] channel).
    pub fn from_instruction<F: FieldBackend>(kind: InstructionKind<F>) -> Option<Self> {
        use InstructionKind as K;
        Some(match kind {
            K::Input {
                result,
                name,
                visibility,
            } => SideEffect::Input {
                output: result,
                name,
                visibility,
            },
            K::AssertEq {
                result,
                lhs,
                rhs,
                message,
            } => SideEffect::AssertEq {
                result,
                lhs,
                rhs,
                message,
            },
            K::Assert {
                result,
                operand,
                message,
            } => SideEffect::Assert {
                result,
                operand,
                message,
            },
            K::RangeCheck {
                result,
                operand,
                bits,
            } => SideEffect::RangeCheck {
                result,
                operand,
                bits,
            },
            K::Decompose {
                result,
                operand,
                bit_results,
                num_bits,
            } => SideEffect::Decompose {
                result,
                operand,
                bit_results,
                num_bits,
            },
            K::WitnessCall {
                outputs,
                inputs,
                program_bytes,
            } => SideEffect::WitnessCall {
                outputs,
                inputs,
                program_bytes,
            },

            // Pure variants: caller must route through `NodeKey`.
            K::Const { .. }
            | K::Add { .. }
            | K::Sub { .. }
            | K::Mul { .. }
            | K::Div { .. }
            | K::Neg { .. }
            | K::Mux { .. }
            | K::PoseidonHash { .. }
            | K::Not { .. }
            | K::And { .. }
            | K::Or { .. }
            | K::IsEq { .. }
            | K::IsNeq { .. }
            | K::IsLt { .. }
            | K::IsLe { .. }
            | K::IsLtBounded { .. }
            | K::IsLeBounded { .. }
            | K::IntDiv { .. }
            | K::IntMod { .. } => return None,
        })
    }

    /// Project back to the flat `InstructionKind`. Materialization
    /// uses this to drop side-effects into the final instruction
    /// stream after the pure nodes have been laid down. `F` is
    /// provided by the caller since `SideEffect` itself is not
    /// field-parameterized.
    pub fn into_instruction<F: FieldBackend>(self) -> InstructionKind<F> {
        use InstructionKind as K;
        match self {
            SideEffect::Input {
                output,
                name,
                visibility,
            } => K::Input {
                result: output,
                name,
                visibility,
            },
            SideEffect::AssertEq {
                result,
                lhs,
                rhs,
                message,
            } => K::AssertEq {
                result,
                lhs,
                rhs,
                message,
            },
            SideEffect::Assert {
                result,
                operand,
                message,
            } => K::Assert {
                result,
                operand,
                message,
            },
            SideEffect::RangeCheck {
                result,
                operand,
                bits,
            } => K::RangeCheck {
                result,
                operand,
                bits,
            },
            SideEffect::Decompose {
                result,
                operand,
                bit_results,
                num_bits,
            } => K::Decompose {
                result,
                operand,
                bit_results,
                num_bits,
            },
            SideEffect::WitnessCall {
                outputs,
                inputs,
                program_bytes,
            } => K::WitnessCall {
                outputs,
                inputs,
                program_bytes,
            },
        }
    }

    /// The primary `NodeId` the effect introduces (for register
    /// binding in the executor). `WitnessCall` returns the first
    /// output; a call with zero outputs panics — the validator
    /// guarantees non-empty.
    pub fn primary_result(&self) -> NodeId {
        match self {
            SideEffect::Input { output, .. } => *output,
            SideEffect::AssertEq { result, .. }
            | SideEffect::Assert { result, .. }
            | SideEffect::RangeCheck { result, .. }
            | SideEffect::Decompose { result, .. } => *result,
            SideEffect::WitnessCall { outputs, .. } => outputs
                .first()
                .copied()
                .expect("WitnessCall must have ≥1 output"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use memory::field::Bn254Fr;

    fn n(i: usize) -> NodeId {
        NodeId::from_zero_based(i)
    }

    #[test]
    fn effect_id_round_trip() {
        let id = EffectId::from_zero_based(0);
        assert_eq!(id.index(), 0);
        assert_eq!(EffectId::from_zero_based(42), EffectId::from_zero_based(42));
        assert_ne!(EffectId::from_zero_based(0), EffectId::from_zero_based(1));
    }

    #[test]
    fn side_effect_size_matches_option() {
        assert_eq!(
            std::mem::size_of::<Option<EffectId>>(),
            std::mem::size_of::<EffectId>()
        );
    }

    #[test]
    fn from_instruction_accepts_side_effect_variants() {
        let input = InstructionKind::<Bn254Fr>::Input {
            result: n(3),
            name: "x".into(),
            visibility: Visibility::Public,
        };
        let eff = SideEffect::from_instruction(input).unwrap();
        assert!(matches!(eff, SideEffect::Input { .. }));

        let assert_eq = InstructionKind::<Bn254Fr>::AssertEq {
            result: n(0),
            lhs: n(1),
            rhs: n(2),
            message: Some("bad".into()),
        };
        assert!(matches!(
            SideEffect::from_instruction(assert_eq).unwrap(),
            SideEffect::AssertEq { .. }
        ));
    }

    #[test]
    fn from_instruction_rejects_pure_variants() {
        let add = InstructionKind::<Bn254Fr>::Add {
            result: n(0),
            lhs: n(1),
            rhs: n(2),
        };
        assert!(SideEffect::from_instruction(add).is_none());

        let c = InstructionKind::<Bn254Fr>::Const {
            result: n(0),
            value: memory::field::FieldElement::<Bn254Fr>::from_canonical([1, 0, 0, 0]),
        };
        assert!(SideEffect::from_instruction(c).is_none());
    }

    #[test]
    fn round_trip_through_instruction() {
        let eff = SideEffect::RangeCheck {
            result: n(5),
            operand: n(3),
            bits: 8,
        };
        match eff.into_instruction::<Bn254Fr>() {
            InstructionKind::RangeCheck {
                result,
                operand,
                bits,
            } => {
                assert_eq!(result, n(5));
                assert_eq!(operand, n(3));
                assert_eq!(bits, 8);
            }
            _ => panic!("expected RangeCheck"),
        }
    }

    #[test]
    fn primary_result_points_at_output() {
        let eff = SideEffect::WitnessCall {
            outputs: vec![n(7), n(8)],
            inputs: vec![n(1)],
            program_bytes: vec![0xAA],
        };
        assert_eq!(eff.primary_result(), n(7));

        let inp = SideEffect::Input {
            output: n(2),
            name: "in".into(),
            visibility: Visibility::Witness,
        };
        assert_eq!(inp.primary_result(), n(2));
    }
}
