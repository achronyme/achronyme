//! `InstructionKind<F>` — Lysis-facing mirror of `ir::Instruction<F>`.
//!
//! Phase 1 cannot depend on the `ir` crate yet because that pulls a
//! deep tree of dependencies (parser, diagnostics, resolve, ...) that
//! we do not want inside Lysis while the VM is still coming online.
//! Keeping a parallel enum here is the minimum wedge that lets the
//! executor produce something concrete now while keeping the schema
//! 1:1 with what the rest of the toolchain speaks.
//!
//! Phase 3 will add the bridge `From<InstructionKind<F>> for
//! ir::Instruction<F>` inside a separate glue module in `ir/` —
//! direction is Lysis → ir because Lysis is the emitter.
//!
//! # The mirror contract
//!
//! Every variant here matches a variant of `ir::Instruction` by name
//! and field shape:
//!
//! | `InstructionKind` variant | `ir::Instruction` variant |
//! |---|---|
//! | `Const { result, value }`                 | `Const`       |
//! | `Input { result, name, visibility }`      | `Input`       |
//! | `Add { result, lhs, rhs }`                | `Add`         |
//! | `Sub { result, lhs, rhs }`                | `Sub`         |
//! | `Mul { result, lhs, rhs }`                | `Mul`         |
//! | `Div { result, lhs, rhs }`                | `Div`         |
//! | `Neg { result, operand }`                 | `Neg`         |
//! | `Mux { result, cond, if_true, if_false }` | `Mux`         |
//! | `PoseidonHash { result, left, right }`    | `PoseidonHash`|
//! | `Not { result, operand }`                 | `Not`         |
//! | `And { result, lhs, rhs }`                | `And`         |
//! | `Or { result, lhs, rhs }`                 | `Or`          |
//! | `Decompose { result, bit_results, operand, num_bits }` | `Decompose` |
//! | `IsEq / IsNeq / IsLt / IsLe`              | same names    |
//! | `IsLtBounded / IsLeBounded { .., bitwidth }` | same       |
//! | `IntDiv / IntMod { .., max_bits }`        | same          |
//! | `AssertEq { result, lhs, rhs, message }`  | `AssertEq`    |
//! | `Assert { result, operand, message }`     | `Assert`      |
//! | `RangeCheck { result, operand, bits }`    | `RangeCheck`  |
//! | `WitnessCall { outputs, inputs, program_bytes }` | `WitnessCall` |
//!
//! Side-effect classification (RFC §5.3 canonical list, minus
//! Decompose/Assert which are side-effectful per downstream analysis
//! but live under the same enum here in Phase 1):
//! **side-effectful** = `Input`, `AssertEq`, `Assert`, `RangeCheck`,
//! `Decompose`, `WitnessCall`. **pure** = everything else.
//!
//! `Decompose` is the borderline case: the bit results are pure
//! values (hash-consable as NodeIds), but the emission itself implies
//! a constraint `Σ bit_i · 2^i == operand` that must not be
//! deduplicated. Phase 2's interner will expose both sides of that
//! duality; Phase 1 simply records the whole instruction in emission
//! order without dedup.

use memory::field::{Bn254Fr, FieldBackend, FieldElement};

use crate::intern::NodeId;

/// Whether a signal is public (verifier-visible) or witness
/// (prover-private). Mirrors `ir::Visibility`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Visibility {
    Public = 0,
    Witness = 1,
}

impl Visibility {
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Public),
            1 => Some(Self::Witness),
            _ => None,
        }
    }

    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// An emitted IR instruction, in the Lysis-internal representation.
#[derive(Debug, Clone)]
pub enum InstructionKind<F: FieldBackend = Bn254Fr> {
    // -----------------------------------------------------------------
    // Data & constants
    // -----------------------------------------------------------------
    Const {
        result: NodeId,
        value: FieldElement<F>,
    },
    Input {
        result: NodeId,
        name: String,
        visibility: Visibility,
    },

    // -----------------------------------------------------------------
    // Pure arithmetic
    // -----------------------------------------------------------------
    Add {
        result: NodeId,
        lhs: NodeId,
        rhs: NodeId,
    },
    Sub {
        result: NodeId,
        lhs: NodeId,
        rhs: NodeId,
    },
    Mul {
        result: NodeId,
        lhs: NodeId,
        rhs: NodeId,
    },
    Div {
        result: NodeId,
        lhs: NodeId,
        rhs: NodeId,
    },
    Neg {
        result: NodeId,
        operand: NodeId,
    },

    // -----------------------------------------------------------------
    // Branching
    // -----------------------------------------------------------------
    Mux {
        result: NodeId,
        cond: NodeId,
        if_true: NodeId,
        if_false: NodeId,
    },

    // -----------------------------------------------------------------
    // Crypto
    // -----------------------------------------------------------------
    PoseidonHash {
        result: NodeId,
        left: NodeId,
        right: NodeId,
    },

    // -----------------------------------------------------------------
    // Bit-level
    // -----------------------------------------------------------------
    Not {
        result: NodeId,
        operand: NodeId,
    },
    And {
        result: NodeId,
        lhs: NodeId,
        rhs: NodeId,
    },
    Or {
        result: NodeId,
        lhs: NodeId,
        rhs: NodeId,
    },
    Decompose {
        result: NodeId,
        bit_results: Vec<NodeId>,
        operand: NodeId,
        num_bits: u32,
    },

    // -----------------------------------------------------------------
    // Comparison
    // -----------------------------------------------------------------
    IsEq {
        result: NodeId,
        lhs: NodeId,
        rhs: NodeId,
    },
    IsNeq {
        result: NodeId,
        lhs: NodeId,
        rhs: NodeId,
    },
    IsLt {
        result: NodeId,
        lhs: NodeId,
        rhs: NodeId,
    },
    IsLe {
        result: NodeId,
        lhs: NodeId,
        rhs: NodeId,
    },
    IsLtBounded {
        result: NodeId,
        lhs: NodeId,
        rhs: NodeId,
        bitwidth: u32,
    },
    IsLeBounded {
        result: NodeId,
        lhs: NodeId,
        rhs: NodeId,
        bitwidth: u32,
    },

    // -----------------------------------------------------------------
    // Integer division
    // -----------------------------------------------------------------
    IntDiv {
        result: NodeId,
        lhs: NodeId,
        rhs: NodeId,
        max_bits: u32,
    },
    IntMod {
        result: NodeId,
        lhs: NodeId,
        rhs: NodeId,
        max_bits: u32,
    },

    // -----------------------------------------------------------------
    // Side-effect wall
    // -----------------------------------------------------------------
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
    WitnessCall {
        outputs: Vec<NodeId>,
        inputs: Vec<NodeId>,
        program_bytes: Vec<u8>,
    },
}

impl<F: FieldBackend> InstructionKind<F> {
    /// The primary result of this instruction.
    ///
    /// For `Decompose` this is an alias of `operand` (matches `ir::Instruction`).
    /// For `WitnessCall` this is `outputs[0]`; extras are in `outputs[1..]`.
    pub fn result(&self) -> NodeId {
        match self {
            Self::Const { result, .. }
            | Self::Input { result, .. }
            | Self::Add { result, .. }
            | Self::Sub { result, .. }
            | Self::Mul { result, .. }
            | Self::Div { result, .. }
            | Self::Neg { result, .. }
            | Self::Mux { result, .. }
            | Self::PoseidonHash { result, .. }
            | Self::Not { result, .. }
            | Self::And { result, .. }
            | Self::Or { result, .. }
            | Self::Decompose { result, .. }
            | Self::IsEq { result, .. }
            | Self::IsNeq { result, .. }
            | Self::IsLt { result, .. }
            | Self::IsLe { result, .. }
            | Self::IsLtBounded { result, .. }
            | Self::IsLeBounded { result, .. }
            | Self::IntDiv { result, .. }
            | Self::IntMod { result, .. }
            | Self::AssertEq { result, .. }
            | Self::Assert { result, .. }
            | Self::RangeCheck { result, .. } => *result,
            Self::WitnessCall { outputs, .. } => outputs
                .first()
                .copied()
                .expect("WitnessCall must have ≥1 output"),
        }
    }

    /// `true` when the instruction must not be hash-consed: two
    /// textually-identical side-effecting instructions can still both
    /// be required for soundness (e.g., two `AssertEq` in different
    /// scopes). See RFC §5.3 for the full argument.
    pub fn is_side_effect(&self) -> bool {
        matches!(
            self,
            Self::Input { .. }
                | Self::AssertEq { .. }
                | Self::Assert { .. }
                | Self::RangeCheck { .. }
                | Self::Decompose { .. }
                | Self::WitnessCall { .. }
        )
    }

    /// Return a copy of `self` with the primary `result` field
    /// replaced by `new_result`. Defined for pure variants only —
    /// panics on side-effects because their id layout is richer (the
    /// caller already pre-fills outputs/bits through
    /// `IrSink::fresh_id` before constructing the kind).
    pub fn with_result(self, new_result: NodeId) -> Self {
        match self {
            Self::Const { value, .. } => Self::Const {
                result: new_result,
                value,
            },
            Self::Add { lhs, rhs, .. } => Self::Add {
                result: new_result,
                lhs,
                rhs,
            },
            Self::Sub { lhs, rhs, .. } => Self::Sub {
                result: new_result,
                lhs,
                rhs,
            },
            Self::Mul { lhs, rhs, .. } => Self::Mul {
                result: new_result,
                lhs,
                rhs,
            },
            Self::Div { lhs, rhs, .. } => Self::Div {
                result: new_result,
                lhs,
                rhs,
            },
            Self::Neg { operand, .. } => Self::Neg {
                result: new_result,
                operand,
            },
            Self::Mux {
                cond,
                if_true,
                if_false,
                ..
            } => Self::Mux {
                result: new_result,
                cond,
                if_true,
                if_false,
            },
            Self::PoseidonHash { left, right, .. } => Self::PoseidonHash {
                result: new_result,
                left,
                right,
            },
            Self::Not { operand, .. } => Self::Not {
                result: new_result,
                operand,
            },
            Self::And { lhs, rhs, .. } => Self::And {
                result: new_result,
                lhs,
                rhs,
            },
            Self::Or { lhs, rhs, .. } => Self::Or {
                result: new_result,
                lhs,
                rhs,
            },
            Self::IsEq { lhs, rhs, .. } => Self::IsEq {
                result: new_result,
                lhs,
                rhs,
            },
            Self::IsNeq { lhs, rhs, .. } => Self::IsNeq {
                result: new_result,
                lhs,
                rhs,
            },
            Self::IsLt { lhs, rhs, .. } => Self::IsLt {
                result: new_result,
                lhs,
                rhs,
            },
            Self::IsLe { lhs, rhs, .. } => Self::IsLe {
                result: new_result,
                lhs,
                rhs,
            },
            Self::IsLtBounded {
                lhs, rhs, bitwidth, ..
            } => Self::IsLtBounded {
                result: new_result,
                lhs,
                rhs,
                bitwidth,
            },
            Self::IsLeBounded {
                lhs, rhs, bitwidth, ..
            } => Self::IsLeBounded {
                result: new_result,
                lhs,
                rhs,
                bitwidth,
            },
            Self::IntDiv {
                lhs, rhs, max_bits, ..
            } => Self::IntDiv {
                result: new_result,
                lhs,
                rhs,
                max_bits,
            },
            Self::IntMod {
                lhs, rhs, max_bits, ..
            } => Self::IntMod {
                result: new_result,
                lhs,
                rhs,
                max_bits,
            },
            Self::Input { .. }
            | Self::AssertEq { .. }
            | Self::Assert { .. }
            | Self::RangeCheck { .. }
            | Self::Decompose { .. }
            | Self::WitnessCall { .. } => {
                panic!("with_result called on side-effect variant; use emit_effect")
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn n(idx: usize) -> NodeId {
        NodeId::from_zero_based(idx)
    }

    #[test]
    fn result_points_at_named_slot() {
        let add = InstructionKind::<Bn254Fr>::Add {
            result: n(3),
            lhs: n(1),
            rhs: n(2),
        };
        assert_eq!(add.result(), n(3));
    }

    #[test]
    fn witness_call_result_is_first_output() {
        let call = InstructionKind::<Bn254Fr>::WitnessCall {
            outputs: vec![n(10), n(11), n(12)],
            inputs: vec![n(1), n(2)],
            program_bytes: vec![0xAA; 8],
        };
        assert_eq!(call.result(), n(10));
    }

    #[test]
    fn side_effect_classification_matches_rfc() {
        let add = InstructionKind::<Bn254Fr>::Add {
            result: n(0),
            lhs: n(0),
            rhs: n(0),
        };
        assert!(!add.is_side_effect());

        let assert_eq = InstructionKind::<Bn254Fr>::AssertEq {
            result: n(0),
            lhs: n(0),
            rhs: n(0),
            message: None,
        };
        assert!(assert_eq.is_side_effect());

        let decompose = InstructionKind::<Bn254Fr>::Decompose {
            result: n(0),
            bit_results: vec![n(1), n(2)],
            operand: n(0),
            num_bits: 2,
        };
        assert!(decompose.is_side_effect());
    }

    #[test]
    fn visibility_roundtrips_through_u8() {
        assert_eq!(Visibility::from_u8(0), Some(Visibility::Public));
        assert_eq!(Visibility::from_u8(1), Some(Visibility::Witness));
        assert_eq!(Visibility::from_u8(2), None);
        assert_eq!(Visibility::Public.as_u8(), 0);
        assert_eq!(Visibility::Witness.as_u8(), 1);
    }
}
