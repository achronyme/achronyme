//! `NodeKey<F>` — the structural key that [`NodeInterner`] hashes
//! and dedupes on (RFC §5.1).
//!
//! Every pure [`InstructionKind`] variant maps 1:1 to a `NodeKey`
//! variant. Side-effecting variants (`Input`, `AssertEq`, `Assert`,
//! `RangeCheck`, `Decompose`, `WitnessCall`) do **not** appear here
//! — they flow through [`crate::intern::effect::SideEffect`] instead
//! (RFC §5.3).
//!
//! Two textually-identical pure instructions produce identical
//! `NodeKey` values; that's what the interner depends on to dedup.
//! The `result` field on `InstructionKind` is deliberately omitted —
//! the interner assigns the `NodeId` *from* the key, so including it
//! in the key would be circular.
//!
//! [`NodeInterner`]: crate::intern::interner::NodeInterner

use memory::field::{Bn254Fr, FieldBackend, FieldElement};

use crate::intern::kind::InstructionKind;
use crate::intern::node::NodeId;

/// Structural key for a pure, hash-consable node. `PartialEq` + `Eq` +
/// `Hash` are derived — equality on a `NodeKey` is exactly the
/// equivalence relation the interner collapses over.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum NodeKey<F: FieldBackend = Bn254Fr> {
    Const(FieldElement<F>),

    Add(NodeId, NodeId),
    Sub(NodeId, NodeId),
    Mul(NodeId, NodeId),
    Div(NodeId, NodeId),
    Neg(NodeId),

    Mux {
        cond: NodeId,
        if_true: NodeId,
        if_false: NodeId,
    },

    PoseidonHash {
        left: NodeId,
        right: NodeId,
    },

    Not(NodeId),
    And(NodeId, NodeId),
    Or(NodeId, NodeId),

    IsEq(NodeId, NodeId),
    IsNeq(NodeId, NodeId),
    IsLt(NodeId, NodeId),
    IsLe(NodeId, NodeId),

    IsLtBounded {
        lhs: NodeId,
        rhs: NodeId,
        bitwidth: u32,
    },
    IsLeBounded {
        lhs: NodeId,
        rhs: NodeId,
        bitwidth: u32,
    },

    IntDiv {
        lhs: NodeId,
        rhs: NodeId,
        max_bits: u32,
    },
    IntMod {
        lhs: NodeId,
        rhs: NodeId,
        max_bits: u32,
    },
}

impl<F: FieldBackend> NodeKey<F> {
    /// Attempt to extract a `NodeKey` from an `InstructionKind`.
    /// Returns `None` for side-effecting variants (which belong on
    /// the [`crate::intern::effect::SideEffect`] channel, not in the
    /// intern table).
    ///
    /// The `result` field on the incoming `InstructionKind` is
    /// **ignored** — the interner produces the id, it is not input.
    pub fn from_instruction(kind: &InstructionKind<F>) -> Option<Self> {
        use InstructionKind as K;
        Some(match kind {
            K::Const { value, .. } => NodeKey::Const(*value),

            K::Add { lhs, rhs, .. } => NodeKey::Add(*lhs, *rhs),
            K::Sub { lhs, rhs, .. } => NodeKey::Sub(*lhs, *rhs),
            K::Mul { lhs, rhs, .. } => NodeKey::Mul(*lhs, *rhs),
            K::Div { lhs, rhs, .. } => NodeKey::Div(*lhs, *rhs),
            K::Neg { operand, .. } => NodeKey::Neg(*operand),

            K::Mux {
                cond,
                if_true,
                if_false,
                ..
            } => NodeKey::Mux {
                cond: *cond,
                if_true: *if_true,
                if_false: *if_false,
            },

            K::PoseidonHash { left, right, .. } => NodeKey::PoseidonHash {
                left: *left,
                right: *right,
            },

            K::Not { operand, .. } => NodeKey::Not(*operand),
            K::And { lhs, rhs, .. } => NodeKey::And(*lhs, *rhs),
            K::Or { lhs, rhs, .. } => NodeKey::Or(*lhs, *rhs),

            K::IsEq { lhs, rhs, .. } => NodeKey::IsEq(*lhs, *rhs),
            K::IsNeq { lhs, rhs, .. } => NodeKey::IsNeq(*lhs, *rhs),
            K::IsLt { lhs, rhs, .. } => NodeKey::IsLt(*lhs, *rhs),
            K::IsLe { lhs, rhs, .. } => NodeKey::IsLe(*lhs, *rhs),

            K::IsLtBounded {
                lhs, rhs, bitwidth, ..
            } => NodeKey::IsLtBounded {
                lhs: *lhs,
                rhs: *rhs,
                bitwidth: *bitwidth,
            },
            K::IsLeBounded {
                lhs, rhs, bitwidth, ..
            } => NodeKey::IsLeBounded {
                lhs: *lhs,
                rhs: *rhs,
                bitwidth: *bitwidth,
            },

            K::IntDiv {
                lhs, rhs, max_bits, ..
            } => NodeKey::IntDiv {
                lhs: *lhs,
                rhs: *rhs,
                max_bits: *max_bits,
            },
            K::IntMod {
                lhs, rhs, max_bits, ..
            } => NodeKey::IntMod {
                lhs: *lhs,
                rhs: *rhs,
                max_bits: *max_bits,
            },

            // Side-effects: caller must route through `SideEffect`.
            K::Input { .. }
            | K::AssertEq { .. }
            | K::Assert { .. }
            | K::RangeCheck { .. }
            | K::Decompose { .. }
            | K::WitnessCall { .. } => return None,
        })
    }

    /// Rebuild an `InstructionKind` from a key + its assigned
    /// `NodeId`. Used by materialization to drop the key back into
    /// the flat instruction stream.
    pub fn into_instruction(&self, result: NodeId) -> InstructionKind<F> {
        use InstructionKind as K;
        match self {
            NodeKey::Const(value) => K::Const {
                result,
                value: *value,
            },
            NodeKey::Add(lhs, rhs) => K::Add {
                result,
                lhs: *lhs,
                rhs: *rhs,
            },
            NodeKey::Sub(lhs, rhs) => K::Sub {
                result,
                lhs: *lhs,
                rhs: *rhs,
            },
            NodeKey::Mul(lhs, rhs) => K::Mul {
                result,
                lhs: *lhs,
                rhs: *rhs,
            },
            NodeKey::Div(lhs, rhs) => K::Div {
                result,
                lhs: *lhs,
                rhs: *rhs,
            },
            NodeKey::Neg(operand) => K::Neg {
                result,
                operand: *operand,
            },
            NodeKey::Mux {
                cond,
                if_true,
                if_false,
            } => K::Mux {
                result,
                cond: *cond,
                if_true: *if_true,
                if_false: *if_false,
            },
            NodeKey::PoseidonHash { left, right } => K::PoseidonHash {
                result,
                left: *left,
                right: *right,
            },
            NodeKey::Not(operand) => K::Not {
                result,
                operand: *operand,
            },
            NodeKey::And(lhs, rhs) => K::And {
                result,
                lhs: *lhs,
                rhs: *rhs,
            },
            NodeKey::Or(lhs, rhs) => K::Or {
                result,
                lhs: *lhs,
                rhs: *rhs,
            },
            NodeKey::IsEq(lhs, rhs) => K::IsEq {
                result,
                lhs: *lhs,
                rhs: *rhs,
            },
            NodeKey::IsNeq(lhs, rhs) => K::IsNeq {
                result,
                lhs: *lhs,
                rhs: *rhs,
            },
            NodeKey::IsLt(lhs, rhs) => K::IsLt {
                result,
                lhs: *lhs,
                rhs: *rhs,
            },
            NodeKey::IsLe(lhs, rhs) => K::IsLe {
                result,
                lhs: *lhs,
                rhs: *rhs,
            },
            NodeKey::IsLtBounded {
                lhs,
                rhs,
                bitwidth,
            } => K::IsLtBounded {
                result,
                lhs: *lhs,
                rhs: *rhs,
                bitwidth: *bitwidth,
            },
            NodeKey::IsLeBounded {
                lhs,
                rhs,
                bitwidth,
            } => K::IsLeBounded {
                result,
                lhs: *lhs,
                rhs: *rhs,
                bitwidth: *bitwidth,
            },
            NodeKey::IntDiv {
                lhs,
                rhs,
                max_bits,
            } => K::IntDiv {
                result,
                lhs: *lhs,
                rhs: *rhs,
                max_bits: *max_bits,
            },
            NodeKey::IntMod {
                lhs,
                rhs,
                max_bits,
            } => K::IntMod {
                result,
                lhs: *lhs,
                rhs: *rhs,
                max_bits: *max_bits,
            },
        }
    }

    /// The operand node-ids this key depends on, in order. Used by
    /// the topological check and by materialization's dependency walk.
    ///
    /// Returns an empty iterator for `Const` (no operands).
    pub fn operands(&self) -> smallvec::SmallVec<[NodeId; 3]> {
        use smallvec::smallvec;
        match self {
            NodeKey::Const(_) => smallvec![],
            NodeKey::Neg(a) | NodeKey::Not(a) => smallvec![*a],
            NodeKey::Add(a, b)
            | NodeKey::Sub(a, b)
            | NodeKey::Mul(a, b)
            | NodeKey::Div(a, b)
            | NodeKey::And(a, b)
            | NodeKey::Or(a, b)
            | NodeKey::IsEq(a, b)
            | NodeKey::IsNeq(a, b)
            | NodeKey::IsLt(a, b)
            | NodeKey::IsLe(a, b) => smallvec![*a, *b],
            NodeKey::Mux {
                cond,
                if_true,
                if_false,
            } => smallvec![*cond, *if_true, *if_false],
            NodeKey::PoseidonHash { left, right } => smallvec![*left, *right],
            NodeKey::IsLtBounded { lhs, rhs, .. }
            | NodeKey::IsLeBounded { lhs, rhs, .. }
            | NodeKey::IntDiv { lhs, rhs, .. }
            | NodeKey::IntMod { lhs, rhs, .. } => smallvec![*lhs, *rhs],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::intern::hash::deterministic_hash;
    use crate::intern::Visibility;

    fn n(i: usize) -> NodeId {
        NodeId::from_zero_based(i)
    }

    fn fe(n: u64) -> FieldElement<Bn254Fr> {
        FieldElement::from_canonical([n, 0, 0, 0])
    }

    #[test]
    fn add_key_dedups_on_operands() {
        let k1 = NodeKey::<Bn254Fr>::Add(n(0), n(1));
        let k2 = NodeKey::<Bn254Fr>::Add(n(0), n(1));
        assert_eq!(k1, k2);
        assert_eq!(deterministic_hash(&k1), deterministic_hash(&k2));
    }

    #[test]
    fn add_keys_differ_on_order() {
        // Add is not commutative for our purposes — the emitter is
        // responsible for canonicalizing the operand order if it wants
        // `Add(a, b) == Add(b, a)`. The interner treats them as distinct.
        let k1 = NodeKey::<Bn254Fr>::Add(n(0), n(1));
        let k2 = NodeKey::<Bn254Fr>::Add(n(1), n(0));
        assert_ne!(k1, k2);
    }

    #[test]
    fn const_keys_distinguish_values() {
        let k1 = NodeKey::<Bn254Fr>::Const(fe(7));
        let k2 = NodeKey::<Bn254Fr>::Const(fe(8));
        let k3 = NodeKey::<Bn254Fr>::Const(fe(7));
        assert_ne!(k1, k2);
        assert_eq!(k1, k3);
        assert_eq!(deterministic_hash(&k1), deterministic_hash(&k3));
    }

    #[test]
    fn from_instruction_extracts_pure_variants() {
        let add = InstructionKind::<Bn254Fr>::Add {
            result: n(5),
            lhs: n(1),
            rhs: n(2),
        };
        let key = NodeKey::from_instruction(&add).unwrap();
        assert_eq!(key, NodeKey::Add(n(1), n(2)));
    }

    #[test]
    fn from_instruction_returns_none_for_side_effects() {
        let assert_eq = InstructionKind::<Bn254Fr>::AssertEq {
            result: n(0),
            lhs: n(1),
            rhs: n(2),
            message: None,
        };
        assert!(NodeKey::from_instruction(&assert_eq).is_none());

        let input = InstructionKind::<Bn254Fr>::Input {
            result: n(0),
            name: "x".into(),
            visibility: Visibility::Public,
        };
        assert!(NodeKey::from_instruction(&input).is_none());

        let dec = InstructionKind::<Bn254Fr>::Decompose {
            result: n(0),
            bit_results: vec![n(1), n(2)],
            operand: n(0),
            num_bits: 2,
        };
        assert!(NodeKey::from_instruction(&dec).is_none());
    }

    #[test]
    fn into_instruction_round_trips_result() {
        let key = NodeKey::<Bn254Fr>::Mul(n(3), n(4));
        let ir = key.into_instruction(n(7));
        match ir {
            InstructionKind::Mul { result, lhs, rhs } => {
                assert_eq!(result, n(7));
                assert_eq!(lhs, n(3));
                assert_eq!(rhs, n(4));
            }
            _ => panic!("expected Mul"),
        }
    }

    #[test]
    fn operands_lists_dependencies_in_order() {
        let mux = NodeKey::<Bn254Fr>::Mux {
            cond: n(0),
            if_true: n(1),
            if_false: n(2),
        };
        assert_eq!(mux.operands().as_slice(), &[n(0), n(1), n(2)]);

        let c = NodeKey::<Bn254Fr>::Const(fe(1));
        assert!(c.operands().is_empty());

        let neg = NodeKey::<Bn254Fr>::Neg(n(5));
        assert_eq!(neg.operands().as_slice(), &[n(5)]);
    }

    #[test]
    fn bounded_variants_hash_bitwidth_too() {
        let k1 = NodeKey::<Bn254Fr>::IsLtBounded {
            lhs: n(0),
            rhs: n(1),
            bitwidth: 8,
        };
        let k2 = NodeKey::<Bn254Fr>::IsLtBounded {
            lhs: n(0),
            rhs: n(1),
            bitwidth: 16,
        };
        assert_ne!(k1, k2);
    }
}
