use memory::{FieldBackend, FieldElement};
use smallvec::SmallVec;

use crate::extended::{IndexedEffectKind, ShiftDirection};
use crate::TemplateId;
use ir_core::{SsaVar, Visibility};

/// Identifier for a slot in a symbolic tree. Two [`SymbolicTree`]s
/// produced from the same body with different probe values are
/// guaranteed to share the same [`SlotId`] sequence — that's what
/// makes `structural_diff` able to locate matching slots across
/// probes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SlotId(pub u16);

impl std::fmt::Display for SlotId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "slot{}", self.0)
    }
}

/// Zero-cost index into [`SymbolicTree::nodes`].
pub type NodeIdx = u32;

/// Shape tag for operation / side-effect nodes. Lives separately
/// from the operand list so `structural_diff` can compare
/// instruction-shape equality without matching operand-by-operand.
///
/// Parameterized variants (e.g. `RangeCheck(u32)`) carry the
/// constant-shape parameters directly so two tags are equal iff
/// the two operations are interchangeable at the R1CS level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OpTag {
    // Pure arithmetic.
    Add,
    Sub,
    Mul,
    Div,
    Neg,
    // Boolean / logic.
    Not,
    And,
    Or,
    Mux,
    // Comparisons.
    IsEq,
    IsNeq,
    IsLt,
    IsLe,
    IsLtBounded(u32),
    IsLeBounded(u32),
    // Hash.
    PoseidonHash,
    // Constraint-producing side-effects.
    AssertEq,
    Assert,
    RangeCheck(u32),
    Decompose(u32),
    // Integer arithmetic with bound.
    IntDiv(u32),
    IntMod(u32),
    /// Witness call identified by program-bytes hash. Two calls with
    /// the same hash + arity are interchangeable; different hashes
    /// imply different bytecode bodies.
    WitnessCall {
        n_inputs: u16,
        n_outputs: u16,
        bytes_hash: u64,
    },
}

/// One node in a [`SymbolicTree`].
#[derive(Debug, Clone)]
pub enum SymbolicNode<F: FieldBackend> {
    /// A field constant. When `from_slot` is present the value was
    /// injected via the probe binding, not lifted from the source
    /// program — `structural_diff` treats differences in `value`
    /// across probes as slot positions, not structural differences.
    Const {
        value: FieldElement<F>,
        from_slot: Option<SlotId>,
    },
    /// A circuit input wire. `name` + `visibility` are stable across
    /// probes so two copies compare equal.
    Input {
        name: String,
        visibility: Visibility,
    },
    /// An SsaVar that the body references but that was defined
    /// outside the probed body (and is NOT a probe binding). These
    /// are future capture candidates; the lifter materializes them
    /// as `LoadCapture` slots once a template is extracted.
    OuterRef(SsaVar),
    /// An arithmetic, logic, or side-effect operation with its
    /// resolved operand indices.
    Op {
        tag: OpTag,
        operands: SmallVec<[NodeIdx; 3]>,
    },
    /// A nested template call. Opaque at the BTA level — the call
    /// itself is treated as structurally equal iff the template id
    /// and capture list agree.
    TemplateCall {
        template_id: TemplateId,
        capture_operands: SmallVec<[NodeIdx; 4]>,
        n_outputs: u16,
    },
    /// A nested `LoopUnroll`. Marker node only — BTA does not
    /// recurse into nested loops, so this sentinel forces the
    /// enclosing loop to classify as `DataDependent` when present.
    /// (A future refinement could recursively classify the nested
    /// loop.)
    NestedLoop,
    /// A symbolic-index write produced by Gap 1
    /// [`ExtendedInstruction::SymbolicIndexedEffect`]. The
    /// `index_operand` typically resolves to the slot-tagged `Const`
    /// pushed by the probe binding (for `arr[i]`-style writes), so two
    /// probes of the same body produce structurally-identical
    /// `IndexedEffect` nodes whose `index_operand`'s slot value is the
    /// only point of divergence — `structural_diff` lifts that as
    /// `OnlyConstants` and BTA classifies the enclosing loop
    /// `Uniform`. `array_anchor` carries the resolved slot wires (one
    /// `NodeIdx` per array element) so two probes targeting different
    /// arrays diverge structurally.
    IndexedEffect {
        kind: IndexedEffectKind,
        array_anchor: SmallVec<[NodeIdx; 4]>,
        index_operand: NodeIdx,
        value_operand: Option<NodeIdx>,
    },
    /// A symbolic-index read produced by Gap 1.5
    /// [`ExtendedInstruction::SymbolicArrayRead`] — the structural
    /// counterpart of [`Self::IndexedEffect`] on the read side. Two
    /// probes targeting the same array with the same body shape
    /// produce identical `ArrayRead` nodes; the only divergence sits
    /// inside the `index_operand` chain (a slot-tagged `Const` from
    /// the probe binding), so `structural_diff` classifies
    /// `OnlyConstants` and BTA marks the enclosing loop `Uniform`.
    ///
    /// `array_anchor` carries the resolved slot wires (`NodeIdx` per
    /// element) — two probes reading from different arrays therefore
    /// diverge structurally.
    ArrayRead {
        array_anchor: SmallVec<[NodeIdx; 4]>,
        index_operand: NodeIdx,
    },
    /// A symbolic-amount shift produced by Gap 3
    /// [`ExtendedInstruction::SymbolicShift`]. The
    /// `operand_anchor` points at the resolved value-being-shifted
    /// (typically an `OuterRef`); `shift_operand` points at the
    /// shift amount (typically a slot-tagged `Const` that picks up
    /// the iter_var across probes). `num_bits` and `direction` are
    /// part of the structural fingerprint — two probes that disagree
    /// on either diverge unconditionally.
    ///
    /// Two probes targeting the same operand + width + direction
    /// produce identical `Shift` nodes; the only divergence sits
    /// inside the `shift_operand` chain (a slot-tagged `Const` from
    /// the probe binding), so `structural_diff` classifies
    /// `OnlyConstants` and BTA marks the enclosing loop `Uniform`.
    Shift {
        operand_anchor: NodeIdx,
        shift_operand: NodeIdx,
        num_bits: u32,
        direction: ShiftDirection,
    },
}

impl<F: FieldBackend> SymbolicNode<F> {
    /// Short-hand — is this node a slot-tagged constant?
    pub fn is_slot_const(&self) -> bool {
        matches!(
            self,
            SymbolicNode::Const {
                from_slot: Some(_),
                ..
            }
        )
    }
}

/// Linear tree produced by [`symbolic_emit`].
///
/// The layout is three-part:
///
/// 1. `nodes` — flat pool indexed by `NodeIdx`.
/// 2. `body_order` — indices of the top-level statements in emission
///    order. `structural_diff` walks this list in lockstep between
///    two probes.
/// 3. `n_slots` — how many distinct probe slots the emission needed.
#[derive(Debug, Clone)]
pub struct SymbolicTree<F: FieldBackend> {
    pub nodes: Vec<SymbolicNode<F>>,
    pub body_order: Vec<NodeIdx>,
    pub n_slots: u16,
}

impl<F: FieldBackend> Default for SymbolicTree<F> {
    fn default() -> Self {
        Self {
            nodes: Vec::new(),
            body_order: Vec::new(),
            n_slots: 0,
        }
    }
}

impl<F: FieldBackend> SymbolicTree<F> {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn push(&mut self, node: SymbolicNode<F>) -> NodeIdx {
        let idx = self.nodes.len() as NodeIdx;
        self.nodes.push(node);
        idx
    }

    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    pub fn get(&self, idx: NodeIdx) -> Option<&SymbolicNode<F>> {
        self.nodes.get(idx as usize)
    }
}
