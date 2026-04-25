//! Symbolic emission for BTA (RFC §6.1).
//!
//! Walks a body once with a specific `loop_var → concrete_value`
//! binding and produces a flat linear-tree ([`SymbolicTree`]) whose
//! `Const` nodes carry a `from_slot` flag when the constant was
//! injected through the binding rather than appearing literally in
//! the source. The BTA classifier calls this twice (actually three
//! times per RFC §6.1.1 v1.1) with different probe values and then
//! runs [`super::diff::structural_diff`] to check whether the bodies
//! differ only in slot positions.
//!
//! ## What "symbolic" means here
//!
//! Not a CAS. The tree is straight-line — it mirrors the emission
//! order of the input body, with SsaVar references resolved to
//! earlier tree nodes. No interning, no constant folding, no algebraic
//! rewriting. The only "symbolic" aspect is that constants derived
//! from the loop binding are tagged so that structural_diff can
//! distinguish them from authentic literals.
//!
//! ## Outer refs vs captures
//!
//! SsaVars referenced in the body but defined outside it (and not in
//! `bindings`) land as [`SymbolicNode::OuterRef`]. These stay stable
//! across the probe walks because the caller's scope is fixed. The
//! lifter later converts them to capture slots once BTA has
//! classified the loop as `Uniform`; that step is in `extract.rs`,
//! not here.

use std::collections::HashMap;

use memory::{FieldBackend, FieldElement};
use smallvec::SmallVec;

use crate::extended::IndexedEffectKind;
use crate::{ExtendedInstruction, TemplateId};
use ir_core::{Instruction, SsaVar, Visibility};

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
    /// A nested `LoopUnroll`. Marker node only — Phase 3's BTA does
    /// not recurse into nested loops, so this sentinel forces the
    /// enclosing loop to classify as `DataDependent` when present.
    /// (A Phase 4 refinement could recursively classify the nested
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

/// Walk `body` once, resolving SsaVar references against the probe
/// `bindings`, and produce a [`SymbolicTree`].
///
/// # Parameters
///
/// - `body` — slice of `ExtendedInstruction<F>` forming one copy of
///   the body to probe (the ORIGINAL body, not a duplicated inlining).
/// - `bindings` — `(SsaVar, value)` pairs the lifter synthesizes
///   before each probe walk. Typically exactly one binding:
///   `(loop_var, concrete_i)`. Each binding occupies one slot in
///   the output tree, in the order passed.
///
/// # Behavior
///
/// - Every binding becomes a `SymbolicNode::Const { value,
///   from_slot: Some(SlotId(i)) }` pushed at the top of `nodes`. The
///   `body_order` does NOT include these — they're pool entries
///   only.
/// - Plain instructions become `Op` or `Input` or `Const (literal)`
///   nodes. Their `result` SSA var is recorded so downstream
///   operands resolve.
/// - `TemplateCall` becomes a `TemplateCall` node; the `outputs` are
///   bound to synthetic `OuterRef`-free placeholders via a
///   `NestedLoop`-style note that structural_diff treats as opaque.
///   (For now Phase 3 classifies bodies containing template calls
///   conservatively: they behave like `OuterRef` operands for the
///   caller's purposes but the call itself lives as a single node.)
/// - `LoopUnroll` inside the body → `NestedLoop` sentinel; the
///   enclosing loop will classify `DataDependent`.
/// - `TemplateBody` inside the body → treated as `NestedLoop` for
///   safety; declaring a template inside a loop body is unusual and
///   Phase 3 doesn't chase it.
///
/// # SsaVar resolution
///
/// When an instruction operand references an SsaVar:
///
/// 1. If it was produced by an earlier emission in this walk,
///    resolve to the corresponding `NodeIdx`.
/// 2. If it was bound via `bindings`, resolve to the synthetic
///    slot `Const` pushed at the top.
/// 3. Otherwise emit (and reuse) a `OuterRef` node for the SsaVar.
pub fn symbolic_emit<F: FieldBackend>(
    body: &[ExtendedInstruction<F>],
    bindings: &[(SsaVar, FieldElement<F>)],
) -> SymbolicTree<F> {
    let mut tree = SymbolicTree::new();
    let mut ssa_to_idx: HashMap<SsaVar, NodeIdx> = HashMap::new();

    // Step 1: inject probe bindings as slot-tagged Const pool entries.
    for (slot_i, (var, value)) in bindings.iter().enumerate() {
        let idx = tree.push(SymbolicNode::Const {
            value: *value,
            from_slot: Some(SlotId(slot_i as u16)),
        });
        ssa_to_idx.insert(*var, idx);
    }
    tree.n_slots = bindings.len() as u16;

    // Step 2: walk the body.
    for inst in body {
        emit_one(inst, &mut tree, &mut ssa_to_idx);
    }

    tree
}

fn emit_one<F: FieldBackend>(
    inst: &ExtendedInstruction<F>,
    tree: &mut SymbolicTree<F>,
    ssa_to_idx: &mut HashMap<SsaVar, NodeIdx>,
) {
    match inst {
        ExtendedInstruction::Plain(i) => {
            let idx = emit_plain(i, tree, ssa_to_idx);
            tree.body_order.push(idx);
        }
        ExtendedInstruction::TemplateCall {
            template_id,
            captures,
            outputs,
        } => {
            let capture_operands: SmallVec<[NodeIdx; 4]> = captures
                .iter()
                .map(|v| resolve_operand(*v, tree, ssa_to_idx))
                .collect();
            let idx = tree.push(SymbolicNode::TemplateCall {
                template_id: *template_id,
                capture_operands,
                n_outputs: outputs.len() as u16,
            });
            // Each output SSA var binds back to this one node — the
            // caller reads specific slots by position elsewhere, but
            // for BTA purposes the whole call is a single node.
            for out in outputs {
                ssa_to_idx.insert(*out, idx);
            }
            tree.body_order.push(idx);
        }
        ExtendedInstruction::LoopUnroll { .. } | ExtendedInstruction::TemplateBody { .. } => {
            // Nested control structures collapse to an opaque marker
            // that forces the enclosing classification to
            // DataDependent. Phase 4 can lift this.
            let idx = tree.push(SymbolicNode::NestedLoop);
            tree.body_order.push(idx);
        }
        ExtendedInstruction::SymbolicIndexedEffect {
            kind,
            array_slots,
            index_var,
            value_var,
            span: _,
        } => {
            let array_anchor: SmallVec<[NodeIdx; 4]> = array_slots
                .iter()
                .map(|v| resolve_operand(*v, tree, ssa_to_idx))
                .collect();
            let index_operand = resolve_operand(*index_var, tree, ssa_to_idx);
            let value_operand = value_var.map(|v| resolve_operand(v, tree, ssa_to_idx));
            let idx = tree.push(SymbolicNode::IndexedEffect {
                kind: *kind,
                array_anchor,
                index_operand,
                value_operand,
            });
            tree.body_order.push(idx);
        }
    }
}

fn emit_plain<F: FieldBackend>(
    inst: &Instruction<F>,
    tree: &mut SymbolicTree<F>,
    ssa_to_idx: &mut HashMap<SsaVar, NodeIdx>,
) -> NodeIdx {
    match inst {
        // ---------- nodes that don't read operands ----------
        Instruction::Const { result, value } => {
            let idx = tree.push(SymbolicNode::Const {
                value: *value,
                from_slot: None,
            });
            ssa_to_idx.insert(*result, idx);
            idx
        }
        Instruction::Input {
            result,
            name,
            visibility,
        } => {
            let idx = tree.push(SymbolicNode::Input {
                name: name.clone(),
                visibility: *visibility,
            });
            ssa_to_idx.insert(*result, idx);
            idx
        }

        // ---------- binary arithmetic ----------
        Instruction::Add { result, lhs, rhs } => {
            bin_op(OpTag::Add, *result, *lhs, *rhs, tree, ssa_to_idx)
        }
        Instruction::Sub { result, lhs, rhs } => {
            bin_op(OpTag::Sub, *result, *lhs, *rhs, tree, ssa_to_idx)
        }
        Instruction::Mul { result, lhs, rhs } => {
            bin_op(OpTag::Mul, *result, *lhs, *rhs, tree, ssa_to_idx)
        }
        Instruction::Div { result, lhs, rhs } => {
            bin_op(OpTag::Div, *result, *lhs, *rhs, tree, ssa_to_idx)
        }

        // ---------- unary ----------
        Instruction::Neg { result, operand } => {
            un_op(OpTag::Neg, *result, *operand, tree, ssa_to_idx)
        }
        Instruction::Not { result, operand } => {
            un_op(OpTag::Not, *result, *operand, tree, ssa_to_idx)
        }

        // ---------- boolean / logic ----------
        Instruction::And { result, lhs, rhs } => {
            bin_op(OpTag::And, *result, *lhs, *rhs, tree, ssa_to_idx)
        }
        Instruction::Or { result, lhs, rhs } => {
            bin_op(OpTag::Or, *result, *lhs, *rhs, tree, ssa_to_idx)
        }
        Instruction::IsEq { result, lhs, rhs } => {
            bin_op(OpTag::IsEq, *result, *lhs, *rhs, tree, ssa_to_idx)
        }
        Instruction::IsNeq { result, lhs, rhs } => {
            bin_op(OpTag::IsNeq, *result, *lhs, *rhs, tree, ssa_to_idx)
        }
        Instruction::IsLt { result, lhs, rhs } => {
            bin_op(OpTag::IsLt, *result, *lhs, *rhs, tree, ssa_to_idx)
        }
        Instruction::IsLe { result, lhs, rhs } => {
            bin_op(OpTag::IsLe, *result, *lhs, *rhs, tree, ssa_to_idx)
        }
        Instruction::IsLtBounded {
            result,
            lhs,
            rhs,
            bitwidth,
        } => bin_op(
            OpTag::IsLtBounded(*bitwidth),
            *result,
            *lhs,
            *rhs,
            tree,
            ssa_to_idx,
        ),
        Instruction::IsLeBounded {
            result,
            lhs,
            rhs,
            bitwidth,
        } => bin_op(
            OpTag::IsLeBounded(*bitwidth),
            *result,
            *lhs,
            *rhs,
            tree,
            ssa_to_idx,
        ),

        // ---------- mux ----------
        Instruction::Mux {
            result,
            cond,
            if_true,
            if_false,
        } => {
            let ops: SmallVec<[NodeIdx; 3]> = smallvec::smallvec![
                resolve_operand(*cond, tree, ssa_to_idx),
                resolve_operand(*if_true, tree, ssa_to_idx),
                resolve_operand(*if_false, tree, ssa_to_idx),
            ];
            let idx = tree.push(SymbolicNode::Op {
                tag: OpTag::Mux,
                operands: ops,
            });
            ssa_to_idx.insert(*result, idx);
            idx
        }

        // ---------- hash / range ----------
        Instruction::PoseidonHash {
            result,
            left,
            right,
        } => bin_op(
            OpTag::PoseidonHash,
            *result,
            *left,
            *right,
            tree,
            ssa_to_idx,
        ),
        Instruction::RangeCheck {
            result,
            operand,
            bits,
        } => un_op(
            OpTag::RangeCheck(*bits),
            *result,
            *operand,
            tree,
            ssa_to_idx,
        ),
        Instruction::Decompose {
            result,
            bit_results,
            operand,
            num_bits,
        } => {
            let op_idx = resolve_operand(*operand, tree, ssa_to_idx);
            let idx = tree.push(SymbolicNode::Op {
                tag: OpTag::Decompose(*num_bits),
                operands: smallvec::smallvec![op_idx],
            });
            // All bit results point at the single Decompose node —
            // same treatment as TemplateCall outputs.
            ssa_to_idx.insert(*result, idx);
            for br in bit_results {
                ssa_to_idx.insert(*br, idx);
            }
            idx
        }

        // ---------- integer div / mod ----------
        Instruction::IntDiv {
            result,
            lhs,
            rhs,
            max_bits,
        } => bin_op(
            OpTag::IntDiv(*max_bits),
            *result,
            *lhs,
            *rhs,
            tree,
            ssa_to_idx,
        ),
        Instruction::IntMod {
            result,
            lhs,
            rhs,
            max_bits,
        } => bin_op(
            OpTag::IntMod(*max_bits),
            *result,
            *lhs,
            *rhs,
            tree,
            ssa_to_idx,
        ),

        // ---------- asserts ----------
        Instruction::AssertEq {
            result,
            lhs,
            rhs,
            message: _,
        } => bin_op(OpTag::AssertEq, *result, *lhs, *rhs, tree, ssa_to_idx),
        Instruction::Assert {
            result,
            operand,
            message: _,
        } => un_op(OpTag::Assert, *result, *operand, tree, ssa_to_idx),

        // ---------- witness call ----------
        Instruction::WitnessCall {
            outputs,
            inputs,
            program_bytes,
        } => {
            let ops: SmallVec<[NodeIdx; 3]> = inputs
                .iter()
                .map(|v| resolve_operand(*v, tree, ssa_to_idx))
                .collect();
            let bytes_hash = fxhash_bytes(program_bytes);
            let idx = tree.push(SymbolicNode::Op {
                tag: OpTag::WitnessCall {
                    n_inputs: inputs.len() as u16,
                    n_outputs: outputs.len() as u16,
                    bytes_hash,
                },
                operands: ops,
            });
            for out in outputs {
                ssa_to_idx.insert(*out, idx);
            }
            idx
        }
    }
}

/// Emit a binary-operand node and bind `result` to it.
fn bin_op<F: FieldBackend>(
    tag: OpTag,
    result: SsaVar,
    lhs: SsaVar,
    rhs: SsaVar,
    tree: &mut SymbolicTree<F>,
    ssa_to_idx: &mut HashMap<SsaVar, NodeIdx>,
) -> NodeIdx {
    let l = resolve_operand(lhs, tree, ssa_to_idx);
    let r = resolve_operand(rhs, tree, ssa_to_idx);
    let idx = tree.push(SymbolicNode::Op {
        tag,
        operands: smallvec::smallvec![l, r],
    });
    ssa_to_idx.insert(result, idx);
    idx
}

/// Emit a unary-operand node and bind `result` to it.
fn un_op<F: FieldBackend>(
    tag: OpTag,
    result: SsaVar,
    operand: SsaVar,
    tree: &mut SymbolicTree<F>,
    ssa_to_idx: &mut HashMap<SsaVar, NodeIdx>,
) -> NodeIdx {
    let op = resolve_operand(operand, tree, ssa_to_idx);
    let idx = tree.push(SymbolicNode::Op {
        tag,
        operands: smallvec::smallvec![op],
    });
    ssa_to_idx.insert(result, idx);
    idx
}

/// Resolve an SsaVar to its defining NodeIdx, synthesizing an
/// `OuterRef` node the first time an outer-scope var is referenced.
fn resolve_operand<F: FieldBackend>(
    var: SsaVar,
    tree: &mut SymbolicTree<F>,
    ssa_to_idx: &mut HashMap<SsaVar, NodeIdx>,
) -> NodeIdx {
    if let Some(&idx) = ssa_to_idx.get(&var) {
        return idx;
    }
    let idx = tree.push(SymbolicNode::OuterRef(var));
    ssa_to_idx.insert(var, idx);
    idx
}

/// Hash of a byte slice, stable within a single process. Used only
/// to tag `WitnessCall` nodes for structural equality — two copies
/// of the same witness program get the same hash; different programs
/// (almost certainly) get different hashes. Collision risk is
/// acceptable because BTA is a classification-not-correctness pass:
/// a false "equal" here merely causes a template to cover slightly
/// more bodies than it should, caught by the oracle gate.
fn fxhash_bytes(bytes: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut h = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut h);
    h.finish()
}

#[cfg(test)]
mod tests {
    use memory::{Bn254Fr, FieldElement};

    use super::*;
    use crate::TemplateId;

    fn fe(n: u64) -> FieldElement<Bn254Fr> {
        FieldElement::from_canonical([n, 0, 0, 0])
    }

    fn ssa(i: u32) -> SsaVar {
        SsaVar(i)
    }

    fn push_const(body: &mut Vec<ExtendedInstruction<Bn254Fr>>, result: u32, v: u64) {
        body.push(
            Instruction::Const {
                result: ssa(result),
                value: fe(v),
            }
            .into(),
        );
    }

    #[test]
    fn empty_body_empty_tree() {
        let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![];
        let t = symbolic_emit(&body, &[]);
        assert!(t.is_empty());
        assert!(t.body_order.is_empty());
        assert_eq!(t.n_slots, 0);
    }

    #[test]
    fn no_bindings_emits_only_literal_consts() {
        let mut body: Vec<ExtendedInstruction<Bn254Fr>> = vec![];
        push_const(&mut body, 0, 42);
        let t = symbolic_emit::<Bn254Fr>(&body, &[]);
        assert_eq!(t.body_order.len(), 1);
        let node = &t.nodes[t.body_order[0] as usize];
        match node {
            SymbolicNode::Const { value, from_slot } => {
                assert_eq!(*value, fe(42));
                assert!(from_slot.is_none());
            }
            _ => panic!("expected literal Const"),
        }
    }

    #[test]
    fn binding_produces_slot_tagged_const_at_top() {
        // Empty body, one binding → one slot at index 0.
        let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![];
        let t = symbolic_emit(&body, &[(ssa(0), fe(5))]);
        assert_eq!(t.n_slots, 1);
        assert_eq!(t.nodes.len(), 1);
        match &t.nodes[0] {
            SymbolicNode::Const {
                value,
                from_slot: Some(SlotId(0)),
            } => {
                assert_eq!(*value, fe(5));
            }
            _ => panic!("expected slot-tagged Const at index 0"),
        }
    }

    #[test]
    fn operand_referencing_bound_var_resolves_to_slot() {
        // body: Mul(r0, r0) where r0 is the loop var bound to fe(3).
        let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![Instruction::Mul {
            result: ssa(1),
            lhs: ssa(0),
            rhs: ssa(0),
        }
        .into()];
        let t = symbolic_emit(&body, &[(ssa(0), fe(3))]);
        // Nodes: [0] slot-Const, [1] Op(Mul, [0, 0]).
        assert_eq!(t.nodes.len(), 2);
        match &t.nodes[1] {
            SymbolicNode::Op { tag, operands } => {
                assert_eq!(*tag, OpTag::Mul);
                assert_eq!(operands.as_slice(), &[0, 0]);
            }
            _ => panic!(),
        }
        assert_eq!(t.body_order, vec![1]);
    }

    #[test]
    fn operand_to_outer_scope_var_becomes_outer_ref() {
        // body: Add(r99 /* outer */, r0 /* literal const */).
        let mut body: Vec<ExtendedInstruction<Bn254Fr>> = vec![];
        push_const(&mut body, 0, 7);
        body.push(
            Instruction::Add {
                result: ssa(10),
                lhs: ssa(99), // outer scope
                rhs: ssa(0),
            }
            .into(),
        );
        let t = symbolic_emit::<Bn254Fr>(&body, &[]);
        // Nodes: [0] literal Const, [1] OuterRef(99), [2] Op(Add, [1,0]).
        assert_eq!(t.nodes.len(), 3);
        assert!(matches!(
            &t.nodes[1],
            SymbolicNode::OuterRef(v) if *v == ssa(99)
        ));
        match &t.nodes[2] {
            SymbolicNode::Op { tag, operands } => {
                assert_eq!(*tag, OpTag::Add);
                assert_eq!(operands.as_slice(), &[1, 0]);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn outer_ref_is_dedup_per_ssavar() {
        let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![
            Instruction::Add {
                result: ssa(10),
                lhs: ssa(99),
                rhs: ssa(99),
            }
            .into(),
            Instruction::Mul {
                result: ssa(11),
                lhs: ssa(99),
                rhs: ssa(10),
            }
            .into(),
        ];
        let t = symbolic_emit::<Bn254Fr>(&body, &[]);
        let outer_refs: Vec<_> = t
            .nodes
            .iter()
            .filter(|n| matches!(n, SymbolicNode::OuterRef(v) if *v == ssa(99)))
            .collect();
        assert_eq!(outer_refs.len(), 1, "same outer SsaVar must dedup");
    }

    #[test]
    fn probe_twice_differs_only_in_slot_value() {
        // body: Add(iter_var, Const(5)). Probe at 0 and 1.
        let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![
            Instruction::Const {
                result: ssa(1),
                value: fe(5),
            }
            .into(),
            Instruction::Add {
                result: ssa(2),
                lhs: ssa(0),
                rhs: ssa(1),
            }
            .into(),
        ];
        let a = symbolic_emit(&body, &[(ssa(0), fe(0))]);
        let b = symbolic_emit(&body, &[(ssa(0), fe(1))]);

        // Structural shape matches.
        assert_eq!(a.nodes.len(), b.nodes.len());
        assert_eq!(a.body_order, b.body_order);

        // Slot at index 0 differs in value, identical slot_id.
        match (&a.nodes[0], &b.nodes[0]) {
            (
                SymbolicNode::Const {
                    value: va,
                    from_slot: Some(sa),
                },
                SymbolicNode::Const {
                    value: vb,
                    from_slot: Some(sb),
                },
            ) => {
                assert_eq!(sa, sb);
                assert_ne!(va, vb);
            }
            _ => panic!(),
        }
        // Literal Const at index 1 is untouched.
        match (&a.nodes[1], &b.nodes[1]) {
            (
                SymbolicNode::Const {
                    value: va,
                    from_slot: None,
                },
                SymbolicNode::Const {
                    value: vb,
                    from_slot: None,
                },
            ) => {
                assert_eq!(va, vb);
                assert_eq!(*va, fe(5));
            }
            _ => panic!(),
        }
    }

    #[test]
    fn decompose_bind_all_bit_results_to_same_node() {
        let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![
            Instruction::Input {
                result: ssa(0),
                name: "x".into(),
                visibility: Visibility::Witness,
            }
            .into(),
            Instruction::Decompose {
                result: ssa(0),
                bit_results: vec![ssa(1), ssa(2), ssa(3), ssa(4)],
                operand: ssa(0),
                num_bits: 4,
            }
            .into(),
        ];
        let t = symbolic_emit::<Bn254Fr>(&body, &[]);
        // Nodes: [0] Input, [1] Op(Decompose(4), [0]).
        assert_eq!(t.nodes.len(), 2);
        match &t.nodes[1] {
            SymbolicNode::Op { tag, .. } => assert_eq!(*tag, OpTag::Decompose(4)),
            _ => panic!(),
        }
    }

    #[test]
    fn witness_call_hashes_program_bytes() {
        let a: Vec<ExtendedInstruction<Bn254Fr>> =
            vec![ExtendedInstruction::Plain(Instruction::WitnessCall {
                outputs: vec![ssa(0)],
                inputs: vec![],
                program_bytes: vec![0xAA, 0xBB],
            })];
        let b: Vec<ExtendedInstruction<Bn254Fr>> =
            vec![ExtendedInstruction::Plain(Instruction::WitnessCall {
                outputs: vec![ssa(0)],
                inputs: vec![],
                program_bytes: vec![0xAA, 0xBB],
            })];
        let c: Vec<ExtendedInstruction<Bn254Fr>> =
            vec![ExtendedInstruction::Plain(Instruction::WitnessCall {
                outputs: vec![ssa(0)],
                inputs: vec![],
                program_bytes: vec![0xCC, 0xDD],
            })];
        let ta = symbolic_emit::<Bn254Fr>(&a, &[]);
        let tb = symbolic_emit::<Bn254Fr>(&b, &[]);
        let tc = symbolic_emit::<Bn254Fr>(&c, &[]);
        let tag = |t: &SymbolicTree<Bn254Fr>| match &t.nodes[0] {
            SymbolicNode::Op { tag, .. } => *tag,
            _ => panic!(),
        };
        assert_eq!(tag(&ta), tag(&tb), "same bytes → same tag");
        assert_ne!(tag(&ta), tag(&tc), "different bytes → different tag");
    }

    #[test]
    fn nested_loop_becomes_opaque_marker() {
        let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![ExtendedInstruction::LoopUnroll {
            iter_var: ssa(0),
            start: 0,
            end: 4,
            body: vec![],
        }];
        let t = symbolic_emit::<Bn254Fr>(&body, &[]);
        assert_eq!(t.nodes.len(), 1);
        assert!(matches!(&t.nodes[0], SymbolicNode::NestedLoop));
    }

    #[test]
    fn template_call_carries_id_and_capture_operands() {
        let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![
            Instruction::Const {
                result: ssa(0),
                value: fe(1),
            }
            .into(),
            ExtendedInstruction::TemplateCall {
                template_id: TemplateId(7),
                captures: vec![ssa(0), ssa(99)],
                outputs: vec![ssa(10), ssa(11)],
            },
        ];
        let t = symbolic_emit::<Bn254Fr>(&body, &[]);
        // Nodes: [0] literal Const, [1] OuterRef(99), [2] TemplateCall.
        let call_idx = t.body_order[1];
        match &t.nodes[call_idx as usize] {
            SymbolicNode::TemplateCall {
                template_id,
                capture_operands,
                n_outputs,
            } => {
                assert_eq!(*template_id, TemplateId(7));
                assert_eq!(*n_outputs, 2);
                assert_eq!(capture_operands.as_slice(), &[0, 1]);
            }
            _ => panic!(),
        }
    }

    #[test]
    fn two_probes_preserve_node_count_and_order() {
        // Sanity: a body of N top-level statements always yields
        // body_order.len() == N regardless of probe value. (Slot
        // pool entries don't count toward body_order.)
        let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![
            Instruction::Const {
                result: ssa(1),
                value: fe(10),
            }
            .into(),
            Instruction::Add {
                result: ssa(2),
                lhs: ssa(0),
                rhs: ssa(1),
            }
            .into(),
            Instruction::Mul {
                result: ssa(3),
                lhs: ssa(2),
                rhs: ssa(0),
            }
            .into(),
        ];
        let a = symbolic_emit(&body, &[(ssa(0), fe(0))]);
        let b = symbolic_emit(&body, &[(ssa(0), fe(5))]);
        assert_eq!(a.body_order, b.body_order);
        assert_eq!(a.body_order.len(), 3);
    }

    #[test]
    fn multiple_bindings_produce_multiple_slots() {
        let body: Vec<ExtendedInstruction<Bn254Fr>> = vec![];
        let t = symbolic_emit(&body, &[(ssa(0), fe(1)), (ssa(1), fe(2))]);
        assert_eq!(t.n_slots, 2);
        assert_eq!(t.nodes.len(), 2);
        assert!(matches!(
            &t.nodes[0],
            SymbolicNode::Const {
                from_slot: Some(SlotId(0)),
                ..
            }
        ));
        assert!(matches!(
            &t.nodes[1],
            SymbolicNode::Const {
                from_slot: Some(SlotId(1)),
                ..
            }
        ));
    }
}
