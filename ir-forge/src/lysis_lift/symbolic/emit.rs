use std::collections::HashMap;

use memory::{FieldBackend, FieldElement};
use smallvec::SmallVec;

use crate::ExtendedInstruction;
use ir_core::SsaVar;

use super::plain::{emit_plain, resolve_operand};
use super::{NodeIdx, SlotId, SymbolicNode, SymbolicTree};

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
///   (Bodies containing template calls are classified
///   conservatively: they behave like `OuterRef` operands for the
///   caller's purposes but the call itself lives as a single node.)
/// - `LoopUnroll` inside the body → `NestedLoop` sentinel; the
///   enclosing loop will classify `DataDependent`.
/// - `TemplateBody` inside the body → treated as `NestedLoop` for
///   safety; declaring a template inside a loop body is unusual and
///   the current pass doesn't chase it.
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
            // DataDependent. Lifting this is future work.
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
        ExtendedInstruction::SymbolicArrayRead {
            result_var,
            array_slots,
            index_var,
            span: _,
        } => {
            let array_anchor: SmallVec<[NodeIdx; 4]> = array_slots
                .iter()
                .map(|v| resolve_operand(*v, tree, ssa_to_idx))
                .collect();
            let index_operand = resolve_operand(*index_var, tree, ssa_to_idx);
            let idx = tree.push(SymbolicNode::ArrayRead {
                array_anchor,
                index_operand,
            });
            // Bind result_var to the ArrayRead node so downstream
            // uses inside the same body (within the same probe walk)
            // resolve to a stable NodeIdx — both probes produce the
            // same NodeIdx at the same body position, and
            // `nodes_equal` matches them as structurally equal.
            ssa_to_idx.insert(*result_var, idx);
            tree.body_order.push(idx);
        }
        ExtendedInstruction::SymbolicShift {
            result_var,
            operand_var,
            shift_var,
            num_bits,
            direction,
            ..
        } => {
            let operand_anchor = resolve_operand(*operand_var, tree, ssa_to_idx);
            let shift_operand = resolve_operand(*shift_var, tree, ssa_to_idx);
            let idx = tree.push(SymbolicNode::Shift {
                operand_anchor,
                shift_operand,
                num_bits: *num_bits,
                direction: *direction,
            });
            // Bind result_var to the Shift node so downstream uses
            // inside the same body (within the same probe walk)
            // resolve to a stable NodeIdx. Two probes produce the
            // same NodeIdx at the same body position, and
            // `nodes_equal`'s `Shift` arm matches them as
            // structurally equal modulo slot divergence.
            ssa_to_idx.insert(*result_var, idx);
            tree.body_order.push(idx);
        }
    }
}
