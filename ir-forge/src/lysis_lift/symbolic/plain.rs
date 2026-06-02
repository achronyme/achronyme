use std::collections::HashMap;

use memory::FieldBackend;
use smallvec::SmallVec;

use ir_core::{Instruction, SsaVar};

use super::{NodeIdx, OpTag, SymbolicNode, SymbolicTree};

pub(super) fn emit_plain<F: FieldBackend>(
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
        Instruction::WitnessCall(call) => {
            let ops: SmallVec<[NodeIdx; 3]> = call
                .inputs
                .iter()
                .map(|v| resolve_operand(*v, tree, ssa_to_idx))
                .collect();
            let bytes_hash = fxhash_bytes(&call.program_bytes);
            let idx = tree.push(SymbolicNode::Op {
                tag: OpTag::WitnessCall {
                    n_inputs: call.inputs.len() as u16,
                    n_outputs: call.outputs.len() as u16,
                    bytes_hash,
                },
                operands: ops,
            });
            for out in &call.outputs {
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
pub(super) fn resolve_operand<F: FieldBackend>(
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
