use ir_core::{Instruction, WitnessCallBody as IrWitnessCallBody};
use lysis_types::InstructionKind;
use memory::FieldBackend;

use super::shared::{map_vec_ids, map_visibility, ssa_var_from_node_id};

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
        K::WitnessCall(call) => Instruction::WitnessCall(Box::new(IrWitnessCallBody {
            outputs: map_vec_ids(&call.outputs),
            inputs: map_vec_ids(&call.inputs),
            program_bytes: call.program_bytes.clone(),
        })),
    }
}
