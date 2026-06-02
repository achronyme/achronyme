use ir_core::{Instruction, WitnessCallBody as IrWitnessCallBody};
use lysis_types::{InstructionKind, WitnessCallBody as LysisWitnessCallBody};
use memory::FieldBackend;

use super::shared::{map_vec_ids_owned, map_visibility, ssa_var_from_node_id};

/// Owning counterpart of
/// [`instruction_from_kind`](super::instruction_from_kind): consumes the
/// `InstructionKind` by value and moves String / `Vec<u8>` fields
/// (`Input.name`, `AssertEq.message`, `Assert.message`,
/// `WitnessCall.program_bytes`) directly into the destination instead
/// of cloning. Output is structurally byte-identical to the by-ref
/// path; the streaming pipeline uses it to avoid one String/byte clone
/// per heap-bearing instruction on the boss-fight scale.
pub fn instruction_from_kind_owned<F: FieldBackend>(kind: InstructionKind<F>) -> Instruction<F> {
    use InstructionKind as K;
    match kind {
        K::Const { result, value } => Instruction::Const {
            result: ssa_var_from_node_id(result),
            value,
        },
        K::Input {
            result,
            name,
            visibility,
        } => Instruction::Input {
            result: ssa_var_from_node_id(result),
            name,
            visibility: map_visibility(visibility),
        },
        K::Add { result, lhs, rhs } => Instruction::Add {
            result: ssa_var_from_node_id(result),
            lhs: ssa_var_from_node_id(lhs),
            rhs: ssa_var_from_node_id(rhs),
        },
        K::Sub { result, lhs, rhs } => Instruction::Sub {
            result: ssa_var_from_node_id(result),
            lhs: ssa_var_from_node_id(lhs),
            rhs: ssa_var_from_node_id(rhs),
        },
        K::Mul { result, lhs, rhs } => Instruction::Mul {
            result: ssa_var_from_node_id(result),
            lhs: ssa_var_from_node_id(lhs),
            rhs: ssa_var_from_node_id(rhs),
        },
        K::Div { result, lhs, rhs } => Instruction::Div {
            result: ssa_var_from_node_id(result),
            lhs: ssa_var_from_node_id(lhs),
            rhs: ssa_var_from_node_id(rhs),
        },
        K::Neg { result, operand } => Instruction::Neg {
            result: ssa_var_from_node_id(result),
            operand: ssa_var_from_node_id(operand),
        },
        K::Mux {
            result,
            cond,
            if_true,
            if_false,
        } => Instruction::Mux {
            result: ssa_var_from_node_id(result),
            cond: ssa_var_from_node_id(cond),
            if_true: ssa_var_from_node_id(if_true),
            if_false: ssa_var_from_node_id(if_false),
        },
        K::AssertEq {
            result,
            lhs,
            rhs,
            message,
        } => Instruction::AssertEq {
            result: ssa_var_from_node_id(result),
            lhs: ssa_var_from_node_id(lhs),
            rhs: ssa_var_from_node_id(rhs),
            message,
        },
        K::PoseidonHash {
            result,
            left,
            right,
        } => Instruction::PoseidonHash {
            result: ssa_var_from_node_id(result),
            left: ssa_var_from_node_id(left),
            right: ssa_var_from_node_id(right),
        },
        K::RangeCheck {
            result,
            operand,
            bits,
        } => Instruction::RangeCheck {
            result: ssa_var_from_node_id(result),
            operand: ssa_var_from_node_id(operand),
            bits,
        },
        K::Not { result, operand } => Instruction::Not {
            result: ssa_var_from_node_id(result),
            operand: ssa_var_from_node_id(operand),
        },
        K::And { result, lhs, rhs } => Instruction::And {
            result: ssa_var_from_node_id(result),
            lhs: ssa_var_from_node_id(lhs),
            rhs: ssa_var_from_node_id(rhs),
        },
        K::Or { result, lhs, rhs } => Instruction::Or {
            result: ssa_var_from_node_id(result),
            lhs: ssa_var_from_node_id(lhs),
            rhs: ssa_var_from_node_id(rhs),
        },
        K::IsEq { result, lhs, rhs } => Instruction::IsEq {
            result: ssa_var_from_node_id(result),
            lhs: ssa_var_from_node_id(lhs),
            rhs: ssa_var_from_node_id(rhs),
        },
        K::IsNeq { result, lhs, rhs } => Instruction::IsNeq {
            result: ssa_var_from_node_id(result),
            lhs: ssa_var_from_node_id(lhs),
            rhs: ssa_var_from_node_id(rhs),
        },
        K::IsLt { result, lhs, rhs } => Instruction::IsLt {
            result: ssa_var_from_node_id(result),
            lhs: ssa_var_from_node_id(lhs),
            rhs: ssa_var_from_node_id(rhs),
        },
        K::IsLe { result, lhs, rhs } => Instruction::IsLe {
            result: ssa_var_from_node_id(result),
            lhs: ssa_var_from_node_id(lhs),
            rhs: ssa_var_from_node_id(rhs),
        },
        K::IsLtBounded {
            result,
            lhs,
            rhs,
            bitwidth,
        } => Instruction::IsLtBounded {
            result: ssa_var_from_node_id(result),
            lhs: ssa_var_from_node_id(lhs),
            rhs: ssa_var_from_node_id(rhs),
            bitwidth,
        },
        K::IsLeBounded {
            result,
            lhs,
            rhs,
            bitwidth,
        } => Instruction::IsLeBounded {
            result: ssa_var_from_node_id(result),
            lhs: ssa_var_from_node_id(lhs),
            rhs: ssa_var_from_node_id(rhs),
            bitwidth,
        },
        K::Assert {
            result,
            operand,
            message,
        } => Instruction::Assert {
            result: ssa_var_from_node_id(result),
            operand: ssa_var_from_node_id(operand),
            message,
        },
        K::Decompose {
            result,
            bit_results,
            operand,
            num_bits,
        } => Instruction::Decompose {
            result: ssa_var_from_node_id(result),
            bit_results: map_vec_ids_owned(bit_results),
            operand: ssa_var_from_node_id(operand),
            num_bits,
        },
        K::IntDiv {
            result,
            lhs,
            rhs,
            max_bits,
        } => Instruction::IntDiv {
            result: ssa_var_from_node_id(result),
            lhs: ssa_var_from_node_id(lhs),
            rhs: ssa_var_from_node_id(rhs),
            max_bits,
        },
        K::IntMod {
            result,
            lhs,
            rhs,
            max_bits,
        } => Instruction::IntMod {
            result: ssa_var_from_node_id(result),
            lhs: ssa_var_from_node_id(lhs),
            rhs: ssa_var_from_node_id(rhs),
            max_bits,
        },
        K::WitnessCall(call) => {
            let LysisWitnessCallBody {
                outputs,
                inputs,
                program_bytes,
            } = *call;
            Instruction::WitnessCall(Box::new(IrWitnessCallBody {
                outputs: map_vec_ids_owned(outputs),
                inputs: map_vec_ids_owned(inputs),
                program_bytes,
            }))
        }
    }
}
