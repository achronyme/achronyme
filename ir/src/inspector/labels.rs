use memory::{FieldBackend, FieldElement};

use crate::types::{Instruction, IrProgram, SsaVar, Visibility};

use super::model::NodeKind;

/// Map an IR instruction to its NodeKind.
pub(super) fn node_kind<F: FieldBackend>(inst: &Instruction<F>) -> NodeKind {
    match inst {
        Instruction::Const { .. } => NodeKind::Const,
        Instruction::Input { .. } => NodeKind::Input,
        Instruction::Add { .. } => NodeKind::Add,
        Instruction::Sub { .. } => NodeKind::Sub,
        Instruction::Mul { .. } => NodeKind::Mul,
        Instruction::Div { .. } => NodeKind::Div,
        Instruction::Neg { .. } => NodeKind::Neg,
        Instruction::Mux { .. } => NodeKind::Mux,
        Instruction::AssertEq { .. } => NodeKind::AssertEq,
        Instruction::Assert { .. } => NodeKind::Assert,
        Instruction::PoseidonHash { .. } => NodeKind::PoseidonHash,
        Instruction::RangeCheck { .. } => NodeKind::RangeCheck,
        Instruction::Not { .. } => NodeKind::Not,
        Instruction::And { .. } => NodeKind::And,
        Instruction::Or { .. } => NodeKind::Or,
        Instruction::IsEq { .. } => NodeKind::IsEq,
        Instruction::IsNeq { .. } => NodeKind::IsNeq,
        Instruction::IsLt { .. } => NodeKind::IsLt,
        Instruction::IsLe { .. } => NodeKind::IsLe,
        Instruction::IsLtBounded { .. } => NodeKind::IsLtBounded,
        Instruction::IsLeBounded { .. } => NodeKind::IsLeBounded,
        Instruction::Decompose { .. } => NodeKind::RangeCheck,
        Instruction::IntDiv { .. } => NodeKind::Div,
        Instruction::IntMod { .. } => NodeKind::Div,
        Instruction::WitnessCall { .. } => NodeKind::WitnessCall,
    }
}

/// Produce a human-readable label for a node.
pub(super) fn node_label<F: FieldBackend>(inst: &Instruction<F>, program: &IrProgram<F>) -> String {
    match inst {
        Instruction::Const { value, .. } => {
            let s = format_field(value);
            format!("Const({s})")
        }
        Instruction::Input {
            name, visibility, ..
        } => {
            let vis = match visibility {
                Visibility::Public => "public",
                Visibility::Witness => "witness",
            };
            format!("Input({name}, {vis})")
        }
        Instruction::Add { result, .. } => label_with_name("Add", *result, program),
        Instruction::Sub { result, .. } => label_with_name("Sub", *result, program),
        Instruction::Mul { result, .. } => label_with_name("Mul", *result, program),
        Instruction::Div { result, .. } => label_with_name("Div", *result, program),
        Instruction::Neg { result, .. } => label_with_name("Neg", *result, program),
        Instruction::Mux { result, .. } => label_with_name("Mux", *result, program),
        Instruction::AssertEq { message, .. } => match message {
            Some(msg) => format!("AssertEq(\"{msg}\")"),
            None => "AssertEq".to_string(),
        },
        Instruction::Assert { message, .. } => match message {
            Some(msg) => format!("Assert(\"{msg}\")"),
            None => "Assert".to_string(),
        },
        Instruction::PoseidonHash { result, .. } => {
            label_with_name("PoseidonHash", *result, program)
        }
        Instruction::RangeCheck { bits, .. } => format!("RangeCheck({bits})"),
        Instruction::Not { .. } => "Not".to_string(),
        Instruction::And { .. } => "And".to_string(),
        Instruction::Or { .. } => "Or".to_string(),
        Instruction::IsEq { .. } => "IsEq".to_string(),
        Instruction::IsNeq { .. } => "IsNeq".to_string(),
        Instruction::IsLt { .. } => "IsLt".to_string(),
        Instruction::IsLe { .. } => "IsLe".to_string(),
        Instruction::IsLtBounded { bitwidth, .. } => format!("IsLtBounded({bitwidth})"),
        Instruction::IsLeBounded { bitwidth, .. } => format!("IsLeBounded({bitwidth})"),
        Instruction::Decompose {
            num_bits, result, ..
        } => {
            let base = format!("Decompose({num_bits})");
            match program.get_name(*result) {
                Some(name) => format!("{base} ({name})"),
                None => base,
            }
        }
        Instruction::IntDiv { result, .. } => label_with_name("IntDiv", *result, program),
        Instruction::IntMod { result, .. } => label_with_name("IntMod", *result, program),
        Instruction::WitnessCall(call) => {
            let primary = call.outputs.first().copied().unwrap_or(SsaVar(0));
            let bytes = call.program_bytes.len();
            let base = format!("WitnessCall[{}x]({} bytes)", call.outputs.len(), bytes);
            match program.get_name(primary) {
                Some(name) => format!("{base} ({name})"),
                None => base,
            }
        }
    }
}

/// Append variable name if available: "Mul" → "Mul (product)".
fn label_with_name<F: FieldBackend>(base: &str, var: SsaVar, program: &IrProgram<F>) -> String {
    match program.get_name(var) {
        Some(name) => format!("{base} ({name})"),
        None => base.to_string(),
    }
}

/// Format a field element for display.
/// Small values (< 2^64) show as decimal; large values as truncated hex.
pub(super) fn format_field<F: FieldBackend>(fe: &FieldElement<F>) -> String {
    let limbs = fe.to_canonical();
    // If upper 3 limbs are zero, it fits in u64 — show decimal
    if limbs[1] == 0 && limbs[2] == 0 && limbs[3] == 0 {
        return limbs[0].to_string();
    }
    // Otherwise show as hex, truncated for readability
    let hex = format!(
        "{:016x}{:016x}{:016x}{:016x}",
        limbs[3], limbs[2], limbs[1], limbs[0]
    );
    let trimmed = hex.trim_start_matches('0');
    if trimmed.len() <= 16 {
        format!("0x{trimmed}")
    } else {
        format!("0x{}…{}", &trimmed[..8], &trimmed[trimmed.len() - 4..])
    }
}
