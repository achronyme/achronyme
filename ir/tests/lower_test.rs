use ir::{Instruction, IrLowering, Visibility};
use memory::FieldElement;

/// Helper: lower a circuit with given public/witness inputs.
fn lower(source: &str, public: &[&str], witness: &[&str]) -> Vec<Instruction> {
    IrLowering::<memory::Bn254Fr>::lower_circuit(source, public, witness)
        .expect("lowering failed")
        .into_instructions()
}

/// Count instructions of a specific type.
fn count<F>(insts: &[Instruction], pred: F) -> usize
where
    F: Fn(&Instruction) -> bool,
{
    insts.iter().filter(|i| pred(i)).count()
}

#[path = "lower_test/atoms_ops.rs"]
mod atoms_ops;

#[path = "lower_test/builtins_control_errors.rs"]
mod builtins_control_errors;

#[path = "lower_test/dce.rs"]
mod dce;

#[path = "lower_test/typing_basics.rs"]
mod typing_basics;

#[path = "lower_test/typing_enforcement.rs"]
mod typing_enforcement;
