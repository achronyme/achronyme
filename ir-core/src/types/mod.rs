mod instruction;
mod primitives;
mod program;
mod visit;

pub use instruction::{Instruction, WitnessCallBody};
pub use primitives::{SsaVar, Visibility};
pub use program::{IrProgram, IrType};

#[cfg(test)]
mod tests;
