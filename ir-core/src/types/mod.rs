mod instruction;
mod primitives;
mod program;

pub use instruction::{Instruction, WitnessCallBody};
pub use primitives::{SsaVar, Visibility};
pub use program::{IrProgram, IrType};

#[cfg(test)]
mod tests;
