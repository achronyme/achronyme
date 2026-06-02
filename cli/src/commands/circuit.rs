mod bn254;
mod entry;
mod inputs;
mod plonkish;
mod r1cs;

pub use entry::circuit_command;

#[cfg(test)]
mod tests;
