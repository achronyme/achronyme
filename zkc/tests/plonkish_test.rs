pub use std::collections::HashMap;

pub use ir::passes::bool_prop::compute_proven_boolean;
pub use ir::types::{Instruction, IrProgram, Visibility};
pub use memory::{Bn254Fr, FieldElement};
pub use zkc::plonkish_backend::{PlonkishCompiler, PlonkishWitnessGenerator};

/// Helper: compile IR, generate witness, verify.
/// Integrates bool_prop analysis to match the real pipeline and avoid
/// redundant boolean checks (B1 audit fix).
pub(crate) fn compile_and_verify(
    program: &IrProgram<Bn254Fr>,
    inputs: &HashMap<String, FieldElement<Bn254Fr>>,
) -> PlonkishCompiler<Bn254Fr> {
    let proven = compute_proven_boolean(program);
    let mut compiler = PlonkishCompiler::<Bn254Fr>::new();
    compiler.set_proven_boolean(proven);
    compiler.compile_ir(program).expect("compilation failed");
    let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
    wg.generate(inputs, &mut compiler.system.assignments)
        .expect("witness gen failed");
    compiler.system.verify().expect("verification failed");
    compiler
}

/// Helper: build program from source string via IR lowering.
pub(crate) fn compile_source(
    source: &str,
    public: &[&str],
    witness: &[&str],
    inputs: &HashMap<String, FieldElement<Bn254Fr>>,
) -> PlonkishCompiler<Bn254Fr> {
    let program = ir::IrLowering::<Bn254Fr>::lower_circuit(source, public, witness).unwrap();
    compile_and_verify(&program, inputs)
}

#[path = "plonkish_test/arrays_functions_merkle.rs"]
mod arrays_functions_merkle;
#[path = "plonkish_test/basic_instructions.rs"]
mod basic_instructions;
#[path = "plonkish_test/boundaries_bounded.rs"]
mod boundaries_bounded;
#[path = "plonkish_test/control_flow_pow.rs"]
mod control_flow_pow;
#[path = "plonkish_test/ir_comparisons.rs"]
mod ir_comparisons;
#[path = "plonkish_test/malicious_prover.rs"]
mod malicious_prover;
#[path = "plonkish_test/negative_soundness.rs"]
mod negative_soundness;
#[path = "plonkish_test/parity_builtins.rs"]
mod parity_builtins;
#[path = "plonkish_test/parity_control_flow.rs"]
mod parity_control_flow;
#[path = "plonkish_test/parity_expressions.rs"]
mod parity_expressions;
#[path = "plonkish_test/parity_ir_soundness.rs"]
mod parity_ir_soundness;
#[path = "plonkish_test/parity_witness.rs"]
mod parity_witness;
#[path = "plonkish_test/poseidon.rs"]
mod poseidon;
