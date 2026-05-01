//! Test helpers shared between integration tests and the cargo-fuzz
//! harness for the R1CS preservation oracle (Phase 0.2.D / 0.4.C).
//!
//! Gated behind `cfg(any(test, feature = "test-support"))` so this
//! module is compiled into integration tests automatically and into
//! external consumers (currently the fuzz crate) only when they opt in
//! via `features = ["test-support"]`. Mirrors the
//! [`ir_forge::test_utils`] pattern.
//!
//! See `zkc/tests/r1cs_preservation_proptest.rs` for the property
//! framing (CompCert two-sided simulation, advisor §2b).

use std::collections::HashMap;

use ir::IrLowering;
use memory::FieldElement;

use crate::r1cs_backend::R1CSCompiler;
use crate::witness::WitnessGenerator;

/// Compile a circuit source to R1CS, generate a satisfying witness,
/// and verify it satisfies the pre-O1 system. Returns the compiler
/// (with `cs` still in its pre-O1 state) and the witness vector.
///
/// Panics if the lowering, R1CS compile, or witness generation fails,
/// or if the resulting witness does not verify against the pre-O1
/// system. Used as the input-side fixture for both the proptest and
/// the cargo-fuzz harness — both treat any of those failures as a
/// fixture-construction error rather than an oracle violation.
pub fn compile_and_solve(
    source: &str,
    public: &[(&str, FieldElement)],
    witness_inputs: &[(&str, FieldElement)],
) -> (R1CSCompiler, Vec<FieldElement>) {
    let pub_names: Vec<&str> = public.iter().map(|(n, _)| *n).collect();
    let wit_names: Vec<&str> = witness_inputs.iter().map(|(n, _)| *n).collect();
    let mut program = IrLowering::lower_circuit(source, &pub_names, &wit_names).unwrap();
    ir::passes::optimize(&mut program);

    let mut compiler = R1CSCompiler::new();
    compiler.compile_ir(&program).unwrap();

    let wg = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    for (name, val) in public.iter().chain(witness_inputs.iter()) {
        inputs.insert(name.to_string(), *val);
    }
    let w = wg.generate(&inputs).unwrap();
    compiler
        .cs
        .verify(&w)
        .expect("pre-O1 R1CS must verify on solved witness");

    (compiler, w)
}

/// Apply the compiler's `substitution_map` to a witness vector,
/// re-deriving each substituted wire's value from its LC. Returns
/// the post-substitution witness — call after `optimize_r1cs()` to
/// fill in eliminated wires before `cs.verify()`.
pub fn apply_substitutions(compiler: &R1CSCompiler, witness: &[FieldElement]) -> Vec<FieldElement> {
    let mut w = witness.to_vec();
    if let Some(subs) = &compiler.substitution_map {
        for (var, lc) in subs {
            w[*var] = lc.evaluate(&w).expect("substitution LC must evaluate");
        }
    }
    w
}
