pub use std::collections::HashMap;

pub use ir::IrLowering;
pub use memory::{Bn254Fr, FieldElement};
pub use zkc::r1cs_backend::R1CSCompiler;
pub use zkc::witness::WitnessGenerator;

/// Full pipeline: source → IR → R1CS → witness → verify.
pub(crate) fn ir_pipeline_verify(public: &[(&str, u64)], witness: &[(&str, u64)], source: &str) {
    ir_pipeline_verify_fe(
        &public
            .iter()
            .map(|(n, v)| (*n, FieldElement::from_u64(*v)))
            .collect::<Vec<_>>(),
        &witness
            .iter()
            .map(|(n, v)| (*n, FieldElement::from_u64(*v)))
            .collect::<Vec<_>>(),
        source,
    );
}

pub(crate) fn ir_pipeline_verify_fe(
    public: &[(&str, FieldElement)],
    witness: &[(&str, FieldElement)],
    source: &str,
) {
    let pub_names: Vec<&str> = public.iter().map(|(n, _)| *n).collect();
    let wit_names: Vec<&str> = witness.iter().map(|(n, _)| *n).collect();
    let program = IrLowering::<Bn254Fr>::lower_circuit(source, &pub_names, &wit_names).unwrap();

    let mut ir_compiler = R1CSCompiler::<Bn254Fr>::new();
    ir_compiler.compile_ir(&program).unwrap();

    // Witness generation + verification
    let gen = WitnessGenerator::from_compiler(&ir_compiler);
    let mut inputs = HashMap::new();
    for (name, val) in public {
        inputs.insert(name.to_string(), *val);
    }
    for (name, val) in witness {
        inputs.insert(name.to_string(), *val);
    }

    let w = gen.generate(&inputs).unwrap();
    ir_compiler
        .cs
        .verify(&w)
        .expect("IR pipeline witness failed verification");
}

/// IR-only pipeline (for features only supported via IR path).
/// Used for features only supported via IR path (comparisons, etc.).
pub(crate) fn ir_only_verify_fe(
    public: &[(&str, FieldElement)],
    witness: &[(&str, FieldElement)],
    source: &str,
) {
    let pub_names: Vec<&str> = public.iter().map(|(n, _)| *n).collect();
    let wit_names: Vec<&str> = witness.iter().map(|(n, _)| *n).collect();
    let program = IrLowering::<Bn254Fr>::lower_circuit(source, &pub_names, &wit_names).unwrap();

    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    for (name, val) in public {
        inputs.insert(name.to_string(), *val);
    }
    for (name, val) in witness {
        inputs.insert(name.to_string(), *val);
    }

    let w = gen.generate(&inputs).unwrap();
    compiler
        .cs
        .verify(&w)
        .expect("IR-only pipeline witness failed verification");
}

/// Same but with optimization enabled.
pub(crate) fn ir_pipeline_optimized_verify(
    public: &[(&str, u64)],
    witness: &[(&str, u64)],
    source: &str,
) {
    let pub_names: Vec<&str> = public.iter().map(|(n, _)| *n).collect();
    let wit_names: Vec<&str> = witness.iter().map(|(n, _)| *n).collect();
    let mut program = IrLowering::<Bn254Fr>::lower_circuit(source, &pub_names, &wit_names).unwrap();

    ir::passes::optimize(&mut program);

    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut inputs = HashMap::new();
    for (name, val) in public {
        inputs.insert(name.to_string(), FieldElement::from_u64(*val));
    }
    for (name, val) in witness {
        inputs.insert(name.to_string(), FieldElement::from_u64(*val));
    }

    let w = gen.generate(&inputs).unwrap();
    compiler
        .cs
        .verify(&w)
        .expect("optimized IR pipeline witness failed verification");
}

/// Self-contained pipeline helper.
pub(crate) fn ir_self_contained_verify(inputs: &[(&str, FieldElement)], source: &str) {
    let (_, _, program) = IrLowering::lower_self_contained(source).unwrap();
    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler.compile_ir(&program).unwrap();

    let gen = WitnessGenerator::from_compiler(&compiler);
    let mut input_map = HashMap::new();
    for (name, val) in inputs {
        input_map.insert(name.to_string(), *val);
    }

    let w = gen.generate(&input_map).unwrap();
    compiler
        .cs
        .verify(&w)
        .expect("self-contained pipeline witness failed verification");
}

/// Compute 2^n as a FieldElement.
pub(crate) fn pow2(n: u32) -> FieldElement {
    let mut v = FieldElement::ONE;
    for _ in 0..n {
        v = v.add(&v);
    }
    v
}

#[path = "r1cs_ir_test/arrays.rs"]
mod arrays;
#[path = "r1cs_ir_test/basics.rs"]
mod basics;
#[path = "r1cs_ir_test/booleans_comparisons.rs"]
mod booleans_comparisons;
#[path = "r1cs_ir_test/boundaries_bounded.rs"]
mod boundaries_bounded;
#[path = "r1cs_ir_test/control_builtins.rs"]
mod control_builtins;
#[path = "r1cs_ir_test/functions_crypto.rs"]
mod functions_crypto;
#[path = "r1cs_ir_test/integration.rs"]
mod integration;
#[path = "r1cs_ir_test/limb_boundaries.rs"]
mod limb_boundaries;
#[path = "r1cs_ir_test/soundness.rs"]
mod soundness;
