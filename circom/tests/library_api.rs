//! Integration tests for the Circom library-mode API.
//!
//! Exercises `compile_template_library`, `instantiate_template_into`,
//! and `evaluate_template_witness` against real circomlib fixtures.
//!
//! These are Phase 1.6 of the circom import feature: end-to-end
//! smoke tests that the public API works against the same Poseidon
//! source the rest of the crate already uses for the R1CS/Groth16
//! compatibility test.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use circom::{
    compile_template_library, evaluate_template_witness, instantiate_template_into, DimensionExpr,
    InstantiationError, LibraryError, TemplateOutput, WitnessEvalError,
};
use diagnostics::Span;
use ir::prove_ir::types::{CircuitExpr, CircuitNode, FieldConst};
use memory::{Bn254Fr, FieldElement};

fn circomlib_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("crate has a parent directory")
        .join("test/circomlib/circuits")
}

fn poseidon_path() -> PathBuf {
    circomlib_dir().join("poseidon.circom")
}

fn dummy_span() -> Span {
    Span {
        byte_start: 0,
        byte_end: 0,
        line_start: 1,
        col_start: 1,
        line_end: 1,
        col_end: 1,
    }
}

/// Load circomlib's Poseidon as a library and verify the templates and
/// functions it declares are all exposed through the public surface.
#[test]
fn load_poseidon_library() {
    let path = poseidon_path();
    if !path.exists() {
        eprintln!("skipping: {path:?} not present");
        return;
    }
    let lib_dirs = vec![circomlib_dir()];
    let lib = compile_template_library(&path, &lib_dirs).expect("library should load");

    // Every template from the source file must be reachable.
    for name in [
        "Sigma",
        "Ark",
        "Mix",
        "MixLast",
        "MixS",
        "PoseidonEx",
        "Poseidon",
    ] {
        assert!(
            lib.template(name).is_some(),
            "missing template {name} in loaded library"
        );
    }

    // Poseidon(nInputs) has a parametric input array and a scalar output.
    let poseidon = lib.template("Poseidon").expect("Poseidon entry");
    assert_eq!(poseidon.params, vec!["nInputs".to_string()]);
    let inputs_sig = poseidon
        .inputs
        .iter()
        .find(|s| s.name == "inputs")
        .expect("Poseidon has `inputs` signal");
    match &inputs_sig.dimensions[0] {
        DimensionExpr::Param(p) => assert_eq!(p, "nInputs"),
        other => panic!("expected nInputs param dim, got {other:?}"),
    }
    let out_sig = poseidon
        .outputs
        .iter()
        .find(|s| s.name == "out")
        .expect("Poseidon has `out` signal");
    assert!(out_sig.is_scalar());
}

/// Evaluate Poseidon(2) off-circuit against concrete inputs. We can't
/// hardcode the reference hash here without importing a Poseidon impl,
/// so we assert (a) the call succeeds, (b) the output is non-zero, and
/// (c) it depends on the inputs (changing an input changes the output).
#[test]
fn evaluate_poseidon_two_inputs_vm_mode() {
    let path = poseidon_path();
    if !path.exists() {
        eprintln!("skipping: {path:?} not present");
        return;
    }
    let lib_dirs = vec![circomlib_dir()];
    let lib = compile_template_library(&path, &lib_dirs).expect("library should load");

    let mut inputs_a: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    inputs_a.insert("inputs_0".to_string(), FieldElement::<Bn254Fr>::from_u64(1));
    inputs_a.insert("inputs_1".to_string(), FieldElement::<Bn254Fr>::from_u64(2));

    let out_a = evaluate_template_witness::<Bn254Fr>(&lib, "Poseidon", &[2], &inputs_a)
        .expect("Poseidon(2) should evaluate off-circuit");
    let hash_a = out_a
        .get("out")
        .and_then(|v| v.as_scalar())
        .expect("out signal present as scalar");
    assert_ne!(
        hash_a,
        FieldElement::<Bn254Fr>::zero(),
        "Poseidon(1, 2) should not hash to zero"
    );

    let mut inputs_b = inputs_a.clone();
    inputs_b.insert("inputs_1".to_string(), FieldElement::<Bn254Fr>::from_u64(3));
    let out_b = evaluate_template_witness::<Bn254Fr>(&lib, "Poseidon", &[2], &inputs_b)
        .expect("Poseidon(2) should evaluate off-circuit");
    let hash_b = out_b
        .get("out")
        .and_then(|v| v.as_scalar())
        .expect("out signal present as scalar");
    assert_ne!(
        hash_a, hash_b,
        "changing an input should change the Poseidon hash"
    );
}

/// Instantiate Poseidon(2) as a template inlining. We don't drive it
/// through a full R1CS compile here — that path is covered by the
/// existing `poseidon_real_circomlib` E2E test. This just checks the
/// public API produces a non-trivial body and a scalar `out` in the
/// outputs map.
#[test]
fn instantiate_poseidon_inline_body() {
    let path = poseidon_path();
    if !path.exists() {
        eprintln!("skipping: {path:?} not present");
        return;
    }
    let lib_dirs = vec![circomlib_dir()];
    let lib = compile_template_library(&path, &lib_dirs).expect("library should load");

    let mut signal_inputs: HashMap<String, CircuitExpr> = HashMap::new();
    // Poseidon(2) expects `inputs[2]` (array input). Array signal
    // inputs aren't yet supported by instantiate_template_into, so
    // the library reports a dedicated UnsupportedArrayInput variant
    // regardless of whether the caller supplied a wiring — useful so
    // Phase 3 can special-case this cleanly later.
    let result = instantiate_template_into(
        &lib,
        "Poseidon",
        &[FieldConst::from_u64(2)],
        &signal_inputs,
        "pi_0",
        &dummy_span(),
    );
    match result {
        Err(InstantiationError::UnsupportedArrayInput { template, signal }) => {
            assert_eq!(template, "Poseidon");
            assert_eq!(signal, "inputs");
        }
        other => panic!("expected UnsupportedArrayInput, got {other:?}"),
    }

    // Instantiate a scalar-only template from the same file (Sigma)
    // to prove the happy path works against real circomlib.
    signal_inputs.clear();
    signal_inputs.insert("in".to_string(), CircuitExpr::Var("ach_x".to_string()));
    let inst = instantiate_template_into(&lib, "Sigma", &[], &signal_inputs, "s0", &dummy_span())
        .expect("Sigma() should instantiate");

    // First node wires the input, body follows, scalar output exposed.
    assert!(
        !inst.body.is_empty(),
        "Sigma body should contain at least the input wiring"
    );
    match &inst.body[0] {
        CircuitNode::Let { name, .. } => assert_eq!(name, "s0_in"),
        other => panic!("expected first node to be Let s0_in, got {other:?}"),
    }
    let out = inst.outputs.get("out").expect("Sigma has out output");
    match out {
        TemplateOutput::Scalar(CircuitExpr::Var(v)) => assert_eq!(v, "s0_out"),
        other => panic!("expected Scalar Var, got {other:?}"),
    }
}

/// Unknown template name should surface a clear error from the witness
/// evaluator (matches the Phase 1.5 error surface used by the VM).
#[test]
fn evaluate_poseidon_unknown_name() {
    let path = poseidon_path();
    if !path.exists() {
        eprintln!("skipping: {path:?} not present");
        return;
    }
    let lib_dirs = vec![circomlib_dir()];
    let lib = compile_template_library(&path, &lib_dirs).expect("library should load");
    let result =
        evaluate_template_witness::<Bn254Fr>(&lib, "DefinitelyNotAPoseidon", &[2], &HashMap::new());
    match result {
        Err(WitnessEvalError::Library(LibraryError::UnknownTemplate { available, .. })) => {
            assert!(available.iter().any(|t| t == "Poseidon"));
        }
        other => panic!("expected UnknownTemplate, got {other:?}"),
    }
}
