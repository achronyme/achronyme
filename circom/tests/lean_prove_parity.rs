//! Lean-instantiate parity for the prove pipeline.
//!
//! Prove-bound CLI flows instantiate through the lean Lysis entry
//! points (`instantiate_lysis_lean*`), which skip the program's
//! metadata maps. This test pins the lean path against the full path
//! on the exact pipeline those flows run: instantiate →
//! `ir::passes::optimize` → bool_prop → R1CS emission → witness fill →
//! O1 → substitution fixup → verify. Everything observable must be
//! identical: constraint structure pre- and post-O1, wire counts, and
//! the witness vector.
//!
//! The full path's metadata maps are keyed by pre-interner variable
//! ids (the interner renumbers), so analyses that read them — notably
//! bool_prop's `var_types` Bool seeds — already see mostly-missing
//! keys. This corpus exists to catch any fixture where the residual
//! entries still steer an analysis: a mismatch here means the lean
//! prove path must keep `var_types` instead of dropping it.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use memory::{Bn254Fr, FieldElement};
use zkc::r1cs_backend::R1CSCompiler;

type Fe = FieldElement<Bn254Fr>;

/// Order-sensitive structural signature of one linear combination:
/// (wire index, canonical coefficient limbs) per term, prefixed with
/// the term count so empty LCs stay distinguishable.
type LcSig = Vec<(usize, [u64; 4])>;

struct PipelineOut {
    pre_o1: Vec<[LcSig; 3]>,
    post_o1: Vec<[LcSig; 3]>,
    num_variables: usize,
    witness: Vec<[u64; 4]>,
}

fn constraint_sigs(compiler: &R1CSCompiler<Bn254Fr>) -> Vec<[LcSig; 3]> {
    compiler
        .cs
        .constraints()
        .iter()
        .map(|c| {
            [&c.a, &c.b, &c.c].map(|lc| {
                lc.terms()
                    .iter()
                    .map(|(var, coeff)| (var.index(), coeff.to_canonical()))
                    .collect()
            })
        })
        .collect()
}

fn run_prove_pipeline(
    name: &str,
    path: &Path,
    lib_dirs: &[PathBuf],
    inputs: &HashMap<String, Fe>,
    lean: bool,
) -> PipelineOut {
    let compile_result = circom::compile_file(path, lib_dirs)
        .unwrap_or_else(|e| panic!("{name}: compilation failed: {e}"));
    let prove_ir = &compile_result.prove_ir;

    let fe_captures: HashMap<String, Fe> = compile_result
        .capture_values
        .iter()
        .map(|(k, v)| (k.clone(), Fe::from_u64(*v)))
        .collect();

    let mut program = if lean {
        prove_ir.instantiate_lysis_lean_with_outputs(&fe_captures, &compile_result.output_names)
    } else {
        prove_ir.instantiate_lysis_with_outputs(&fe_captures, &compile_result.output_names)
    }
    .unwrap_or_else(|e| panic!("{name}: instantiation (lean={lean}) failed: {e}"));

    ir::passes::optimize(&mut program);
    let proven = ir::passes::bool_prop::compute_proven_boolean(&program);

    let mut all_signals = circom::witness::compute_witness_hints_with_captures(
        prove_ir,
        inputs,
        &compile_result.capture_values,
    )
    .unwrap_or_else(|e| panic!("{name}: witness hint computation failed: {e}"));
    for (cname, fe) in &fe_captures {
        all_signals.entry(cname.clone()).or_insert(*fe);
    }

    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler.set_proven_boolean(proven);
    compiler.set_skip_eval_validation(true);
    compiler
        .compile_ir(&program)
        .unwrap_or_else(|e| panic!("{name}: R1CS compilation (lean={lean}) failed: {e}"));
    compiler.release_emission_state();
    drop(program);

    let mut witness = compiler
        .fill_witness(&all_signals)
        .unwrap_or_else(|e| panic!("{name}: witness fill (lean={lean}) failed: {e}"));

    let pre_o1 = constraint_sigs(&compiler);

    compiler.optimize_r1cs();
    if let Some(subs) = &compiler.substitution_map {
        for (var_idx, lc) in subs {
            witness[*var_idx] = lc
                .evaluate(&witness)
                .unwrap_or_else(|e| panic!("{name}: witness fixup (lean={lean}) failed: {e}"));
        }
    }
    compiler
        .cs
        .verify(&witness)
        .unwrap_or_else(|e| panic!("{name}: verify (lean={lean}) failed: {e}"));

    PipelineOut {
        pre_o1,
        post_o1: constraint_sigs(&compiler),
        num_variables: compiler.cs.num_variables(),
        witness: witness.iter().map(|v| v.to_canonical()).collect(),
    }
}

fn assert_parity(name: &str, circom_file: &str, inputs: &HashMap<String, Fe>) {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join(circom_file);
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let full = run_prove_pipeline(name, &path, &lib_dirs, inputs, false);
    let lean = run_prove_pipeline(name, &path, &lib_dirs, inputs, true);

    assert_eq!(
        lean.num_variables, full.num_variables,
        "{name}: wire count diverged between lean and full instantiate"
    );
    for (stage, full_cs, lean_cs) in [
        ("pre-O1", &full.pre_o1, &lean.pre_o1),
        ("post-O1", &full.post_o1, &lean.post_o1),
    ] {
        assert_eq!(
            lean_cs.len(),
            full_cs.len(),
            "{name}: {stage} constraint count diverged"
        );
        for (idx, (f, l)) in full_cs.iter().zip(lean_cs.iter()).enumerate() {
            assert_eq!(
                l, f,
                "{name}: {stage} constraint {idx} diverged between lean and full"
            );
        }
    }
    assert_eq!(
        lean.witness, full.witness,
        "{name}: witness vector diverged between lean and full"
    );
    eprintln!(
        "  {name}: lean == full ({} pre-O1 / {} post-O1 / {} wires) ✓",
        full.pre_o1.len(),
        full.post_o1.len(),
        full.num_variables
    );
}

fn u64_inputs(pairs: &[(&str, u64)]) -> HashMap<String, Fe> {
    pairs
        .iter()
        .map(|&(name, val)| (name.to_string(), Fe::from_u64(val)))
        .collect()
}

#[test]
fn lean_prove_parity_switcher() {
    assert_parity(
        "Switcher",
        "test/circomlib/switcher_test.circom",
        &u64_inputs(&[("sel", 0), ("L", 10), ("R", 20)]),
    );
}

#[test]
fn lean_prove_parity_compconstant() {
    assert_parity(
        "CompConstant",
        "test/circomlib/compconstant_test.circom",
        &u64_inputs(&[("in", 42)]),
    );
}

#[test]
fn lean_prove_parity_mux3() {
    assert_parity(
        "Mux3",
        "test/circomlib/mux3_test.circom",
        &u64_inputs(&[
            ("c_0", 10),
            ("c_1", 20),
            ("c_2", 30),
            ("c_3", 40),
            ("c_4", 50),
            ("c_5", 60),
            ("c_6", 70),
            ("c_7", 80),
            ("s_0", 1),
            ("s_1", 0),
            ("s_2", 1),
        ]),
    );
}

#[test]
fn lean_prove_parity_poseidon() {
    assert_parity(
        "Poseidon(2)",
        "test/circomlib/poseidon_test.circom",
        &u64_inputs(&[("inputs_0", 1), ("inputs_1", 2), ("initialState", 0)]),
    );
}
