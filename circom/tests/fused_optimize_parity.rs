//! Differential gate for the fused optimizer on the circom corpus.
//!
//! The lean prove flow optimizes the instantiate sink directly
//! (`ir::passes::fused::optimize_lean_sink`) instead of materializing
//! and running `ir::passes::optimize`. The reference pipeline is the
//! semantic spec: for every fixture, the fused output must equal it
//! byte-for-byte — instruction stream (per-instruction Debug
//! equality), `next_var`, and every `OptimizeStats` field. A fixture
//! whose stream the fast path refuses (duplicate definitions — e.g.
//! any `Decompose`-bearing stream) must STILL be equal, because the
//! fused entry falls back to the reference pipeline; the test then
//! pins that the fallback fired where expected.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use memory::{Bn254Fr, FieldElement};

type Fe = FieldElement<Bn254Fr>;

/// `Some(expected)` pins the fallback discriminator; `None` only
/// reports it (used while a fixture's lowering is in flux).
fn assert_fused_parity(name: &str, circom_file: &str, expect_fallback: Option<bool>) {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join(circom_file);
    let lib_dirs: Vec<PathBuf> = vec![manifest_dir.join("test/circomlib")];

    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("{name}: compilation failed: {e}"));
    let prove_ir = &compile_result.prove_ir;
    let fe_captures: HashMap<String, Fe> = compile_result
        .capture_values
        .iter()
        .map(|(k, v)| (k.clone(), Fe::from_u64(*v)))
        .collect();

    let mut reference = prove_ir
        .instantiate_lysis_lean_with_outputs(&fe_captures, &compile_result.output_names)
        .unwrap_or_else(|e| panic!("{name}: reference instantiation failed: {e}"));
    let ref_stats = ir::passes::optimize(&mut reference);

    let bundle = prove_ir
        .instantiate_lysis_lean_sink_with_outputs(&fe_captures, &compile_result.output_names)
        .unwrap_or_else(|e| panic!("{name}: sink instantiation failed: {e}"));
    let outcome = ir::passes::fused::optimize_lean_sink(bundle);

    assert_eq!(
        outcome.program.instructions.len(),
        reference.instructions.len(),
        "{name}: post-optimize instruction count diverged"
    );
    for (i, (fused, refr)) in outcome
        .program
        .instructions
        .iter()
        .zip(reference.instructions.iter())
        .enumerate()
    {
        assert_eq!(
            format!("{fused:?}"),
            format!("{refr:?}"),
            "{name}: instruction {i} diverged"
        );
    }
    assert_eq!(
        outcome.program.next_var, reference.next_var,
        "{name}: next_var diverged"
    );

    let s = &outcome.stats;
    assert_eq!(
        s.total_before, ref_stats.total_before,
        "{name}: total_before"
    );
    assert_eq!(s.total_after, ref_stats.total_after, "{name}: total_after");
    assert_eq!(
        s.const_fold_converted, ref_stats.const_fold_converted,
        "{name}: const_fold_converted"
    );
    assert_eq!(s.cse_eliminated, ref_stats.cse_eliminated, "{name}: cse");
    assert_eq!(s.dce_eliminated, ref_stats.dce_eliminated, "{name}: dce");
    assert_eq!(
        s.tautological_asserts_eliminated, ref_stats.tautological_asserts_eliminated,
        "{name}: taut"
    );
    assert_eq!(
        s.bound_inference.rewritten, ref_stats.bound_inference.rewritten,
        "{name}: bound rewrites"
    );
    assert_eq!(
        s.bound_inference.unbounded, ref_stats.bound_inference.unbounded,
        "{name}: unbounded comparisons (W003 surface)"
    );
    assert_eq!(
        s.bit_pattern_bounds, ref_stats.bit_pattern_bounds,
        "{name}: bit-pattern bounds"
    );
    assert_eq!(
        s.bit_pattern_booleans, ref_stats.bit_pattern_booleans,
        "{name}: bit-pattern booleans"
    );

    if let Some(expected) = expect_fallback {
        assert_eq!(
            outcome.used_fallback, expected,
            "{name}: fallback discriminator changed — re-measure the corpus fallback rate"
        );
    }
    eprintln!(
        "  {name}: fused == reference ({} instructions, fallback={}) ✓",
        reference.instructions.len(),
        outcome.used_fallback
    );
}

#[test]
fn fused_parity_iszero() {
    assert_fused_parity("IsZero", "test/circom/iszero.circom", Some(false));
}

#[test]
fn fused_parity_lessthan() {
    assert_fused_parity("LessThan(8)", "test/circom/lessthan_8.circom", Some(false));
}

#[test]
fn fused_parity_num2bits() {
    assert_fused_parity("Num2Bits(8)", "test/circom/num2bits_8.circom", Some(false));
}

#[test]
fn fused_parity_switcher() {
    assert_fused_parity(
        "Switcher",
        "test/circomlib/switcher_test.circom",
        Some(false),
    );
}

#[test]
fn fused_parity_compconstant() {
    assert_fused_parity(
        "CompConstant",
        "test/circomlib/compconstant_test.circom",
        Some(false),
    );
}

#[test]
fn fused_parity_mux3() {
    assert_fused_parity("Mux3", "test/circomlib/mux3_test.circom", Some(false));
}

#[test]
fn fused_parity_poseidon() {
    assert_fused_parity(
        "Poseidon(2)",
        "test/circomlib/poseidon_test.circom",
        Some(false),
    );
}

#[test]
fn fused_parity_babyjub() {
    assert_fused_parity("BabyJub", "test/circomlib/babyjub_test.circom", Some(false));
}

#[test]
fn fused_parity_mimcsponge() {
    assert_fused_parity(
        "MiMCSponge",
        "test/circomlib/mimcsponge_test.circom",
        Some(false),
    );
}

#[test]
fn fused_parity_pedersen() {
    assert_fused_parity(
        "Pedersen",
        "test/circomlib/pedersen_test.circom",
        Some(false),
    );
}

#[test]
fn fused_parity_pedersen_old() {
    assert_fused_parity(
        "Pedersen (old)",
        "test/circomlib/pedersen_old_test.circom",
        Some(false),
    );
}

#[test]
fn fused_parity_eddsaposeidon() {
    assert_fused_parity(
        "EdDSAPoseidon",
        "test/circomlib/eddsaposeidon_test.circom",
        Some(false),
    );
}

#[test]
fn fused_parity_escalarmulfix() {
    assert_fused_parity(
        "EscalarMulFix",
        "test/circomlib/escalarmulfix_test.circom",
        Some(false),
    );
}

#[test]
fn fused_parity_point2bits() {
    assert_fused_parity(
        "Point2Bits",
        "test/circomlib/point2bits_test.circom",
        Some(false),
    );
}

#[test]
fn fused_parity_sha256_2() {
    assert_fused_parity(
        "Sha256(2)",
        "test/circomlib/sha256_2_test.circom",
        Some(false),
    );
}
