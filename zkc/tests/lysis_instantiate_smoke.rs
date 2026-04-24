//! Phase 3.C.6 Stage 2 commit 2.6 smoke gate.
//!
//! Cross-validates [`ProveIR::instantiate_lysis`] against the legacy
//! [`ProveIR::instantiate`] using
//! [`zkc::lysis_oracle::semantic_equivalence`].
//!
//! This is the bigger sibling of `lysis_roundtrip_smoke.rs`:
//!
//! - `lysis_roundtrip_smoke` validates the wrap-then-lift cable
//!   (instantiate → wrap as Plain → Walker → materialize). Loops are
//!   inlined N times in the Plain stream, so SHA-256(64) sees no
//!   structural reduction.
//! - This file validates the **real Lysis path** (instantiate_extended
//!   → Walker → InterningSink → materialize). Loops are emitted as
//!   single `LoopUnroll` nodes (Phase 3.C.6 commit 2.5), so the
//!   interner can hash-cons across iterations and the SHA-256(64)
//!   amplification disappears.
//!
//! The oracle uses `optimize` on both sides so CSE-equivalent
//! divergences (legacy emits duplicates that Lysis dedupes natively)
//! collapse before the multiset compare.

use std::collections::HashMap;

use ir_forge::test_utils::compile_circuit;
use memory::Bn254Fr;

use zkc::lysis_oracle::{semantic_equivalence, OracleResult};

type F = Bn254Fr;

/// Compile + instantiate (legacy) + instantiate_lysis on the same
/// source, optimize both, oracle-compare, expect Equivalent.
fn assert_lysis_equivalent(label: &str, source: &str) {
    let prove_ir = compile_circuit(source).expect("compile_circuit");

    let mut legacy = prove_ir
        .instantiate::<F>(&HashMap::new())
        .expect("instantiate");
    let mut lysis = prove_ir
        .instantiate_lysis::<F>(&HashMap::new())
        .unwrap_or_else(|e| panic!("instantiate_lysis failed for `{label}`: {e}"));

    ir::passes::optimize(&mut legacy);
    ir::passes::optimize(&mut lysis);

    let outcome = semantic_equivalence(&legacy, &lysis, &[]);
    assert_eq!(
        outcome,
        OracleResult::Equivalent,
        "fixture `{label}` legacy/lysis disagreement: {outcome:?}"
    );
}

#[test]
fn no_loop_arithmetic_chain_matches_legacy() {
    assert_lysis_equivalent(
        "no_loop_arithmetic_chain",
        "public z\nwitness x\nlet s = x + x;\nlet p = s * x;\nassert(p == z)",
    );
}

#[test]
fn unrolled_loop_via_loop_unroll_matches_legacy() {
    // The first fixture that actually exercises LoopUnroll emission
    // (commit 2.5). The Lysis path emits ONE LoopUnroll node containing
    // `acc = acc + a` referencing iter_var symbolically; the executor
    // unrolls 4 iterations at run time and the InterningSink hash-cons
    // collapses identical sub-trees. Legacy emits 4 inlined copies,
    // then `optimize` CSE collapses the equivalent ones — both sides
    // converge on the same multiset.
    assert_lysis_equivalent(
        "unrolled_loop",
        "public sum\nwitness a\nmut acc = 0\nfor i in 0..4 {\n  acc = acc + a\n}\nassert(acc == sum)",
    );
}

#[test]
fn boolean_combinators_match_legacy_after_lowering() {
    // Validates that the Stage-2.0 Option-A lowering (Not/And/Or →
    // primitives) survives the Lysis round-trip end-to-end.
    assert_lysis_equivalent(
        "boolean_combinators",
        "public out\nwitness a\nwitness b\nlet na = !a;\nlet both = a && b;\nlet either = a || b;\nlet combined = na + both + either;\nassert(combined == out)",
    );
}

#[test]
fn comparison_chain_matches_legacy() {
    assert_lysis_equivalent(
        "comparison_chain",
        "public out\nwitness a\nwitness b\nlet ne = a != b;\nlet le = a <= b;\nlet ge = a >= b;\nlet combined = ne + le + ge;\nassert(combined == out)",
    );
}

#[test]
fn nested_loop_matches_legacy() {
    // Both nested for loops emit nested LoopUnroll nodes (commit 2.5
    // supports this via loop_stack). The Lysis pipeline materializes
    // them with proper iteration binding.
    assert_lysis_equivalent(
        "nested_loop",
        "public out\nwitness a\nmut acc = 0\nfor i in 0..3 {\n  for j in 0..2 {\n    acc = acc + a\n  }\n}\nassert(acc == out)",
    );
}
