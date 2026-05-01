//! Fuzz target: R1CS optimization preservation (Phase 0.4.C).
//!
//! Coverage-guided companion to the proptest at
//! `zkc/tests/r1cs_preservation_proptest.rs`. The proptest covers
//! `Strategy`-driven shrinking of the same property; this target adds
//! libfuzzer's coverage-guided exploration over the same oracle —
//! useful for finding inputs near field-overflow / underflow corners
//! that `proptest::Strategy` ranges don't naturally reach.
//!
//! Both share the helper module `zkc::test_support` (gated by
//! `feature = "test-support"`) so the property check stays in one
//! place: forward simulation + substitution-map consistency.
//! The generators differ (proptest uses `Strategy::any`,
//! the fuzz target derives `(a, b)` from raw bytes), but the oracle
//! is identical.
//!
//! ## The narrowed property (advisor §2b — see proptest docstring)
//!
//! Forward simulation: `R(w) = 0  ⟹  R'(π(w)) = 0`. Concretely, the
//! pre-O1 satisfying witness `w_pre` after `apply_substitutions` must
//! also satisfy the post-O1 system. Plus map-consistency: every
//! `(var, lc)` in `compiler.substitution_map` must satisfy
//! `lc.evaluate(w_pre) == w_pre[var]`.
//!
//! ## Discriminator coverage gap (intentional, inherited from proptest)
//!
//! Same blind spot as the proptest: catches "wrong LC" optimizer
//! regressions but not "drop a constraint without recording in
//! substitution_map". Closing that requires a different oracle
//! (constraint-count accounting or adversarial witness sampling) —
//! tracked in the proptest's docstring §"Discriminator coverage gap".
//! This target ships at parity with the proptest, not as an extension.
//!
//! ## Discriminator (verified during development)
//!
//! Patching `optimize_r1cs` in `zkc/src/r1cs_backend.rs` to corrupt
//! the first substitution entry's LC (replace with constant zero)
//! makes this fuzz target catch the consistency violation on any
//! fixture whose optimizer pass produces a substitution_map. Verified
//! by running `cargo +nightly fuzz run fuzz_r1cs_preservation
//! -- -max_total_time=15` on the patched code; expectation is a
//! `panicked at` line within seconds. Reverted before commit.

#![no_main]

use libfuzzer_sys::fuzz_target;
use memory::FieldElement;
use zkc::test_support::{apply_substitutions, compile_and_solve};

fuzz_target!(|data: &[u8]| {
    // Need at least 16 bytes to derive (a, b). Below that, the input
    // is too small to be interesting — bail without running the oracle.
    if data.len() < 16 {
        return;
    }

    // Mirror the proptest's input shape: a in [0, 1_000_000), b in [1, 10_000].
    // Bytes → u64 → modular reduction. Keeps the fuzz seed surface
    // identical to the proptest's `Strategy` even though the generator
    // differs.
    let a_raw = u64::from_le_bytes(data[0..8].try_into().unwrap());
    let b_raw = u64::from_le_bytes(data[8..16].try_into().unwrap());
    let a = a_raw % 1_000_000;
    let b_mod = b_raw % 10_000;
    let b = if b_mod == 0 { 1 } else { b_mod };

    let a_fe = FieldElement::from_u64(a);
    let b_fe = FieldElement::from_u64(b);
    let out_fe = a_fe.mul(&b_fe).add(&a_fe);

    let (mut compiler, w_pre) = compile_and_solve(
        "assert_eq(a * b + a, out)",
        &[("out", out_fe)],
        &[("a", a_fe), ("b", b_fe)],
    );

    compiler.optimize_r1cs();

    // Map-consistency: substitution LCs must evaluate to the recorded
    // wire values on the pre-O1 witness.
    if let Some(subs) = &compiler.substitution_map {
        for (var, lc) in subs {
            let computed = lc
                .evaluate(&w_pre)
                .expect("substitution LC must evaluate");
            assert_eq!(
                w_pre[*var], computed,
                "substitution_map[{var}] inconsistent: lc={computed:?}, witness={:?}",
                w_pre[*var],
            );
        }
    }

    // Forward simulation: w_pre ∘ subs must satisfy post-O1.
    let w_post = apply_substitutions(&compiler, &w_pre);
    compiler
        .cs
        .verify(&w_post)
        .expect("post-O1 R1CS rejected witness that satisfied pre-O1");
});
