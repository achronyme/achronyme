//! Property-based test: `optimize_r1cs` preserves satisfying-assignment
//! semantics.
//!
//! ## The property
//!
//! "Pre-O1 multiset = post-O1 multiset modulo elimination" is too
//! strong — multiset equality fails by definition (the optimizer
//! eliminates constraints).
//!
//! The genuine property is the CompCert-style two-sided simulation
//! (Leroy, CACM 2009):
//!
//!   ∀ w. R(w) = 0  ⟹  R'(π(w)) = 0     (forward)
//!   ∀ w'. R'(w') = 0  ⟹  R(ext(w')) = 0  (backward)
//!
//! where `R` is pre-O1, `R'` post-O1, `π` is the projection that drops
//! eliminated wires, and `ext` is the extension that fills them back
//! in via the `substitution_map`.
//!
//! In Achronyme `optimize_r1cs` mutates `compiler.cs` in-place — the
//! wire-index space is preserved across the optimization, but
//! `substitution_map` records the eliminated wires' values as linear
//! combinations over surviving wires. Implication: if the
//! substitution map is *consistent* (every entry's LC evaluates to
//! the witness's stored value at that wire) and the same witness
//! satisfies both `R` and `R'`, the simulation invariant holds.
//!
//! This test pins **the forward direction** + **map consistency** at
//! proptest scale. The backward direction (no spurious witnesses
//! admitted by `R'`) is checked at hand-built scale via the `wrong
//! witness rejected` companion test.
//!
//! Reference impl pattern: gnark's `test/assert_fuzz.go` fills a
//! witness with random / binary / corner / zero values and asserts
//! cross-engine agreement. Noir's `tooling/ssa_fuzzer/` runs three
//! builders (ACIR / Brillig / morphed) and asserts execution
//! equivalence. Both are semantic (witness-level), not structural
//! (multiset-level).
//!
//! ## Discriminator (verified during development)
//!
//! Patching `optimize_r1cs` in `zkc/src/r1cs_backend.rs` to corrupt
//! the first substitution entry's LC (replace with constant zero)
//! makes `optimize_substitution_map_is_consistent` fail at the very
//! first proptest case — the consistency check catches the wrong-LC
//! regression class.
//!
//! ## Discriminator coverage gap (intentional)
//!
//! The "wrong LC" discriminator is *one* class of optimizer regression.
//! A second class that this test does NOT cover:
//! "drop a constraint without recording in `substitution_map`". For
//! that class the substitution_map is *missing* an entry rather than
//! holding a wrong one, so the consistency check has nothing to
//! verify and trivially passes. The forward-simulation tests also
//! pass vacuously because the dropped constraint was satisfiable to
//! begin with — same witness still satisfies the smaller post-O1
//! system. Catching this class requires either:
//!  - Constraint-count accounting: assert subs.len() bounds the
//!    constraint count delta within a known ratio for the input
//!    shape; rejected here because optimizer fold-ratios are highly
//!    input-dependent and a tight bound would false-positive.
//!  - Adversarial witness sampling: generate a w' satisfying R',
//!    extend via subs, verify R(w_ext) — but if subs is missing an
//!    entry, ext is incomplete and the resulting w_ext still
//!    happens to satisfy R for most random w'.
//!
//! Both are deferred to a future tightening pass. The "wrong LC" class
//! is the most common kind of optimizer bug (Markowitz pivot picking
//! the wrong elimination, off-by-one in linear extraction) and is what
//! this test catches today.

use constraints::poseidon::native::poseidon_hash;
use constraints::PoseidonParamsProvider;
use memory::{Bn254Fr, FieldElement};
use proptest::prelude::*;
use zkc::test_support::{apply_substitutions, compile_and_solve, compile_and_solve_incremental};

// ============================================================================
// Forward simulation: same witness verifies before and after optimize
// ============================================================================

proptest! {
    #![proptest_config(ProptestConfig::with_cases(150))]

    /// `R(w) = 0  ⟹  R'(w_post) = 0` where `w_post` is `w` after
    /// the substitution_map has filled in eliminated wires.
    /// (Forward simulation.)
    #[test]
    fn optimize_preserves_satisfaction_arith(
        a in 0u64..1_000_000,
        b in 1u64..10_000,
    ) {
        let a_fe = FieldElement::from_u64(a);
        let b_fe = FieldElement::from_u64(b);
        let out_fe = a_fe.mul(&b_fe).add(&a_fe);
        let (mut compiler, w_pre) = compile_and_solve(
            "assert_eq(a * b + a, out)",
            &[("out", out_fe)],
            &[("a", a_fe), ("b", b_fe)],
        );

        compiler.optimize_r1cs();
        let w_post = apply_substitutions(&compiler, &w_pre);
        prop_assert!(
            compiler.cs.verify(&w_post).is_ok(),
            "post-O1 R1CS rejected witness that satisfied pre-O1",
        );
    }

    /// Same property with division (exercises witness/inverse hint).
    #[test]
    fn optimize_preserves_satisfaction_div(
        a in 0u64..1_000_000,
        b in 1u64..10_000,
    ) {
        let a_fe = FieldElement::from_u64(a);
        let b_fe = FieldElement::from_u64(b);
        let prod = a_fe.mul(&b_fe);
        // (a*b) / b == a
        let (mut compiler, w_pre) = compile_and_solve(
            "assert_eq(ab / b, out)",
            &[("out", a_fe)],
            &[("ab", prod), ("b", b_fe)],
        );

        compiler.optimize_r1cs();
        let w_post = apply_substitutions(&compiler, &w_pre);
        prop_assert!(
            compiler.cs.verify(&w_post).is_ok(),
            "post-O1 R1CS rejected witness that satisfied pre-O1 (div)",
        );
    }

    /// `substitution_map` consistency: every (var, lc) pair must
    /// satisfy `lc.evaluate(w) == w[var]` on the pre-O1 satisfying
    /// witness. A buggy optimizer that records a wrong LC trips this.
    #[test]
    fn optimize_substitution_map_is_consistent(
        a in 0u64..1_000_000,
        b in 1u64..10_000,
    ) {
        let a_fe = FieldElement::from_u64(a);
        let b_fe = FieldElement::from_u64(b);
        let out_fe = a_fe.mul(&b_fe).add(&a_fe);
        let (mut compiler, w_pre) = compile_and_solve(
            "assert_eq(a * b + a, out)",
            &[("out", out_fe)],
            &[("a", a_fe), ("b", b_fe)],
        );

        compiler.optimize_r1cs();
        if let Some(subs) = &compiler.substitution_map {
            for (var, lc) in subs {
                let computed = lc
                    .evaluate(&w_pre)
                    .expect("substitution LC must evaluate");
                prop_assert_eq!(
                    w_pre[*var],
                    computed,
                    "substitution_map[{}] = lc evaluating to {:?} but witness has {:?}",
                    var,
                    computed,
                    w_pre[*var],
                );
            }
        }
    }
}

// ============================================================================
// Incremental collapse: the same simulation through collapse + finalize
// ============================================================================
//
// The incremental compiler folds linear elimination into emission, then
// `optimize_r1cs` finalizes over the survivors and composes the two
// substitution maps. These pin that the composed-map reconstruction
// preserves satisfaction (forward) and stays consistent — i.e. landing
// the collapse path does not weaken the property the batch path holds.
//
// Flow A is mandatory here: `compile_and_solve_incremental` builds the
// full witness on the collapse-survivor system *before* `optimize_r1cs`,
// so every wire (including direct-`Variable` op inputs) is computed by an
// intact op; the post-finalize `apply_substitutions` is then a consistent
// re-derive over the composed map. A regenerate-after-optimize flow would
// replay pruned ops and spuriously fail on materialized op inputs.

proptest! {
    #![proptest_config(ProptestConfig::with_cases(150))]

    /// Forward simulation through collapse + finalize for an arithmetic
    /// circuit.
    #[test]
    fn incremental_preserves_satisfaction_arith(
        a in 0u64..1_000_000,
        b in 1u64..10_000,
    ) {
        let a_fe = FieldElement::from_u64(a);
        let b_fe = FieldElement::from_u64(b);
        let out_fe = a_fe.mul(&b_fe).add(&a_fe);
        let (mut compiler, w_pre) = compile_and_solve_incremental(
            "assert_eq(a * b + a, out)",
            &[("out", out_fe)],
            &[("a", a_fe), ("b", b_fe)],
        );

        compiler.optimize_r1cs();
        let w_post = apply_substitutions(&compiler, &w_pre);
        prop_assert!(
            compiler.cs.verify(&w_post).is_ok(),
            "collapse + finalize rejected witness that satisfied the survivors",
        );
    }

    /// Forward simulation through collapse + finalize with division
    /// (exercises a witness hint op).
    #[test]
    fn incremental_preserves_satisfaction_div(
        a in 0u64..1_000_000,
        b in 1u64..10_000,
    ) {
        let a_fe = FieldElement::from_u64(a);
        let b_fe = FieldElement::from_u64(b);
        let prod = a_fe.mul(&b_fe);
        let (mut compiler, w_pre) = compile_and_solve_incremental(
            "assert_eq(ab / b, out)",
            &[("out", a_fe)],
            &[("ab", prod), ("b", b_fe)],
        );

        compiler.optimize_r1cs();
        let w_post = apply_substitutions(&compiler, &w_pre);
        prop_assert!(
            compiler.cs.verify(&w_post).is_ok(),
            "collapse + finalize rejected witness that satisfied the survivors (div)",
        );
    }

    /// Forward simulation through collapse + an **O2** finalize.
    /// `optimize_r1cs_o2` routes through the same composed-map install as
    /// O1, so this pins that DEDUCE-on-survivors composes soundly with the
    /// collapse map (DEDUCE cannot re-eliminate a collapse wire — same
    /// disjoint-domain invariant the composition asserts).
    #[test]
    fn incremental_preserves_satisfaction_o2_finalize(
        a in 0u64..1_000_000,
        b in 1u64..10_000,
    ) {
        let a_fe = FieldElement::from_u64(a);
        let b_fe = FieldElement::from_u64(b);
        let out_fe = a_fe.mul(&b_fe).add(&a_fe);
        let (mut compiler, w_pre) = compile_and_solve_incremental(
            "assert_eq(a * b + a, out)",
            &[("out", out_fe)],
            &[("a", a_fe), ("b", b_fe)],
        );

        compiler.optimize_r1cs_o2();
        let w_post = apply_substitutions(&compiler, &w_pre);
        prop_assert!(
            compiler.cs.verify(&w_post).is_ok(),
            "collapse + O2 finalize rejected witness that satisfied the survivors",
        );
    }

    /// Composed-map consistency *and canonicity*. Consistency (every
    /// `(var, lc)` reconstructs the wire's true value) catches a
    /// value-corrupting compose bug. Canonicity (no replacement
    /// references an eliminated wire) is the invariant the Flow-A
    /// forward-simulation cannot see — on a full witness, a single-pass
    /// re-derive yields correct values even from a non-canonical map, so
    /// "forgot to fold the finalize map into a collapse replacement"
    /// would pass forward-sim silently. This assertion catches it
    /// directly, which is what makes the composition itself a tested
    /// invariant rather than an argued one.
    #[test]
    fn incremental_composed_map_is_consistent_and_canonical(
        a in 0u64..1_000_000,
        b in 1u64..10_000,
    ) {
        let a_fe = FieldElement::from_u64(a);
        let b_fe = FieldElement::from_u64(b);
        let out_fe = a_fe.mul(&b_fe).add(&a_fe);
        let (mut compiler, w_pre) = compile_and_solve_incremental(
            "assert_eq(a * b + a, out)",
            &[("out", out_fe)],
            &[("a", a_fe), ("b", b_fe)],
        );

        compiler.optimize_r1cs();
        let subs = compiler
            .substitution_map
            .as_ref()
            .expect("collapse + finalize must produce a substitution map");
        // Non-vacuity: this circuit must actually eliminate a wire, else
        // the canonicity sweep below would pass on an empty map.
        prop_assert!(!subs.is_empty(), "composed map is empty — collapse made no progress");
        for (var, lc) in subs {
            let computed = lc
                .evaluate(&w_pre)
                .expect("composed substitution LC must evaluate");
            prop_assert_eq!(
                w_pre[*var],
                computed,
                "composed_map[{}] reconstructs {:?} but witness has {:?}",
                var,
                computed,
                w_pre[*var],
            );
            for (v, _) in lc.terms() {
                prop_assert!(
                    !subs.contains_key(&v.index()),
                    "composed_map[{}] references eliminated wire {} — \
                     non-canonical map (a single-pass witness fixup would \
                     be order-dependent)",
                    var,
                    v.index(),
                );
            }
        }
    }
}

proptest! {
    // Poseidon is ~360 constraints per hash; fewer cases keep this brisk
    // while still sweeping inputs. This is the hash-op shape whose inputs
    // are materialized into fresh wires — the case a pure-arithmetic
    // generator would never reach.
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// Forward simulation through collapse + finalize for a native
    /// poseidon whose first argument (`a + b`) is materialized into a
    /// fresh wire fed as a direct-`Variable` op input.
    #[test]
    fn incremental_preserves_satisfaction_poseidon(
        a in 0u64..1_000_000,
        b in 0u64..1_000_000,
        c in 1u64..1_000_000,
        d in 1u64..1_000_000,
    ) {
        let params = <Bn254Fr as PoseidonParamsProvider>::default_poseidon_t3();
        let a_fe = FieldElement::from_u64(a);
        let b_fe = FieldElement::from_u64(b);
        let c_fe = FieldElement::from_u64(c);
        let d_fe = FieldElement::from_u64(d);
        let out_fe = poseidon_hash(&params, a_fe.add(&b_fe), c_fe.mul(&d_fe));
        let (mut compiler, w_pre) = compile_and_solve_incremental(
            "assert_eq(poseidon(a + b, c * d), out)",
            &[("out", out_fe)],
            &[("a", a_fe), ("b", b_fe), ("c", c_fe), ("d", d_fe)],
        );

        compiler.optimize_r1cs();
        let w_post = apply_substitutions(&compiler, &w_pre);
        prop_assert!(
            compiler.cs.verify(&w_post).is_ok(),
            "collapse + finalize rejected a valid poseidon witness",
        );
    }
}

// ============================================================================
// Backward direction (hand-built): perturbed witness rejected by both
// pre-O1 and post-O1
// ============================================================================

/// If a pre-O1-satisfying witness gets a *non-substituted* wire
/// flipped to a wrong value, both the pre-O1 and post-O1 systems
/// reject it. This is the backward-simulation pin: post-O1 doesn't
/// admit witnesses that pre-O1 rejects on a wire neither system
/// eliminated.
#[test]
fn optimize_does_not_admit_perturbed_witness() {
    let a = FieldElement::from_u64(7);
    let b = FieldElement::from_u64(11);
    let out = a.mul(&b).add(&a);
    let (mut compiler, w_pre) = compile_and_solve(
        "assert_eq(a * b + a, out)",
        &[("out", out)],
        &[("a", a), ("b", b)],
    );

    // Identify a wire in w_pre that is NOT in the substitution_map
    // (so flipping it is a "non-substituted perturbation"). The "out"
    // public input wire is always allocated and never substituted away
    // by linear elimination (public inputs are protected — see
    // `r1cs_optimize/predicates.rs`).
    let out_wire = compiler.bindings.get("out").copied().expect("out wire");

    // Verify the honest witness against pre-O1 (sanity).
    assert!(
        compiler.cs.verify(&w_pre).is_ok(),
        "honest pre-O1 must verify"
    );

    // Optimize and verify forward direction first.
    compiler.optimize_r1cs();
    let mut w_post = apply_substitutions(&compiler, &w_pre);
    assert!(
        compiler.cs.verify(&w_post).is_ok(),
        "honest post-O1 must verify (forward simulation)"
    );

    // Perturb the public-input wire to a wrong value.
    let wrong = FieldElement::from_u64(99999);
    assert_ne!(
        w_post[out_wire.index()],
        wrong,
        "test setup: perturbation must differ from honest"
    );
    w_post[out_wire.index()] = wrong;

    // Post-O1 must reject the perturbed witness — public inputs are
    // not eliminated, so their constraint chain remains live.
    assert!(
        compiler.cs.verify(&w_post).is_err(),
        "post-O1 admitted a witness with a perturbed public input wire — \
         backward simulation broken: an adversary could forge `out` post-O1 \
         while the pre-O1 system would reject it."
    );
}

/// Backward-simulation pin for the incremental path: a perturbed public
/// input wire is rejected after collapse + finalize. Public inputs are
/// barred from collapse and protected by the finalize pass, so their
/// constraint chain survives both — an adversary cannot forge `out`.
#[test]
fn incremental_does_not_admit_perturbed_witness() {
    let a = FieldElement::from_u64(7);
    let b = FieldElement::from_u64(11);
    let out = a.mul(&b).add(&a);
    let (mut compiler, w_pre) = compile_and_solve_incremental(
        "assert_eq(a * b + a, out)",
        &[("out", out)],
        &[("a", a), ("b", b)],
    );

    let out_wire = compiler.bindings.get("out").copied().expect("out wire");

    assert!(
        compiler.cs.verify(&w_pre).is_ok(),
        "honest collapse-survivor system must verify"
    );

    compiler.optimize_r1cs();
    let mut w_post = apply_substitutions(&compiler, &w_pre);
    assert!(
        compiler.cs.verify(&w_post).is_ok(),
        "honest collapse + finalize must verify (forward simulation)"
    );

    let wrong = FieldElement::from_u64(99999);
    assert_ne!(
        w_post[out_wire.index()],
        wrong,
        "test setup: perturbation must differ from honest"
    );
    w_post[out_wire.index()] = wrong;

    assert!(
        compiler.cs.verify(&w_post).is_err(),
        "collapse + finalize admitted a witness with a perturbed public input wire — \
         backward simulation broken: an adversary could forge `out`."
    );
}
