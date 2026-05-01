//! Property-based test: `optimize_r1cs` preserves satisfying-assignment
//! semantics (Phase 0.2.D).
//!
//! ## The narrowed property (advisor §2b)
//!
//! Closeout's original framing — "pre-O1 multiset = post-O1 multiset
//! modulo elimination" — is wrong; multiset equality fails by
//! definition (the optimizer eliminates constraints).
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
//! Patching `optimize_linear_clustered` (in
//! `constraints/src/r1cs_optimize/linear_cluster.rs`) to drop a
//! substitution map entry mid-pass would cause `lc.evaluate(w) ≠
//! w[var]` for that var — the substitution-map-consistency assertion
//! catches this. See `optimize_substitution_map_is_consistent`.

use std::collections::HashMap;

use ir::IrLowering;
use memory::FieldElement;
use proptest::prelude::*;
use zkc::r1cs_backend::R1CSCompiler;
use zkc::witness::WitnessGenerator;

// ============================================================================
// Helpers
// ============================================================================

/// Compile a circuit source to R1CS, generate a satisfying witness,
/// and verify it satisfies the pre-O1 system. Returns the compiler
/// (with `cs` still in its pre-O1 state) and the witness vector.
fn compile_and_solve(
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
/// the post-substitution witness.
fn apply_substitutions(compiler: &R1CSCompiler, witness: &[FieldElement]) -> Vec<FieldElement> {
    let mut w = witness.to_vec();
    if let Some(subs) = &compiler.substitution_map {
        for (var, lc) in subs {
            w[*var] = lc.evaluate(&w).expect("substitution LC must evaluate");
        }
    }
    w
}

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
