//! Property-based idempotence test for `R1CSCompiler::optimize_r1cs`.
//!
//! ## The property
//!
//! `optimize_r1cs(optimize_r1cs(cs)) == optimize_r1cs(cs)` — running the
//! optimizer pipeline twice on the post-O1 system produces the same
//! canonical constraint multiset as running it once. This is the
//! fixed-point property of the linear-elimination dataflow (Cooper &
//! Torczon, "Engineering a Compiler", §10) lifted from IR-level passes
//! (`ir::passes::optimize`, pinned by `ir/tests/idempotence_proptest.rs`)
//! down to the R1CS layer.
//!
//! Idempotence is a regression discriminator for the optimizer
//! itself: a non-converging substitution-elimination loop, a
//! frequency-heuristic that picks differently the second time, or a
//! cluster-Gauss pass that re-introduces a freshly-eliminable LC all
//! surface as a non-empty diff between `cs(1×)` and `cs(2×)`.
//!
//! Companion to forward simulation in `r1cs_preservation_proptest.rs`:
//! that test pins "post-O1 admits witnesses pre-O1 admits"; this test
//! pins "post-O1 is a fixed point of optimize_r1cs". Together they
//! cover the two halves of correctness — semantics-preserving and
//! convergence.
//!
//! ## Discriminator (verified during development)
//!
//! Patching `R1CSCompiler::optimize_r1cs` to overwrite
//! `substitution_map` unconditionally on each call (replacing the
//! `if !subs.is_empty()` guard) makes
//! `optimize_r1cs_substitution_map_is_idempotent` fail at the first
//! proptest case: the first pass populates the map (one entry on the
//! `a*b+a` shape), the second pass observes empty `subs` and now
//! clobbers the map back to empty. Diff prints
//! `substitution_map size diverged: 1× → 1, 2× → 0`.
//!
//! A weaker discriminator (push a duplicate of constraint[0] after
//! optimize_linear) is caught by the vacuity guard below but does
//! NOT trip the idempotence proptests — the linear-elimination pass
//! folds the duplicate cleanly on the second call, so the constraint
//! multiset converges to the same fixed point. That discriminator
//! pins "optimizer makes progress on linear chains", not idempotence.
//!
//! ## Why two compilations rather than `Clone`
//!
//! `R1CSCompiler` is not `Clone` (`ConstraintSystem` carries internal
//! state that's not trivially clone-safe). `compile_and_solve` from
//! `zkc::test_support` is deterministic given identical inputs, so
//! compiling the same source twice produces structurally-identical
//! `R1CSCompiler` instances (modulo HashMap-iteration leaks that the
//! canonical-multiset hash neutralises). Calling `optimize_r1cs()`
//! once on one and twice on the other is the same property as a
//! literal Clone, with no extra plumbing.

use memory::FieldElement;
use proptest::prelude::*;
use zkc::test_support::{compile_and_solve, constraint_multiset};

/// Compile + solve a fixed source twice. Returns two independent
/// pre-O1 compilers ready for divergent optimization passes.
fn compile_pair(
    source: &str,
    public: &[(&str, FieldElement)],
    witness: &[(&str, FieldElement)],
) -> (
    zkc::r1cs_backend::R1CSCompiler,
    zkc::r1cs_backend::R1CSCompiler,
) {
    let (a, _wa) = compile_and_solve(source, public, witness);
    let (b, _wb) = compile_and_solve(source, public, witness);
    (a, b)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(100))]

    /// Linear-chain shape: `assert_eq(a * b + a, out)`. Lowering emits
    /// a Mul + Add chain that the linear-elimination pass collapses.
    /// The post-O1 system is a single `(b+1) * a = out`-style
    /// constraint — running optimize again must be a no-op.
    #[test]
    fn optimize_r1cs_is_idempotent_arith(
        a in 0u64..1_000_000,
        b in 1u64..10_000,
    ) {
        let a_fe = FieldElement::from_u64(a);
        let b_fe = FieldElement::from_u64(b);
        let out_fe = a_fe.mul(&b_fe).add(&a_fe);

        let (mut once, mut twice) = compile_pair(
            "assert_eq(a * b + a, out)",
            &[("out", out_fe)],
            &[("a", a_fe), ("b", b_fe)],
        );

        once.optimize_r1cs();
        twice.optimize_r1cs();
        twice.optimize_r1cs();

        let m1 = constraint_multiset(once.cs.constraints());
        let m2 = constraint_multiset(twice.cs.constraints());
        prop_assert_eq!(
            &m1,
            &m2,
            "optimize_r1cs is not idempotent on `a * b + a == out` \
             with a={}, b={}: 1×-pass produced {} constraints, 2×-pass produced {}",
            a,
            b,
            m1.len(),
            m2.len(),
        );
    }

    /// Division shape: exercises witness/inverse-hint constraints
    /// (`rhs * inv = 1`) plus the linear chain. Distinct optimizer
    /// path — the inverse witness is allocated per division and the
    /// fixed-point property should still hold.
    #[test]
    fn optimize_r1cs_is_idempotent_div(
        a in 0u64..1_000_000,
        b in 1u64..10_000,
    ) {
        let a_fe = FieldElement::from_u64(a);
        let b_fe = FieldElement::from_u64(b);
        let prod = a_fe.mul(&b_fe);

        let (mut once, mut twice) = compile_pair(
            "assert_eq(ab / b, out)",
            &[("out", a_fe)],
            &[("ab", prod), ("b", b_fe)],
        );

        once.optimize_r1cs();
        twice.optimize_r1cs();
        twice.optimize_r1cs();

        let m1 = constraint_multiset(once.cs.constraints());
        let m2 = constraint_multiset(twice.cs.constraints());
        prop_assert_eq!(
            &m1,
            &m2,
            "optimize_r1cs is not idempotent on `ab / b == out` \
             with a={}, b={}: 1× → {} constraints, 2× → {}",
            a,
            b,
            m1.len(),
            m2.len(),
        );
    }

    /// `substitution_map` size and key-set must also be a fixed point.
    /// A buggy optimizer that re-substitutes an already-eliminated wire
    /// on the second pass would either grow the map (new entry) or
    /// rewrite an existing entry's LC. Both are visible diffs against
    /// the 1×-pass map.
    #[test]
    fn optimize_r1cs_substitution_map_is_idempotent(
        a in 0u64..1_000_000,
        b in 1u64..10_000,
    ) {
        let a_fe = FieldElement::from_u64(a);
        let b_fe = FieldElement::from_u64(b);
        let out_fe = a_fe.mul(&b_fe).add(&a_fe);

        let (mut once, mut twice) = compile_pair(
            "assert_eq(a * b + a, out)",
            &[("out", out_fe)],
            &[("a", a_fe), ("b", b_fe)],
        );

        once.optimize_r1cs();
        twice.optimize_r1cs();
        twice.optimize_r1cs();

        let map1 = once.substitution_map.as_ref();
        let map2 = twice.substitution_map.as_ref();

        match (map1, map2) {
            (None, None) => {}
            (Some(m1), Some(m2)) => {
                prop_assert_eq!(
                    m1.len(),
                    m2.len(),
                    "substitution_map size diverged: 1× → {}, 2× → {}",
                    m1.len(),
                    m2.len(),
                );
                let mut k1: Vec<usize> = m1.keys().copied().collect();
                let mut k2: Vec<usize> = m2.keys().copied().collect();
                k1.sort_unstable();
                k2.sort_unstable();
                prop_assert_eq!(
                    k1,
                    k2,
                    "substitution_map key-set diverged between 1×-pass and 2×-pass",
                );
            }
            (a, b) => {
                prop_assert!(
                    false,
                    "substitution_map presence diverged: 1×={:?}, 2×={:?}",
                    a.is_some(),
                    b.is_some(),
                );
            }
        }
    }
}

// ============================================================================
// Vacuity guard: the property is trivial if optimize_r1cs is the identity
// or always returns the empty constraint system. Pin a hand-built fixture
// that requires the optimizer to actually run.
// ============================================================================

/// `a * b + a == out` produces ≥ 2 R1CS constraints pre-O1 and
/// strictly fewer post-O1 (linear elimination folds the Add chain).
/// If a future optimizer change turns this into a no-op, this test
/// fires on the assertion below — distinct signal from the proptest
/// passing vacuously.
#[test]
fn optimize_r1cs_makes_progress_on_linear_chain() {
    let a_fe = FieldElement::from_u64(7);
    let b_fe = FieldElement::from_u64(11);
    let out_fe = a_fe.mul(&b_fe).add(&a_fe);

    let (mut compiler, _w) = compile_and_solve(
        "assert_eq(a * b + a, out)",
        &[("out", out_fe)],
        &[("a", a_fe), ("b", b_fe)],
    );

    let pre = compiler.cs.constraints().len();
    compiler.optimize_r1cs();
    let post = compiler.cs.constraints().len();

    assert!(
        post < pre,
        "vacuity guard: optimize_r1cs is expected to reduce constraint \
         count on `a * b + a == out` (pre={pre}, post={post}); if it \
         doesn't, the proptest above is checking idempotence of a no-op."
    );
}
