use super::*;

// ============================================================================
// LessThan(8) — output forgery
// ============================================================================

/// Attack: flip the top-level `out` wire from its honest value to
/// the opposite boolean. The constraint `out <== 1 - n2b.out[n]`
/// must catch this since bit[n] is still pinned by the embedded
/// Num2Bits(9) constraints.
///
/// Honest case: in_0=10, in_1=3 → 10 < 3 is false → out = 0.
/// Forged value: out = 1.
///
/// Under the wire: `n2b.in = 10 + 256 - 3 = 263 = 0b100000111`, so
/// `n2b.out_8 = 1` and `out = 1 - 1 = 0`. Setting out = 1 violates
/// the linear equation.
#[test]
fn lessthan_forge_output_false_to_true_rejected() {
    // optimize = false: the R1CS optimizer substitutes LessThan's
    // `out` wire away into `1 - n2b.out_n`, leaving no standalone
    // output wire to mutate. Running against the pre-optimization
    // constraint system preserves the output wire and proves that
    // the `out <== 1 - n2b.out[n]` constraint catches the forgery.
    let (compiler, mut witness) = compile_valid_witness(
        "test/circom/lessthan_8.circom",
        &[("in_0", 10), ("in_1", 3)],
        false,
    );

    let w_out = wire(&compiler, "out");
    // Honest: 10 < 3 is false → out = 0.
    assert_eq!(witness[w_out.index()], Fe::from_u64(0));

    // Forge: claim 10 < 3.
    witness[w_out.index()] = Fe::from_u64(1);

    assert!(
        compiler.cs.verify(&witness).is_err(),
        "LessThan(8): forging out=1 when in_0 >= in_1 must be rejected \
         by the `out === 1 - n2b.out_n` constraint."
    );
}

/// Opposite direction: the honest answer is `out = 1` and we forge
/// it to 0 (claim `in_0` is not less than `in_1` when it is).
#[test]
fn lessthan_forge_output_true_to_false_rejected() {
    let (compiler, mut witness) = compile_valid_witness(
        "test/circom/lessthan_8.circom",
        &[("in_0", 3), ("in_1", 10)],
        false,
    );

    let w_out = wire(&compiler, "out");
    // Honest: 3 < 10 is true → out = 1.
    assert_eq!(witness[w_out.index()], Fe::from_u64(1));

    // Forge: claim 3 is not less than 10.
    witness[w_out.index()] = Fe::from_u64(0);

    assert!(
        compiler.cs.verify(&witness).is_err(),
        "LessThan(8): forging out=0 when in_0 < in_1 must be rejected \
         by the `out === 1 - n2b.out_n` constraint."
    );
}

// ============================================================================
// IsZero — output forgery
// ============================================================================
//
// IsZero is a template whose soundness is routinely cited as the
// canonical "elegant R1CS" pattern, but that only works if both of its
// constraints are actually emitted:
//
//   out <== -in * inv + 1;   // linear-through-a-multiplication
//   in * out === 0;           // forces out = 0 when in ≠ 0
//
// The tests below forge each direction of the output and assert that
// `cs.verify` catches both. Together they prove the constraint system
// is sufficient to pin `out` to exactly the indicator of `in == 0`.

/// Attack: claim `in = 7 is zero` (forge `out = 1`).
///
/// The `in * out === 0` constraint fires because `7 * 1 = 7 ≠ 0`.
/// This is the constraint that would be missing in a naïve under-
/// constrained IsZero; its presence is what makes the template sound.
#[test]
fn iszero_forge_nonzero_claimed_zero_rejected() {
    let (compiler, mut witness) =
        compile_valid_witness("test/circom/iszero.circom", &[("in", 7)], false);

    let w_out = wire(&compiler, "out");
    // Honest: 7 is non-zero → out = 0.
    assert_eq!(witness[w_out.index()], Fe::from_u64(0));

    // Forge: claim 7 is zero.
    witness[w_out.index()] = Fe::from_u64(1);

    assert!(
        compiler.cs.verify(&witness).is_err(),
        "IsZero: forging out=1 when in ≠ 0 must be rejected by the \
         `in * out === 0` constraint."
    );
}

/// Attack: claim `in = 0 is nonzero` (forge `out = 0`).
///
/// The `out <== -in * inv + 1` constraint fires because when in=0, the
/// constraint collapses to `out === 1`, so any forged `out = 0` fails
/// the linear check regardless of what the prover puts in `inv`.
#[test]
fn iszero_forge_zero_claimed_nonzero_rejected() {
    let (compiler, mut witness) =
        compile_valid_witness("test/circom/iszero.circom", &[("in", 0)], false);

    let w_out = wire(&compiler, "out");
    // Honest: 0 is zero → out = 1.
    assert_eq!(witness[w_out.index()], Fe::from_u64(1));

    // Forge: claim 0 is nonzero.
    witness[w_out.index()] = Fe::from_u64(0);

    assert!(
        compiler.cs.verify(&witness).is_err(),
        "IsZero: forging out=0 when in = 0 must be rejected by the \
         `out === -in * inv + 1` linear constraint (which collapses to \
         out === 1 when in = 0)."
    );
}

// ============================================================================
// Switcher — output / intermediate-wire forgery
// ============================================================================
//
// Switcher does not constrain `sel ∈ {0, 1}` — that's the caller's
// responsibility in circomlib. Still, the three linear / quadratic
// constraints on the intermediate wire `aux` and the outputs must
// ensure that once `sel`, `L`, and `R` are fixed, `outL` and `outR`
// are uniquely determined. The tests below forge each output in turn
// and prove the constraint system rejects each forgery.

/// Attack: with sel=1, the honest outputs are `outL = R` and `outR = L`.
/// Forge outL to be L (the "sel=0" answer) without changing aux.
/// The `outL <== aux + L` constraint fires because aux was computed
/// as `(R-L)*1 = R-L`, so `outL` must equal `R-L+L = R`, not `L`.
#[test]
fn switcher_forge_outl_rejected() {
    let (compiler, mut witness) = compile_valid_witness(
        "test/circom/switcher.circom",
        &[("sel", 1), ("L", 10), ("R", 99)],
        false,
    );

    let w_outl = wire(&compiler, "outL");
    let w_outr = wire(&compiler, "outR");
    // Honest with sel=1: outputs swap (outL=R, outR=L).
    assert_eq!(witness[w_outl.index()], Fe::from_u64(99));
    assert_eq!(witness[w_outr.index()], Fe::from_u64(10));

    // Forge: claim outL = 10 (as if sel were 0) while leaving aux alone.
    witness[w_outl.index()] = Fe::from_u64(10);

    assert!(
        compiler.cs.verify(&witness).is_err(),
        "Switcher: forging outL without adjusting `aux` must be rejected \
         by `outL <== aux + L` — a wire substitution that bypasses the \
         selector logic would be a soundness break."
    );
}

/// Attack: with sel=1, outR = L honestly. Forge outR to R (the "sel=0"
/// answer) to prove the mirror constraint `outR <== -aux + R` catches
/// it exactly the way `outL` is caught in the test above.
#[test]
fn switcher_forge_outr_rejected() {
    let (compiler, mut witness) = compile_valid_witness(
        "test/circom/switcher.circom",
        &[("sel", 1), ("L", 10), ("R", 99)],
        false,
    );

    let w_outr = wire(&compiler, "outR");
    // Honest with sel=1: outR = L = 10.
    assert_eq!(witness[w_outr.index()], Fe::from_u64(10));

    // Forge: claim outR = 99 (as if sel were 0).
    witness[w_outr.index()] = Fe::from_u64(99);

    assert!(
        compiler.cs.verify(&witness).is_err(),
        "Switcher: forging outR must be rejected by `outR <== -aux + R`. \
         Any inconsistency between the paired outputs is a soundness \
         break the two linear constraints are precisely there to catch."
    );
}
