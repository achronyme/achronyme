use super::*;

// ============================================================================
// BinSum(4, 2) — sum-violation forgery
// ============================================================================
//
// Honest case: a = [1, 1, 0, 1] (LE bits, value = 11), b = [0, 1, 1, 0]
// (value = 6), sum = 17 = 0b10001 (LE) → out = [1, 0, 0, 0, 1].
//
// Attack: flip `out_0` from 1 to 0, leaving the rest of the witness
// alone. The boolean check `out_0 * (out_0 - 1) === 0` still passes
// (`0 * -1 = 0`), so the only constraint that can catch this forgery
// is the sum equation `Σ a_i * 2^i + Σ b_i * 2^i === Σ out_i * 2^i`.
//
// If Achronyme's lowered constraint set were missing the sum equation
// (or had it wired against dangling output wires — the historical
// component-output-wiring re-inlining pattern), this forgery would
// slip through. The test pins both the soundness property and the
// re-inlining fix simultaneously: a regression in either would let
// `out_0 = 0` verify against an honest 17-sum.
#[test]
fn binsum_forge_sum_violation_rejected() {
    // `optimize = false`: the linear sum equation folds `out_0` away as
    // a substituted wire under O1 (it's pinned by `lin === lout`), so a
    // direct mutation against the optimised constraint set is invisible.
    // Keeping the unoptimised constraints exposes the wire and the
    // sum-violation constraint that catches the forgery.
    let (compiler, mut witness) = compile_valid_witness(
        "test/circomlib/binsum_test.circom",
        &[
            ("a_0", 1),
            ("a_1", 1),
            ("a_2", 0),
            ("a_3", 1),
            ("b_0", 0),
            ("b_1", 1),
            ("b_2", 1),
            ("b_3", 0),
        ],
        false,
    );

    let w_out_0 = wire(&compiler, "out_0");
    assert_eq!(witness[w_out_0.index()], Fe::from_u64(1));

    witness[w_out_0.index()] = Fe::from_u64(0);

    assert!(
        compiler.cs.verify(&witness).is_err(),
        "BinSum(4, 2): clearing out_0 drops the LE sum from 17 to 16. \
         Only the `lin === lout` linear equation can catch this — the \
         booleanity check still passes. Rejecting this forgery proves \
         the sum constraint survived lowering and is wired against \
         the live output wires (no component-output-wiring re-inlining \
         residue)."
    );
}

// ============================================================================
// Point2Bits_Strict — booleanity / sum / sign forgeries
// ============================================================================
//
// The benchmark reports Point2Bits_Strict at 915 R1CS constraints
// post-O1 against circom O2's 1,293 — a 378-constraint (-29.3%) lead.
// Same shape across (0, 1) and the BabyJubjub generator, so the
// difference is structural, not input-dependent. The most plausible
// honest mechanism: cross-template propagation of `proven_boolean`
// lets us eliminate redundant per-bit booleanity checks that circom
// re-emits inside CompConstant / AliasCheck. The most plausible
// dishonest mechanism: a missing booleanity or sum constraint at
// some seam where the IR optimiser aliased two wires that shouldn't
// have collapsed.
//
// These three tests discriminate between those two cases. Each
// constructs an honest witness for the identity point (x = 0, y = 1)
// and mutates one or more wires to a value that:
//   - Satisfies the linear sum constraint of Num2Bits, AND
//   - Violates a booleanity / sum / sign-bit constraint that the
//     honest constraint system MUST emit somewhere.
// If `cs.verify` accepts any forgery, we have an under-constrained
// circuit and the −378c "advantage" is a soundness bug.

/// Forge `out_0` to a non-boolean value while keeping the n2bY sum
/// constraint satisfied.
///
/// Honest witness for (x=0, y=1):
///   - n2bY.out_0 = 1, n2bY.out_1 = 0, ..., n2bY.out_253 = 0
///   - Sum check: 1·1 + 0·2 + ... = 1 ✓
///   - Booleanity: 1·(1-1) = 0 ✓ for every bit
///
/// Forged witness:
///   - out_0 = 2  (non-boolean)
///   - out_1 = (p-1)/2  (also non-boolean)
///   - Sum: 2·1 + ((p-1)/2)·2 + 0 + ... = 2 + (p-1) = p + 1 ≡ 1 (mod p) ✓
///
/// The ONLY constraint that catches this is booleanity on at least
/// one of out_0 / out_1. If both checks were eliminated by the IR
/// optimiser (e.g. via a buggy `proven_boolean` propagation), the
/// forgery satisfies every other constraint in the system.
#[test]
fn point2bits_strict_forge_nonbool_bits_rejected() {
    let (compiler, mut witness) = compile_valid_witness(
        "test/circomlib/point2bits_test.circom",
        &[("in_0", 0), ("in_1", 1)],
        true,
    );

    let w_out_0 = wire(&compiler, "out_0");
    let w_out_1 = wire(&compiler, "out_1");

    assert_eq!(
        witness[w_out_0.index()],
        Fe::from_u64(1),
        "honest n2bY.out_0 = 1 (lsb of y=1)"
    );
    assert_eq!(
        witness[w_out_1.index()],
        Fe::from_u64(0),
        "honest n2bY.out_1 = 0"
    );

    // (p-1)/2 mod p — the half-field-order constant used by CompConstant
    // for sign-bit extraction. Conveniently, it's a non-boolean value
    // that pairs with `2` to leave the LE sum invariant.
    let half_field = Fe::ZERO
        .sub(&Fe::ONE)
        .div(&Fe::from_u64(2))
        .expect("(p-1)/2 mod p");

    witness[w_out_0.index()] = Fe::from_u64(2);
    witness[w_out_1.index()] = half_field;

    assert!(
        compiler.cs.verify(&witness).is_err(),
        "Point2Bits_Strict: non-boolean (out_0, out_1) = (2, (p-1)/2) \
         keeps the n2bY sum at 1 mod p but violates booleanity on both \
         bits. If `cs.verify` accepts this, the booleanity constraints \
         on n2bY's bits were eliminated by an over-aggressive optimiser \
         pass — this is the soundness bug the −378c lead would be hiding."
    );
}

/// Forge a single bit's value without preserving the sum.
///
/// This is the simpler attack: bump out_0 from 1 to 3, leave the
/// rest alone. The sum becomes 3 instead of 1; the linear equation
/// `Σ n2bY.out_i · 2^i === in_1` is the only constraint that catches
/// this. Booleanity on out_0 ALSO fires (3 ∉ {0,1}), but the sum
/// constraint is the structurally interesting target — losing it
/// would let a malicious prover redefine the bit decomposition of y.
#[test]
fn point2bits_strict_forge_sum_violation_rejected() {
    let (compiler, mut witness) = compile_valid_witness(
        "test/circomlib/point2bits_test.circom",
        &[("in_0", 0), ("in_1", 1)],
        true,
    );

    let w_out_0 = wire(&compiler, "out_0");
    assert_eq!(witness[w_out_0.index()], Fe::from_u64(1));

    witness[w_out_0.index()] = Fe::from_u64(3);

    assert!(
        compiler.cs.verify(&witness).is_err(),
        "Point2Bits_Strict: bumping out_0 from 1 to 3 breaks both the \
         n2bY booleanity check and its linear sum. Either constraint \
         is sufficient to catch the forgery; if both were missing, the \
         circuit would be catastrophically under-constrained."
    );
}

/// Forge `out_255` (the sign bit) to flip sign without touching the
/// signCalc inputs.
///
/// Honest witness for (x=0, y=1): out_255 = 0 (sign of x=0 vs (p-1)/2).
/// Forge: out_255 = 1.
///
/// The constraint `signCalc.out === in[255]` is the only one that
/// catches this. The bits that feed signCalc (n2bX.out_0..253) are
/// untouched, so signCalc's internal logic still computes 0; only
/// the equality assertion against the public output bit catches the
/// forgery. If the assertion was eliminated by the IR optimiser
/// (e.g. via a buggy `proven_boolean` collapse on signCalc.out), a
/// malicious prover could pack arbitrary sign bits.
#[test]
fn point2bits_strict_forge_sign_bit_rejected() {
    let (compiler, mut witness) = compile_valid_witness(
        "test/circomlib/point2bits_test.circom",
        &[("in_0", 0), ("in_1", 1)],
        true,
    );

    let w_out_255 = wire(&compiler, "out_255");
    assert_eq!(
        witness[w_out_255.index()],
        Fe::from_u64(0),
        "honest sign bit = 0 for x = 0"
    );

    witness[w_out_255.index()] = Fe::from_u64(1);

    assert!(
        compiler.cs.verify(&witness).is_err(),
        "Point2Bits_Strict: forging out_255 from 0 to 1 must be rejected \
         by the `signCalc.out === in[255]` assertion. If this passes, \
         the sign-bit binding was lost during optimisation."
    );
}

// ============================================================================
// Bits2Point_Strict — hardcoded-input + sign-bit forgeries
// ============================================================================
//
// Bits2Point_Strict (665 R1CS post-O1 vs circom O2's 1,041, −36.1%)
// inherits the cross-template `proven_boolean` story from
// Point2Bits_Strict but adds a witness hint via `<--` on `out[0]`
// pinned by BabyCheck's quadratic Edwards-curve equation. For the
// identity point (y=1), BabyCheck collapses x to 0, making forgery
// of `out[0]` impossible at this input — we attack the cheaper
// vectors instead: the hardcoded `in[254] === 0` constraint and
// the `signCalc.out === in[255]` binding.

/// `in[254]` is hardcoded to 0 by the template body. Forging it to 1
/// must be rejected by the equality assertion the lowering emits
/// for `in[254] === 0`. Without this assertion, a malicious prover
/// could feed an aliased 254-bit y representation through the
/// circuit unchallenged.
#[test]
fn bits2point_strict_forge_in254_rejected() {
    let mut inputs: Vec<(&str, u64)> = Vec::with_capacity(256);
    inputs.push(("in_0", 1)); // y = 1 lsb
    for _ in 1..254 {
        // placeholder; concrete value set below per index
    }
    let names: Vec<String> = (0..256).map(|i| format!("in_{i}")).collect();
    let inputs_owned: Vec<(&str, u64)> = (0..256)
        .map(|i| (names[i].as_str(), if i == 0 { 1 } else { 0 }))
        .collect();

    let (compiler, mut witness) =
        compile_valid_witness("test/circomlib/bits2point_test.circom", &inputs_owned, true);

    let w_in_254 = wire(&compiler, "in_254");
    assert_eq!(witness[w_in_254.index()], Fe::from_u64(0));

    witness[w_in_254.index()] = Fe::from_u64(1);

    assert!(
        compiler.cs.verify(&witness).is_err(),
        "Bits2Point_Strict: forging in_254 from 0 to 1 must be rejected \
         by the hardcoded `in[254] === 0` constraint. If this passes, \
         the constraint was eliminated during optimisation."
    );
}

/// `in[255]` carries the public sign bit; `signCalc.out === in[255]`
/// binds it to the sign computed from x's bit decomposition. For
/// the identity point (x=0, y=1), signCalc.out = 0. Forging
/// in[255] = 1 means a malicious prover claims x has the high-half
/// sign while the actual x = 0 has low-half sign — the equality
/// assertion catches it.
#[test]
fn bits2point_strict_forge_sign_bit_rejected() {
    let names: Vec<String> = (0..256).map(|i| format!("in_{i}")).collect();
    let inputs_owned: Vec<(&str, u64)> = (0..256)
        .map(|i| (names[i].as_str(), if i == 0 { 1 } else { 0 }))
        .collect();

    let (compiler, mut witness) =
        compile_valid_witness("test/circomlib/bits2point_test.circom", &inputs_owned, true);

    let w_in_255 = wire(&compiler, "in_255");
    assert_eq!(
        witness[w_in_255.index()],
        Fe::from_u64(0),
        "honest sign bit = 0 for x = 0"
    );

    witness[w_in_255.index()] = Fe::from_u64(1);

    assert!(
        compiler.cs.verify(&witness).is_err(),
        "Bits2Point_Strict: forging in_255 from 0 to 1 (claiming a \
         negative-sign x while the witness has x = 0) must be rejected \
         by `signCalc.out === in[255]`. A regression here would let a \
         malicious prover decouple the public sign bit from the actual \
         curve point coordinates."
    );
}

// ============================================================================
// Known coverage gap — Multiplexer
// ============================================================================
//
// `Multiplexer(wIn, nIn)` feeds a 2-D signal input `inp[nIn][wIn]`
// through a Decoder + EscalarProduct. The witness evaluator lacks the
// flattened-naming pass for 2-D signal arrays. Distinct surface from
// BinSum's (now fixed) re-inlining bug — pinning a soundness test
// requires the 2-D naming pass first.
