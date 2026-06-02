use super::*;

// ============================================================================
// Num2Bits(8) — booleanity forgery
// ============================================================================

/// Attack: set `out_0` to the non-boolean value 2 and adjust `out_1`
/// to 0 so the sum constraint `Σ bit_i * 2^i === in` stays satisfied.
///
/// Honest witness for in=42 (0b00101010): [0, 1, 0, 1, 0, 1, 0, 0].
/// Forged witness:                        [2, 0, 0, 1, 0, 1, 0, 0].
/// Sum check: 2*1 + 0*2 + 0*4 + 1*8 + 0*16 + 1*32 = 42 — still valid.
///
/// The ONLY constraint that can catch this forgery is the booleanity
/// constraint `out_0 * (out_0 - 1) === 0`. If Achronyme's 9-constraint
/// output were missing it, `cs.verify` would accept the forgery — a
/// soundness break that would allow a malicious prover to claim
/// arbitrary bit decompositions.
#[test]
fn num2bits_forge_nonbool_bits_rejected() {
    let (compiler, mut witness) =
        compile_valid_witness("test/circom/num2bits_8.circom", &[("in", 42)], true);

    // Sanity: the benchmark reports 9 constraints post-O1; we want
    // the same shape here so the test speaks to the benchmark result.
    assert_eq!(
        compiler.cs.num_constraints(),
        9,
        "Num2Bits(8) should emit 9 R1CS constraints"
    );

    let w_out_0 = wire(&compiler, "out_0");
    let w_out_1 = wire(&compiler, "out_1");

    // Honest witness sanity: out_0 = 0, out_1 = 1 for in=42.
    assert_eq!(witness[w_out_0.index()], Fe::from_u64(0));
    assert_eq!(witness[w_out_1.index()], Fe::from_u64(1));

    // Forge: out_0 = 2 (non-boolean), out_1 = 0 — keeps Σ bit_i * 2^i = 42.
    witness[w_out_0.index()] = Fe::from_u64(2);
    witness[w_out_1.index()] = Fe::from_u64(0);

    assert!(
        compiler.cs.verify(&witness).is_err(),
        "Num2Bits(8): non-boolean `out_0 = 2` must be rejected by the \
         booleanity constraint `out_0 * (out_0 - 1) === 0`. If this test \
         starts passing the constraint set has become under-constrained."
    );
}

/// Companion attack: set `out_0 = 3` while keeping the rest of the
/// bits honest. The sum check fires immediately (0 -> 3 changes the
/// total by +3), so this path exercises the linear sum constraint
/// rather than booleanity. Both must be present for soundness.
#[test]
fn num2bits_forge_sum_violation_rejected() {
    let (compiler, mut witness) =
        compile_valid_witness("test/circom/num2bits_8.circom", &[("in", 42)], true);

    let w_out_0 = wire(&compiler, "out_0");
    assert_eq!(witness[w_out_0.index()], Fe::from_u64(0));

    // Forge: bump bit 0 by 3 without adjusting anything else.
    // Sum becomes 45, breaking the `Σ bit_i * 2^i === in` constraint.
    witness[w_out_0.index()] = Fe::from_u64(3);

    assert!(
        compiler.cs.verify(&witness).is_err(),
        "Num2Bits(8): a bit flip that breaks Σ bit_i * 2^i === in must \
         be rejected by the linear sum constraint."
    );
}
