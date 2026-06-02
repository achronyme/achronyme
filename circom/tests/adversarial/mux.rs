use super::*;

// ============================================================================
// Mux2 — 4-to-1 multiplexer driven by a 2-bit selector
// ============================================================================
//
// Mux2 wraps `MultiMux2(1)` and composes four input constants with a
// 2-bit selector via the algebraic identity
//
//     out = (c[3]-c[2]-c[1]+c[0])*s10 + (c[2]-c[0])*s[1] + (c[1]-c[0])*s[0] + c[0]
//
// where `s10 <== s[1] * s[0]` is the quadratic intermediate. The
// template does *not* booleanity-constrain `s[i]` (caller's job, same
// upstream-circomlib convention as Mux3/Mux4 above). The soundness
// tests below assume an honest selector and target the linear output
// equation plus the quadratic `s10` — together they pin the output
// uniquely given a fixed selector.

/// Attack: keep the selector at `[0,0]` (honest output is `c[0]`) and
/// forge the top-level `out` wire to `c[1]`. With every selector bit
/// pinned at zero, `s10 = 0`, `a0 = 0`, `a1 = 0`, `a10 = 0`, `a = c[0]`,
/// so the output equation `out <== a10 + a1 + a0 + a` collapses to
/// `out = c[0]`. The forgery violates this linear constraint.
#[test]
fn mux2_forge_wrong_output_rejected() {
    let (compiler, mut witness) = compile_valid_witness(
        "test/circomlib/mux2_test.circom",
        &[
            ("c_0", 10),
            ("c_1", 20),
            ("c_2", 30),
            ("c_3", 40),
            ("s_0", 0),
            ("s_1", 0),
        ],
        false,
    );

    let w_out = wire(&compiler, "out");
    // Honest: index = 0+2*0 = 0 → out = c[0] = 10.
    assert_eq!(witness[w_out.index()], Fe::from_u64(10));

    // Forge: claim out = c[1] = 20 without touching any other wire.
    witness[w_out.index()] = Fe::from_u64(20);

    assert!(
        compiler.cs.verify(&witness).is_err(),
        "Mux2: forging `out` to a non-selected constant while the \
         selector bits stay at [0,0] must be rejected by the linear \
         output equation `out <== a10 + a1 + a0 + a`. A template whose \
         constraints don't pin the output value given a fixed selector \
         is trivially under-constrained."
    );
}

/// Attack: feed selector `[1,1]` so the honest index is `1 + 2*1 = 3`
/// and `out = c[3] = 40`. Then flip `out` to `c[0] = 10` (pretending
/// the selector was all-zero). Changing the output without touching
/// `s10`, `a10`, `a1`, `a0`, or `a` breaks the linear sum.
///
/// This direction also exercises the *quadratic* intermediate `s10`:
/// when `s = [1,1]`, `s10 = 1`, so the `a10` term carries the cross-
/// bit information that distinguishes `c[3]` from the other constants.
/// Mux3/Mux4 hit the same algebra at higher bit counts; Mux2 is the
/// minimum-width version that still has a non-trivial cross-bit term.
#[test]
fn mux2_forge_output_with_active_selector_rejected() {
    let (compiler, mut witness) = compile_valid_witness(
        "test/circomlib/mux2_test.circom",
        &[
            ("c_0", 10),
            ("c_1", 20),
            ("c_2", 30),
            ("c_3", 40),
            ("s_0", 1),
            ("s_1", 1),
        ],
        false,
    );

    let w_out = wire(&compiler, "out");
    // Honest: index = 1+2 = 3 → out = c[3] = 40.
    assert_eq!(witness[w_out.index()], Fe::from_u64(40));

    // Forge: claim out = 10 (c[0]), as if s were [0,0].
    witness[w_out.index()] = Fe::from_u64(10);

    assert!(
        compiler.cs.verify(&witness).is_err(),
        "Mux2: when the selector bits are fixed to encode index 3, the \
         output is uniquely determined. Flipping `out` to match a \
         different selector without updating the selector itself must \
         be caught by the linear-plus-quadratic output chain."
    );
}

// Discriminator note (methodology requirement): both Mux2 tests above
// were verified to catch a soundness regression by patching the wrapper
// `mux2_test.circom` to leave `out` unconstrained (`out <-- mux.out`
// without paired `===`). Achronyme's circom frontend rejects this at
// the static-check stage with "signal `Mux2::out` is assigned with `<--`
// but has no `===` constraint", which is *itself* a form of soundness
// detection (compile-time rather than R1CS-time). The combination of
// the static-check + R1CS-verify catches the targeted class of
// under-constrainment regressions.
//
// Internal signals like `s10`/`a10`/`a` are not exposed in the
// wrapper's R1CS bindings (`compile_valid_witness` only surfaces names
// from the top-level main component), so single-wire forgeries on
// them aren't reachable from the test harness. The chain `s10 →
// a10/a1/a0/a → out` is exercised end-to-end via the `out` forgery:
// any break in the chain that leaves `out` reachable from a
// different-selector witness would surface as a forgery success.

// ============================================================================
// Mux3 — 8-to-1 multiplexer driven by a 3-bit selector
// ============================================================================
//
// Mux3 wraps `MultiMux3(1)` and composes eight input constants with a
// 3-bit selector via the algebraic identity
//
//     out = (a210 + a21 + a20 + a2) * s[2] + (a10 + a1 + a0 + a)
//
// where each `aXY` is itself a quadratic of differences between the
// constants multiplied by one of the selector bits. The template does
// *not* booleanity-constrain `s[i]`; the caller is expected to feed
// valid bits (this matches circomlib upstream — see the Switcher notes
// above). The soundness tests below therefore assume an honest selector
// and target the linear output equation plus the quadratic intermediate
// `s10 <== s[1] * s[0]` — the two constraints that pin the output to
// exactly `c[s[0] + 2*s[1] + 4*s[2]]`.

/// Attack: keep the selector fixed at `[0,0,0]` (so the honest output
/// is `c[0]`) and forge the top-level `out` wire to `c[1]`. The
/// top-level constraint `out <== mux.out` plus the chain back through
/// `MultiMux3.out[0] <== ... * s[2] + ...` with every selector bit
/// pinned at zero forces `out = c[0]`, so the forgery is rejected.
#[test]
fn mux3_forge_wrong_output_rejected() {
    let (compiler, mut witness) = compile_valid_witness(
        "test/circomlib/mux3_test.circom",
        &[
            ("c_0", 10),
            ("c_1", 20),
            ("c_2", 30),
            ("c_3", 40),
            ("c_4", 50),
            ("c_5", 60),
            ("c_6", 70),
            ("c_7", 80),
            ("s_0", 0),
            ("s_1", 0),
            ("s_2", 0),
        ],
        false,
    );

    let w_out = wire(&compiler, "out");
    // Honest: index = 0+2*0+4*0 = 0 → out = c[0] = 10.
    assert_eq!(witness[w_out.index()], Fe::from_u64(10));

    // Forge: claim out = c[1] = 20 without touching any other wire.
    witness[w_out.index()] = Fe::from_u64(20);

    assert!(
        compiler.cs.verify(&witness).is_err(),
        "Mux3: forging `out` to a non-selected constant while the \
         selector bits stay at [0,0,0] must be rejected by the output \
         linear chain. A template whose constraints don't pin the \
         output value given a fixed selector is trivially under-constrained."
    );
}

/// Attack: feed selector `[1,1,0]` so the honest index is
/// `1 + 2*1 + 0 = 3` and out = c[3] = 40. Then flip `out` to c[0]=10
/// (pretending the selector was all-zero). Changing a single output
/// wire without touching the selector or the cached products must be
/// rejected by `out <== (a210 + a21 + a20 + a2) * s[2] + ...`.
#[test]
fn mux3_forge_output_with_active_selector_rejected() {
    let (compiler, mut witness) = compile_valid_witness(
        "test/circomlib/mux3_test.circom",
        &[
            ("c_0", 10),
            ("c_1", 20),
            ("c_2", 30),
            ("c_3", 40),
            ("c_4", 50),
            ("c_5", 60),
            ("c_6", 70),
            ("c_7", 80),
            ("s_0", 1),
            ("s_1", 1),
            ("s_2", 0),
        ],
        false,
    );

    let w_out = wire(&compiler, "out");
    // Honest: index = 1+2+0 = 3 → out = c[3] = 40.
    assert_eq!(witness[w_out.index()], Fe::from_u64(40));

    // Forge: claim out = 10 (c[0]), as if s were [0,0,0].
    witness[w_out.index()] = Fe::from_u64(10);

    assert!(
        compiler.cs.verify(&witness).is_err(),
        "Mux3: when the selector bits are fixed to encode index 3, the \
         output is uniquely determined. Flipping `out` to match a \
         different selector without updating the selector itself must \
         be caught by the `out` linear-plus-quadratic chain."
    );
}

// ============================================================================
// Mux4 — 16-to-1 multiplexer driven by a 4-bit selector
// ============================================================================
//
// Mux4 wraps `MultiMux4(1)` and uses the same pattern as Mux3 but with
// one more selector bit, doubling the number of intermediate products.
// Adding an adversarial pair here is meaningful: with four bits the
// output chain is deeper, so a missing intermediate constraint would
// be harder to spot by inspection and easier to paper over with test
// vectors that happen to line up. The forgery below attacks the last
// possible layer of that chain.

/// Attack: with selector `[1,1,0,0]` the honest index is
/// `1 + 2 + 0 + 0 = 3` so out = c[3]. Keep everything else honest
/// and flip `out` to c[15] (the "all selector bits set" answer). The
/// MultiMux4 output equation is the only constraint pinning `out` to
/// `c[index]`; if any link in that chain is missing, the forgery
/// slips through.
#[test]
fn mux4_forge_output_rejected() {
    let mut inputs: Vec<(&str, u64)> = (0..16)
        .map(|i| {
            let name: &'static str = match i {
                0 => "c_0",
                1 => "c_1",
                2 => "c_2",
                3 => "c_3",
                4 => "c_4",
                5 => "c_5",
                6 => "c_6",
                7 => "c_7",
                8 => "c_8",
                9 => "c_9",
                10 => "c_10",
                11 => "c_11",
                12 => "c_12",
                13 => "c_13",
                14 => "c_14",
                _ => "c_15",
            };
            (name, (i as u64 + 1) * 100)
        })
        .collect();
    inputs.push(("s_0", 1));
    inputs.push(("s_1", 1));
    inputs.push(("s_2", 0));
    inputs.push(("s_3", 0));
    // index = 1+2+0+0 = 3 → out = c[3] = 400.

    let (compiler, mut witness) =
        compile_valid_witness("test/circomlib/mux4_test.circom", &inputs, false);

    let w_out = wire(&compiler, "out");
    assert_eq!(witness[w_out.index()], Fe::from_u64(400));

    // Forge: claim out = c[15] = 1600 (the "all selector bits on" value).
    witness[w_out.index()] = Fe::from_u64(1600);

    assert!(
        compiler.cs.verify(&witness).is_err(),
        "Mux4: forging the output to a different constant while the \
         selector bits are untouched must be rejected by the MultiMux4 \
         output equation. The 4-bit variant has a deeper product chain \
         than Mux3; a missing intermediate here would still be caught \
         because the final `out` equation closes over the full chain."
    );
}
