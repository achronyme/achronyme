//! Adversarial soundness tests for imported circomlib primitives.
//!
//! The `r1cs_optimization_benchmark` in `e2e.rs` shows Achronyme producing
//! fewer constraints than circom 2.x O2 on `Num2Bits(8)` (9 vs 17) and
//! `LessThan(8)` (10 vs 20). The deltas come from LC folding — circom
//! materializes linear combinations that Achronyme keeps free — but
//! "fewer constraints" is also the signature of an under-constrained
//! circuit, which is the #1 class of ZK vulnerability.
//!
//! These tests prove that the constraint systems emitted for those two
//! templates are sufficient for soundness by constructing valid witnesses,
//! mutating a specific wire to impersonate a malicious prover, and
//! asserting that `cs.verify` rejects the forgery.
//!
//! Each test names the exact constraint that must catch the attack in
//! its comment so a future reader can audit whether the forgery would
//! bypass a simpler constraint system.

use std::collections::HashMap;
use std::path::Path;
use std::sync::Mutex;

use constraints::r1cs::Variable;
use memory::{Bn254Fr, FieldElement};
use zkc::r1cs_backend::R1CSCompiler;

/// Serialise tests that mutate the `R1PP_ENABLED` process env var. The
/// var is read on every `lower_for_loop` call, so two parallel tests
/// flipping it would race. Tests in this file that DON'T touch the var
/// are insensitive to its value (the multi-dim/component-call gates in
/// `is_memoizable` reject memoization for the surrounding circuits) so
/// they don't need the guard. Note: this Mutex prevents Rust-side
/// concurrency races within these tests; it does NOT satisfy the
/// stdlib `set_var` safety contract against concurrent C-side `getenv`
/// readers, which is a theoretical TSAN concern not hit on Linux glibc
/// under `cargo test`.
static R1PP_ENV_LOCK: Mutex<()> = Mutex::new(());

/// RAII guard that pins `R1PP_ENABLED` for its lifetime and restores
/// the prior value on Drop. Crucially, the restoration runs even if
/// the test panics, so a leaked env var cannot poison subsequent test
/// runs in the same process (and the `R1PP_ENV_LOCK` Mutex never
/// inherits a polluted state via poison-recovery).
struct R1ppEnvGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    prior: Option<String>,
}

impl R1ppEnvGuard {
    fn new(value: &str) -> Self {
        let lock = R1PP_ENV_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let prior = std::env::var("R1PP_ENABLED").ok();
        // SAFETY: env mutation is guarded by R1PP_ENV_LOCK against
        // concurrent Rust callers in this test file. Other test files
        // do not read R1PP_ENABLED. This does not protect against
        // simultaneous C-side getenv readers, but cargo test on Linux
        // glibc has no such readers.
        unsafe {
            std::env::set_var("R1PP_ENABLED", value);
        }
        Self { _lock: lock, prior }
    }
}

impl Drop for R1ppEnvGuard {
    fn drop(&mut self) {
        // SAFETY: see R1ppEnvGuard::new — same lock held for Drop.
        unsafe {
            match &self.prior {
                Some(v) => std::env::set_var("R1PP_ENABLED", v),
                None => std::env::remove_var("R1PP_ENABLED"),
            }
        }
    }
}

type Fe = FieldElement<Bn254Fr>;

/// Compile a circom file through the full Achronyme pipeline,
/// optionally run the R1CS optimizer, generate a valid witness,
/// and return the compiler plus witness ready for adversarial
/// mutation.
///
/// Some attacks target wires that survive optimization (e.g. the
/// bit outputs of Num2Bits, which are the template's public
/// outputs); for those, pass `optimize = true` so the test speaks
/// to the exact 9-constraint system the benchmark publishes.
///
/// Other attacks target wires that the R1CS optimizer substitutes
/// away via linear elimination (e.g. LessThan's `out` wire, which
/// is purely `1 - n2b.out_n`); for those, pass `optimize = false`
/// so the output wire still exists as an independent variable.
fn compile_valid_witness(
    circom_file: &str,
    inputs: &[(&str, u64)],
    optimize: bool,
) -> (R1CSCompiler<Bn254Fr>, Vec<Fe>) {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join(circom_file);
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("compile {circom_file} failed: {e}"));
    let prove_ir = &compile_result.prove_ir;
    let capture_values = &compile_result.capture_values;
    let fe_captures: HashMap<String, Fe> = capture_values
        .iter()
        .map(|(k, v)| (k.clone(), Fe::from_u64(*v)))
        .collect();

    let mut program = prove_ir
        .instantiate_with_outputs(&fe_captures, &compile_result.output_names)
        .unwrap_or_else(|e| panic!("instantiate failed: {e}"));
    ir::passes::optimize(&mut program);

    let fe_inputs: HashMap<String, Fe> = inputs
        .iter()
        .map(|(k, v)| (k.to_string(), Fe::from_u64(*v)))
        .collect();

    let mut all_signals =
        circom::witness::compute_witness_hints_with_captures(prove_ir, &fe_inputs, capture_values)
            .unwrap_or_else(|e| panic!("witness failed: {e}"));
    for (cname, fe) in &fe_captures {
        all_signals.entry(cname.clone()).or_insert(*fe);
    }

    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    let mut witness = compiler
        .compile_ir_with_witness(&program, &all_signals)
        .unwrap_or_else(|e| panic!("r1cs compile failed: {e}"));

    if optimize {
        // Re-fill substituted wires from the substitution map so the
        // honest witness still verifies against the optimized system.
        compiler.optimize_r1cs();
        if let Some(subs) = &compiler.substitution_map {
            for (var_idx, lc) in subs {
                witness[*var_idx] = lc.evaluate(&witness).unwrap();
            }
        }
    }

    // Honest witness MUST verify — otherwise the test below can't
    // distinguish "forgery caught" from "circuit is broken".
    compiler
        .cs
        .verify(&witness)
        .expect("honest witness must verify before mutation");

    (compiler, witness)
}

/// Look up a wire by name, failing loudly with the full binding
/// list if the name is absent — this catches renaming drift in the
/// lowering pipeline without masking soundness bugs.
fn wire(compiler: &R1CSCompiler<Bn254Fr>, name: &str) -> Variable {
    compiler.bindings.get(name).copied().unwrap_or_else(|| {
        let mut names: Vec<&str> = compiler.bindings.keys().map(String::as_str).collect();
        names.sort_unstable();
        panic!("wire `{name}` not found in R1CS bindings; available names: {names:?}",)
    })
}

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

// ============================================================================
// Known coverage gap — BinSum / Multiplexer
// ============================================================================
//
// The beta.20 pre-release audit flagged adversarial tests for `BinSum`
// and the general `Multiplexer(wIn, nIn)` template. Both compile
// through `circom::compile_file` today (see `binsum_circomlib_compile`
// and `multiplexer_circomlib_compile` in `e2e.rs`) but neither reaches
// R1CS yet:
//
//   * BinSum uses the `var lin += signal * e2` pattern followed by
//     `out[k] <-- (lin >> k) & 1`. Achronyme's lowering does not yet
//     track compile-time `var`s that accumulate signal expressions,
//     so the resulting R1CS is incomplete.
//   * Multiplexer feeds a 2-D signal input `inp[nIn][wIn]` through a
//     Decoder + EscalarProduct. The witness evaluator still lacks the
//     flattened-naming pass for 2-D signal arrays.
//
// Adversarial soundness tests for these two templates are therefore
// deferred until the R1CS path works end-to-end; attempting a forgery
// against a circuit that isn't fully constrained yet would be noise,
// not signal. The deferral is tracked in
// `project_beta20_circom_session_apr4.md` under "BinSum / Multiplexer
// pending E2E".

// ============================================================================
// R1″ Phase 6 / Follow-up A — placeholder-aware lower_multi_index
// ============================================================================
//
// Edit 2 of Follow-up A made `lower_multi_index` skip its const-fold
// fast path when the active R1″ memoization placeholder loop variable
// appears in any index slot. Edit 4 (not yet landed at this commit)
// will drop the `body_has_multi_dim_index` disqualifier from
// `is_memoizable` so that bodies with multi-dim shapes like `c[i][k]`
// become memoizable.
//
// This regression test pins the contract: under both R1PP_ENABLED=0
// and R1PP_ENABLED=1, the Mux3 wrapper must produce IDENTICAL
// constraint counts AND must continue to reject the same forgery
// (`out` flipped while the selector encodes a different index). The
// test is "trivially passing" today — Mux3's MultiMux3(1) instance
// has n=1 < 4 so the iteration-count gate already rejects memoization
// regardless of the multi-dim gate. Once Edit 4 widens the population
// of memoizable bodies, this test becomes the regression watchdog
// proving Edits 1+2 keep the IR byte-identical.
//
// Counter-factual procedure (manual, off-CI): stage Edit 4 (gate
// removed) WITHOUT Edits 1+2 on a temporary branch and re-run this
// test under R1PP_ENABLED=1. It MUST fail (witness mismatch or
// constraint divergence), proving the placeholder gates were
// load-bearing.

fn compile_mux3_active_selector() -> (R1CSCompiler<Bn254Fr>, Vec<Fe>) {
    compile_valid_witness(
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
    )
}

#[test]
fn r1pp_followup_a_mux3_constraint_count_byte_identical_across_modes() {
    let (compiler_off, _w_off) = {
        let _g = R1ppEnvGuard::new("0");
        compile_mux3_active_selector()
    };
    let count_off = compiler_off.cs.num_constraints();

    let (compiler_on, _w_on) = {
        let _g = R1ppEnvGuard::new("1");
        compile_mux3_active_selector()
    };
    let count_on = compiler_on.cs.num_constraints();

    assert_eq!(
        count_off, count_on,
        "R1″ Follow-up A regression: Mux3 must produce byte-identical \
         constraint counts under R1PP_ENABLED=0 and R1PP_ENABLED=1. A \
         divergence here means Edits 1+2 (placeholder-aware \
         lower_multi_index) failed to keep memoized lowering equivalent \
         to legacy unrolling. Counter-factual: this test is what fails \
         when Edit 4 ships without Edits 1+2."
    );
}

/// Dormant until Edit 4 widens memoization to multi-dim bodies. With
/// the current iteration-count gate (`< 4`) and the still-active
/// `body_has_multi_dim_index` gate, Mux3's MultiMux3(1) instance never
/// memoizes regardless of `R1PP_ENABLED` value, so this test asserts
/// the same property as `mux3_forge_output_with_active_selector_rejected`
/// for now. It earns its keep AFTER Edit 4: the constraint-count test
/// above pins structural divergence, but a lowering bug that produces
/// the SAME constraint COUNT with WRONG constraint CONTENTS would slip
/// past it. This forgery test catches that residue by exercising the
/// soundness property under R1PP=1 specifically.
#[test]
fn r1pp_followup_a_mux3_forgery_rejected_under_r1pp_on() {
    let (compiler, mut witness) = {
        let _g = R1ppEnvGuard::new("1");
        compile_mux3_active_selector()
    };

    let w_out = wire(&compiler, "out");
    // Honest: index = 1+2+0 = 3 → out = c[3] = 40.
    assert_eq!(witness[w_out.index()], Fe::from_u64(40));

    witness[w_out.index()] = Fe::from_u64(10);

    assert!(
        compiler.cs.verify(&witness).is_err(),
        "R1″ Follow-up A regression: forging Mux3's `out` under \
         R1PP_ENABLED=1 must still be rejected. If memoized lowering \
         dropped a constraint OR produced same-count-different-contents \
         IR, this assertion catches the under-constraint silently \
         introduced by the optimisation."
    );
}

// ============================================================================
// R1″ Phase 6 / Follow-up B — vestigial gate cleanup
// ============================================================================
//
// Follow-up B dropped the `body_reads_capture_array` gate from
// `is_memoizable` after empirical investigation showed the gate
// fired 5 times across the full e2e suite and never returned
// `true`. The cleanup is behaviourally a no-op today (no template
// memoizes that wouldn't have memoized before).
//
// This regression pin compiles EdDSAPoseidon — the heaviest circuit
// in the corpus, exercising Ark/Mix/PoseidonEx/EscalarMulFix —
// under both R1PP modes and asserts the constraint counts are
// byte-identical. If a future change accidentally re-introduces a
// behaviour-altering gate or breaks the cross-mode equivalence
// contract, this test trips immediately.

fn compile_eddsaposeidon_constraint_count() -> usize {
    use std::collections::HashMap;
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/eddsaposeidon_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("EdDSAPoseidon compile failed: {e}"));
    let prove_ir = &compile_result.prove_ir;
    let capture_values = &compile_result.capture_values;
    let fe_captures: HashMap<String, Fe> = capture_values
        .iter()
        .map(|(k, v)| (k.clone(), Fe::from_u64(*v)))
        .collect();

    let mut program = prove_ir
        .instantiate_with_outputs(&fe_captures, &compile_result.output_names)
        .unwrap_or_else(|e| panic!("EdDSAPoseidon instantiate failed: {e}"));
    ir::passes::optimize(&mut program);

    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    compiler
        .compile_ir(&program)
        .unwrap_or_else(|e| panic!("EdDSAPoseidon R1CS compile failed: {e}"));
    compiler.cs.num_constraints()
}

#[test]
fn r1pp_followup_b_eddsaposeidon_constraint_count_byte_identical_across_modes() {
    let count_off = {
        let _g = R1ppEnvGuard::new("0");
        compile_eddsaposeidon_constraint_count()
    };

    let count_on = {
        let _g = R1ppEnvGuard::new("1");
        compile_eddsaposeidon_constraint_count()
    };

    assert_eq!(
        count_off, count_on,
        "R1″ Follow-up B regression: EdDSAPoseidon must produce \
         byte-identical R1CS constraint counts under R1PP_ENABLED=0 \
         and R1PP_ENABLED=1. A divergence here means a behaviour-\
         altering gate slipped into is_memoizable since Follow-up B's \
         vestigial-gate cleanup, breaking cross-mode equivalence."
    );
}
