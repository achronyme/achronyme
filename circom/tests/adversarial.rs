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

use compiler::r1cs_backend::R1CSCompiler;
use constraints::r1cs::Variable;
use memory::{Bn254Fr, FieldElement};

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
