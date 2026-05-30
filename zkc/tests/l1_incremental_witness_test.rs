//! L1 incremental-collapse witness-reconstruction soundness.
//!
//! The incremental collapse path folds linear-constraint elimination into
//! constraint emission, then a batch finalize pass mops up the rest. Both
//! produce substitution maps; the compiler composes them
//! ([`compose_substitution_maps`]) so a single witness fixup reconstructs
//! every eliminated wire — both those collapsed during emission and those
//! the finalize pass removed.
//!
//! Two witness-build flows exist; this file pins both.
//!
//! - **Flow A (production).** Generate the witness on the *un-optimized*
//!   system (`compile_ir_with_witness`, all witness ops intact), then
//!   `optimize_r1cs`, then re-derive eliminated wires from the
//!   substitution map. This is what `cli` does. The full initial replay
//!   computes every wire — including direct-`Variable` op inputs — before
//!   any op is pruned, so reconstruction is just a consistent re-derive.
//!   The requirement is that the incremental-collapse path verifies here.
//!
//! - **Flow B (regenerate-after-optimize).** Build the witness *after*
//!   `optimize_r1cs` by replaying the pruned ops from scratch
//!   (`WitnessGenerator::generate`). `IntDivMod`/`PoseidonHash`/`ArtikCall`
//!   read some inputs as raw `Variable`s and never consult the map, so if
//!   a materialized op-input wire was eliminated its op is gone and replay
//!   reads zero. No current code path regenerates after optimize, but the
//!   `l1_flow_b_*` probes document the latent hazard (it affects the batch
//!   optimizer identically — it is not collapse-specific).

use std::collections::HashMap;

use constraints::poseidon::native::poseidon_hash;
use constraints::PoseidonParamsProvider;
use ir::IrLowering;
use memory::{Bn254Fr, FieldElement};
use zkc::r1cs_backend::R1CSCompiler;
use zkc::witness::WitnessGenerator;

type F = Bn254Fr;

fn fe(v: u64) -> FieldElement<F> {
    FieldElement::<F>::from_u64(v)
}

fn lower(source: &str, inputs: &[(&str, FieldElement<F>)]) -> ir::types::IrProgram<F> {
    let witness_names: Vec<&str> = inputs.iter().map(|(n, _)| *n).collect();
    let mut program =
        IrLowering::<F>::lower_circuit(source, &[], &witness_names).expect("circuit must lower");
    ir::passes::optimize(&mut program);
    program
}

fn input_map(inputs: &[(&str, FieldElement<F>)]) -> HashMap<String, FieldElement<F>> {
    inputs.iter().map(|(n, v)| ((*n).to_string(), *v)).collect()
}

fn make_compiler(incremental: bool) -> R1CSCompiler<F> {
    if incremental {
        R1CSCompiler::<F>::new_incremental()
    } else {
        R1CSCompiler::<F>::new()
    }
}

/// Production flow: full witness on the un-optimized system → optimize →
/// re-fill eliminated wires from the substitution map → verify. Mirrors
/// `cli/src/commands/circom.rs`.
fn flow_a_verifies(
    incremental: bool,
    source: &str,
    inputs: &[(&str, FieldElement<F>)],
) -> (bool, usize) {
    let program = lower(source, inputs);
    let mut compiler = make_compiler(incremental);
    let mut witness = compiler
        .compile_ir_with_witness(&program, &input_map(inputs))
        .expect("compile_ir_with_witness must succeed");
    compiler.optimize_r1cs();
    if let Some(subs) = &compiler.substitution_map {
        for (var_idx, lc) in subs {
            witness[*var_idx] = lc.evaluate(&witness).expect("witness fixup must evaluate");
        }
    }
    (
        compiler.cs.verify(&witness).is_ok(),
        compiler.cs.num_constraints(),
    )
}

/// Regenerate-after-optimize flow: optimize first, then replay the pruned
/// ops from scratch via `WitnessGenerator`.
fn flow_b_verifies(
    incremental: bool,
    source: &str,
    inputs: &[(&str, FieldElement<F>)],
) -> (bool, usize) {
    let program = lower(source, inputs);
    let mut compiler = make_compiler(incremental);
    compiler
        .compile_ir(&program)
        .expect("compile_ir must succeed");
    compiler.optimize_r1cs();
    let wg = WitnessGenerator::from_compiler(&compiler);
    let witness = wg
        .generate(&input_map(inputs))
        .expect("witness generation must not error");
    (
        compiler.cs.verify(&witness).is_ok(),
        compiler.cs.num_constraints(),
    )
}

/// Assert the production (Flow A) path verifies for both the batch and
/// the incremental compiler, and that the circuit is non-vacuous (DCE
/// could otherwise leave an empty system that verifies trivially).
fn assert_flow_a(source: &str, inputs: &[(&str, FieldElement<F>)]) {
    let (batch_ok, batch_n) = flow_a_verifies(false, source, inputs);
    assert!(batch_n > 0, "circuit `{source}` produced no constraints");
    assert!(
        batch_ok,
        "batch Flow-A must verify for `{source}` (n={batch_n})"
    );

    let (inc_ok, inc_n) = flow_a_verifies(true, source, inputs);
    assert!(inc_n > 0, "incremental `{source}` produced no constraints");
    assert!(
        inc_ok,
        "incremental collapse Flow-A must verify for `{source}` (n={inc_n})"
    );
}

// Native poseidon with a multi-term argument: `a + b` materializes into a
// fresh wire fed as a direct-`Variable` input to PoseidonHash.
fn poseidon_materialized() -> (String, Vec<(&'static str, FieldElement<F>)>) {
    let params = <F as PoseidonParamsProvider>::default_poseidon_t3();
    let (a, b, c, d) = (3u64, 5u64, 7u64, 11u64);
    let out = poseidon_hash(&params, fe(a).add(&fe(b)), fe(c).mul(&fe(d)));
    (
        "assert_eq(poseidon(a + b, c * d), out)".to_string(),
        vec![
            ("a", fe(a)),
            ("b", fe(b)),
            ("c", fe(c)),
            ("d", fe(d)),
            ("out", out),
        ],
    )
}

fn poseidon_shared() -> (String, Vec<(&'static str, FieldElement<F>)>) {
    let params = <F as PoseidonParamsProvider>::default_poseidon_t3();
    let (a, b, c) = (2u64, 9u64, 4u64);
    let ab = fe(a).add(&fe(b));
    let out = poseidon_hash(&params, ab, fe(c)).add(&poseidon_hash(&params, fe(c), ab));
    (
        "assert_eq(poseidon(a + b, c) + poseidon(c, a + b), out)".to_string(),
        vec![("a", fe(a)), ("b", fe(b)), ("c", fe(c)), ("out", out)],
    )
}

fn arithmetic_control() -> (String, Vec<(&'static str, FieldElement<F>)>) {
    let (a, b, c) = (6u64, 7u64, 8u64);
    let out = fe(a).mul(&fe(b)).add(&fe(c).mul(&fe(c))).add(&fe(a));
    (
        "assert_eq(a * b + c * c + a, out)".to_string(),
        vec![("a", fe(a)), ("b", fe(b)), ("c", fe(c)), ("out", out)],
    )
}

#[test]
fn l1_flow_a_poseidon_materialized_input() {
    let (src, inputs) = poseidon_materialized();
    assert_flow_a(&src, &inputs);
}

#[test]
fn l1_flow_a_poseidon_shared_materialized_input() {
    let (src, inputs) = poseidon_shared();
    assert_flow_a(&src, &inputs);
}

#[test]
fn l1_flow_a_arithmetic_control() {
    let (src, inputs) = arithmetic_control();
    assert_flow_a(&src, &inputs);
}

/// Collapse across the streaming (`compile_instructions_streaming`) path,
/// split over multiple batches. This is the chunk-drain shape used at
/// scale — every other L1 test drives the single-batch `compile_ir`.
/// `(a + b)` and `(c + d)` are materialized into fresh wires that collapse
/// eliminates; splitting the instruction stream exercises collapse folding
/// across batch boundaries plus cross-batch operand resolution, then the
/// production Flow-A witness path (full witness on intact ops → finalize →
/// re-fill from the composed map).
#[test]
fn l1_streaming_collapse_multibatch_verifies() {
    let (a, b, c, d) = (3u64, 5u64, 7u64, 11u64);
    // out = (a + b) * (c + d) + a
    let out = fe(a).add(&fe(b)).mul(&fe(c).add(&fe(d))).add(&fe(a));
    let inputs = [
        ("a", fe(a)),
        ("b", fe(b)),
        ("c", fe(c)),
        ("d", fe(d)),
        ("out", out),
    ];

    let program = lower("assert_eq((a + b) * (c + d) + a, out)", &inputs);
    let instrs: Vec<_> = program.into_instructions();
    assert!(instrs.len() >= 3, "need enough instructions to split");
    let third = instrs.len() / 3;
    let b1 = instrs[..third].to_vec();
    let b2 = instrs[third..2 * third].to_vec();
    let b3 = instrs[2 * third..].to_vec();

    let mut rc = R1CSCompiler::<F>::new_incremental();
    rc.compile_instructions_streaming(b1)
        .expect("batch 1 must compile");
    rc.compile_instructions_streaming(b2)
        .expect("batch 2 must compile");
    rc.compile_instructions_streaming(b3)
        .expect("batch 3 must compile");

    // Non-vacuity: collapse must actually fold something on this circuit.
    let survivors_pre = rc.cs.num_constraints();

    // Flow A: build the full witness on the intact op trace (collapse does
    // not prune ops), before finalize. It must satisfy the collapse
    // survivors.
    let imap = input_map(&inputs);
    let witness = WitnessGenerator::from_compiler(&rc)
        .generate(&imap)
        .expect("streaming witness generation must succeed");
    assert!(
        rc.cs.verify(&witness).is_ok(),
        "collapse survivors rejected the streaming witness"
    );

    // Finalize composes the collapse map with the batch map, then re-fill.
    rc.optimize_r1cs();
    let subs = rc
        .substitution_map
        .as_ref()
        .expect("streaming collapse + finalize must produce a substitution map");
    assert!(
        !subs.is_empty(),
        "collapse made no progress on streaming path"
    );
    let mut w_post = witness.clone();
    for (var_idx, lc) in subs {
        w_post[*var_idx] = lc.evaluate(&w_post).expect("composed fixup must evaluate");
    }
    assert!(
        rc.cs.verify(&w_post).is_ok(),
        "streaming collapse + finalize rejected the reconstructed witness"
    );
    assert!(
        rc.cs.num_constraints() <= survivors_pre,
        "finalize must not grow the system"
    );
}

/// Latent regenerate-after-optimize hazard (Flow B). Pure-arithmetic
/// circuits have no direct-Variable op inputs, so they survive Flow B on
/// both compilers; the poseidon probes are expected to break under Flow B
/// on *both* batch and incremental until op-input wires are protected
/// from elimination. Asserted here as the current (documented) reality so
/// a future fix that makes Flow B sound flips this test loudly.
#[test]
fn l1_flow_b_arithmetic_control_holds() {
    let (src, inputs) = arithmetic_control();
    assert!(
        flow_b_verifies(false, &src, &inputs).0,
        "batch Flow-B arithmetic"
    );
    assert!(
        flow_b_verifies(true, &src, &inputs).0,
        "incremental Flow-B arithmetic"
    );
}

#[test]
fn l1_flow_b_poseidon_hazard_is_present_on_both_compilers() {
    let (src, inputs) = poseidon_materialized();
    // The materialized direct-Variable op input is eliminated by both the
    // batch (max-frequency) and incremental (highest-index) pivot rules,
    // so neither survives a from-scratch replay of the pruned ops. This is
    // a latent, non-production hazard; pinning it documents the boundary.
    assert!(
        !flow_b_verifies(false, &src, &inputs).0,
        "batch Flow-B unexpectedly verified — the op-input hazard may have been fixed; \
         update this pin and the Flow-A story"
    );
    assert!(
        !flow_b_verifies(true, &src, &inputs).0,
        "incremental Flow-B unexpectedly verified — update this pin"
    );
}
