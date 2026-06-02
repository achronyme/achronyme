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
        .instantiate_lysis_with_outputs(&fe_captures, &compile_result.output_names)
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

#[path = "adversarial/bit_primitives.rs"]
mod bit_primitives;

#[path = "adversarial/comparators.rs"]
mod comparators;

#[path = "adversarial/mux.rs"]
mod mux;

#[path = "adversarial/num2bits.rs"]
mod num2bits;

#[path = "adversarial/r1pp_followups.rs"]
mod r1pp_followups;
