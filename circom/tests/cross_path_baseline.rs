//! Frozen-baseline regression test for circom benchmark templates.
//!
//! Each circom template is compiled through Lysis, hashed via
//! `zkc::test_support::compute_frozen_baseline`, and compared
//! against a pinned `FrozenBaseline` literal stored below.
//!
//! ## Why a frozen baseline
//!
//! Frozen-baseline pins the structural identity of each template's
//! R1CS, surfacing any future drift — both intentional changes
//! (re-pin via REGEN) and silent regressions (assertion fails with
//! actionable diff).
//!
//! The canonical-multiset hash is **sort-based**
//! (`zkc::test_support::canonical_multiset_hash`), which neutralizes
//! term-order permutations within a single linear combination. It
//! does NOT neutralize wire-index permutations across constraints —
//! and a residual EdDSAPoseidon HashMap iteration leak in wire
//! allocation produces exactly that pattern. EdDSAPoseidon is
//! therefore pinned shape-only via
//! `assert_frozen_baseline_shape_matches`: counts, variable count,
//! and public partition are pinned, but hash drift is accepted.
//! Determinism follow-up tracked separately.
//!
//! ## Re-generating pinned values
//!
//! ```ignore
//! REGEN_FROZEN_BASELINES=1 cargo test --release -p circom \
//!     --test cross_path_baseline -- --nocapture
//! ```
//! Then copy each printed `FrozenBaseline { ... }` literal into the
//! corresponding `PIN_*` constants below. Every re-pin is a
//! documented intentional change — a passing test that later starts
//! failing means a regression that needs root-cause, not a re-pin.
//!
//! ## SHA-256(64)
//!
//! Skipped here. SHA-256(64) has its own hard-gate in
//! `circom/tests/e2e.rs::sha256_64_lysis_hard_gate` (and the (8/16/32)
//! variants). Pinning it twice would only invite re-pin churn.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::Instant;

use ir::passes::canonicalize_ssa;
use ir::types::IrProgram;
use memory::{Bn254Fr, FieldElement};
use zkc::test_support::{
    assert_frozen_baseline_matches, assert_frozen_baseline_shape_matches, compute_frozen_baseline,
    FrozenBaseline,
};

#[path = "cross_path_baseline/pins.rs"]
mod pins;
use pins::*;

// ============================================================================
// Pipeline (Lysis-only)
// ============================================================================

#[derive(Debug)]
enum CompileOutcome {
    Ok(FrozenBaseline),
    Failed(String),
}

fn run_template_lysis(
    name: &str,
    path: &Path,
    lib_dirs: &[PathBuf],
    shape_only: bool,
) -> CompileOutcome {
    let t0 = Instant::now();

    let compile_result = match circom::compile_file(path, lib_dirs) {
        Ok(r) => r,
        Err(e) => {
            return CompileOutcome::Failed(format!("[{name}] compile failed: {e}"));
        }
    };

    let prove_ir = &compile_result.prove_ir;
    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = compile_result
        .capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();

    let baseline_for = |lean: bool| -> Result<FrozenBaseline, String> {
        let mut program: IrProgram<Bn254Fr> = if lean {
            prove_ir.instantiate_lysis_lean_with_outputs::<Bn254Fr>(
                &fe_captures,
                &compile_result.output_names,
            )
        } else {
            prove_ir.instantiate_lysis_with_outputs::<Bn254Fr>(
                &fe_captures,
                &compile_result.output_names,
            )
        }
        .map_err(|e| format!("[{name}] instantiate (lean={lean}) failed: {e}"))?;

        ir::passes::optimize(&mut program);
        // Defensive vs fresh-var counter drift across runs.
        let program = canonicalize_ssa(&program);
        Ok(compute_frozen_baseline(&program))
    };

    let baseline = match baseline_for(false) {
        Ok(b) => b,
        Err(e) => return CompileOutcome::Failed(e),
    };

    // Lean parity: the lean instantiate (no metadata maps) must
    // reproduce the full path's R1CS identically. Templates with the
    // known nondeterministic wire allocation compare shape only — the
    // hash drifts between any two instantiations, lean or not.
    let lean = match baseline_for(true) {
        Ok(b) => b,
        Err(e) => return CompileOutcome::Failed(e),
    };
    let shape_matches = lean.pre_o1_count == baseline.pre_o1_count
        && lean.post_o1_count == baseline.post_o1_count
        && lean.num_variables == baseline.num_variables
        && lean.public_inputs == baseline.public_inputs;
    let lean_matches = if shape_only {
        shape_matches
    } else {
        shape_matches
            && lean.pre_o1_hash == baseline.pre_o1_hash
            && lean.post_o1_hash == baseline.post_o1_hash
    };
    if !lean_matches {
        return CompileOutcome::Failed(format!(
            "[{name}] lean/full instantiate parity mismatch: full=({} pre / {} post / {} vars), lean=({} pre / {} post / {} vars), hashes_equal={}",
            baseline.pre_o1_count,
            baseline.post_o1_count,
            baseline.num_variables,
            lean.pre_o1_count,
            lean.post_o1_count,
            lean.num_variables,
            lean.pre_o1_hash == baseline.pre_o1_hash && lean.post_o1_hash == baseline.post_o1_hash,
        ));
    }

    eprintln!(
        "  {} compiled+pinned in {:.2}s ({} pre-O1 / {} post-O1 / {} vars, lean parity ok)",
        name,
        t0.elapsed().as_secs_f64(),
        baseline.pre_o1_count,
        baseline.post_o1_count,
        baseline.num_variables,
    );

    CompileOutcome::Ok(baseline)
}

fn check_pin(name: &str, actual: &FrozenBaseline, expected: &FrozenBaseline) {
    if std::env::var("REGEN_FROZEN_BASELINES").is_ok() {
        println!("\n=== regen baseline for `{name}` ===");
        println!("FrozenBaseline {{");
        println!("    pre_o1_hash: {:?},", actual.pre_o1_hash);
        println!("    pre_o1_count: {},", actual.pre_o1_count);
        println!("    post_o1_hash: {:?},", actual.post_o1_hash);
        println!("    post_o1_count: {},", actual.post_o1_count);
        println!("    num_variables: {},", actual.num_variables);
        println!("    public_inputs: {:?},", actual.public_inputs);
        println!("}}\n");
        return;
    }
    assert_frozen_baseline_matches(actual, expected);
}

// ============================================================================
// Test entry
// ============================================================================

#[test]
fn cross_path_baseline_circom() {
    let t0 = Instant::now();

    eprintln!();
    eprintln!("=== Cross-path baseline (frozen): circom benchmark templates ===");
    eprintln!();

    let lib_dirs: Vec<PathBuf> = Vec::new();
    // Manifest dir is `circom/`; templates live in `<workspace>/test/...`.
    let workspace_root = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let mut violations: Vec<String> = Vec::new();
    let mut pinned = 0usize;

    // Templates whose hash drifts non-deterministically across runs
    // (HashMap iteration leak in wire allocation upstream).
    // Sort-based canonicalization neutralizes term-order permutations
    // *within* an LC but not wire-index permutations *across* LCs.
    // For these, pin shape only (counts + vars + public) not hash.
    // Tracked as a deterministic-allocation follow-up.
    const HASH_NONDETERMINISTIC: &[&str] = &["EdDSAPoseidon"];

    let templates: Vec<(&str, &str, FrozenBaseline)> = vec![
        (
            "Num2Bits(8)",
            "test/circom/num2bits_8.circom",
            pin_num2bits_8(),
        ),
        ("IsZero", "test/circom/iszero.circom", pin_iszero()),
        (
            "LessThan(8)",
            "test/circom/lessthan_8.circom",
            pin_lessthan_8(),
        ),
        (
            "Pedersen(8)",
            "test/circomlib/pedersen_test.circom",
            pin_pedersen_8(),
        ),
        (
            "EscalarMulFix(253)",
            "test/circomlib/escalarmulfix_test.circom",
            pin_escalarmulfix_253(),
        ),
        (
            "EscalarMulAny(254)",
            "test/circomlib/escalarmulany254_test.circom",
            pin_escalarmulany_254(),
        ),
        (
            "Poseidon(2)",
            "test/circomlib/poseidon_test.circom",
            pin_poseidon_2(),
        ),
        (
            "MiMCSponge(2,220,1)",
            "test/circomlib/mimcsponge_test.circom",
            pin_mimcsponge(),
        ),
        (
            "BabyJubjub",
            "test/circomlib/babyjub_test.circom",
            pin_babyjubjub(),
        ),
        (
            "Pedersen_old(8)",
            "test/circomlib/pedersen_old_test.circom",
            pin_pedersen_old_8(),
        ),
        (
            "EdDSAPoseidon",
            "test/circomlib/eddsaposeidon_test.circom",
            pin_eddsaposeidon(),
        ),
    ];

    let regen = std::env::var("REGEN_FROZEN_BASELINES").is_ok();

    for (name, path, expected) in &templates {
        let path = workspace_root.join(path);
        let shape_only = HASH_NONDETERMINISTIC.contains(name);
        match run_template_lysis(name, &path, &lib_dirs, shape_only) {
            CompileOutcome::Ok(actual) => {
                if regen {
                    check_pin(name, &actual, expected); // prints regen literal
                } else {
                    // Wrap assertion to capture violations rather than panic
                    // mid-loop. Aggregate so the user sees all drift at once.
                    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                        if shape_only {
                            assert_frozen_baseline_shape_matches(&actual, expected);
                        } else {
                            assert_frozen_baseline_matches(&actual, expected);
                        }
                    }));
                    if let Err(e) = result {
                        let msg = if let Some(s) = e.downcast_ref::<String>() {
                            s.clone()
                        } else if let Some(s) = e.downcast_ref::<&str>() {
                            (*s).to_string()
                        } else {
                            "<panic with non-string payload>".into()
                        };
                        violations.push(format!("{name}: {}", msg.lines().next().unwrap_or("")));
                    } else {
                        pinned += 1;
                    }
                }
            }
            CompileOutcome::Failed(err) => {
                violations.push(format!("{name}: {err}"));
            }
        }
    }

    eprintln!();
    eprintln!("Total wall-clock: {:.1}s", t0.elapsed().as_secs_f64());
    eprintln!();
    eprintln!("=== Summary ===");
    eprintln!("- pinned + matching: {pinned}");
    eprintln!("- violations:        {}", violations.len());
    eprintln!();

    if regen {
        eprintln!("REGEN mode: skipping assertion. Copy printed literals into PIN_* constants.");
        return;
    }

    if !violations.is_empty() {
        panic!(
            "cross_path_baseline_circom: {} violation(s):\n  - {}",
            violations.len(),
            violations.join("\n  - ")
        );
    }
}
