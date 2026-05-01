//! Frozen-baseline regression test for circom benchmark templates.
//!
//! Phase 2.C — converted from a Lysis-vs-Legacy byte-identity gate
//! (`38913753`, Phase 1.A) to a frozen-baseline regression gate.
//! Each circom template is compiled through Lysis, hashed via
//! `zkc::test_support::compute_frozen_baseline`, and compared against
//! a pinned `FrozenBaseline` literal stored below.
//!
//! ## Why frozen baseline replaces Lysis-vs-Legacy
//!
//! With Lysis as default and the Legacy path scheduled for deletion in
//! Phase 2.A, dual-path comparison becomes vacuous (Lysis-vs-Lysis).
//! Frozen-baseline pins the structural identity of each template's
//! R1CS at HEAD-of-Phase-2.B, surfacing any future drift — both
//! intentional changes (re-pin via REGEN) and silent regressions
//! (assertion fails with actionable diff).
//!
//! The canonical-multiset hash is **sort-based**
//! (`zkc::test_support::canonical_multiset_hash`), which neutralizes
//! term-order permutations within a single linear combination. It
//! does NOT neutralize wire-index permutations across constraints —
//! and the EdDSAPoseidon HashMap iteration leak (flagged in Phase 1.A)
//! produces exactly that pattern. EdDSAPoseidon is therefore pinned
//! shape-only via `assert_frozen_baseline_shape_matches`: counts,
//! variable count, and public partition are pinned, but hash drift
//! is accepted. Tracked as a determinism follow-up post-tag.
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

// ============================================================================
// Pipeline (Lysis-only)
// ============================================================================

#[derive(Debug)]
enum CompileOutcome {
    Ok(FrozenBaseline),
    Failed(String),
}

fn run_template_lysis(name: &str, path: &Path, lib_dirs: &[PathBuf]) -> CompileOutcome {
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

    let mut program: IrProgram<Bn254Fr> = match prove_ir
        .instantiate_lysis_with_outputs::<Bn254Fr>(&fe_captures, &compile_result.output_names)
    {
        Ok(p) => p,
        Err(e) => {
            return CompileOutcome::Failed(format!(
                "[{name}] instantiate_lysis_with_outputs failed: {e}"
            ));
        }
    };

    ir::passes::optimize(&mut program);
    // Defensive vs fresh-var counter drift across runs.
    let program = canonicalize_ssa(&program);

    let baseline = compute_frozen_baseline(&program);
    eprintln!(
        "  {} compiled+pinned in {:.2}s ({} pre-O1 / {} post-O1 / {} vars)",
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
    // (HashMap iteration leak in wire allocation upstream — Phase 1.A
    // noted). Sort-based canonicalization neutralizes term-order
    // permutations *within* an LC but not wire-index permutations
    // *across* LCs. For these, pin shape only (counts + vars + public)
    // not hash. Tracked as a deterministic-allocation follow-up.
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
        match run_template_lysis(name, &path, &lib_dirs) {
            CompileOutcome::Ok(actual) => {
                if regen {
                    check_pin(name, &actual, expected); // prints regen literal
                } else {
                    let shape_only = HASH_NONDETERMINISTIC.contains(name);
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

// ============================================================================
// Pinned canonical-multiset baselines
// ============================================================================

fn pin_num2bits_8() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            22, 170, 64, 81, 90, 153, 56, 218, 110, 128, 40, 166, 159, 78, 229, 120, 101, 110, 239,
            140, 108, 198, 91, 188, 157, 170, 125, 164, 110, 92, 133, 175,
        ],
        pre_o1_count: 25,
        post_o1_hash: [
            9, 27, 54, 13, 204, 78, 211, 178, 34, 132, 195, 10, 254, 69, 169, 64, 236, 223, 211,
            119, 35, 12, 234, 41, 4, 22, 42, 67, 202, 9, 243, 245,
        ],
        post_o1_count: 9,
        num_variables: 26,
        public_inputs: vec![
            "in".into(),
            "out_0".into(),
            "out_1".into(),
            "out_2".into(),
            "out_3".into(),
            "out_4".into(),
            "out_5".into(),
            "out_6".into(),
            "out_7".into(),
        ],
    }
}

fn pin_iszero() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            52, 44, 65, 177, 195, 202, 234, 59, 202, 203, 18, 224, 74, 209, 11, 144, 20, 106, 123,
            127, 74, 80, 9, 74, 225, 254, 88, 148, 197, 92, 247, 230,
        ],
        pre_o1_count: 4,
        post_o1_hash: [
            217, 70, 234, 155, 128, 234, 125, 16, 14, 196, 247, 114, 143, 130, 24, 228, 234, 171,
            24, 209, 250, 87, 18, 189, 69, 214, 38, 122, 26, 222, 58, 25,
        ],
        post_o1_count: 2,
        num_variables: 6,
        public_inputs: vec!["in".into(), "out".into()],
    }
}

fn pin_lessthan_8() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            138, 141, 86, 1, 5, 122, 166, 228, 14, 119, 185, 236, 203, 20, 255, 226, 102, 13, 193,
            224, 19, 177, 162, 120, 225, 55, 93, 56, 43, 154, 31, 248,
        ],
        pre_o1_count: 30,
        post_o1_hash: [
            176, 242, 80, 176, 11, 255, 89, 7, 147, 126, 242, 169, 79, 161, 179, 147, 34, 211, 10,
            69, 145, 106, 245, 103, 229, 89, 160, 115, 186, 173, 89, 126,
        ],
        post_o1_count: 9,
        num_variables: 33,
        public_inputs: vec!["in_0".into(), "in_1".into(), "out".into()],
    }
}

fn pin_pedersen_8() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            83, 47, 226, 200, 86, 3, 177, 90, 255, 16, 70, 233, 97, 159, 132, 255, 26, 107, 74,
            107, 118, 253, 129, 163, 146, 76, 110, 146, 102, 144, 209, 142,
        ],
        pre_o1_count: 30,
        post_o1_hash: [
            240, 198, 55, 137, 174, 219, 237, 91, 127, 203, 92, 102, 200, 22, 173, 135, 156, 228,
            108, 143, 121, 81, 59, 187, 121, 133, 157, 72, 180, 34, 67, 72,
        ],
        post_o1_count: 13,
        num_variables: 57,
        public_inputs: vec!["out_0".into(), "out_1".into()],
    }
}

fn pin_escalarmulfix_253() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            8, 52, 148, 216, 41, 153, 46, 152, 92, 155, 189, 54, 144, 227, 141, 190, 35, 124, 57,
            106, 168, 142, 245, 176, 32, 41, 148, 92, 35, 75, 169, 169,
        ],
        pre_o1_count: 27,
        post_o1_hash: [
            228, 230, 80, 210, 118, 228, 106, 181, 76, 203, 19, 68, 189, 116, 36, 68, 99, 143, 30,
            104, 138, 44, 36, 236, 246, 150, 16, 56, 131, 216, 21, 117,
        ],
        post_o1_count: 11,
        num_variables: 44,
        public_inputs: vec!["out_0".into(), "out_1".into()],
    }
}

fn pin_escalarmulany_254() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            246, 160, 73, 112, 140, 17, 214, 216, 137, 204, 185, 102, 177, 17, 204, 234, 241, 250,
            51, 134, 191, 164, 218, 93, 148, 62, 7, 122, 165, 211, 205, 231,
        ],
        pre_o1_count: 5325,
        post_o1_hash: [
            82, 93, 224, 100, 151, 59, 194, 221, 117, 131, 16, 31, 56, 85, 82, 144, 90, 28, 197,
            137, 190, 28, 36, 80, 17, 61, 218, 228, 111, 53, 111, 43,
        ],
        post_o1_count: 2310,
        num_variables: 5582,
        public_inputs: vec!["out_0".into(), "out_1".into()],
    }
}

fn pin_poseidon_2() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            10, 36, 63, 36, 171, 14, 78, 202, 254, 82, 238, 72, 249, 65, 129, 161, 53, 175, 58,
            247, 57, 84, 45, 85, 122, 194, 235, 2, 168, 85, 53, 178,
        ],
        pre_o1_count: 491,
        post_o1_hash: [
            155, 15, 251, 46, 236, 19, 201, 89, 251, 223, 195, 198, 231, 90, 74, 111, 143, 180,
            211, 114, 108, 97, 185, 104, 99, 19, 105, 1, 65, 75, 254, 155,
        ],
        post_o1_count: 240,
        num_variables: 494,
        public_inputs: vec!["inputs_0".into(), "inputs_1".into(), "out".into()],
    }
}

fn pin_mimcsponge() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            21, 105, 6, 67, 74, 40, 158, 193, 201, 7, 18, 192, 184, 196, 52, 95, 74, 88, 34, 20,
            154, 59, 164, 25, 222, 238, 171, 19, 106, 13, 234, 132,
        ],
        pre_o1_count: 2581,
        post_o1_hash: [
            238, 17, 118, 93, 21, 197, 216, 208, 114, 144, 10, 33, 217, 223, 240, 217, 182, 55,
            139, 123, 225, 139, 26, 161, 163, 208, 247, 96, 185, 251, 94, 112,
        ],
        post_o1_count: 1317,
        num_variables: 2585,
        public_inputs: vec!["outs_0".into()],
    }
}

fn pin_babyjubjub() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            94, 33, 189, 175, 173, 144, 34, 119, 31, 155, 206, 153, 226, 25, 118, 123, 4, 182, 67,
            196, 110, 107, 245, 62, 191, 106, 20, 136, 13, 177, 210, 48,
        ],
        pre_o1_count: 30,
        post_o1_hash: [
            255, 1, 85, 58, 96, 215, 109, 91, 15, 212, 178, 94, 43, 27, 183, 11, 14, 102, 111, 132,
            199, 103, 30, 0, 105, 117, 224, 248, 152, 95, 24, 38,
        ],
        post_o1_count: 15,
        num_variables: 34,
        public_inputs: vec!["xout".into(), "yout".into()],
    }
}

fn pin_pedersen_old_8() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            211, 50, 45, 195, 124, 51, 201, 112, 210, 13, 114, 37, 146, 153, 121, 4, 236, 197, 96,
            218, 94, 219, 58, 125, 48, 228, 72, 196, 96, 154, 254, 78,
        ],
        pre_o1_count: 37,
        post_o1_hash: [
            167, 177, 144, 32, 220, 107, 139, 158, 58, 130, 88, 180, 64, 88, 177, 232, 121, 185,
            151, 38, 90, 166, 225, 161, 80, 55, 130, 139, 202, 138, 135, 65,
        ],
        post_o1_count: 18,
        num_variables: 46,
        public_inputs: vec!["out_0".into(), "out_1".into()],
    }
}

fn pin_eddsaposeidon() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            46, 60, 63, 224, 235, 241, 9, 142, 21, 20, 136, 59, 192, 205, 235, 241, 38, 31, 226,
            81, 139, 249, 252, 4, 67, 3, 48, 16, 103, 117, 21, 224,
        ],
        pre_o1_count: 9719,
        post_o1_hash: [
            240, 149, 78, 219, 114, 124, 39, 198, 10, 186, 154, 82, 176, 223, 127, 71, 178, 235,
            41, 124, 181, 152, 33, 150, 57, 189, 64, 229, 57, 205, 255, 189,
        ],
        post_o1_count: 3965,
        num_variables: 10410,
        public_inputs: vec!["dummy".into()],
    }
}
