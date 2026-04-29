//! Lysis-vs-Legacy cross-path equivalence baseline (circom templates).
//!
//! Goal: for every benchmark circom template, verify that
//! `instantiate_with_outputs` (Legacy frontend) and
//! `instantiate_lysis_with_outputs` (Lysis frontend) produce
//! byte-identical R1CS, both pre-O1 and post-O1.
//!
//! "Byte-identical" = canonical multiset equality on constraints
//! (each constraint's A/B/C linear combinations sorted+simplified, then
//! constraint vec sorted), matching variable count, matching
//! public/private partition.
//!
//! This is the gating data for Phase 1.A in BETA20-CLOSEOUT.md
//! (Lysis as default for circom). See cross-path-baseline-2026-04-28
//! plan dir for the report.
//!
//! Pipeline per side, exactly mirroring `r1cs_optimization_benchmark`
//! but without the witness verification (we want constraint identity,
//! not witness identity, and the witness-hint pipeline can shape-
//! diverge between frontends without affecting R1CS):
//!
//! 1. `compile_file_with_frontend(path, libs, Frontend::{Legacy,Lysis})`
//! 2. `instantiate_with_outputs` (legacy) or `instantiate_lysis_with_outputs` (lysis)
//! 3. `ir::passes::optimize(&mut program)`
//! 4. `canonicalize_ssa(&program)` — defensive; neutralises fresh-var counter drift
//! 5. `R1CSCompiler::compile_ir(&program)`
//! 6. snapshot constraints → pre-O1 multiset
//! 7. `compiler.optimize_r1cs()` → post-O1 multiset
//!
//! `canonicalize_constraint` / `lc_to_terms` are copied locally from
//! `zkc::lysis_oracle::compare` (private). The oracle's
//! `semantic_equivalence` does *only* pre-O1 comparison and returns a
//! boolean variant — it can't surface the constraint diff or the
//! post-O1 step the baseline needs.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use circom::Frontend;
use constraints::r1cs::{Constraint, LinearCombination};
use ir::passes::canonicalize_ssa;
use ir::types::{Instruction, IrProgram, Visibility};
use memory::{Bn254Fr, FieldBackend, FieldElement};
use zkc::r1cs_backend::R1CSCompiler;

// ── Canonicalisation helpers (copied from zkc::lysis_oracle::compare) ──

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CanonicalConstraint {
    a: Vec<(usize, [u64; 4])>,
    b: Vec<(usize, [u64; 4])>,
    c: Vec<(usize, [u64; 4])>,
}

fn lc_to_terms<F: FieldBackend>(lc: &LinearCombination<F>) -> Vec<(usize, [u64; 4])> {
    lc.simplify()
        .terms()
        .iter()
        .map(|(v, coeff)| (v.index(), coeff.to_canonical()))
        .collect()
}

fn canonicalize_constraint<F: FieldBackend>(c: &Constraint<F>) -> CanonicalConstraint {
    CanonicalConstraint {
        a: lc_to_terms(&c.a),
        b: lc_to_terms(&c.b),
        c: lc_to_terms(&c.c),
    }
}

fn constraint_multiset<F: FieldBackend>(constraints: &[Constraint<F>]) -> Vec<CanonicalConstraint> {
    let mut out: Vec<CanonicalConstraint> =
        constraints.iter().map(canonicalize_constraint).collect();
    out.sort();
    out
}

fn extract_public_inputs<F: FieldBackend>(program: &IrProgram<F>) -> Vec<String> {
    program
        .iter()
        .filter_map(|inst| match inst {
            Instruction::Input {
                name,
                visibility: Visibility::Public,
                ..
            } => Some(name.clone()),
            _ => None,
        })
        .collect()
}

// ── Per-side compile + measure ────────────────────────────────────

#[derive(Debug)]
struct SideResult {
    pre_o1: Vec<CanonicalConstraint>,
    post_o1: Vec<CanonicalConstraint>,
    constraints_pre: usize,
    constraints_post: usize,
    variables: usize,
    public_inputs: Vec<String>,
    elapsed: Duration,
}

#[derive(Debug)]
enum Side {
    Legacy,
    Lysis,
}

#[derive(Debug)]
enum SideOutcome {
    Ok(SideResult),
    Failed(String),
}

fn run_side(side: Side, name: &str, path: &Path, lib_dirs: &[PathBuf]) -> SideOutcome {
    let t0 = Instant::now();

    // Step 1: compile (frontend-aware).
    let frontend = match side {
        Side::Legacy => Frontend::Legacy,
        Side::Lysis => Frontend::Lysis,
    };
    let compile_result = match circom::compile_file_with_frontend(path, lib_dirs, frontend) {
        Ok(r) => r,
        Err(e) => {
            return SideOutcome::Failed(format!("[{name}/{side:?}] compile failed: {e}"));
        }
    };

    let prove_ir = &compile_result.prove_ir;
    let capture_values = &compile_result.capture_values;
    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();

    // Step 2: instantiate.
    let mut program: IrProgram<Bn254Fr> = match side {
        Side::Legacy => match prove_ir
            .instantiate_with_outputs::<Bn254Fr>(&fe_captures, &compile_result.output_names)
        {
            Ok(p) => p,
            Err(e) => {
                return SideOutcome::Failed(format!(
                    "[{name}/Legacy] instantiate_with_outputs failed: {e}"
                ));
            }
        },
        Side::Lysis => match prove_ir
            .instantiate_lysis_with_outputs::<Bn254Fr>(&fe_captures, &compile_result.output_names)
        {
            Ok(p) => p,
            Err(e) => {
                return SideOutcome::Failed(format!(
                    "[{name}/Lysis] instantiate_lysis_with_outputs failed: {e}"
                ));
            }
        },
    };

    // Step 3: optimize (IR-level). Critical: we want any optimize-side
    // asymmetry to surface, not be hidden.
    ir::passes::optimize(&mut program);

    // Step 4: canonicalise SSA (defensive vs fresh-var counter drift).
    let program = canonicalize_ssa(&program);

    // Step 5: R1CS compile.
    let mut compiler = R1CSCompiler::<Bn254Fr>::new();
    if let Err(e) = compiler.compile_ir(&program) {
        return SideOutcome::Failed(format!("[{name}/{side:?}] R1CS compile_ir failed: {e}"));
    }

    // Step 6: snapshot pre-O1.
    let pre_o1_raw: Vec<Constraint<Bn254Fr>> = compiler.cs.constraints().to_vec();
    let pre_o1 = constraint_multiset(&pre_o1_raw);
    let constraints_pre = compiler.cs.num_constraints();

    // Step 7: O1.
    let _stats = compiler.optimize_r1cs();
    let post_o1 = constraint_multiset(compiler.cs.constraints());
    let constraints_post = compiler.cs.num_constraints();
    let variables = compiler.cs.num_variables();
    let public_inputs = extract_public_inputs(&program);

    SideOutcome::Ok(SideResult {
        pre_o1,
        post_o1,
        constraints_pre,
        constraints_post,
        variables,
        public_inputs,
        elapsed: t0.elapsed(),
    })
}

// ── Diff helpers ──────────────────────────────────────────────────

/// Symmetric difference: returns (only_in_a, only_in_b). Both inputs
/// must already be sorted (multisets).
fn multiset_sym_diff(
    a: &[CanonicalConstraint],
    b: &[CanonicalConstraint],
) -> (Vec<CanonicalConstraint>, Vec<CanonicalConstraint>) {
    use std::collections::BTreeMap;

    let mut count_a: BTreeMap<&CanonicalConstraint, i64> = BTreeMap::new();
    for c in a {
        *count_a.entry(c).or_default() += 1;
    }
    for c in b {
        *count_a.entry(c).or_default() -= 1;
    }

    let mut only_a = Vec::new();
    let mut only_b = Vec::new();
    for (c, n) in count_a {
        if n > 0 {
            for _ in 0..n {
                only_a.push(c.clone());
            }
        } else if n < 0 {
            for _ in 0..(-n) {
                only_b.push(c.clone());
            }
        }
    }
    (only_a, only_b)
}

fn fmt_term(term: &(usize, [u64; 4])) -> String {
    let (wire, coeff) = term;
    // Render coefficient compactly: if only the low limb is non-zero, print decimal;
    // otherwise print full hex limbs (canonical Montgomery form, MSB last).
    if coeff[1] == 0 && coeff[2] == 0 && coeff[3] == 0 {
        format!("{}*w{}", coeff[0], wire)
    } else {
        format!(
            "0x{:016x}{:016x}{:016x}{:016x}*w{}",
            coeff[3], coeff[2], coeff[1], coeff[0], wire
        )
    }
}

fn fmt_lc(terms: &[(usize, [u64; 4])]) -> String {
    if terms.is_empty() {
        "0".into()
    } else {
        terms.iter().map(fmt_term).collect::<Vec<_>>().join(" + ")
    }
}

fn fmt_constraint(c: &CanonicalConstraint) -> String {
    format!(
        "({}) * ({}) = ({})",
        fmt_lc(&c.a),
        fmt_lc(&c.b),
        fmt_lc(&c.c)
    )
}

// ── Per-template orchestration ────────────────────────────────────

#[derive(Debug)]
#[allow(clippy::large_enum_variant)]
enum Verdict {
    /// Both sides ran; constraint multisets compared.
    Ran {
        legacy: SideResult,
        lysis: SideResult,
        pre_eq: bool,
        post_eq: bool,
        pre_only_legacy: Vec<CanonicalConstraint>,
        pre_only_lysis: Vec<CanonicalConstraint>,
        post_only_legacy: Vec<CanonicalConstraint>,
        post_only_lysis: Vec<CanonicalConstraint>,
    },
    /// One or both sides failed; diff impossible.
    Failed {
        legacy_err: Option<String>,
        lysis_err: Option<String>,
        legacy_constraints: Option<usize>,
        lysis_constraints: Option<usize>,
    },
}

#[derive(Debug)]
#[allow(dead_code)]
struct Row {
    template: String,
    file: String,
    skipped_reason: Option<String>,
    verdict: Option<Verdict>,
    total_elapsed: Duration,
}

fn run_template(
    name: &str,
    file: &str,
    inputs: HashMap<String, FieldElement<Bn254Fr>>,
    skip_reason: Option<&str>,
) -> Row {
    let _ = inputs; // We don't run witness; inputs reserved for future witness step.
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join(file);
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];
    let t0 = Instant::now();

    if let Some(reason) = skip_reason {
        eprintln!("|| {name:24}  SKIPPED: {reason}");
        return Row {
            template: name.into(),
            file: file.into(),
            skipped_reason: Some(reason.into()),
            verdict: None,
            total_elapsed: t0.elapsed(),
        };
    }

    eprintln!("|| {name:24}  starting (file={file})…");

    let legacy_outcome = run_side(Side::Legacy, name, &path, &lib_dirs);
    let lysis_outcome = run_side(Side::Lysis, name, &path, &lib_dirs);

    let verdict = match (legacy_outcome, lysis_outcome) {
        (SideOutcome::Ok(legacy), SideOutcome::Ok(lysis)) => {
            let pre_eq = legacy.pre_o1 == lysis.pre_o1
                && legacy.public_inputs == lysis.public_inputs
                && legacy.variables == lysis.variables;
            let post_eq =
                legacy.post_o1 == lysis.post_o1 && legacy.public_inputs == lysis.public_inputs;
            let (pre_only_legacy, pre_only_lysis) =
                multiset_sym_diff(&legacy.pre_o1, &lysis.pre_o1);
            let (post_only_legacy, post_only_lysis) =
                multiset_sym_diff(&legacy.post_o1, &lysis.post_o1);
            eprintln!(
                "||   legacy: pre={}, post={}, vars={}, pub={} | {:.0}ms",
                legacy.constraints_pre,
                legacy.constraints_post,
                legacy.variables,
                legacy.public_inputs.len(),
                legacy.elapsed.as_secs_f64() * 1000.0
            );
            eprintln!(
                "||   lysis : pre={}, post={}, vars={}, pub={} | {:.0}ms",
                lysis.constraints_pre,
                lysis.constraints_post,
                lysis.variables,
                lysis.public_inputs.len(),
                lysis.elapsed.as_secs_f64() * 1000.0
            );
            eprintln!(
                "||   pre-O1 byte-identical: {}, post-O1 byte-identical: {}",
                pre_eq, post_eq
            );
            Some(Verdict::Ran {
                legacy,
                lysis,
                pre_eq,
                post_eq,
                pre_only_legacy,
                pre_only_lysis,
                post_only_legacy,
                post_only_lysis,
            })
        }
        (legacy_o, lysis_o) => {
            let (legacy_err, legacy_c) = match legacy_o {
                SideOutcome::Ok(s) => (None, Some(s.constraints_post)),
                SideOutcome::Failed(e) => {
                    eprintln!("||   legacy FAILED: {e}");
                    (Some(e), None)
                }
            };
            let (lysis_err, lysis_c) = match lysis_o {
                SideOutcome::Ok(s) => (None, Some(s.constraints_post)),
                SideOutcome::Failed(e) => {
                    eprintln!("||   lysis  FAILED: {e}");
                    (Some(e), None)
                }
            };
            Some(Verdict::Failed {
                legacy_err,
                lysis_err,
                legacy_constraints: legacy_c,
                lysis_constraints: lysis_c,
            })
        }
    };

    Row {
        template: name.into(),
        file: file.into(),
        skipped_reason: None,
        verdict,
        total_elapsed: t0.elapsed(),
    }
}

// ── Report rendering ──────────────────────────────────────────────

fn render_report(rows: &[Row], total: Duration) {
    eprintln!();
    eprintln!("# Cross-path baseline report");
    eprintln!();
    eprintln!(
        "| Template | Legacy (post-O1) | Lysis (post-O1) | Pre-O1 ident? | Post-O1 ident? | Notes |"
    );
    eprintln!(
        "|----------|------------------|-----------------|---------------|----------------|-------|"
    );

    let mut byte_identical_post = 0usize;
    let mut diverged = 0usize;
    let mut failed = 0usize;
    let mut skipped = 0usize;

    for row in rows {
        if let Some(reason) = &row.skipped_reason {
            eprintln!(
                "| {} | n/a | n/a | n/a | n/a | SKIPPED: {} |",
                row.template, reason
            );
            skipped += 1;
            continue;
        }
        match &row.verdict {
            Some(Verdict::Ran {
                legacy,
                lysis,
                pre_eq,
                post_eq,
                ..
            }) => {
                let note = match (*pre_eq, *post_eq) {
                    (true, true) => format!(
                        "vars: legacy={} lysis={} | t: legacy={:.0}ms lysis={:.0}ms",
                        legacy.variables,
                        lysis.variables,
                        legacy.elapsed.as_secs_f64() * 1000.0,
                        lysis.elapsed.as_secs_f64() * 1000.0
                    ),
                    (false, true) => "pre-O1 differs but O1 erases it".into(),
                    (true, false) => "DANGEROUS: pre-O1 identical but O1 diverges".into(),
                    (false, false) => format!(
                        "pre Δ={} (legacy={} lysis={}) | post Δ={} (legacy={} lysis={})",
                        legacy.constraints_pre as i64 - lysis.constraints_pre as i64,
                        legacy.constraints_pre,
                        lysis.constraints_pre,
                        legacy.constraints_post as i64 - lysis.constraints_post as i64,
                        legacy.constraints_post,
                        lysis.constraints_post
                    ),
                };
                eprintln!(
                    "| {} | {} | {} | {} | {} | {} |",
                    row.template,
                    legacy.constraints_post,
                    lysis.constraints_post,
                    if *pre_eq { "yes" } else { "no" },
                    if *post_eq { "yes" } else { "no" },
                    note
                );
                if *post_eq && *pre_eq {
                    byte_identical_post += 1;
                } else {
                    diverged += 1;
                }
            }
            Some(Verdict::Failed {
                legacy_err,
                lysis_err,
                legacy_constraints,
                lysis_constraints,
            }) => {
                let note = match (legacy_err.as_ref(), lysis_err.as_ref()) {
                    (Some(e), Some(_)) => format!("BOTH FAILED — legacy: {}", truncate(e, 80)),
                    (Some(e), None) => format!("LEGACY FAILED: {}", truncate(e, 80)),
                    (None, Some(e)) => format!("LYSIS FAILED: {}", truncate(e, 80)),
                    (None, None) => unreachable!(),
                };
                eprintln!(
                    "| {} | {} | {} | n/a | n/a | {} |",
                    row.template,
                    legacy_constraints
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "FAIL".into()),
                    lysis_constraints
                        .map(|n| n.to_string())
                        .unwrap_or_else(|| "FAIL".into()),
                    note
                );
                failed += 1;
            }
            None => {}
        }
    }

    eprintln!();
    eprintln!("Total wall-clock: {:.1}s", total.as_secs_f64());
    eprintln!();
    eprintln!("## Summary");
    eprintln!();
    eprintln!("- byte-identical (pre+post): {}", byte_identical_post);
    eprintln!("- diverged                 : {}", diverged);
    eprintln!("- failed (one or both)     : {}", failed);
    eprintln!("- skipped                  : {}", skipped);
    eprintln!(
        "- TOTAL                    : {}",
        byte_identical_post + diverged + failed + skipped
    );
    eprintln!();

    // Detailed divergence dumps.
    for row in rows {
        if let Some(Verdict::Ran {
            pre_eq,
            post_eq,
            pre_only_legacy,
            pre_only_lysis,
            post_only_legacy,
            post_only_lysis,
            ..
        }) = &row.verdict
        {
            if !*pre_eq || !*post_eq {
                eprintln!("### Divergence detail: {}", row.template);
                eprintln!();
                if !*pre_eq {
                    eprintln!(
                        "Pre-O1 sym-diff: {} only in legacy, {} only in lysis. Top 10 each:",
                        pre_only_legacy.len(),
                        pre_only_lysis.len()
                    );
                    eprintln!();
                    eprintln!("```");
                    eprintln!("# only in LEGACY (pre-O1)");
                    for c in pre_only_legacy.iter().take(10) {
                        eprintln!("  {}", fmt_constraint(c));
                    }
                    eprintln!("# only in LYSIS  (pre-O1)");
                    for c in pre_only_lysis.iter().take(10) {
                        eprintln!("  {}", fmt_constraint(c));
                    }
                    eprintln!("```");
                    eprintln!();
                }
                if !*post_eq {
                    eprintln!(
                        "Post-O1 sym-diff: {} only in legacy, {} only in lysis. Top 10 each:",
                        post_only_legacy.len(),
                        post_only_lysis.len()
                    );
                    eprintln!();
                    eprintln!("```");
                    eprintln!("# only in LEGACY (post-O1)");
                    for c in post_only_legacy.iter().take(10) {
                        eprintln!("  {}", fmt_constraint(c));
                    }
                    eprintln!("# only in LYSIS  (post-O1)");
                    for c in post_only_lysis.iter().take(10) {
                        eprintln!("  {}", fmt_constraint(c));
                    }
                    eprintln!("```");
                    eprintln!();
                }
            }
        }
    }
}

fn truncate(s: &str, n: usize) -> String {
    if s.len() <= n {
        s.into()
    } else {
        format!("{}…", &s[..n])
    }
}

// ── Test entry ────────────────────────────────────────────────────

fn fe_inputs(map: &[(&str, u64)]) -> HashMap<String, FieldElement<Bn254Fr>> {
    map.iter()
        .map(|(k, v)| ((*k).to_string(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect()
}

#[test]
fn cross_path_baseline_circom() {
    let t0 = Instant::now();
    let mut rows: Vec<Row> = Vec::new();

    eprintln!();
    eprintln!("=== Cross-path baseline: circom benchmark templates ===");
    eprintln!();

    // Each row is one of the BETA20 benchmark templates.
    // Skipped templates are kept in the table for completeness.

    rows.push(run_template(
        "Num2Bits(8)",
        "test/circom/num2bits_8.circom",
        fe_inputs(&[("in", 13)]),
        None,
    ));

    rows.push(run_template(
        "IsZero",
        "test/circom/iszero.circom",
        fe_inputs(&[("in", 0)]),
        None,
    ));

    rows.push(run_template(
        "LessThan(8)",
        "test/circom/lessthan_8.circom",
        fe_inputs(&[("in_0", 3), ("in_1", 10)]),
        None,
    ));

    rows.push(run_template(
        "Pedersen(8)",
        "test/circomlib/pedersen_test.circom",
        (0..8)
            .map(|i| (format!("in_{i}"), FieldElement::<Bn254Fr>::from_u64(i % 2)))
            .collect(),
        None,
    ));

    rows.push(run_template(
        "EscalarMulFix(253)",
        "test/circomlib/escalarmulfix_test.circom",
        (0..253)
            .map(|i| (format!("e_{i}"), FieldElement::<Bn254Fr>::from_u64(0)))
            .collect(),
        None,
    ));

    {
        let mut ema_inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
        for i in 0..254 {
            ema_inputs.insert(format!("e_{i}"), FieldElement::<Bn254Fr>::from_u64(0));
        }
        ema_inputs.insert("p_0".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
        ema_inputs.insert("p_1".to_string(), FieldElement::<Bn254Fr>::from_u64(1));
        rows.push(run_template(
            "EscalarMulAny(254)",
            "test/circomlib/escalarmulany254_test.circom",
            ema_inputs,
            None,
        ));
    }

    rows.push(run_template(
        "Poseidon(2)",
        "test/circomlib/poseidon_test.circom",
        fe_inputs(&[("inputs_0", 1), ("inputs_1", 2)]),
        None,
    ));

    rows.push(run_template(
        "MiMCSponge(2,220,1)",
        "test/circomlib/mimcsponge_test.circom",
        fe_inputs(&[("ins_0", 1), ("ins_1", 2), ("k", 0)]),
        None,
    ));

    rows.push(run_template(
        "BabyJubjub",
        "test/circomlib/babyjub_test.circom",
        HashMap::new(),
        None,
    ));

    rows.push(run_template(
        "Pedersen_old(8)",
        "test/circomlib/pedersen_old_test.circom",
        (0..8)
            .map(|i| (format!("in_{i}"), FieldElement::<Bn254Fr>::from_u64(i % 2)))
            .collect(),
        None,
    ));

    // EdDSAPoseidon — heavy template (~47s compile/legacy per memory).
    // We still attempt it; if budget is tight the run will surface it
    // as a slow row but won't crash the sweep.
    rows.push(run_template(
        "EdDSAPoseidon",
        "test/circomlib/eddsaposeidon_test.circom",
        HashMap::new(),
        None,
    ));

    // SHA-256(64) — Legacy frontend OOMs on amplification (memory note,
    // and is the canonical case the Lysis HARD GATE was built around).
    // Skip outright per the task brief.
    rows.push(run_template(
        "SHA-256(64)",
        "test/circomlib/sha256_test.circom",
        HashMap::new(),
        Some("Legacy OOMs on amplification — Lysis-only hard-gate (BETA20-CLOSEOUT line 39)"),
    ));

    let total = t0.elapsed();
    render_report(&rows, total);

    // Phase 1.A hard-gate. Every non-skipped template must either be
    // byte-identical (pre-O1 + post-O1) or appear in the allowlist of
    // known wire-id divergences below. Any unexpected skip, side-level
    // failure, or unknown divergence aborts the test.
    //
    // Known divergences:
    //   * `EdDSAPoseidon`: pure wire-id pair-swap — same constraint
    //     count (9719 → 3965), variables (10410), and public partition
    //     (1) on both sides; only the SSA wire IDs allocated to four
    //     pre-O1 BabyAdd witness pairs (w10395 ↔ w10403, w10397 ↔
    //     w10405) differ. Each swapped pair shares its definition
    //     across the swap, so R1CS satisfiability is preserved under
    //     the renaming. Confirmed deterministic at HEAD `6e6a4629`
    //     pre-flip and persists post-flip; the README claim of "11/12
    //     byte-identical" mis-counted this row, which the print-only
    //     baseline did not surface.
    //
    // The SHA-256(64) row is permitted to skip (Legacy OOMs).
    const ALLOW_DIVERGE: &[&str] = &["EdDSAPoseidon"];
    const ALLOW_SKIP: &[&str] = &["SHA-256(64)"];

    let mut violations: Vec<String> = Vec::new();
    for row in &rows {
        if let Some(reason) = &row.skipped_reason {
            if !ALLOW_SKIP.contains(&row.template.as_str()) {
                violations.push(format!(
                    "{}: unexpected SKIP ({reason}) — not in ALLOW_SKIP",
                    row.template
                ));
            }
            continue;
        }
        match &row.verdict {
            Some(Verdict::Ran {
                pre_eq, post_eq, ..
            }) => {
                let identical = *pre_eq && *post_eq;
                let allowed = ALLOW_DIVERGE.contains(&row.template.as_str());
                if !identical && !allowed {
                    violations.push(format!(
                        "{}: divergence (pre_eq={pre_eq}, post_eq={post_eq}) and not in ALLOW_DIVERGE",
                        row.template
                    ));
                }
                if identical && allowed {
                    violations.push(format!(
                        "{}: ALLOW_DIVERGE entry is now byte-identical — remove it from the allowlist",
                        row.template
                    ));
                }
            }
            Some(Verdict::Failed {
                legacy_err,
                lysis_err,
                ..
            }) => {
                let which = match (legacy_err.is_some(), lysis_err.is_some()) {
                    (true, true) => "both",
                    (true, false) => "Legacy",
                    (false, true) => "Lysis",
                    (false, false) => unreachable!(),
                };
                violations.push(format!("{}: {which} side failed", row.template));
            }
            None => {
                violations.push(format!("{}: no verdict recorded", row.template));
            }
        }
    }

    if !violations.is_empty() {
        panic!(
            "cross_path_baseline_circom: {} violation(s) — Phase 1.A gate not satisfied:\n  - {}",
            violations.len(),
            violations.join("\n  - ")
        );
    }
}
