//! Inspection test for the SHA-256 / BinSum Lysis pipeline.
//!
//! Diagnostic only. Goal: figure out whether SHA-256(64) hits the
//! Bug Class A pattern (var-accumulator-escapes-loop) at all, given
//! that the canonical Num2Bits Lysis-fail trips it but SHA-256 has
//! historically passed the Lysis hard-gate.
//!
//! We exercise three fixtures:
//!   1. test/circom/binsum.circom (BinSum(4) standalone)
//!   2. test/circom/bits2num_8.circom (Bits2Num(8) standalone)
//!   3. test/circomlib/sha256_test.circom (Sha256(64) — the hard-gate)
//!
//! For each: walk the ExtendedInstruction stream, count
//! `SymbolicArrayRead` definitions whose `result_var` is consumed by a
//! `Plain` instruction OUTSIDE the `LoopUnroll` that defines them.
//! That's the exact malformation pattern the walker rejects in
//! Num2Bits.
//!
//! Run: `cargo test --release --test sha256_lysis_inspect -- --nocapture`

use std::collections::{HashMap, HashSet};

use ir_core::SsaVar;
use ir_forge::extended::ExtendedInstruction;
use memory::{Bn254Fr, FieldElement};

use circom::{compile_file_with_frontend, Frontend};

#[derive(Default)]
struct Stats {
    /// SsaVar -> the smallest depth at which it was defined (0 = top).
    def_depths: HashMap<SsaVar, usize>,
    /// SsaVar -> set of depths it was used at.
    use_depths: HashMap<SsaVar, Vec<usize>>,
    /// SsaVars defined by SymbolicArrayRead specifically.
    sym_read_defs: HashSet<SsaVar>,
    /// SsaVars defined inside LoopUnroll (depth > 0).
    inside_loop_defs: HashSet<SsaVar>,
    /// SsaVars used by Plain instructions specifically (vs by SymbolicArrayRead etc.).
    plain_uses: HashMap<SsaVar, Vec<usize>>,
    /// Bug Class B counters — SymbolicIndexedEffect writes.
    eff_total: usize,
    eff_in_loop: usize,
    /// First few examples: (slots_len, depth, index_var, has_value).
    eff_examples: Vec<(usize, usize, SsaVar, bool)>,
    /// Histogram of slots.len() for symbolic effects (helps identify
    /// sub-component sized arrays — e.g. 32 = SHA-256 word).
    eff_slot_len_hist: HashMap<usize, usize>,
}

fn record_def(stats: &mut Stats, v: SsaVar, depth: usize) {
    stats.def_depths.entry(v).or_insert(depth);
    if depth > 0 {
        stats.inside_loop_defs.insert(v);
    }
}

fn record_use(stats: &mut Stats, v: SsaVar, depth: usize, plain: bool) {
    stats.use_depths.entry(v).or_default().push(depth);
    if plain {
        stats.plain_uses.entry(v).or_default().push(depth);
    }
}

fn walk<F: memory::FieldBackend>(body: &[ExtendedInstruction<F>], depth: usize, stats: &mut Stats) {
    for ext in body {
        match ext {
            ExtendedInstruction::Plain(inst) => {
                let res = inst.result_var();
                record_def(stats, res, depth);
                for v in inst.extra_result_vars() {
                    record_def(stats, *v, depth);
                }
                for u in inst.operands() {
                    record_use(stats, u, depth, true);
                }
            }
            ExtendedInstruction::TemplateBody { body: inner, .. } => {
                walk(inner, depth, stats);
            }
            ExtendedInstruction::TemplateCall {
                captures, outputs, ..
            } => {
                for v in outputs {
                    record_def(stats, *v, depth);
                }
                for v in captures {
                    record_use(stats, *v, depth, false);
                }
            }
            ExtendedInstruction::LoopUnroll {
                iter_var,
                body: inner,
                ..
            } => {
                record_def(stats, *iter_var, depth + 1);
                walk(inner, depth + 1, stats);
            }
            ExtendedInstruction::SymbolicIndexedEffect {
                array_slots,
                index_var,
                value_var,
                ..
            } => {
                stats.eff_total += 1;
                if depth > 0 {
                    stats.eff_in_loop += 1;
                }
                let n = array_slots.len();
                *stats.eff_slot_len_hist.entry(n).or_default() += 1;
                if stats.eff_examples.len() < 10 {
                    stats
                        .eff_examples
                        .push((n, depth, *index_var, value_var.is_some()));
                }
                record_use(stats, *index_var, depth, false);
                if let Some(v) = value_var {
                    record_use(stats, *v, depth, false);
                }
                for v in array_slots {
                    record_def(stats, *v, depth);
                }
            }
            ExtendedInstruction::SymbolicArrayRead {
                result_var,
                array_slots,
                index_var,
                ..
            } => {
                record_def(stats, *result_var, depth);
                stats.sym_read_defs.insert(*result_var);
                record_use(stats, *index_var, depth, false);
                for v in array_slots {
                    record_use(stats, *v, depth, false);
                }
            }
            ExtendedInstruction::SymbolicShift {
                result_var,
                operand_var,
                shift_var,
                ..
            } => {
                record_def(stats, *result_var, depth);
                record_use(stats, *operand_var, depth, false);
                record_use(stats, *shift_var, depth, false);
            }
        }
    }
}

fn analyze(label: &str, path_rel: &str, captures: &[(&str, u64)], output_names: &[&str]) {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let path = manifest_dir.join(path_rel);
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];
    if !path.exists() {
        println!("[{label}] missing: {}", path.display());
        return;
    }

    println!("\n========== {label} ({}) ==========", path_rel);

    let result = match compile_file_with_frontend(&path, &lib_dirs, Frontend::Lysis) {
        Ok(r) => r,
        Err(e) => {
            println!("[{label}] compile_file_with_frontend(Lysis) FAILED: {e}");
            return;
        }
    };
    let prove_ir = result.prove_ir;
    let mut fe_caps: HashMap<String, FieldElement<Bn254Fr>> = result
        .capture_values
        .into_iter()
        .map(|(k, v)| (k, FieldElement::<Bn254Fr>::from_u64(v)))
        .collect();
    // Allow override
    for (k, v) in captures {
        fe_caps.insert((*k).to_string(), FieldElement::<Bn254Fr>::from_u64(*v));
    }
    let mut on: HashSet<String> = result.output_names.into_iter().collect();
    for n in output_names {
        on.insert((*n).to_string());
    }

    let extended = match prove_ir.instantiate_with_outputs_extended::<Bn254Fr>(&fe_caps, &on) {
        Ok(e) => e,
        Err(e) => {
            println!("[{label}] instantiate_extended FAILED: {e}");
            return;
        }
    };

    println!("[{label}] body length: {}", extended.body.len());

    let mut stats = Stats::default();
    walk(&extended.body, 0, &mut stats);

    println!(
        "[{label}] symbolic-array-read defs total: {}",
        stats.sym_read_defs.len()
    );

    // KEY METRIC: SsaVars defined by SymbolicArrayRead AT depth>=1 (inside a LoopUnroll)
    // that are USED at depth=0 (outside that loop) by a Plain instruction.
    let mut leak_count = 0usize;
    let mut leak_examples = Vec::new();
    for v in &stats.sym_read_defs {
        let def_depth = match stats.def_depths.get(v) {
            Some(d) => *d,
            None => continue,
        };
        if def_depth == 0 {
            continue; // top-level SymArrRead is fine
        }
        if let Some(uses) = stats.plain_uses.get(v) {
            if uses.iter().any(|d| *d < def_depth) {
                leak_count += 1;
                if leak_examples.len() < 5 {
                    leak_examples.push((*v, def_depth, uses.clone()));
                }
            }
        }
    }
    println!(
        "[{label}] SymArrRead defs that LEAK out of loop into Plain: {}",
        leak_count
    );
    for (v, dd, uses) in &leak_examples {
        println!(
            "  - %{} defined at depth {}, plain-used at depths {:?}",
            v.0, dd, uses
        );
    }

    // Bug Class B: SymbolicIndexedEffect writes.
    println!(
        "[{label}] SymbolicIndexedEffect total: {}  (inside-LoopUnroll: {})",
        stats.eff_total, stats.eff_in_loop
    );
    if !stats.eff_slot_len_hist.is_empty() {
        let mut hist: Vec<_> = stats.eff_slot_len_hist.iter().collect();
        hist.sort_by_key(|(k, _)| *k);
        let s: Vec<String> = hist.iter().map(|(k, v)| format!("{k}->{v}")).collect();
        println!("[{label}]   slot_len histogram: {{{}}}", s.join(", "));
    }
    for (n, depth, idx, has_val) in &stats.eff_examples {
        println!(
            "  - eff: slots_len={}, depth={}, index_var=%{}, has_value={}",
            n, depth, idx.0, has_val
        );
    }

    // Run the walker and report.
    println!("[{label}] Walker run:");
    let walker_result = prove_ir.instantiate_lysis_with_outputs::<Bn254Fr>(&fe_caps, &on);
    match walker_result {
        Ok(prog) => println!("  WALKER OK: {} instructions", prog.instructions().len()),
        Err(e) => println!("  WALKER FAIL: {e}"),
    }
}

#[test]
fn binsum_lysis_inspect() {
    analyze("BinSum(4)", "test/circom/binsum.circom", &[], &["out"]);
}

#[test]
fn bits2num_lysis_inspect() {
    analyze(
        "Bits2Num(8)",
        "test/circom/bits2num_8.circom",
        &[],
        &["out"],
    );
}

#[test]
fn sha256_lysis_inspect() {
    // Note: SHA-256(64) has a giant body; we only count, no full dump.
    analyze(
        "Sha256(64)",
        "test/circomlib/sha256_test.circom",
        &[],
        &["out"],
    );
}

// === Bug Class B candidates ===
// These four templates currently FAIL Lysis at instantiate time with
// "symbolic indexed write into <comp>.<arr> but the array is not
// declared in this scope". The `analyze` helper runs the full pipeline
// and prints the failure path so we can confirm where the error fires
// vs. how many SymbolicIndexedEffect writes the SHA-256 baseline
// emits without failure.

#[test]
fn pedersen_lysis_inspect_classb() {
    analyze(
        "Pedersen(8)",
        "test/circomlib/pedersen_test.circom",
        &[],
        &["out"],
    );
}

#[test]
fn escalarmulfix_lysis_inspect_classb() {
    analyze(
        "EscalarMulFix(3)",
        "test/circomlib/escalarmulfix_test.circom",
        &[],
        &["out"],
    );
}

#[test]
fn escalarmulany_lysis_inspect_classb() {
    analyze(
        "EscalarMulAny(254)",
        "test/circomlib/escalarmulany254_test.circom",
        &[],
        &["out"],
    );
}

#[test]
fn poseidon_lysis_inspect_classb() {
    analyze(
        "Poseidon(2)",
        "test/circomlib/poseidon_test.circom",
        &[],
        &["out"],
    );
}
