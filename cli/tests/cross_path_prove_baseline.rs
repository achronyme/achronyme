//! Frozen-baseline regression test for `prove {}` blocks across the
//! `examples/` and `test/prove/` corpora.
//!
//! Phase 2.C-prove — converted from a Lysis-vs-Legacy byte-identity
//! gate to a frozen-baseline regression gate. Sister sweep to
//! `circom/tests/cross_path_baseline.rs` (Phase 2.C-circom).
//!
//! For every `.ach` example listed in [`EXAMPLES`], this test:
//!
//! 1. Compiles the source via `cli::new_compiler()`.
//! 2. Runs the resulting bytecode in an Akron VM with a custom
//!    [`CapturingProveHandler`] that records `(seq, name, prove_ir_bytes,
//!    scope_values)` on every `Prove` opcode and returns
//!    `ProveResult::VerifiedOnly` so the script proceeds.
//! 3. Replays each captured prove block via `instantiate_lysis`,
//!    compiles the resulting `IrProgram` to R1CS, runs `optimize_r1cs`,
//!    and computes a `FrozenBaseline` snapshot.
//! 4. Compares the snapshot to a pinned `FrozenBaseline` keyed by
//!    `format!("{file}/{block}")`. Drift surfaces as actionable
//!    panic with the diff site (counts, public partition, hash).
//!
//! ## Why frozen baseline replaces Lysis-vs-Legacy
//!
//! With Lysis as default and the Legacy path scheduled for deletion in
//! Phase 2.A, dual-path comparison becomes vacuous (Lysis-vs-Lysis).
//! Frozen-baseline pins the structural identity of each prove block at
//! HEAD-of-Phase-2.C, surfacing both intentional changes (re-pin via
//! `REGEN_FROZEN_BASELINES=1`) and silent regressions (assertion fails
//! with a diff that names the drift surface).
//!
//! ## Determinism precondition (verified empirically pre-refactor)
//!
//! Before refactoring this test, five consecutive runs of the
//! pre-refactor Lysis-vs-Legacy version (commit `da72e885`, prior to
//! `2a06c551`) produced byte-identical output across every column
//! except wall-clock time (measured 2026-05-01). All 34 captured prove
//! blocks use hardcoded literal inputs (no `OsRng`, no time-based
//! seeds, no HashMap-iteration leaks reaching scope_values).
//! Sort-based canonicalization in
//! `zkc::test_support::canonical_multiset_hash` handles the term-order
//! axis. Full hash pinning is therefore safe; no shape-only allowlist
//! needed (unlike circom's EdDSAPoseidon). To re-verify determinism on
//! this refactored test, run it 5+ times and confirm the assertion
//! body's printed counts and hashes match across runs.
//!
//! ## Re-generating pinned values
//!
//! ```ignore
//! REGEN_FROZEN_BASELINES=1 cargo test --release -p cli \
//!     --test cross_path_prove_baseline -- --nocapture
//! ```
//! Then copy each printed `FrozenBaseline { ... }` literal into the
//! corresponding `pin_*` function below. Every re-pin is a documented
//! intentional change — a passing pin that later starts failing means
//! a regression that needs root-cause, not a re-pin.

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, Instant};

use akron::{CallFrame, ProveError, ProveHandler, ProveResult, VM};
use cli::commands::{new_compiler, register_std_modules};
use ir_forge::{ArraySize, ProveIR};
use memory::{Bn254Fr, FieldElement, Function};
use zkc::test_support::{assert_frozen_baseline_matches, compute_frozen_baseline, FrozenBaseline};

type F = Bn254Fr;

// ---------------------------------------------------------------------------
// Examples list — paths relative to the workspace root (`achronyme/`).
// circom_lib_dirs is set per-row when the example imports `.circom`.
// ---------------------------------------------------------------------------

struct Example {
    label: &'static str,
    rel_path: &'static str,
    circom_libs: &'static [&'static str],
    /// Hard wall-clock budget. Tornado-Cash sized circuits get a fatter
    /// budget; unit tests run in milliseconds.
    budget: Duration,
}

const EXAMPLES: &[Example] = &[
    Example {
        label: "proof_of_membership",
        rel_path: "examples/proof_of_membership.ach",
        circom_libs: &[],
        budget: Duration::from_secs(180),
    },
    Example {
        label: "circom_merkle_membership",
        rel_path: "examples/circom_merkle_membership.ach",
        circom_libs: &["test/circomlib/circuits"],
        budget: Duration::from_secs(180),
    },
    Example {
        label: "circom_poseidon_chain",
        rel_path: "examples/circom_poseidon_chain.ach",
        circom_libs: &["test/circomlib/circuits"],
        budget: Duration::from_secs(180),
    },
    Example {
        label: "tornado_mixer",
        rel_path: "examples/tornado_mixer.ach",
        circom_libs: &[],
        budget: Duration::from_secs(240),
    },
    Example {
        label: "tornado_multifile",
        rel_path: "examples/tornado/src/main.ach",
        circom_libs: &["test/circomlib/circuits"],
        budget: Duration::from_secs(300),
    },
    Example {
        label: "test/basic_prove",
        rel_path: "test/prove/basic_prove.ach",
        circom_libs: &[],
        budget: Duration::from_secs(60),
    },
    Example {
        label: "test/prove_array_sum",
        rel_path: "test/prove/prove_array_sum.ach",
        circom_libs: &[],
        budget: Duration::from_secs(60),
    },
    Example {
        label: "test/prove_assert_message",
        rel_path: "test/prove/prove_assert_message.ach",
        circom_libs: &[],
        budget: Duration::from_secs(60),
    },
    Example {
        label: "test/prove_boolean_mux",
        rel_path: "test/prove/prove_boolean_mux.ach",
        circom_libs: &[],
        budget: Duration::from_secs(60),
    },
    Example {
        label: "test/prove_capture",
        rel_path: "test/prove/prove_capture.ach",
        circom_libs: &[],
        budget: Duration::from_secs(60),
    },
    Example {
        label: "test/prove_chain",
        rel_path: "test/prove/prove_chain.ach",
        circom_libs: &[],
        budget: Duration::from_secs(60),
    },
    Example {
        label: "test/prove_comparison",
        rel_path: "test/prove/prove_comparison.ach",
        circom_libs: &[],
        budget: Duration::from_secs(60),
    },
    Example {
        label: "test/prove_division",
        rel_path: "test/prove/prove_division.ach",
        circom_libs: &[],
        budget: Duration::from_secs(60),
    },
    Example {
        label: "test/prove_for_loop",
        rel_path: "test/prove/prove_for_loop.ach",
        circom_libs: &[],
        budget: Duration::from_secs(60),
    },
    Example {
        label: "test/prove_for_loop_nested",
        rel_path: "test/prove/prove_for_loop_nested.ach",
        circom_libs: &[],
        budget: Duration::from_secs(60),
    },
    Example {
        label: "test/prove_for_loop_dynamic",
        rel_path: "test/prove/prove_for_loop_dynamic.ach",
        circom_libs: &[],
        budget: Duration::from_secs(60),
    },
    Example {
        label: "test/prove_if_else",
        rel_path: "test/prove/prove_if_else.ach",
        circom_libs: &[],
        budget: Duration::from_secs(60),
    },
    Example {
        label: "test/prove_outer_fn",
        rel_path: "test/prove/prove_outer_fn.ach",
        circom_libs: &[],
        budget: Duration::from_secs(60),
    },
    Example {
        label: "test/prove_outer_fn_circuit",
        rel_path: "test/prove/prove_outer_fn_circuit.ach",
        circom_libs: &[],
        budget: Duration::from_secs(60),
    },
    Example {
        label: "test/prove_power",
        rel_path: "test/prove/prove_power.ach",
        circom_libs: &[],
        budget: Duration::from_secs(60),
    },
    Example {
        label: "test/prove_range_check",
        rel_path: "test/prove/prove_range_check.ach",
        circom_libs: &[],
        budget: Duration::from_secs(60),
    },
    Example {
        label: "test/prove_secret_vote",
        rel_path: "test/prove/prove_secret_vote.ach",
        circom_libs: &[],
        budget: Duration::from_secs(60),
    },
    Example {
        label: "test/prove_with_poseidon",
        rel_path: "test/prove/prove_with_poseidon.ach",
        circom_libs: &[],
        budget: Duration::from_secs(60),
    },
    Example {
        label: "test/typed_prove",
        rel_path: "test/prove/typed_prove.ach",
        circom_libs: &[],
        budget: Duration::from_secs(60),
    },
    Example {
        label: "test/babyadd",
        rel_path: "test/circom_imports/babyadd.ach",
        circom_libs: &["test/circomlib/circuits"],
        budget: Duration::from_secs(120),
    },
];

// ---------------------------------------------------------------------------
// Capturing prove handler: records inputs + returns VerifiedOnly so the
// VM keeps running.
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct Capture {
    /// Sequence number, in source-evaluation order. Stable across runs
    /// because the Akron VM is single-threaded.
    seq: usize,
    /// `Some(name)` when the user wrote `prove name(...)`, else `None`.
    name: Option<String>,
    /// Raw ProveIR bytes (deserialize via `ProveIR::from_bytes`).
    bytes: Vec<u8>,
    /// All in-scope FieldElement values at the moment of the Prove
    /// opcode. Includes captures, public/witness inputs, array
    /// elements (`{name}_{i}`).
    scope: HashMap<String, FieldElement<F>>,
}

#[derive(Default)]
struct CapturingProveHandler {
    captured: RefCell<Vec<Capture>>,
}

impl ProveHandler for CapturingProveHandler {
    fn execute_prove_ir(
        &self,
        prove_ir_bytes: &[u8],
        scope_values: &HashMap<String, FieldElement<F>>,
    ) -> Result<ProveResult, ProveError> {
        let name = ProveIR::from_bytes(prove_ir_bytes)
            .ok()
            .and_then(|(p, _)| p.name);
        let mut buf = self.captured.borrow_mut();
        let seq = buf.len();
        buf.push(Capture {
            seq,
            name,
            bytes: prove_ir_bytes.to_vec(),
            scope: scope_values.clone(),
        });
        Ok(ProveResult::VerifiedOnly)
    }
}

/// Shared wrapper so we can stash the same handler in both
/// `vm.prove_handler` and `vm.verify_handler` slots.
struct SharedCapturing(Rc<CapturingProveHandler>);

impl ProveHandler for SharedCapturing {
    fn execute_prove_ir(
        &self,
        prove_ir_bytes: &[u8],
        scope_values: &HashMap<String, FieldElement<F>>,
    ) -> Result<ProveResult, ProveError> {
        self.0.execute_prove_ir(prove_ir_bytes, scope_values)
    }
}

impl akron::VerifyHandler for SharedCapturing {
    fn verify_proof(&self, _proof: &memory::ProofObject) -> Result<bool, String> {
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Per-row outcome
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct RowOutcome {
    file: String,
    block: String,
    /// `Some` when instantiate_lysis + R1CS compile succeeded.
    baseline: Option<FrozenBaseline>,
    wall_clock: Duration,
    /// Set when an unrecoverable error short-circuits the row.
    error: Option<String>,
}

// ---------------------------------------------------------------------------
// Compile + VM run a single .ach example.
// Returns the captured prove blocks, or an error string.
// ---------------------------------------------------------------------------

fn run_example_capture(example: &Example, workspace_root: &Path) -> Result<Vec<Capture>, String> {
    let abs_path = workspace_root.join(example.rel_path);
    let source = std::fs::read_to_string(&abs_path)
        .map_err(|e| format!("read {}: {e}", abs_path.display()))?;

    let mut compiler = new_compiler();
    compiler.prime_id = memory::field::PrimeId::Bn254;
    compiler.base_path = Some(abs_path.parent().unwrap_or(Path::new(".")).to_path_buf());
    compiler.circom_lib_dirs = example
        .circom_libs
        .iter()
        .map(|s| workspace_root.join(s))
        .collect();
    if let Ok(canonical) = abs_path.canonicalize() {
        compiler.compiling_modules.insert(canonical);
    }

    let bytecode = compiler
        .compile(&source)
        .map_err(|e| format!("compile error: {e:?}"))?;

    let mut vm = VM::new();
    register_std_modules(&mut vm).map_err(|e| format!("register_std_modules: {e:?}"))?;

    let handler = Rc::new(CapturingProveHandler::default());
    vm.prove_handler = Some(Box::new(SharedCapturing(Rc::clone(&handler))));
    vm.verify_handler = Some(Box::new(SharedCapturing(Rc::clone(&handler))));

    vm.import_strings(compiler.interner.strings);
    vm.heap.import_bytes(compiler.bytes_interner.blobs);
    vm.heap
        .import_circom_handles(std::mem::take(&mut compiler.circom_handle_interner.handles));
    vm.circom_handler = Some(Box::new(
        cli::circom_handler::DefaultCircomWitnessHandler::new(
            compiler.circom_library_registry.take_libraries(),
        ),
    ));

    let field_map = vm
        .heap
        .import_fields(compiler.field_interner.fields)
        .map_err(|e| format!("import_fields: {e:?}"))?;
    let bigint_map = vm
        .heap
        .import_bigints(compiler.bigint_interner.bigints)
        .map_err(|e| format!("import_bigints: {e:?}"))?;
    for proto in &mut compiler.prototypes {
        cli::commands::run::remap_field_handles(&mut proto.constants, &field_map);
        cli::commands::run::remap_bigint_handles(&mut proto.constants, &bigint_map);
    }

    let main_func = compiler
        .compilers
        .last()
        .ok_or_else(|| "compiler has no main function".to_string())?;

    for proto in &compiler.prototypes {
        let h = vm
            .heap
            .alloc_function(proto.clone())
            .map_err(|e| format!("alloc_function: {e:?}"))?;
        vm.prototypes.push(h);
    }

    let mut main_constants = main_func.constants.clone();
    cli::commands::run::remap_field_handles(&mut main_constants, &field_map);
    cli::commands::run::remap_bigint_handles(&mut main_constants, &bigint_map);

    let func = Function {
        name: "main".to_string(),
        arity: 0,
        chunk: bytecode,
        constants: main_constants,
        max_slots: main_func.max_slots,
        upvalue_info: vec![],
        line_info: main_func.line_info.clone(),
    };

    let func_idx = vm
        .heap
        .alloc_function(func)
        .map_err(|e| format!("alloc main: {e:?}"))?;
    let closure_idx = vm
        .heap
        .alloc_closure(memory::Closure {
            function: func_idx,
            upvalues: vec![],
        })
        .map_err(|e| format!("alloc_closure: {e:?}"))?;

    vm.frames.push(CallFrame {
        closure: closure_idx,
        ip: 0,
        base: 0,
        dest_reg: 0,
    });

    vm.interpret().map_err(|e| format!("vm interpret: {e}"))?;

    drop(vm);
    let captures = std::mem::take(&mut *handler.captured.borrow_mut());
    Ok(captures)
}

// ---------------------------------------------------------------------------
// Replay one captured prove block through Lysis. Compute frozen baseline.
// ---------------------------------------------------------------------------

fn replay_one(capture: &Capture, file_label: &str) -> RowOutcome {
    let started = Instant::now();
    let block_name = capture
        .name
        .clone()
        .unwrap_or_else(|| format!("(anonymous #{})", capture.seq));

    let prove_ir = match ProveIR::from_bytes(&capture.bytes) {
        Ok((p, _prime)) => p,
        Err(e) => {
            return RowOutcome {
                file: file_label.into(),
                block: block_name,
                baseline: None,
                wall_clock: started.elapsed(),
                error: Some(format!("ProveIR::from_bytes: {e}")),
            };
        }
    };

    let captures_map = collect_captures(&prove_ir, &capture.scope);

    let mut program = match prove_ir.instantiate_lysis::<F>(&captures_map) {
        Ok(p) => p,
        Err(e) => {
            return RowOutcome {
                file: file_label.into(),
                block: block_name,
                baseline: None,
                wall_clock: started.elapsed(),
                error: Some(format!("instantiate_lysis: {e}")),
            };
        }
    };

    ir::passes::optimize(&mut program);

    let baseline = compute_frozen_baseline(&program);

    RowOutcome {
        file: file_label.into(),
        block: block_name,
        baseline: Some(baseline),
        wall_clock: started.elapsed(),
        error: None,
    }
}

/// Build the captures map for `instantiate_lysis` by selecting just
/// the names the ProveIR template declares as captures (scalar +
/// per-element of capture_arrays). The VM scope contains everything
/// in scope at the prove site; `instantiate_lysis` validates that we
/// passed exactly the declared captures (extra keys are ignored).
fn collect_captures(
    prove_ir: &ProveIR,
    scope: &HashMap<String, FieldElement<F>>,
) -> HashMap<String, FieldElement<F>> {
    let mut out: HashMap<String, FieldElement<F>> = HashMap::new();
    for cap in &prove_ir.captures {
        if let Some(v) = scope.get(&cap.name) {
            out.insert(cap.name.clone(), *v);
        }
    }
    for arr in &prove_ir.capture_arrays {
        for i in 0..arr.size {
            let elem = format!("{}_{i}", arr.name);
            if let Some(v) = scope.get(&elem) {
                out.insert(elem, *v);
            }
        }
    }
    let _ = ArraySize::Literal(0); // pull the import in even when unused
    out
}

// ---------------------------------------------------------------------------
// Pin lookup + REGEN print helper
// ---------------------------------------------------------------------------

fn pin_for(key: &str) -> Option<FrozenBaseline> {
    Some(match key {
        "proof_of_membership/membership" => pin_proof_of_membership_membership(),
        "proof_of_membership/membership_0" => pin_proof_of_membership_membership_0(),
        "circom_merkle_membership/membership" => pin_circom_merkle_membership(),
        "circom_poseidon_chain/(anonymous #0)" => pin_circom_poseidon_chain(),
        "tornado_mixer/withdrawal" => pin_tornado_mixer_withdrawal(),
        "tornado_mixer/double_spend_check" => pin_tornado_mixer_double_spend_check(),
        "tornado_mixer/withdrawal_2" => pin_tornado_mixer_withdrawal_2(),
        "tornado_multifile/withdraw" => pin_tornado_multifile_withdraw(),
        "test/basic_prove/(anonymous #0)" => pin_basic_prove(),
        "test/prove_array_sum/(anonymous #0)" => pin_prove_array_sum(),
        "test/prove_assert_message/(anonymous #0)" => pin_prove_assert_message(),
        "test/prove_boolean_mux/(anonymous #0)" => pin_prove_boolean_mux(),
        "test/prove_capture/(anonymous #0)" => pin_prove_capture_0(),
        "test/prove_capture/(anonymous #1)" => pin_prove_capture_1(),
        "test/prove_chain/(anonymous #0)" => pin_prove_chain_0(),
        "test/prove_chain/(anonymous #1)" => pin_prove_chain_1(),
        "test/prove_comparison/(anonymous #0)" => pin_prove_comparison(),
        "test/prove_division/(anonymous #0)" => pin_prove_division(),
        "test/prove_for_loop/(anonymous #0)" => pin_prove_for_loop(),
        "test/prove_for_loop_nested/(anonymous #0)" => pin_prove_for_loop_nested(),
        "test/prove_for_loop_dynamic/(anonymous #0)" => pin_prove_for_loop_dynamic(),
        "test/prove_if_else/(anonymous #0)" => pin_prove_if_else_0(),
        "test/prove_if_else/(anonymous #1)" => pin_prove_if_else_1(),
        "test/prove_outer_fn/(anonymous #0)" => pin_prove_outer_fn_0(),
        "test/prove_outer_fn/(anonymous #1)" => pin_prove_outer_fn_1(),
        "test/prove_outer_fn_circuit/tripler" => pin_prove_outer_fn_circuit(),
        "test/prove_power/(anonymous #0)" => pin_prove_power(),
        "test/prove_range_check/(anonymous #0)" => pin_prove_range_check_0(),
        "test/prove_range_check/(anonymous #1)" => pin_prove_range_check_1(),
        "test/prove_secret_vote/(anonymous #0)" => pin_prove_secret_vote(),
        "test/prove_with_poseidon/(anonymous #0)" => pin_prove_with_poseidon(),
        "test/typed_prove/(anonymous #0)" => pin_typed_prove_0(),
        "test/typed_prove/(anonymous #1)" => pin_typed_prove_1(),
        "test/babyadd/(anonymous #0)" => pin_babyadd(),
        _ => return None,
    })
}

fn print_regen(key: &str, actual: &FrozenBaseline) {
    println!("\n=== regen baseline for `{key}` ===");
    println!("FrozenBaseline {{");
    println!("    pre_o1_hash: {:?},", actual.pre_o1_hash);
    println!("    pre_o1_count: {},", actual.pre_o1_count);
    println!("    post_o1_hash: {:?},", actual.post_o1_hash);
    println!("    post_o1_count: {},", actual.post_o1_count);
    println!("    num_variables: {},", actual.num_variables);
    println!("    public_inputs: {:?},", actual.public_inputs);
    println!("}}\n");
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

#[test]
fn cross_path_prove_baseline() {
    let workspace_root = workspace_root();
    eprintln!("workspace_root = {}", workspace_root.display());

    let regen = std::env::var("REGEN_FROZEN_BASELINES").is_ok();

    let total_started = Instant::now();
    let mut rows: Vec<RowOutcome> = Vec::new();

    for example in EXAMPLES {
        eprintln!(
            "\n=== {} ({}) — budget {:?} ===",
            example.label, example.rel_path, example.budget
        );
        let example_started = Instant::now();

        let captures = match run_example_capture(example, &workspace_root) {
            Ok(c) => c,
            Err(e) => {
                rows.push(RowOutcome {
                    file: example.label.into(),
                    block: "(file)".into(),
                    baseline: None,
                    wall_clock: example_started.elapsed(),
                    error: Some(format!("compile/vm: {e}")),
                });
                continue;
            }
        };
        eprintln!("  captured {} prove block(s)", captures.len());

        if captures.is_empty() {
            rows.push(RowOutcome {
                file: example.label.into(),
                block: "(no prove block)".into(),
                baseline: None,
                wall_clock: example_started.elapsed(),
                error: Some("no Prove opcodes encountered".into()),
            });
            continue;
        }

        for cap in &captures {
            if example_started.elapsed() > example.budget {
                rows.push(RowOutcome {
                    file: example.label.into(),
                    block: cap
                        .name
                        .clone()
                        .unwrap_or_else(|| format!("(anonymous #{})", cap.seq)),
                    baseline: None,
                    wall_clock: Duration::ZERO,
                    error: Some(format!("budget exhausted ({:?})", example.budget)),
                });
                continue;
            }
            let row = replay_one(cap, example.label);
            eprintln!(
                "  block {:?}: ok={} ({:?})",
                row.block,
                row.baseline.is_some(),
                row.wall_clock
            );
            rows.push(row);
        }
    }

    let total_elapsed = total_started.elapsed();

    // ---- markdown table -------------------------------------------
    println!("\n## Cross-path prove-block frozen baseline\n");
    println!("| file | block | ok | pre-O1 | post-O1 | vars | wall_clock | error |");
    println!("|------|-------|----|------:|-------:|----:|-----------:|-------|");
    for row in &rows {
        let (ok, pre, post, vars) = match &row.baseline {
            Some(b) => (
                "yes",
                b.pre_o1_count.to_string(),
                b.post_o1_count.to_string(),
                b.num_variables.to_string(),
            ),
            None => ("no", "—".into(), "—".into(), "—".into()),
        };
        let err = row.error.as_deref().unwrap_or("");
        println!(
            "| {} | {} | {} | {} | {} | {} | {:.3}s | {} |",
            row.file,
            row.block,
            ok,
            pre,
            post,
            vars,
            row.wall_clock.as_secs_f64(),
            err.replace('|', "\\|"),
        );
    }

    // ---- pin compare or regen -------------------------------------
    let mut violations: Vec<String> = Vec::new();
    let mut pinned = 0usize;

    for row in &rows {
        let baseline = match &row.baseline {
            Some(b) => b,
            None => {
                violations.push(format!(
                    "{}/{}: no baseline produced ({})",
                    row.file,
                    row.block,
                    row.error.as_deref().unwrap_or("unknown")
                ));
                continue;
            }
        };
        let key = format!("{}/{}", row.file, row.block);

        if regen {
            print_regen(&key, baseline);
            continue;
        }

        let expected = match pin_for(&key) {
            Some(p) => p,
            None => {
                violations.push(format!(
                    "{key}: no pin found in pin_for() — add an arm or run REGEN_FROZEN_BASELINES=1"
                ));
                continue;
            }
        };

        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            assert_frozen_baseline_matches(baseline, &expected);
        }));
        match result {
            Ok(()) => pinned += 1,
            Err(e) => {
                let msg = if let Some(s) = e.downcast_ref::<String>() {
                    s.clone()
                } else if let Some(s) = e.downcast_ref::<&str>() {
                    (*s).to_string()
                } else {
                    "<panic with non-string payload>".into()
                };
                violations.push(format!(
                    "{key}: {}",
                    msg.lines().next().unwrap_or("<empty panic>")
                ));
            }
        }
    }

    println!("\n### Summary\n");
    println!(
        "**{pinned} / {} prove blocks matched pinned baseline.**",
        rows.len()
    );
    println!("Total runtime: {:.2}s.", total_elapsed.as_secs_f64());

    if regen {
        eprintln!(
            "\nREGEN mode: skipping assertion. Copy printed literals into pin_*() functions."
        );
        return;
    }

    if !violations.is_empty() {
        panic!(
            "cross_path_prove_baseline: {} violation(s):\n  - {}",
            violations.len(),
            violations.join("\n  - ")
        );
    }
}

/// CARGO_MANIFEST_DIR is `cli/`; the workspace root is one level up.
fn workspace_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .map(|p| p.to_path_buf())
        .unwrap_or(manifest)
}

// ===========================================================================
// Pinned canonical-multiset baselines (34 prove blocks)
//
// These are placeholder zero-hashes — populated via REGEN_FROZEN_BASELINES=1.
// The empty zero-hashes deliberately fail on first run; the regen flag prints
// the actual values to copy in.
// ===========================================================================

// Found 34 baselines

fn pin_proof_of_membership_membership() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            232, 74, 80, 4, 62, 123, 179, 33, 39, 189, 101, 161, 140, 224, 55, 170, 166, 87, 87,
            72, 218, 214, 155, 28, 213, 42, 243, 249, 53, 211, 44, 92,
        ],
        pre_o1_count: 1467,
        post_o1_hash: [
            160, 141, 182, 152, 190, 209, 26, 216, 199, 168, 229, 228, 178, 121, 63, 113, 109, 217,
            33, 144, 183, 111, 15, 26, 212, 108, 177, 126, 103, 151, 148, 144,
        ],
        post_o1_count: 966,
        num_variables: 1472,
        public_inputs: vec!["merkle_root".into()],
    }
}

fn pin_proof_of_membership_membership_0() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            244, 133, 199, 120, 228, 52, 61, 255, 39, 74, 133, 242, 170, 167, 40, 33, 224, 107,
            168, 131, 142, 200, 198, 149, 191, 222, 157, 213, 14, 136, 119, 111,
        ],
        pre_o1_count: 1467,
        post_o1_hash: [
            188, 169, 175, 148, 80, 39, 245, 216, 114, 170, 245, 202, 122, 56, 85, 201, 163, 246,
            228, 205, 195, 145, 44, 244, 113, 129, 170, 16, 246, 193, 235, 59,
        ],
        post_o1_count: 966,
        num_variables: 1472,
        public_inputs: vec!["merkle_root".into()],
    }
}

fn pin_circom_merkle_membership() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            166, 73, 159, 70, 139, 195, 225, 185, 116, 158, 216, 76, 199, 20, 239, 59, 21, 71, 238,
            73, 54, 77, 223, 158, 33, 121, 141, 176, 163, 184, 197, 159,
        ],
        pre_o1_count: 1465,
        post_o1_hash: [
            209, 80, 150, 219, 154, 69, 147, 113, 205, 16, 12, 219, 35, 221, 232, 234, 177, 163,
            165, 13, 63, 121, 232, 191, 63, 249, 66, 53, 188, 37, 1, 74,
        ],
        post_o1_count: 717,
        num_variables: 1469,
        public_inputs: vec!["merkle_root".into()],
    }
}

fn pin_circom_poseidon_chain() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            137, 145, 158, 23, 212, 176, 214, 194, 125, 162, 2, 84, 217, 106, 35, 84, 120, 19, 90,
            68, 199, 242, 241, 160, 22, 202, 24, 235, 150, 184, 93, 125,
        ],
        pre_o1_count: 2421,
        post_o1_hash: [
            194, 29, 243, 0, 142, 237, 92, 68, 7, 196, 241, 49, 160, 107, 137, 74, 108, 21, 160,
            83, 121, 52, 66, 129, 131, 148, 87, 23, 23, 212, 162, 14,
        ],
        post_o1_count: 1185,
        num_variables: 2423,
        public_inputs: vec!["final_hash".into()],
    }
}

fn pin_tornado_mixer_withdrawal() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            34, 52, 73, 190, 29, 5, 48, 126, 247, 68, 3, 132, 238, 36, 192, 2, 189, 180, 90, 170,
            238, 120, 226, 148, 221, 45, 30, 25, 26, 87, 247, 89,
        ],
        pre_o1_count: 1461,
        post_o1_hash: [
            244, 54, 156, 199, 10, 57, 53, 118, 251, 137, 228, 92, 145, 219, 132, 8, 186, 164, 119,
            167, 238, 70, 170, 213, 239, 233, 250, 60, 37, 69, 220, 74,
        ],
        post_o1_count: 963,
        num_variables: 1467,
        public_inputs: vec!["root".into(), "nullifier_hash".into(), "recipient".into()],
    }
}

fn pin_tornado_mixer_double_spend_check() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            190, 100, 22, 96, 93, 204, 139, 145, 243, 239, 252, 147, 157, 228, 65, 123, 46, 205,
            10, 227, 156, 107, 53, 205, 180, 130, 162, 133, 255, 138, 241, 162,
        ],
        pre_o1_count: 363,
        post_o1_hash: [
            142, 23, 75, 240, 167, 220, 142, 207, 232, 193, 21, 62, 112, 175, 105, 229, 192, 149,
            254, 170, 76, 130, 125, 140, 90, 13, 241, 122, 151, 135, 15, 34,
        ],
        post_o1_count: 237,
        num_variables: 365,
        public_inputs: vec!["nullifier_hash".into()],
    }
}

fn pin_tornado_mixer_withdrawal_2() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            34, 52, 73, 190, 29, 5, 48, 126, 247, 68, 3, 132, 238, 36, 192, 2, 189, 180, 90, 170,
            238, 120, 226, 148, 221, 45, 30, 25, 26, 87, 247, 89,
        ],
        pre_o1_count: 1461,
        post_o1_hash: [
            244, 54, 156, 199, 10, 57, 53, 118, 251, 137, 228, 92, 145, 219, 132, 8, 186, 164, 119,
            167, 238, 70, 170, 213, 239, 233, 250, 60, 37, 69, 220, 74,
        ],
        post_o1_count: 963,
        num_variables: 1467,
        public_inputs: vec![
            "root".into(),
            "nullifier_hash_2".into(),
            "recipient_2".into(),
        ],
    }
}

fn pin_tornado_multifile_withdraw() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            23, 166, 200, 155, 86, 117, 200, 29, 200, 238, 21, 201, 23, 36, 81, 132, 211, 164, 110,
            72, 76, 51, 22, 235, 117, 216, 15, 78, 40, 49, 128, 37,
        ],
        pre_o1_count: 2968,
        post_o1_hash: [
            243, 91, 28, 141, 172, 129, 76, 131, 36, 79, 228, 47, 23, 143, 128, 163, 127, 14, 39,
            37, 184, 23, 81, 48, 144, 54, 98, 83, 146, 168, 46, 126,
        ],
        post_o1_count: 1453,
        num_variables: 2979,
        public_inputs: vec!["root".into(), "nh".into()],
    }
}

fn pin_basic_prove() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            103, 62, 152, 139, 48, 217, 149, 137, 115, 187, 194, 183, 248, 72, 219, 141, 87, 137,
            70, 171, 47, 208, 201, 102, 207, 129, 89, 127, 117, 150, 91, 3,
        ],
        pre_o1_count: 2,
        post_o1_hash: [
            217, 207, 0, 42, 164, 232, 81, 250, 143, 157, 168, 11, 57, 228, 116, 121, 130, 145,
            135, 226, 135, 69, 167, 2, 249, 146, 0, 235, 213, 88, 217, 30,
        ],
        post_o1_count: 1,
        num_variables: 5,
        public_inputs: vec!["product".into()],
    }
}

fn pin_prove_array_sum() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            181, 240, 120, 148, 86, 237, 169, 18, 165, 117, 22, 121, 162, 28, 105, 233, 231, 1, 6,
            202, 205, 55, 93, 189, 91, 116, 96, 198, 249, 252, 223, 157,
        ],
        pre_o1_count: 1,
        post_o1_hash: [
            227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174,
            65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
        ],
        post_o1_count: 0,
        num_variables: 5,
        public_inputs: vec!["total".into()],
    }
}

fn pin_prove_assert_message() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            103, 62, 152, 139, 48, 217, 149, 137, 115, 187, 194, 183, 248, 72, 219, 141, 87, 137,
            70, 171, 47, 208, 201, 102, 207, 129, 89, 127, 117, 150, 91, 3,
        ],
        pre_o1_count: 2,
        post_o1_hash: [
            217, 207, 0, 42, 164, 232, 81, 250, 143, 157, 168, 11, 57, 228, 116, 121, 130, 145,
            135, 226, 135, 69, 167, 2, 249, 146, 0, 235, 213, 88, 217, 30,
        ],
        post_o1_count: 1,
        num_variables: 5,
        public_inputs: vec!["product".into()],
    }
}

fn pin_prove_boolean_mux() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            213, 155, 148, 62, 158, 102, 135, 208, 15, 232, 140, 105, 121, 65, 21, 56, 115, 66, 20,
            79, 60, 96, 210, 10, 94, 69, 129, 191, 88, 251, 200, 156,
        ],
        pre_o1_count: 6,
        post_o1_hash: [
            102, 134, 105, 141, 110, 85, 72, 205, 8, 8, 81, 96, 217, 208, 34, 25, 162, 116, 242,
            155, 170, 231, 56, 4, 182, 128, 149, 164, 97, 140, 239, 135,
        ],
        post_o1_count: 2,
        num_variables: 8,
        public_inputs: vec!["expected".into()],
    }
}

fn pin_prove_capture_0() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            94, 193, 186, 192, 174, 58, 212, 59, 247, 175, 186, 51, 158, 178, 161, 113, 19, 35,
            248, 253, 244, 224, 12, 178, 50, 6, 101, 159, 18, 183, 136, 109,
        ],
        pre_o1_count: 1,
        post_o1_hash: [
            227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174,
            65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
        ],
        post_o1_count: 0,
        num_variables: 4,
        public_inputs: vec!["sum".into()],
    }
}

fn pin_prove_capture_1() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            103, 62, 152, 139, 48, 217, 149, 137, 115, 187, 194, 183, 248, 72, 219, 141, 87, 137,
            70, 171, 47, 208, 201, 102, 207, 129, 89, 127, 117, 150, 91, 3,
        ],
        pre_o1_count: 2,
        post_o1_hash: [
            217, 207, 0, 42, 164, 232, 81, 250, 143, 157, 168, 11, 57, 228, 116, 121, 130, 145,
            135, 226, 135, 69, 167, 2, 249, 146, 0, 235, 213, 88, 217, 30,
        ],
        post_o1_count: 1,
        num_variables: 5,
        public_inputs: vec!["product".into()],
    }
}

fn pin_prove_chain_0() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            250, 76, 21, 101, 7, 25, 125, 172, 4, 24, 89, 106, 30, 51, 3, 72, 188, 169, 218, 7,
            179, 210, 5, 57, 26, 222, 232, 133, 133, 221, 51, 211,
        ],
        pre_o1_count: 362,
        post_o1_hash: [
            61, 234, 174, 64, 197, 152, 224, 49, 68, 104, 81, 42, 135, 231, 191, 0, 189, 117, 169,
            72, 202, 116, 203, 3, 177, 1, 33, 187, 50, 47, 152, 206,
        ],
        post_o1_count: 240,
        num_variables: 365,
        public_inputs: vec!["commitment".into()],
    }
}

fn pin_prove_chain_1() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            250, 76, 21, 101, 7, 25, 125, 172, 4, 24, 89, 106, 30, 51, 3, 72, 188, 169, 218, 7,
            179, 210, 5, 57, 26, 222, 232, 133, 133, 221, 51, 211,
        ],
        pre_o1_count: 362,
        post_o1_hash: [
            61, 234, 174, 64, 197, 152, 224, 49, 68, 104, 81, 42, 135, 231, 191, 0, 189, 117, 169,
            72, 202, 116, 203, 3, 177, 1, 33, 187, 50, 47, 152, 206,
        ],
        post_o1_count: 240,
        num_variables: 365,
        public_inputs: vec!["nullifier".into()],
    }
}

fn pin_prove_comparison() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            184, 117, 232, 153, 171, 42, 138, 231, 129, 173, 156, 146, 251, 60, 49, 134, 235, 47,
            213, 19, 202, 229, 121, 85, 195, 154, 80, 83, 77, 175, 174, 223,
        ],
        pre_o1_count: 1527,
        post_o1_hash: [
            37, 89, 184, 191, 51, 95, 174, 39, 176, 169, 115, 11, 186, 23, 11, 108, 135, 229, 33,
            100, 204, 121, 104, 19, 83, 112, 250, 89, 119, 34, 63, 184,
        ],
        post_o1_count: 1513,
        num_variables: 1521,
        public_inputs: Vec::new(),
    }
}

fn pin_prove_division() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            59, 21, 210, 121, 95, 41, 254, 159, 11, 135, 153, 150, 141, 84, 162, 142, 65, 240, 213,
            172, 109, 107, 254, 247, 240, 255, 113, 152, 17, 75, 16, 155,
        ],
        pre_o1_count: 3,
        post_o1_hash: [
            179, 73, 234, 80, 45, 227, 184, 188, 5, 201, 21, 213, 28, 116, 233, 12, 8, 208, 50,
            164, 151, 180, 206, 235, 50, 83, 154, 47, 203, 190, 136, 215,
        ],
        post_o1_count: 2,
        num_variables: 6,
        public_inputs: vec!["q".into()],
    }
}

fn pin_prove_for_loop() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            231, 134, 31, 240, 111, 95, 24, 34, 63, 149, 144, 181, 104, 1, 92, 112, 98, 14, 249,
            232, 104, 41, 44, 255, 153, 19, 241, 164, 196, 169, 123, 97,
        ],
        pre_o1_count: 1,
        post_o1_hash: [
            227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174,
            65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
        ],
        post_o1_count: 0,
        num_variables: 6,
        public_inputs: vec!["total".into()],
    }
}

fn pin_prove_for_loop_nested() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            131, 198, 85, 76, 70, 99, 168, 46, 135, 59, 81, 255, 103, 177, 237, 127, 12, 250, 228,
            203, 71, 156, 41, 111, 10, 160, 46, 177, 105, 75, 252, 254,
        ],
        pre_o1_count: 1,
        post_o1_hash: [
            131, 198, 85, 76, 70, 99, 168, 46, 135, 59, 81, 255, 103, 177, 237, 127, 12, 250, 228,
            203, 71, 156, 41, 111, 10, 160, 46, 177, 105, 75, 252, 254,
        ],
        post_o1_count: 1,
        num_variables: 2,
        public_inputs: vec!["expected".into()],
    }
}

fn pin_prove_for_loop_dynamic() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            99, 41, 87, 14, 200, 72, 232, 183, 138, 226, 94, 200, 12, 145, 136, 198, 220, 36, 237,
            203, 205, 216, 205, 164, 62, 52, 189, 86, 100, 163, 118, 64,
        ],
        pre_o1_count: 5,
        post_o1_hash: [
            23, 69, 36, 227, 97, 0, 218, 10, 79, 141, 159, 241, 70, 37, 129, 184, 99, 120, 206,
            207, 241, 112, 104, 137, 203, 119, 162, 242, 34, 169, 227, 145,
        ],
        post_o1_count: 2,
        num_variables: 4,
        public_inputs: vec!["target_sq".into()],
    }
}

fn pin_prove_if_else_0() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            149, 196, 126, 240, 243, 70, 166, 183, 115, 58, 55, 127, 205, 220, 60, 132, 239, 173,
            99, 134, 162, 49, 127, 93, 185, 139, 97, 140, 123, 231, 58, 119,
        ],
        pre_o1_count: 8,
        post_o1_hash: [
            236, 147, 248, 223, 172, 12, 186, 30, 221, 39, 62, 17, 39, 62, 151, 125, 127, 16, 27,
            75, 105, 57, 91, 44, 95, 141, 44, 168, 93, 155, 202, 101,
        ],
        post_o1_count: 5,
        num_variables: 10,
        public_inputs: vec!["expected".into()],
    }
}

fn pin_prove_if_else_1() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            149, 196, 126, 240, 243, 70, 166, 183, 115, 58, 55, 127, 205, 220, 60, 132, 239, 173,
            99, 134, 162, 49, 127, 93, 185, 139, 97, 140, 123, 231, 58, 119,
        ],
        pre_o1_count: 8,
        post_o1_hash: [
            236, 147, 248, 223, 172, 12, 186, 30, 221, 39, 62, 17, 39, 62, 151, 125, 127, 16, 27,
            75, 105, 57, 91, 44, 95, 141, 44, 168, 93, 155, 202, 101,
        ],
        post_o1_count: 5,
        num_variables: 10,
        public_inputs: vec!["expected_off".into()],
    }
}

fn pin_prove_outer_fn_0() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            134, 125, 211, 250, 52, 228, 176, 186, 18, 9, 47, 0, 74, 21, 129, 130, 57, 115, 89,
            225, 144, 87, 19, 89, 141, 40, 171, 162, 47, 209, 143, 158,
        ],
        pre_o1_count: 1,
        post_o1_hash: [
            227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174,
            65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
        ],
        post_o1_count: 0,
        num_variables: 3,
        public_inputs: vec!["expected".into()],
    }
}

fn pin_prove_outer_fn_1() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            181, 240, 120, 148, 86, 237, 169, 18, 165, 117, 22, 121, 162, 28, 105, 233, 231, 1, 6,
            202, 205, 55, 93, 189, 91, 116, 96, 198, 249, 252, 223, 157,
        ],
        pre_o1_count: 1,
        post_o1_hash: [
            227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174,
            65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
        ],
        post_o1_count: 0,
        num_variables: 5,
        public_inputs: vec!["sum".into()],
    }
}

fn pin_prove_outer_fn_circuit() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            128, 62, 41, 169, 3, 94, 128, 125, 250, 1, 33, 138, 96, 116, 112, 9, 22, 110, 102, 42,
            107, 29, 156, 92, 10, 149, 213, 112, 221, 15, 117, 238,
        ],
        pre_o1_count: 1,
        post_o1_hash: [
            128, 62, 41, 169, 3, 94, 128, 125, 250, 1, 33, 138, 96, 116, 112, 9, 22, 110, 102, 42,
            107, 29, 156, 92, 10, 149, 213, 112, 221, 15, 117, 238,
        ],
        post_o1_count: 1,
        num_variables: 3,
        public_inputs: vec!["input".into(), "expected".into()],
    }
}

fn pin_prove_power() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            131, 134, 99, 127, 20, 4, 83, 89, 93, 121, 186, 33, 20, 191, 103, 193, 210, 16, 183,
            90, 67, 186, 74, 179, 253, 163, 237, 244, 83, 60, 69, 242,
        ],
        pre_o1_count: 4,
        post_o1_hash: [
            239, 87, 19, 175, 190, 236, 243, 252, 115, 171, 13, 53, 125, 35, 235, 246, 214, 191,
            215, 109, 28, 162, 102, 255, 44, 153, 239, 144, 180, 123, 180, 151,
        ],
        post_o1_count: 2,
        num_variables: 6,
        public_inputs: vec!["sq".into(), "cube".into()],
    }
}

fn pin_prove_range_check_0() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            212, 224, 33, 236, 243, 175, 169, 150, 44, 75, 58, 88, 108, 109, 218, 126, 170, 174,
            134, 235, 187, 220, 181, 196, 24, 118, 93, 184, 231, 102, 34, 90,
        ],
        pre_o1_count: 9,
        post_o1_hash: [
            70, 180, 244, 221, 25, 109, 208, 1, 227, 189, 139, 77, 82, 2, 247, 216, 132, 124, 108,
            211, 95, 135, 206, 240, 135, 104, 163, 149, 239, 167, 129, 32,
        ],
        post_o1_count: 8,
        num_variables: 10,
        public_inputs: Vec::new(),
    }
}

fn pin_prove_range_check_1() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            97, 143, 110, 218, 73, 46, 35, 49, 121, 199, 212, 39, 7, 245, 188, 130, 124, 80, 121,
            226, 129, 220, 173, 209, 142, 64, 199, 101, 54, 47, 99, 186,
        ],
        pre_o1_count: 17,
        post_o1_hash: [
            170, 68, 139, 200, 255, 234, 125, 87, 240, 193, 137, 232, 164, 50, 251, 243, 32, 32,
            244, 135, 185, 194, 103, 79, 176, 125, 214, 208, 211, 254, 35, 23,
        ],
        post_o1_count: 16,
        num_variables: 18,
        public_inputs: Vec::new(),
    }
}

fn pin_prove_secret_vote() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            217, 3, 43, 253, 45, 89, 227, 221, 63, 167, 84, 55, 89, 246, 144, 47, 164, 55, 102,
            215, 142, 63, 82, 4, 156, 129, 34, 140, 235, 187, 75, 167,
        ],
        pre_o1_count: 1463,
        post_o1_hash: [
            76, 29, 150, 19, 127, 41, 121, 187, 92, 225, 116, 7, 174, 120, 249, 90, 18, 228, 157,
            119, 61, 186, 218, 26, 226, 85, 151, 12, 116, 16, 19, 130,
        ],
        post_o1_count: 964,
        num_variables: 1468,
        public_inputs: vec![
            "merkle_root".into(),
            "nullifier".into(),
            "vote".into(),
            "election_id".into(),
        ],
    }
}

fn pin_prove_with_poseidon() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            165, 49, 103, 201, 26, 66, 96, 21, 162, 203, 58, 52, 74, 46, 99, 24, 187, 254, 144, 34,
            138, 198, 23, 238, 155, 132, 157, 25, 187, 17, 149, 109,
        ],
        pre_o1_count: 362,
        post_o1_hash: [
            38, 248, 251, 186, 170, 70, 52, 22, 245, 120, 58, 192, 104, 140, 70, 180, 205, 190, 52,
            32, 25, 209, 37, 25, 206, 128, 106, 28, 14, 29, 10, 93,
        ],
        post_o1_count: 240,
        num_variables: 365,
        public_inputs: vec!["h".into()],
    }
}

fn pin_typed_prove_0() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            103, 62, 152, 139, 48, 217, 149, 137, 115, 187, 194, 183, 248, 72, 219, 141, 87, 137,
            70, 171, 47, 208, 201, 102, 207, 129, 89, 127, 117, 150, 91, 3,
        ],
        pre_o1_count: 2,
        post_o1_hash: [
            217, 207, 0, 42, 164, 232, 81, 250, 143, 157, 168, 11, 57, 228, 116, 121, 130, 145,
            135, 226, 135, 69, 167, 2, 249, 146, 0, 235, 213, 88, 217, 30,
        ],
        post_o1_count: 1,
        num_variables: 5,
        public_inputs: vec!["product".into()],
    }
}

fn pin_typed_prove_1() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            94, 193, 186, 192, 174, 58, 212, 59, 247, 175, 186, 51, 158, 178, 161, 113, 19, 35,
            248, 253, 244, 224, 12, 178, 50, 6, 101, 159, 18, 183, 136, 109,
        ],
        pre_o1_count: 1,
        post_o1_hash: [
            227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174,
            65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
        ],
        post_o1_count: 0,
        num_variables: 4,
        public_inputs: vec!["sum".into()],
    }
}

fn pin_babyadd() -> FrozenBaseline {
    FrozenBaseline {
        pre_o1_hash: [
            195, 74, 183, 224, 72, 180, 184, 140, 154, 130, 88, 199, 189, 119, 72, 205, 2, 20, 36,
            242, 46, 106, 76, 30, 154, 2, 107, 194, 155, 75, 25, 101,
        ],
        pre_o1_count: 2,
        post_o1_hash: [
            227, 176, 196, 66, 152, 252, 28, 20, 154, 251, 244, 200, 153, 111, 185, 36, 39, 174,
            65, 228, 100, 155, 147, 76, 164, 149, 153, 27, 120, 82, 184, 85,
        ],
        post_o1_count: 0,
        num_variables: 3,
        public_inputs: Vec::new(),
    }
}
