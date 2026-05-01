//! Lysis-vs-Legacy cross-path equivalence baseline for **`.ach` files
//! containing `prove {}` blocks**.
//!
//! Sister sweep to the circom-template baseline. For every `.ach`
//! example listed in [`EXAMPLES`], this test:
//!
//! 1. Compiles the source via `cli::new_compiler()`.
//! 2. Runs the resulting bytecode in an Akron VM with a custom
//!    [`CapturingProveHandler`] that records `(name, prove_ir_bytes,
//!    scope_values)` on every `Prove` opcode and returns
//!    `ProveResult::VerifiedOnly` so the script proceeds.
//! 3. Replays each captured prove block twice — once through
//!    `ProveIR::instantiate` (legacy) and once through
//!    `ProveIR::instantiate_lysis` (Lysis path) — using the same
//!    captures both times.
//! 4. Lowers each IR program to R1CS, calls `optimize_r1cs` (O1), and
//!    compares pre-O1 + post-O1 multisets via
//!    `zkc::lysis_oracle::compare::semantic_equivalence`.
//!
//! Failures (Lysis Walker rejection, divergence, timeout) are
//! recorded into the row and printed as a markdown table at the end.
//! No row is allowed to abort the test — the entire grid runs to
//! completion.
//!
//! Output: a markdown table on stdout (run with `--nocapture`). The
//! companion report at
//! `.claude/plans/cross-path-baseline-2026-04-28/prove-examples.md`
//! is written by hand from this output.

use std::cell::RefCell;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::time::{Duration, Instant};

use akron::{CallFrame, ProveError, ProveHandler, ProveResult, VM};
use cli::commands::{new_compiler, register_std_modules};
use ir_forge::{ArraySize, ProveIR};
use memory::{Bn254Fr, FieldElement, Function};
use zkc::lysis_oracle::compare::{semantic_equivalence, OracleResult};
use zkc::r1cs_backend::R1CSCompiler;

type F = Bn254Fr;

// ---------------------------------------------------------------------------
// Examples list — paths relative to the workspace root (`achronyme/`).
// circom_lib_dirs is set per-row when the example imports `.circom`.
// ---------------------------------------------------------------------------

struct Example {
    /// Display label for the table.
    label: &'static str,
    /// Path relative to `achronyme/` (the cargo manifest dir for `cli`
    /// is `cli/`, so we go one level up from CARGO_MANIFEST_DIR).
    rel_path: &'static str,
    /// Extra `-l/--lib` directories to feed the akronc compiler. Used
    /// for examples that do circom imports.
    circom_libs: &'static [&'static str],
    /// Hard wall-clock budget for the entire example (compile + VM
    /// run + replay of every prove block). Tornado-Cash sized
    /// circuits get a fatter budget.
    budget: Duration,
}

const EXAMPLES: &[Example] = &[
    // -- examples/proof_of_membership.ach -- 2 named prove blocks
    Example {
        label: "proof_of_membership",
        rel_path: "examples/proof_of_membership.ach",
        circom_libs: &[],
        budget: Duration::from_secs(180),
    },
    // -- examples/circom_merkle_membership.ach -- depth-2 + circom Poseidon
    Example {
        label: "circom_merkle_membership",
        rel_path: "examples/circom_merkle_membership.ach",
        circom_libs: &["test/circomlib/circuits"],
        budget: Duration::from_secs(180),
    },
    // -- examples/circom_poseidon_chain.ach -- 5x Poseidon(2) chain
    Example {
        label: "circom_poseidon_chain",
        rel_path: "examples/circom_poseidon_chain.ach",
        circom_libs: &["test/circomlib/circuits"],
        budget: Duration::from_secs(180),
    },
    // -- examples/tornado_mixer.ach -- 3 prove blocks
    Example {
        label: "tornado_mixer",
        rel_path: "examples/tornado_mixer.ach",
        circom_libs: &[],
        budget: Duration::from_secs(240),
    },
    // -- examples/tornado/src/main.ach -- multi-file, depth-4 Merkle
    Example {
        label: "tornado_multifile",
        rel_path: "examples/tornado/src/main.ach",
        circom_libs: &["test/circomlib/circuits"],
        budget: Duration::from_secs(300),
    },
    // -- test/prove/*.ach -- small unit examples
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
    // -- Phase 1.B fixtures: in-circuit `for` and `if/else` --
    Example {
        label: "test/prove_for_loop",
        rel_path: "test/prove/prove_for_loop.ach",
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
    // -- test/circom_imports/babyadd.ach -- multi-output circom template
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
    /// Sequence number, in source-evaluation order.
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
        // Pull the optional `name` from the bytes — handy for the
        // table output, doesn't gate anything.
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

// Shared wrapper so we can stash the same handler in both
// `vm.prove_handler` and `vm.verify_handler` slots and still pull the
// captures out after the VM run drops them.
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
    legacy_ok: bool,
    lysis_ok: bool,
    /// Constraint count after legacy lower → R1CS, pre-O1.
    legacy_pre: Option<usize>,
    /// Constraint count after lysis lower → R1CS, pre-O1.
    lysis_pre: Option<usize>,
    /// Pre-O1 multiset / partition / variable equality verdict.
    pre_o1_eq: EqVerdict,
    /// Post-O1 multiset equality verdict.
    post_o1_eq: EqVerdict,
    /// Wall-clock for the row (legacy + lysis combined).
    wall_clock: Duration,
    /// Single human-readable error class label, if any.
    error: Option<String>,
}

#[derive(Debug, Clone, PartialEq)]
enum EqVerdict {
    Equivalent,
    Differs(String),
    Skipped,
}

impl EqVerdict {
    fn as_cell(&self) -> &'static str {
        match self {
            EqVerdict::Equivalent => "yes",
            EqVerdict::Differs(_) => "no",
            EqVerdict::Skipped => "n/a",
        }
    }
}

// ---------------------------------------------------------------------------
// Compile + VM run a single .ach example.
// Returns the captured prove blocks, or an error string.
// ---------------------------------------------------------------------------

fn run_example_capture(example: &Example, workspace_root: &Path) -> Result<Vec<Capture>, String> {
    let abs_path = workspace_root.join(example.rel_path);
    let source = std::fs::read_to_string(&abs_path)
        .map_err(|e| format!("read {}: {e}", abs_path.display()))?;

    // 1. Compile via the same path `ach run` uses.
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

    // 2. Build a VM with our capturing handler.
    let mut vm = VM::new();
    register_std_modules(&mut vm).map_err(|e| format!("register_std_modules: {e:?}"))?;

    let handler = Rc::new(CapturingProveHandler::default());
    vm.prove_handler = Some(Box::new(SharedCapturing(Rc::clone(&handler))));
    vm.verify_handler = Some(Box::new(SharedCapturing(Rc::clone(&handler))));

    // 3. Transfer compiler state into the VM (mirrors `cli::commands::run`).
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
// Replay one captured prove block through Legacy + Lysis. Compare.
// ---------------------------------------------------------------------------

fn replay_one(capture: &Capture, file_label: &str) -> RowOutcome {
    let started = Instant::now();
    let block_name = capture
        .name
        .clone()
        .unwrap_or_else(|| format!("(anonymous #{})", capture.seq));

    // Deserialize ProveIR.
    let prove_ir = match ProveIR::from_bytes(&capture.bytes) {
        Ok((p, _prime)) => p,
        Err(e) => {
            return RowOutcome {
                file: file_label.into(),
                block: block_name,
                legacy_ok: false,
                lysis_ok: false,
                legacy_pre: None,
                lysis_pre: None,
                pre_o1_eq: EqVerdict::Skipped,
                post_o1_eq: EqVerdict::Skipped,
                wall_clock: started.elapsed(),
                error: Some(format!("ProveIR::from_bytes: {e}")),
            };
        }
    };

    let captures_map = collect_captures(&prove_ir, &capture.scope);

    // Legacy.
    let legacy_program = prove_ir.instantiate::<F>(&captures_map);
    let legacy_ok = legacy_program.is_ok();

    // Lysis.
    let lysis_program = prove_ir.instantiate_lysis::<F>(&captures_map);
    let lysis_ok = lysis_program.is_ok();

    let mut error: Option<String> = None;

    let (mut legacy_program, mut lysis_program) = match (legacy_program, lysis_program) {
        (Ok(l), Ok(r)) => (l, r),
        (Err(e), _) => {
            error = Some(format!("legacy instantiate failed: {e}"));
            return RowOutcome {
                file: file_label.into(),
                block: block_name,
                legacy_ok: false,
                lysis_ok,
                legacy_pre: None,
                lysis_pre: None,
                pre_o1_eq: EqVerdict::Skipped,
                post_o1_eq: EqVerdict::Skipped,
                wall_clock: started.elapsed(),
                error,
            };
        }
        (Ok(_), Err(e)) => {
            error = Some(format!("lysis instantiate failed: {e}"));
            return RowOutcome {
                file: file_label.into(),
                block: block_name,
                legacy_ok: true,
                lysis_ok: false,
                legacy_pre: None,
                lysis_pre: None,
                pre_o1_eq: EqVerdict::Skipped,
                post_o1_eq: EqVerdict::Skipped,
                wall_clock: started.elapsed(),
                error,
            };
        }
    };

    // Run identical optimize() on both — that's what
    // `prove_handler.rs` does before R1CS compile, so for a baseline
    // we mirror it.
    ir::passes::optimize(&mut legacy_program);
    ir::passes::optimize(&mut lysis_program);

    // Pre-O1 R1CS compare.
    let pre_eq = compare_via_oracle(&legacy_program, &lysis_program);
    let (legacy_pre, lysis_pre) = (
        compile_and_count(&legacy_program),
        compile_and_count(&lysis_program),
    );

    // Post-O1: same compare path, but each side runs optimize_r1cs(O1)
    // before the multiset is collected. We re-do the work because
    // `semantic_equivalence` doesn't take a post-compile hook.
    let post_eq = compare_post_o1(&legacy_program, &lysis_program);

    RowOutcome {
        file: file_label.into(),
        block: block_name,
        legacy_ok,
        lysis_ok,
        legacy_pre,
        lysis_pre,
        pre_o1_eq: pre_eq,
        post_o1_eq: post_eq,
        wall_clock: started.elapsed(),
        error,
    }
}

/// Build the captures map for `instantiate(_lysis)` by selecting just
/// the names the ProveIR template declares as captures (scalar +
/// per-element of capture_arrays). The VM scope contains everything
/// in scope at the prove site, but `instantiate` validates that we
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
        // Element-level captures `{name}_{i}` are what
        // `run_walk` step 4b reassembles into the array.
        for i in 0..arr.size {
            let elem = format!("{}_{i}", arr.name);
            if let Some(v) = scope.get(&elem) {
                out.insert(elem, *v);
            }
        }
    }
    // Inputs are also threaded through `instantiate` for input array
    // sizes resolved via Capture (but there's no explicit "input
    // captures" path — we rely on declared captures only). Public /
    // witness Inputs flow through `prove_handler`'s `inputs` map at
    // R1CS-compile time, NOT through `captures`.
    let _ = ArraySize::Literal(0); // pull the import in even when array_size never fires
    out
}

fn compile_and_count(program: &ir::IrProgram<F>) -> Option<usize> {
    let mut compiler = R1CSCompiler::<F>::new();
    match compiler.compile_ir(program) {
        Ok(()) => Some(compiler.cs.num_constraints()),
        Err(_) => None,
    }
}

fn compare_via_oracle(a: &ir::IrProgram<F>, b: &ir::IrProgram<F>) -> EqVerdict {
    match semantic_equivalence(a, b, &[]) {
        OracleResult::Equivalent => EqVerdict::Equivalent,
        other => EqVerdict::Differs(format!("{other:?}")),
    }
}

/// Compare post-O1 R1CS. We compile both sides, run `optimize_r1cs`,
/// then build a canonical multiset by hand using the same key shape
/// `lysis_oracle::compare` uses internally. (The oracle exposes
/// `semantic_equivalence` only at the IrProgram level, not the
/// post-optimize R1CS level — for post-O1 we do it inline.)
fn compare_post_o1(a: &ir::IrProgram<F>, b: &ir::IrProgram<F>) -> EqVerdict {
    let mut ca = R1CSCompiler::<F>::new();
    let mut cb = R1CSCompiler::<F>::new();
    if let Err(e) = ca.compile_ir(a) {
        return EqVerdict::Differs(format!("legacy R1CS compile failed: {e}"));
    }
    if let Err(e) = cb.compile_ir(b) {
        return EqVerdict::Differs(format!("lysis R1CS compile failed: {e}"));
    }
    ca.optimize_r1cs();
    cb.optimize_r1cs();

    let na = ca.cs.num_constraints();
    let nb = cb.cs.num_constraints();
    let va = ca.cs.num_variables();
    let vb = cb.cs.num_variables();
    if na != nb || va != vb {
        return EqVerdict::Differs(format!(
            "post-O1 cardinality differs: legacy=({na} c, {va} v) lysis=({nb} c, {vb} v)"
        ));
    }

    // Multiset: canonicalize each constraint's A/B/C as a sorted
    // `(wire_index, [u64;4])` vector, then sort the whole list.
    let canon_a = canonical_multiset(&ca);
    let canon_b = canonical_multiset(&cb);
    if canon_a == canon_b {
        EqVerdict::Equivalent
    } else {
        EqVerdict::Differs("post-O1 multiset differs".to_string())
    }
}

fn canonical_multiset(c: &R1CSCompiler<F>) -> Vec<Vec<(usize, [u64; 4])>> {
    let mut out: Vec<Vec<(usize, [u64; 4])>> = Vec::new();
    for k in c.cs.constraints() {
        let mut combined: Vec<(usize, [u64; 4])> = Vec::new();
        for lc in [&k.a, &k.b, &k.c] {
            for (v, coeff) in lc.simplify().terms() {
                combined.push((v.index(), coeff.to_canonical()));
            }
            // separator so swapping a term across A/B/C doesn't alias
            combined.push((usize::MAX, [u64::MAX; 4]));
        }
        out.push(combined);
    }
    out.sort();
    out
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

#[test]
fn cross_path_prove_baseline() {
    let workspace_root = workspace_root();
    eprintln!("workspace_root = {}", workspace_root.display());

    let total_started = Instant::now();
    let mut rows: Vec<RowOutcome> = Vec::new();

    for example in EXAMPLES {
        eprintln!(
            "\n=== {} ({}) — budget {:?} ===",
            example.label, example.rel_path, example.budget
        );
        let example_started = Instant::now();

        // Threading note: we run synchronously and rely on the
        // example's own size to stay under budget. A separate watchdog
        // thread that aborts a captured prove block partway is more
        // surgery than this baseline needs — Tornado-Cash sized
        // examples in release mode finish in a couple of seconds each.
        // If a future row hangs, we'd add a `std::process::exit` from
        // a watchdog thread here.

        let captures = match run_example_capture(example, &workspace_root) {
            Ok(c) => c,
            Err(e) => {
                rows.push(RowOutcome {
                    file: example.label.into(),
                    block: "(file)".into(),
                    legacy_ok: false,
                    lysis_ok: false,
                    legacy_pre: None,
                    lysis_pre: None,
                    pre_o1_eq: EqVerdict::Skipped,
                    post_o1_eq: EqVerdict::Skipped,
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
                legacy_ok: false,
                lysis_ok: false,
                legacy_pre: None,
                lysis_pre: None,
                pre_o1_eq: EqVerdict::Skipped,
                post_o1_eq: EqVerdict::Skipped,
                wall_clock: example_started.elapsed(),
                error: Some("no Prove opcodes encountered".into()),
            });
            continue;
        }

        for cap in &captures {
            // Per-block soft budget: if we've already burned the
            // example's whole budget on earlier blocks, mark the rest
            // as timed out without running.
            if example_started.elapsed() > example.budget {
                rows.push(RowOutcome {
                    file: example.label.into(),
                    block: cap
                        .name
                        .clone()
                        .unwrap_or_else(|| format!("(anonymous #{})", cap.seq)),
                    legacy_ok: false,
                    lysis_ok: false,
                    legacy_pre: None,
                    lysis_pre: None,
                    pre_o1_eq: EqVerdict::Skipped,
                    post_o1_eq: EqVerdict::Skipped,
                    wall_clock: Duration::ZERO,
                    error: Some(format!("budget exhausted ({:?})", example.budget)),
                });
                continue;
            }
            let row = replay_one(cap, example.label);
            eprintln!(
                "  block {:?}: legacy_ok={} lysis_ok={} pre={:?} post={:?} ({:?})",
                row.block,
                row.legacy_ok,
                row.lysis_ok,
                row.pre_o1_eq,
                row.post_o1_eq,
                row.wall_clock
            );
            rows.push(row);
        }
    }

    let total_elapsed = total_started.elapsed();

    // ---- markdown table -------------------------------------------
    println!("\n## Cross-path prove-block baseline\n");
    println!(
        "| file | block | legacy_ok | lysis_ok | pre-O1 eq | post-O1 eq | legacy_pre | lysis_pre | wall_clock | error |"
    );
    println!(
        "|------|-------|-----------|----------|-----------|------------|-----------:|----------:|-----------:|-------|"
    );
    for row in &rows {
        let legacy_pre = row
            .legacy_pre
            .map(|n| n.to_string())
            .unwrap_or_else(|| "—".into());
        let lysis_pre = row
            .lysis_pre
            .map(|n| n.to_string())
            .unwrap_or_else(|| "—".into());
        let err = row.error.as_deref().unwrap_or("");
        println!(
            "| {} | {} | {} | {} | {} | {} | {} | {} | {:.3}s | {} |",
            row.file,
            row.block,
            ok_cell(row.legacy_ok),
            ok_cell(row.lysis_ok),
            row.pre_o1_eq.as_cell(),
            row.post_o1_eq.as_cell(),
            legacy_pre,
            lysis_pre,
            row.wall_clock.as_secs_f64(),
            err.replace('|', "\\|"),
        );
    }

    // ---- divergences detail ---------------------------------------
    let mut diverging: Vec<&RowOutcome> = rows
        .iter()
        .filter(|r| {
            matches!(r.pre_o1_eq, EqVerdict::Differs(_))
                || matches!(r.post_o1_eq, EqVerdict::Differs(_))
        })
        .collect();
    if !diverging.is_empty() {
        println!("\n### Divergences\n");
        diverging.sort_by_key(|r| (r.file.clone(), r.block.clone()));
        for r in diverging {
            println!("- **{} / {}**", r.file, r.block);
            if let EqVerdict::Differs(d) = &r.pre_o1_eq {
                println!("  - pre-O1: {d}");
            }
            if let EqVerdict::Differs(d) = &r.post_o1_eq {
                println!("  - post-O1: {d}");
            }
        }
    }

    // ---- failures detail ------------------------------------------
    let failing: Vec<&RowOutcome> = rows
        .iter()
        .filter(|r| !r.legacy_ok || !r.lysis_ok || r.error.is_some())
        .collect();
    if !failing.is_empty() {
        println!("\n### Failures (Lysis or Legacy)\n");
        for r in failing {
            println!(
                "- **{} / {}**: legacy_ok={}, lysis_ok={}",
                r.file, r.block, r.legacy_ok, r.lysis_ok
            );
            if let Some(e) = &r.error {
                println!("  - error: {e}");
            }
        }
    }

    // ---- summary --------------------------------------------------
    let total_blocks = rows.len();
    let byte_identical = rows
        .iter()
        .filter(|r| {
            r.legacy_ok
                && r.lysis_ok
                && r.pre_o1_eq == EqVerdict::Equivalent
                && r.post_o1_eq == EqVerdict::Equivalent
        })
        .count();
    let lysis_failures = rows.iter().filter(|r| r.legacy_ok && !r.lysis_ok).count();
    let divergences = rows
        .iter()
        .filter(|r| {
            r.legacy_ok
                && r.lysis_ok
                && (matches!(r.pre_o1_eq, EqVerdict::Differs(_))
                    || matches!(r.post_o1_eq, EqVerdict::Differs(_)))
        })
        .count();

    println!("\n### Summary\n");
    println!(
        "**{byte_identical} / {total_blocks} prove blocks byte-identical, {lysis_failures} fail Lysis, {divergences} diverge.**"
    );
    println!("Total runtime: {:.2}s.", total_elapsed.as_secs_f64());

    // ---- hard-gate ------------------------------------------------
    // Phase 1.B promoted this test from informational to assertion-
    // style. Any divergence, Lysis failure, or unexpected skip fails
    // the run. Mirrors `circom/tests/cross_path_baseline.rs` policy.
    if byte_identical != total_blocks {
        panic!(
            "cross_path_prove_baseline: {byte_identical}/{total_blocks} byte-identical \
             ({lysis_failures} Lysis failures, {divergences} divergences). \
             Inspect table above for offending rows."
        );
    }
}

fn ok_cell(b: bool) -> &'static str {
    if b {
        "yes"
    } else {
        "no"
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
