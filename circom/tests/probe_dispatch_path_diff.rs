//! Probe — dispatch-path A/B comparison for SHA-256(64).
//!
//! Empirical disambiguation between three failure-mode hypotheses for
//! the `frame overflow: register slot 255 exceeds max frame size 255`
//! error that hits when a `.ach prove` block invokes a heavy circomlib
//! template:
//!
//! - **H1** — outer-wrapping miss: pure-circom's top-level body has
//!   structure that the walker sees as its own frame; the `.ach`
//!   dispatch flattens into a parent body without that boundary.
//! - **H2** — nested-lift gap: both bodies have `LoopUnroll` nodes,
//!   but the per-iter split heuristic doesn't fire when the parent is
//!   a flat body rather than a top-level template.
//! - **H3** — wide single instruction: a giant `Decompose` or
//!   similarly-sized leaf overflows within one iter that the walker
//!   can't pre-emit-split.
//!
//! Run with:
//!
//! ```bash
//! cargo test --release -p circom --test probe_dispatch_path_diff -- --ignored --nocapture
//! ```
//!
//! Add `LYSIS_WALKER_TRACE=1` to capture the slot/cost numbers on the
//! failing path:
//!
//! ```bash
//! LYSIS_WALKER_TRACE=1 cargo test --release -p circom --test probe_dispatch_path_diff -- --ignored --nocapture
//! ```
//!
//! Both probes are `#[ignore]`-gated to keep CI green; this file is
//! observation-only and produces no assertions beyond bare smoke
//! checks. The output is the deliverable.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use circom::{
    compile_file, compile_template_library, instantiate_template_into, lower_library_template,
};
use diagnostics::Span;
use ir_core::IrType;
use ir_forge::types::{CircuitExpr, CircuitNode, FieldConst, ForRange, ProveIR};
use ir_forge::ExtendedInstruction;
use memory::{Bn254Fr, FieldElement};

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap()
}

fn lib_dirs() -> Vec<PathBuf> {
    vec![workspace_root().join("test/circomlib")]
}

fn dummy_span() -> Span {
    Span {
        byte_start: 0,
        byte_end: 0,
        line_start: 0,
        col_start: 0,
        line_end: 0,
        col_end: 0,
    }
}

// ---------------------------------------------------------------------------
// Side A — pure-circom (top-level Sha256(64) entry, works today)
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn probe_pure_circom_sha256_64() {
    let path = workspace_root().join("test/circomlib/sha256_test.circom");
    let result = compile_file(&path, &lib_dirs()).expect("compile pure-circom Sha256(64)");
    let prove_ir = result.prove_ir;

    eprintln!();
    eprintln!("================================================================");
    eprintln!("SIDE A — pure-circom (entry = sha256_test.circom, Sha256(64))");
    eprintln!("================================================================");
    eprintln!();
    eprintln!("[ProveIR header]");
    eprintln!("  body.len()     = {}", prove_ir.body.len());
    eprintln!("  captures       = {:?}", prove_ir.captures.len());
    eprintln!("  public_inputs  = {}", prove_ir.public_inputs.len());
    eprintln!("  witness_inputs = {}", prove_ir.witness_inputs.len());
    eprintln!("  output_names   = {}", result.output_names.len());
    eprintln!();

    eprintln!("[ProveIR CircuitNode stats — pure-circom]");
    let pure_stats = collect_circuit_node_stats(&prove_ir.body);
    pure_stats.print("pure-circom");

    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = result
        .capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();

    let extended = prove_ir
        .instantiate_with_outputs_extended::<Bn254Fr>(&fe_captures, &result.output_names)
        .expect("pure-circom instantiate_extended succeeds");

    eprintln!();
    eprintln!("[ExtendedInstruction stats — pure-circom (instantiate_with_outputs_extended)]");
    let pure_ext_stats = collect_extended_stats(&extended.body);
    pure_ext_stats.print("pure-circom");

    eprintln!();
    eprintln!("[Sanity: the Lysis path completes for this side]");
    let lysis =
        prove_ir.instantiate_lysis_with_outputs::<Bn254Fr>(&fe_captures, &result.output_names);
    match lysis {
        Ok(prog) => eprintln!(
            "  ✓ instantiate_lysis_with_outputs OK — {} flat instructions",
            prog.len()
        ),
        Err(e) => panic!("pure-circom Lysis FAILED unexpectedly: {e}"),
    }
}

// ---------------------------------------------------------------------------
// Side B — .ach dispatch (instantiate_template_into → flat body)
// ---------------------------------------------------------------------------

#[test]
#[ignore]
fn probe_ach_dispatch_sha256_64() {
    let path = workspace_root().join("test/circomlib/circuits/sha256/sha256.circom");
    let library = compile_template_library(&path, &lib_dirs())
        .expect("load circomlib/sha256/sha256.circom as a library");

    eprintln!();
    eprintln!("================================================================");
    eprintln!("SIDE B — .ach dispatch (library.instantiate_template Sha256(64))");
    eprintln!("================================================================");
    eprintln!();
    eprintln!(
        "[Library header] templates exposed: {}",
        library.template_names().count()
    );

    let template_args: Vec<FieldConst> = vec![FieldConst::from_u64(64)];

    // Sha256(nBits): signal input in[nBits]. Build 64 dummy var keys
    // matching the row-major naming convention `in_<i>`.
    let mut signal_inputs: HashMap<String, CircuitExpr> = HashMap::new();
    for i in 0..64u64 {
        signal_inputs.insert(format!("in_{i}"), CircuitExpr::Var(format!("user_in_{i}")));
    }

    let span = dummy_span();
    let instantiation = instantiate_template_into(
        &library,
        "Sha256",
        &template_args,
        &signal_inputs,
        "main",
        &span,
    )
    .expect("library instantiate_template_into Sha256(64) succeeds at the inliner level");

    eprintln!();
    eprintln!(
        "[Inliner output — instantiate_template_into.body.len() = {}]",
        instantiation.body.len()
    );
    eprintln!(
        "[Inliner output — outputs.len() = {}]",
        instantiation.outputs.len()
    );

    eprintln!();
    eprintln!("[CircuitNode stats — .ach dispatch (raw inliner output)]");
    let dispatch_stats = collect_circuit_node_stats(&instantiation.body);
    dispatch_stats.print(".ach-dispatch");

    // Build a synthetic ProveIR that mirrors what the .ach prove block
    // ends up with after `body.extend(instantiation.body)`. We add 64
    // witness-input declarations matching the user's `user_in_<i>`
    // references so the captures resolve cleanly.
    let mut witness_inputs = Vec::new();
    for i in 0..64u64 {
        witness_inputs.push(ir_forge::types::ProveInputDecl {
            name: format!("user_in_{i}"),
            array_size: None,
            ir_type: IrType::Field,
        });
    }

    let synthetic = ProveIR {
        name: Some("dispatch_probe".into()),
        public_inputs: vec![],
        witness_inputs,
        captures: vec![],
        body: instantiation.body,
        capture_arrays: vec![],
        component_bodies: Default::default(),
    };

    eprintln!();
    eprintln!(
        "[Synthetic ProveIR shape] body.len() = {}",
        synthetic.body.len()
    );

    // Try instantiate_extended FIRST — it's the ProveIR-side step
    // before Lysis. We expect it to succeed (or at worst surface a
    // ProveIR-level lowering error, NOT the frame overflow which is
    // a Lysis issue).
    let captures = HashMap::<String, FieldElement<Bn254Fr>>::new();
    let extended_result = synthetic.instantiate_extended::<Bn254Fr>(&captures);

    match extended_result {
        Ok(extended) => {
            eprintln!();
            eprintln!("[ExtendedInstruction stats — .ach dispatch (instantiate_extended)]");
            let dispatch_ext_stats = collect_extended_stats(&extended.body);
            dispatch_ext_stats.print(".ach-dispatch");

            eprintln!();
            eprintln!("[Now driving through Lysis — expecting frame overflow]");
            let lysis_result = synthetic.instantiate_lysis::<Bn254Fr>(&captures);
            match lysis_result {
                Ok(prog) => eprintln!(
                    "  ! Lysis SUCCEEDED on .ach dispatch ({} insts) — \
                     this contradicts the failure premise; recheck sha256_64 vs Sha256_2",
                    prog.len()
                ),
                Err(e) => {
                    eprintln!("  ✓ Lysis failed as expected: {e}");
                }
            }
        }
        Err(e) => {
            eprintln!();
            eprintln!("[!] instantiate_extended itself failed (ProveIR-side): {e}");
            eprintln!(
                "    This means the .ach dispatch can't even build the ExtendedInstruction \
                 stream — the bug is upstream of Lysis."
            );
        }
    }
}

// ---------------------------------------------------------------------------
// CircuitNode stats helper
// ---------------------------------------------------------------------------

#[derive(Default)]
struct CircuitNodeStats {
    total: usize,
    n_let: usize,
    n_let_array: usize,
    n_let_indexed: usize,
    n_assert_eq: usize,
    n_assert: usize,
    n_for: usize,
    n_if: usize,
    n_expr: usize,
    n_decompose: usize,
    n_witness_hint: usize,
    n_witness_hint_indexed: usize,
    n_witness_array_decl: usize,
    n_witness_call: usize,
    n_component_call: usize,
    /// (name, num_bits) for any Decompose >= 100 bits.
    wide_decomposes: Vec<(String, u32)>,
    /// (label, body_len, range_repr) for top-level For nodes.
    for_summary: Vec<(String, usize, String)>,
}

impl CircuitNodeStats {
    fn print(&self, label: &str) {
        eprintln!("  [{label}] CircuitNode total: {}", self.total);
        eprintln!("    Let               : {}", self.n_let);
        eprintln!("    LetArray          : {}", self.n_let_array);
        eprintln!("    LetIndexed        : {}", self.n_let_indexed);
        eprintln!("    AssertEq          : {}", self.n_assert_eq);
        eprintln!("    Assert            : {}", self.n_assert);
        eprintln!("    For               : {}", self.n_for);
        eprintln!("    If                : {}", self.n_if);
        eprintln!("    Expr              : {}", self.n_expr);
        eprintln!("    Decompose         : {}", self.n_decompose);
        eprintln!("    WitnessHint       : {}", self.n_witness_hint);
        eprintln!("    WitnessHintIndexed: {}", self.n_witness_hint_indexed);
        eprintln!("    WitnessArrayDecl  : {}", self.n_witness_array_decl);
        eprintln!("    WitnessCall       : {}", self.n_witness_call);
        eprintln!("    ComponentCall     : {}", self.n_component_call);
        if !self.wide_decomposes.is_empty() {
            eprintln!("    Wide Decompose (>= 100 bits):");
            for (name, n) in &self.wide_decomposes {
                eprintln!("      {name} num_bits={n}");
            }
        }
        if !self.for_summary.is_empty() {
            eprintln!("    For nodes (top-level body):");
            for (label, body_len, range) in &self.for_summary {
                eprintln!("      {label}: body.len={body_len} range={range}");
            }
        }
    }
}

fn collect_circuit_node_stats(body: &[CircuitNode]) -> CircuitNodeStats {
    let mut s = CircuitNodeStats::default();
    walk_nodes(body, "", &mut s);
    s
}

fn walk_nodes(body: &[CircuitNode], path: &str, s: &mut CircuitNodeStats) {
    for (i, node) in body.iter().enumerate() {
        s.total += 1;
        match node {
            CircuitNode::Let { .. } => s.n_let += 1,
            CircuitNode::LetArray { .. } => s.n_let_array += 1,
            CircuitNode::LetIndexed { .. } => s.n_let_indexed += 1,
            CircuitNode::AssertEq { .. } => s.n_assert_eq += 1,
            CircuitNode::Assert { .. } => s.n_assert += 1,
            CircuitNode::For {
                var,
                range,
                body: inner,
                ..
            } => {
                s.n_for += 1;
                let label = if path.is_empty() {
                    format!("[{i}] var={var}")
                } else {
                    format!("{path}.[{i}] var={var}")
                };
                s.for_summary
                    .push((label.clone(), inner.len(), format_range(range)));
                walk_nodes(inner, &label, s);
            }
            CircuitNode::If {
                then_body,
                else_body,
                ..
            } => {
                s.n_if += 1;
                let then_path = if path.is_empty() {
                    format!("[{i}].then")
                } else {
                    format!("{path}.[{i}].then")
                };
                let else_path = if path.is_empty() {
                    format!("[{i}].else")
                } else {
                    format!("{path}.[{i}].else")
                };
                walk_nodes(then_body, &then_path, s);
                walk_nodes(else_body, &else_path, s);
            }
            CircuitNode::Expr { .. } => s.n_expr += 1,
            CircuitNode::Decompose { name, num_bits, .. } => {
                s.n_decompose += 1;
                if *num_bits >= 100 {
                    s.wide_decomposes.push((name.clone(), *num_bits));
                }
            }
            CircuitNode::WitnessHint { .. } => s.n_witness_hint += 1,
            CircuitNode::WitnessHintIndexed { .. } => s.n_witness_hint_indexed += 1,
            CircuitNode::WitnessArrayDecl { .. } => s.n_witness_array_decl += 1,
            CircuitNode::WitnessCall { .. } => s.n_witness_call += 1,
            CircuitNode::ComponentCall { .. } => s.n_component_call += 1,
        }
    }
}

fn format_range(r: &ForRange) -> String {
    match r {
        ForRange::Literal { start, end } => format!("{start}..{end}"),
        ForRange::WithCapture { start, end_capture } => format!("{start}..{end_capture}"),
        ForRange::WithExpr { start, .. } => format!("{start}..<expr>"),
        ForRange::Array(name) => format!("over Array({name})"),
    }
}

// ---------------------------------------------------------------------------
// ExtendedInstruction stats helper
// ---------------------------------------------------------------------------

#[derive(Default)]
struct ExtendedStats {
    total: usize,
    n_plain: usize,
    n_template_body: usize,
    n_template_call: usize,
    n_loop_unroll: usize,
    n_sym_indexed_effect: usize,
    n_sym_array_read: usize,
    n_sym_shift: usize,
    /// Largest `body.len()` seen across any `LoopUnroll` (top + nested).
    max_loop_body_len: usize,
    /// Longest run of consecutive `Plain` ops at the top level.
    max_plain_run_top: usize,
    /// Per-LoopUnroll summary at the top level: (start..end, body_len).
    top_loops: Vec<(i64, i64, usize)>,
}

impl ExtendedStats {
    fn print(&self, label: &str) {
        eprintln!("  [{label}] ExtendedInstruction total: {}", self.total);
        eprintln!("    Plain                 : {}", self.n_plain);
        eprintln!("    TemplateBody          : {}", self.n_template_body);
        eprintln!("    TemplateCall          : {}", self.n_template_call);
        eprintln!("    LoopUnroll            : {}", self.n_loop_unroll);
        eprintln!("    SymbolicIndexedEffect : {}", self.n_sym_indexed_effect);
        eprintln!("    SymbolicArrayRead     : {}", self.n_sym_array_read);
        eprintln!("    SymbolicShift         : {}", self.n_sym_shift);
        eprintln!("    Max LoopUnroll body   : {}", self.max_loop_body_len);
        eprintln!("    Max top-level Plain run: {}", self.max_plain_run_top);
        if !self.top_loops.is_empty() {
            eprintln!("    Top-level LoopUnroll summary:");
            for (start, end, len) in &self.top_loops {
                eprintln!("      {start}..{end} body.len={len}");
            }
        }
    }
}

fn collect_extended_stats(body: &[ExtendedInstruction<Bn254Fr>]) -> ExtendedStats {
    let mut s = ExtendedStats::default();
    walk_extended(body, true, &mut s);
    s
}

fn walk_extended(body: &[ExtendedInstruction<Bn254Fr>], top_level: bool, s: &mut ExtendedStats) {
    let mut current_plain_run: usize = 0;
    for inst in body {
        s.total += 1;
        match inst {
            ExtendedInstruction::Plain(_) => {
                s.n_plain += 1;
                if top_level {
                    current_plain_run += 1;
                    if current_plain_run > s.max_plain_run_top {
                        s.max_plain_run_top = current_plain_run;
                    }
                }
            }
            other => {
                if top_level {
                    current_plain_run = 0;
                }
                match other {
                    ExtendedInstruction::TemplateBody { body, .. } => {
                        s.n_template_body += 1;
                        walk_extended(body, false, s);
                    }
                    ExtendedInstruction::TemplateCall { .. } => s.n_template_call += 1,
                    ExtendedInstruction::LoopUnroll {
                        start, end, body, ..
                    } => {
                        s.n_loop_unroll += 1;
                        if body.len() > s.max_loop_body_len {
                            s.max_loop_body_len = body.len();
                        }
                        if top_level {
                            s.top_loops.push((*start, *end, body.len()));
                        }
                        walk_extended(body, false, s);
                    }
                    ExtendedInstruction::SymbolicIndexedEffect { .. } => {
                        s.n_sym_indexed_effect += 1;
                    }
                    ExtendedInstruction::SymbolicArrayRead { .. } => s.n_sym_array_read += 1,
                    ExtendedInstruction::SymbolicShift { .. } => s.n_sym_shift += 1,
                    ExtendedInstruction::Plain(_) => unreachable!(),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Side C — `lower_library_template` (For-preserving) for Sha256(64).
//
// Routes through the same primitive top-level circom compiles use
// (`lower_template_with_captures`), exposed without a `component
// main` AST. If For nodes and LoopUnrolls match Side A and Lysis
// succeeds, the dispatch path is structurally aligned with the
// top-level circom path.
// ---------------------------------------------------------------------------

/// Drive `instantiate_template_into` for Sha256(N) with the given
/// signal-input shape, build a synthetic ProveIR mirroring what an
/// `.ach prove { let r = Sha256(N)([...]) }` block produces, run
/// Lysis, and report. Used to bisect which axis triggers walker
/// `UndefinedSsaVar` for N < 64.
fn probe_embedded_sha256(n_bits: u64, all_const: bool, label: &str) {
    let path = workspace_root().join("test/circomlib/circuits/sha256/sha256.circom");
    let library = compile_template_library(&path, &lib_dirs())
        .expect("load circomlib/sha256/sha256.circom as a library");

    eprintln!();
    eprintln!("================================================================");
    eprintln!("Embedded Sha256({n_bits}) {label} — synthetic ProveIR + Lysis");
    eprintln!("================================================================");

    let template_args = vec![FieldConst::from_u64(n_bits)];
    let mut signal_inputs: HashMap<String, CircuitExpr> = HashMap::new();
    for i in 0..n_bits {
        let key = format!("in_{i}");
        let expr = if all_const {
            CircuitExpr::Const(FieldConst::from_u64(0))
        } else {
            CircuitExpr::Var(format!("user_in_{i}"))
        };
        signal_inputs.insert(key, expr);
    }

    let span = dummy_span();
    let instantiation = instantiate_template_into(
        &library,
        "Sha256",
        &template_args,
        &signal_inputs,
        "main",
        &span,
    )
    .expect("instantiate_template_into Sha256 succeeds");

    eprintln!(
        "  body.len()={}, outputs.len()={}",
        instantiation.body.len(),
        instantiation.outputs.len()
    );

    // Mirror the .ach prove block's witness-input wiring.
    let mut witness_inputs = Vec::new();
    if !all_const {
        for i in 0..n_bits {
            witness_inputs.push(ir_forge::types::ProveInputDecl {
                name: format!("user_in_{i}"),
                array_size: None,
                ir_type: IrType::Field,
            });
        }
    }

    let synthetic = ProveIR {
        name: Some("dispatch_probe".into()),
        public_inputs: vec![],
        witness_inputs,
        captures: vec![],
        body: instantiation.body,
        capture_arrays: vec![],
        component_bodies: Default::default(),
    };

    let captures = HashMap::<String, FieldElement<Bn254Fr>>::new();
    match synthetic.instantiate_lysis::<Bn254Fr>(&captures) {
        Ok(prog) => eprintln!("  Lysis OK — {} flat instructions", prog.len()),
        Err(e) => eprintln!("  Lysis FAILED: {e}"),
    }
}

#[test]
#[ignore]
fn probe_embedded_sha256_8_const() {
    probe_embedded_sha256(8, true, "all-Const inputs");
}

#[test]
#[ignore]
fn probe_embedded_sha256_8_var() {
    probe_embedded_sha256(8, false, "all-Var inputs");
}

#[test]
#[ignore]
fn probe_embedded_sha256_64_const() {
    probe_embedded_sha256(64, true, "all-Const inputs");
}

/// One Const + (n_bits-1) Var inputs — disambiguates "any Const
/// triggers the bug" vs "fully-Const wiring is the trigger".
fn probe_embedded_sha256_one_const(n_bits: u64, label: &str) {
    let path = workspace_root().join("test/circomlib/circuits/sha256/sha256.circom");
    let library = compile_template_library(&path, &lib_dirs())
        .expect("load circomlib/sha256/sha256.circom as a library");

    eprintln!();
    eprintln!("================================================================");
    eprintln!("Embedded Sha256({n_bits}) {label} — synthetic ProveIR + Lysis");
    eprintln!("================================================================");

    let template_args = vec![FieldConst::from_u64(n_bits)];
    let mut signal_inputs: HashMap<String, CircuitExpr> = HashMap::new();
    for i in 0..n_bits {
        let key = format!("in_{i}");
        let expr = if i == 0 {
            CircuitExpr::Const(FieldConst::from_u64(0))
        } else {
            CircuitExpr::Var(format!("user_in_{i}"))
        };
        signal_inputs.insert(key, expr);
    }

    let span = dummy_span();
    let instantiation = instantiate_template_into(
        &library,
        "Sha256",
        &template_args,
        &signal_inputs,
        "main",
        &span,
    )
    .expect("instantiate_template_into Sha256 succeeds");

    let mut witness_inputs = Vec::new();
    for i in 1..n_bits {
        witness_inputs.push(ir_forge::types::ProveInputDecl {
            name: format!("user_in_{i}"),
            array_size: None,
            ir_type: IrType::Field,
        });
    }

    let synthetic = ProveIR {
        name: Some("dispatch_probe".into()),
        public_inputs: vec![],
        witness_inputs,
        captures: vec![],
        body: instantiation.body,
        capture_arrays: vec![],
        component_bodies: Default::default(),
    };

    let captures = HashMap::<String, FieldElement<Bn254Fr>>::new();
    match synthetic.instantiate_lysis::<Bn254Fr>(&captures) {
        Ok(prog) => eprintln!("  Lysis OK — {} flat instructions", prog.len()),
        Err(e) => eprintln!("  Lysis FAILED: {e}"),
    }
}

#[test]
#[ignore]
fn probe_embedded_sha256_8_one_const_rest_var() {
    probe_embedded_sha256_one_const(8, "in_0=Const, rest=Var");
}

/// Same dump but for the working case (Var inputs). Compares with
/// the failing-case dump to spot the structural divergence.
#[test]
#[ignore]
fn probe_embedded_sha256_8_var_dump_first_30() {
    let path = workspace_root().join("test/circomlib/circuits/sha256/sha256.circom");
    let library = compile_template_library(&path, &lib_dirs())
        .expect("load circomlib/sha256/sha256.circom as a library");

    let template_args = vec![FieldConst::from_u64(8)];
    let mut signal_inputs: HashMap<String, CircuitExpr> = HashMap::new();
    for i in 0..8u64 {
        signal_inputs.insert(format!("in_{i}"), CircuitExpr::Var(format!("user_in_{i}")));
    }
    let span = dummy_span();
    let instantiation = instantiate_template_into(
        &library,
        "Sha256",
        &template_args,
        &signal_inputs,
        "main",
        &span,
    )
    .expect("instantiate_template_into Sha256(8) succeeds");

    let mut witness_inputs = Vec::new();
    for i in 0..8u64 {
        witness_inputs.push(ir_forge::types::ProveInputDecl {
            name: format!("user_in_{i}"),
            array_size: None,
            ir_type: IrType::Field,
        });
    }

    let synthetic = ProveIR {
        name: Some("dispatch_probe".into()),
        public_inputs: vec![],
        witness_inputs,
        captures: vec![],
        body: instantiation.body,
        capture_arrays: vec![],
        component_bodies: Default::default(),
    };

    let captures = HashMap::<String, FieldElement<Bn254Fr>>::new();
    let extended = synthetic
        .instantiate_extended::<Bn254Fr>(&captures)
        .expect("instantiate_extended succeeds");

    eprintln!();
    eprintln!("================================================================");
    eprintln!("First 30 ExtendedInstructions (Sha256(8) Var, embedded - WORKS)");
    eprintln!("================================================================");
    for (i, inst) in extended.body.iter().take(30).enumerate() {
        eprintln!("[{i:3}] {inst:?}");
    }
}

/// Walk the extended instruction stream for the failing case and
/// report (def_idx, use_idxs[]) for the first 5 SsaVars. Pinpoints
/// the use that the walker fails on.
#[test]
#[ignore]
fn probe_embedded_sha256_8_const_track_low_ssa() {
    use ir_core::Instruction;

    let path = workspace_root().join("test/circomlib/circuits/sha256/sha256.circom");
    let library = compile_template_library(&path, &lib_dirs())
        .expect("load circomlib/sha256/sha256.circom as a library");

    let template_args = vec![FieldConst::from_u64(8)];
    let mut signal_inputs: HashMap<String, CircuitExpr> = HashMap::new();
    for i in 0..8u64 {
        signal_inputs.insert(
            format!("in_{i}"),
            CircuitExpr::Const(FieldConst::from_u64(0)),
        );
    }
    let span = dummy_span();
    let instantiation = instantiate_template_into(
        &library,
        "Sha256",
        &template_args,
        &signal_inputs,
        "main",
        &span,
    )
    .expect("instantiate succeeds");

    let synthetic = ProveIR {
        name: Some("dispatch_probe".into()),
        public_inputs: vec![],
        witness_inputs: vec![],
        captures: vec![],
        body: instantiation.body,
        capture_arrays: vec![],
        component_bodies: Default::default(),
    };

    let captures = HashMap::<String, FieldElement<Bn254Fr>>::new();
    let extended = synthetic
        .instantiate_extended::<Bn254Fr>(&captures)
        .expect("instantiate_extended succeeds");

    fn collect_uses<F: memory::FieldBackend>(
        inst: &ExtendedInstruction<F>,
        path: &str,
        target: ir_core::SsaVar,
        out: &mut Vec<String>,
    ) {
        match inst {
            ExtendedInstruction::Plain(i) => {
                if instruction_uses(i, target) {
                    out.push(format!("{path}: Plain({:?})", short_inst(i)));
                }
            }
            ExtendedInstruction::LoopUnroll { body, .. } => {
                for (j, nested) in body.iter().enumerate() {
                    collect_uses(nested, &format!("{path}.LoopUnroll[{j}]"), target, out);
                }
            }
            ExtendedInstruction::TemplateBody { body, captures, .. } => {
                if captures.contains(&target) {
                    out.push(format!("{path}: TemplateBody captures={:?}", captures));
                }
                for (j, nested) in body.iter().enumerate() {
                    collect_uses(nested, &format!("{path}.TemplateBody[{j}]"), target, out);
                }
            }
            ExtendedInstruction::TemplateCall { captures, .. } => {
                if captures.contains(&target) {
                    out.push(format!("{path}: TemplateCall captures={:?}", captures));
                }
            }
            _ => {}
        }
    }

    fn instruction_uses<F: memory::FieldBackend>(
        inst: &Instruction<F>,
        target: ir_core::SsaVar,
    ) -> bool {
        let mut found = false;
        macro_rules! check {
            ($v:expr) => {
                if *$v == target {
                    found = true;
                }
            };
        }
        match inst {
            Instruction::Const { .. } | Instruction::Input { .. } => {}
            Instruction::Add { lhs, rhs, .. }
            | Instruction::Sub { lhs, rhs, .. }
            | Instruction::Mul { lhs, rhs, .. }
            | Instruction::Div { lhs, rhs, .. } => {
                check!(lhs);
                check!(rhs);
            }
            Instruction::AssertEq { lhs, rhs, .. } => {
                check!(lhs);
                check!(rhs);
            }
            _ => {}
        }
        found
    }

    fn short_inst<F: memory::FieldBackend>(inst: &Instruction<F>) -> String {
        format!("{inst:?}").chars().take(120).collect::<String>()
    }

    eprintln!();
    eprintln!("================================================================");
    eprintln!("SsaVar(0) tracking — Sha256(8) Const embedded");
    eprintln!("================================================================");
    eprintln!("Total top-level extended insts: {}", extended.body.len());
    let target = ir_core::SsaVar(0);
    let mut uses: Vec<String> = Vec::new();
    for (i, inst) in extended.body.iter().enumerate() {
        collect_uses(inst, &format!("[{i}]"), target, &mut uses);
    }
    eprintln!("Uses of SsaVar(0):");
    for (i, u) in uses.iter().take(20).enumerate() {
        eprintln!("  [{i}] {u}");
    }
    if uses.len() > 20 {
        eprintln!("  ... ({} more)", uses.len() - 20);
    }
}

/// Drive the failing case through `instantiate_extended` and dump
/// the first 30 ExtendedInstructions so we can spot where SsaVar %0
/// is defined vs used.
#[test]
#[ignore]
fn probe_embedded_sha256_8_const_dump_first_30() {
    let path = workspace_root().join("test/circomlib/circuits/sha256/sha256.circom");
    let library = compile_template_library(&path, &lib_dirs())
        .expect("load circomlib/sha256/sha256.circom as a library");

    let template_args = vec![FieldConst::from_u64(8)];
    let mut signal_inputs: HashMap<String, CircuitExpr> = HashMap::new();
    for i in 0..8u64 {
        signal_inputs.insert(
            format!("in_{i}"),
            CircuitExpr::Const(FieldConst::from_u64(0)),
        );
    }
    let span = dummy_span();
    let instantiation = instantiate_template_into(
        &library,
        "Sha256",
        &template_args,
        &signal_inputs,
        "main",
        &span,
    )
    .expect("instantiate_template_into Sha256(8) succeeds");

    let synthetic = ProveIR {
        name: Some("dispatch_probe".into()),
        public_inputs: vec![],
        witness_inputs: vec![],
        captures: vec![],
        body: instantiation.body,
        capture_arrays: vec![],
        component_bodies: Default::default(),
    };

    let captures = HashMap::<String, FieldElement<Bn254Fr>>::new();
    let extended = synthetic
        .instantiate_extended::<Bn254Fr>(&captures)
        .expect("instantiate_extended succeeds");

    eprintln!();
    eprintln!("================================================================");
    eprintln!("First 30 ExtendedInstructions (Sha256(8) Const, embedded)");
    eprintln!("================================================================");
    for (i, inst) in extended.body.iter().take(30).enumerate() {
        eprintln!("[{i:3}] {inst:?}");
    }
}

#[test]
#[ignore]
fn probe_lower_library_template_sha256_8() {
    let path = workspace_root().join("test/circomlib/circuits/sha256/sha256.circom");
    let library = compile_template_library(&path, &lib_dirs())
        .expect("load circomlib/sha256/sha256.circom as a library");

    eprintln!();
    eprintln!("================================================================");
    eprintln!("Sha256(8) — standalone via lower_library_template + Lysis");
    eprintln!("================================================================");

    let mut captures = HashMap::new();
    captures.insert("nBits".to_string(), FieldConst::from_u64(8));

    let lower_result = lower_library_template(&library, "Sha256", captures.clone())
        .expect("lower_library_template Sha256(8) succeeds");

    let stats = collect_circuit_node_stats(&lower_result.prove_ir.body);
    stats.print("Sha256(8)");

    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = captures
        .keys()
        .map(|k| (k.clone(), FieldElement::<Bn254Fr>::from_u64(8)))
        .collect();

    let lysis_result = lower_result
        .prove_ir
        .instantiate_lysis_with_outputs::<Bn254Fr>(&fe_captures, &lower_result.output_names);
    match lysis_result {
        Ok(prog) => eprintln!("  Lysis OK — {} flat instructions", prog.len()),
        Err(e) => eprintln!("  Lysis FAILED: {e}"),
    }
}

#[test]
#[ignore]
fn probe_lower_library_template_sha256_64() {
    let path = workspace_root().join("test/circomlib/circuits/sha256/sha256.circom");
    let library = compile_template_library(&path, &lib_dirs())
        .expect("load circomlib/sha256/sha256.circom as a library");

    eprintln!();
    eprintln!("================================================================");
    eprintln!("SIDE C — lower_library_template (For-preserving) for Sha256(64)");
    eprintln!("================================================================");
    eprintln!();

    let mut captures = HashMap::new();
    captures.insert("nBits".to_string(), FieldConst::from_u64(64));

    let lower_result = lower_library_template(&library, "Sha256", captures.clone())
        .expect("lower_library_template Sha256(64) succeeds");

    eprintln!("[ProveIR header]");
    eprintln!("  body.len()     = {}", lower_result.prove_ir.body.len());
    eprintln!("  output_names   = {}", lower_result.output_names.len());
    eprintln!();

    eprintln!("[ProveIR CircuitNode stats]");
    let stats = collect_circuit_node_stats(&lower_result.prove_ir.body);
    stats.print("for-preserving");

    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = captures
        .keys()
        .map(|k| (k.clone(), FieldElement::<Bn254Fr>::from_u64(64)))
        .collect();

    let extended = lower_result
        .prove_ir
        .instantiate_with_outputs_extended::<Bn254Fr>(&fe_captures, &lower_result.output_names)
        .expect("instantiate_extended succeeds");

    eprintln!();
    eprintln!("[ExtendedInstruction stats]");
    let ext_stats = collect_extended_stats(&extended.body);
    ext_stats.print("for-preserving");

    eprintln!();
    eprintln!("[Driving through Lysis]");
    let lysis_result = lower_result
        .prove_ir
        .instantiate_lysis_with_outputs::<Bn254Fr>(&fe_captures, &lower_result.output_names);
    match lysis_result {
        Ok(prog) => {
            eprintln!("  Lysis OK — {} flat instructions", prog.len());
            eprintln!("    For nodes preserved: {}", stats.n_for);
            eprintln!("    LoopUnrolls produced: {}", ext_stats.n_loop_unroll);
        }
        Err(e) => {
            eprintln!("  Lysis FAILED: {e}");
            eprintln!("    For nodes preserved: {}", stats.n_for);
            eprintln!("    LoopUnrolls produced: {}", ext_stats.n_loop_unroll);
        }
    }
}
