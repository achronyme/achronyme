//! Discriminating-template inspection for Bug Class B.
//!
//! Cross-path baseline 2026-04-28 identified four templates that fail
//! `Frontend::Lysis` with `symbolic indexed write into '...' but the
//! array is not declared in this scope`:
//!
//!   - Pedersen(8)        → `ped.in`
//!   - EscalarMulFix(253) → `mulFix.e`
//!   - EscalarMulAny(254) → `mul.e`
//!   - Poseidon(2)        → `pEx.inputs`
//!
//! All four parent templates wrap a sub-component and bridge the
//! parent's input array into the sub-component's input array via:
//!
//! ```circom
//! component sub = SomeTemplate(...);
//! for (var i = 0; i < N; i++) {
//!     sub.arr[i] <== in[i];      // <-- symbolic-index write into sub.arr
//! }
//! ```
//!
//! This dump confirms the bug-site model:
//!   - failing templates emit `SymbolicIndexedEffect` with `array_slots`
//!     pointing at sub-component arrays NEVER declared via
//!     `WitnessArrayDecl` (or any other slot-allocating IR);
//!   - bare-scalar wires (LessThan: `n2b.in <== ...`) bypass the
//!     symbolic-index path entirely — they go through `Substitution
//!     { target: AssignTarget::Scalar("n2b.in") }` → `CircuitNode::Let`;
//!   - SHA-256(64) (currently passing under Lysis) has the very same
//!     `for (k) { compArray[i].inp[k] <== paddedIn[...] }` pattern as
//!     the failures; verifying whether it actually hits the
//!     `SymbolicIndexedEffect` path or skirts it via classifier
//!     eager-unroll is the empirical question for option-A safety.
//!
//! Run: `cargo test --release --test bug_class_b_discriminate -- --nocapture`

use std::collections::{HashMap, HashSet};

use ir_core::SsaVar;
use ir_forge::extended::ExtendedInstruction;
use memory::{Bn254Fr, FieldElement};

use circom::{compile_file_with_frontend, Frontend};

#[derive(Default)]
struct Stats {
    total_loops: usize,
    total_sym_eff: usize,
    total_sym_read: usize,
    // (array-name-hint, slot-array-vars-len, idx)
    sym_effs: Vec<(String, usize, u32)>,
}

fn fmt_var(v: SsaVar) -> String {
    format!("%{}", v.0)
}

#[allow(clippy::only_used_in_recursion)]
fn walk<F: memory::FieldBackend>(
    body: &[ExtendedInstruction<F>],
    in_loop_depth: usize,
    stats: &mut Stats,
    indent: usize,
    print: bool,
) {
    let pad = " ".repeat(indent);
    for (i, ext) in body.iter().enumerate() {
        match ext {
            ExtendedInstruction::Plain(inst) => {
                if print {
                    let kind = format!("{:?}", inst);
                    let kind_short = kind.split_whitespace().next().unwrap_or("?").to_string();
                    let uses: Vec<String> = inst.operands().into_iter().map(fmt_var).collect();
                    println!(
                        "{pad}[{i:>3}] Plain        def=%{:<3} uses={:<26} | {}",
                        inst.result_var().0,
                        uses.join(","),
                        kind_short
                    );
                }
            }
            ExtendedInstruction::TemplateBody {
                id,
                frame_size,
                n_params,
                captures,
                body: inner,
            } => {
                if print {
                    println!(
                        "{pad}[{i:>3}] TemplateBody id={:?} frame={} params={} captures={:?}",
                        id, frame_size, n_params, captures
                    );
                }
                walk(inner, in_loop_depth, stats, indent + 2, print);
            }
            ExtendedInstruction::TemplateCall { .. } => {
                if print {
                    println!("{pad}[{i:>3}] TemplateCall");
                }
            }
            ExtendedInstruction::LoopUnroll {
                iter_var,
                start,
                end,
                body: inner,
            } => {
                stats.total_loops += 1;
                if print {
                    println!(
                        "{pad}[{i:>3}] LoopUnroll   iter=%{} range=[{}..{}]",
                        iter_var.0, start, end
                    );
                }
                walk(inner, in_loop_depth + 1, stats, indent + 2, print);
            }
            ExtendedInstruction::SymbolicIndexedEffect {
                array_slots,
                index_var,
                value_var,
                ..
            } => {
                stats.total_sym_eff += 1;
                stats
                    .sym_effs
                    .push((String::from("<unknown>"), array_slots.len(), index_var.0));
                if print {
                    let slots: Vec<String> = array_slots.iter().map(|v| fmt_var(*v)).collect();
                    let head: Vec<String> = slots.iter().take(3).cloned().collect();
                    let tail = if slots.len() > 6 {
                        format!("…+{}", slots.len() - 6)
                    } else {
                        String::new()
                    };
                    println!(
                        "{pad}[{i:>3}] SymIndEff    slots[{}]=[{}{}] idx=%{} val={:?}",
                        slots.len(),
                        head.join(","),
                        tail,
                        index_var.0,
                        value_var.map(fmt_var)
                    );
                }
            }
            ExtendedInstruction::SymbolicArrayRead {
                result_var,
                array_slots,
                index_var,
                ..
            } => {
                stats.total_sym_read += 1;
                if print {
                    println!(
                        "{pad}[{i:>3}] SymArrRead   res=%{} slots[{}] idx=%{}",
                        result_var.0,
                        array_slots.len(),
                        index_var.0
                    );
                }
            }
            ExtendedInstruction::SymbolicShift {
                result_var,
                operand_var,
                shift_var,
                ..
            } => {
                if print {
                    println!(
                        "{pad}[{i:>3}] SymShift     res=%{} op=%{} amt=%{}",
                        result_var.0, operand_var.0, shift_var.0
                    );
                }
            }
        }
    }
}

fn try_dump(name: &str, fixture: &str, captures_kv: &[(&str, u64)], print: bool) {
    println!("\n========================================");
    println!("== {name}  ({fixture})");
    println!("========================================");
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let path = manifest_dir.join(fixture);
    let lib_dirs = vec![
        manifest_dir.join("test/circomlib"),
        manifest_dir.join("test/circomlib/circuits"),
    ];
    if !path.exists() {
        println!("FIXTURE MISSING: {}", path.display());
        return;
    }

    let result = match compile_file_with_frontend(&path, &lib_dirs, Frontend::Lysis) {
        Ok(r) => r,
        Err(e) => {
            println!("compile failed: {e}");
            return;
        }
    };
    let prove_ir = result.prove_ir;
    let mut captures: HashMap<String, FieldElement<Bn254Fr>> = result
        .capture_values
        .into_iter()
        .map(|(k, v)| (k, FieldElement::<Bn254Fr>::from_u64(v)))
        .collect();
    for (k, v) in captures_kv {
        captures.insert(k.to_string(), FieldElement::<Bn254Fr>::from_u64(*v));
    }
    let output_names: HashSet<String> = result.output_names.into_iter().collect();

    let extended =
        match prove_ir.instantiate_with_outputs_extended::<Bn254Fr>(&captures, &output_names) {
            Ok(p) => p,
            Err(e) => {
                println!("instantiate_extended FAIL — {e}");
                return;
            }
        };

    println!(
        "body len: {}, next_var: %{}",
        extended.body.len(),
        extended.next_var
    );
    let mut stats = Stats::default();
    walk(&extended.body, 0, &mut stats, 0, print);

    println!("\n-- Stats --");
    println!("LoopUnroll nodes:               {}", stats.total_loops);
    println!("SymbolicIndexedEffect nodes:    {}", stats.total_sym_eff);
    println!("SymbolicArrayRead nodes:        {}", stats.total_sym_read);
    if !stats.sym_effs.is_empty() {
        println!(
            "SymIndEff array_slots-counts: {:?}",
            stats
                .sym_effs
                .iter()
                .map(|(_, n, _)| *n)
                .collect::<Vec<_>>()
        );
    }

    let walker_result =
        prove_ir.instantiate_lysis_with_outputs::<Bn254Fr>(&captures, &output_names);
    match walker_result {
        Ok(prog) => println!("Walker: OK ({} instructions)", prog.instructions().len()),
        Err(e) => println!("Walker: FAIL — {e}"),
    }
}

#[test]
fn dump_discriminating_templates_class_b() {
    // ── Class B confirmed-failing ────────────────────────────────────
    // All four hit `for { sub.in[i] <== ... }` against a sub-component
    // input array.
    try_dump(
        "Pedersen(8)",
        "test/circomlib/pedersen_test.circom",
        &[],
        true,
    );
    try_dump(
        "Poseidon(2)",
        "test/circomlib/poseidon_test.circom",
        &[],
        false,
    );
    try_dump(
        "EscalarMulFix(3)",
        "test/circomlib/escalarmulfix_test.circom",
        &[],
        false,
    );
    try_dump(
        "EscalarMulAny(149)",
        "test/circomlib/escalarmulany_test.circom",
        &[],
        false,
    );

    // ── Discriminating control: bare-scalar wire to sub-component ───
    // LessThan(8): `n2b.in <== ...` — `n2b.in` is a SCALAR signal in
    // Num2Bits, so the substitution lowers as `Let { name: "n2b.in" }`,
    // bypassing LetIndexed entirely. Expected to pass.
    try_dump("LessThan(8)", "test/circom/lessthan_8.circom", &[], false);

    // ── Const-index control: const-only sub-component array writes ──
    // Pedersen_old uses Window4 with `mux.c[0][k] <== ...` const index
    // writes only. Expected to pass — `LetIndexed { index: Const(k) }`
    // routes through `emit_let_indexed_const` which lazy-allocates
    // slots via `ensure_array_slot`.
    try_dump(
        "Pedersen_old(8)",
        "test/circomlib/pedersen_old_test.circom",
        &[],
        false,
    );

    // ── SHA-256 control: same pattern, currently-passing ────────────
    // SHA-256 has `for (k) { sha256compression[i].inp[k] <== paddedIn[...] }`
    // inside an outer i-loop that's eager-unrolled (ComponentArrayOps).
    // After unroll, the inner k-loop has a fully resolved component
    // index (`sha256compression_0.inp[k]`) — does this hit the same
    // SymbolicIndexedEffect path the failing templates do? If not,
    // what classifier branch absorbs it? Critical for option-A safety.
    if std::path::Path::new(
        "/home/eddndev/dev/achronyme/achronyme/test/circomlib/sha256_test.circom",
    )
    .exists()
    {
        try_dump(
            "Sha256_test (small)",
            "test/circomlib/sha256_test.circom",
            &[],
            false,
        );
    }
}

/// Instrumentation pass: dump every WitnessArrayDecl name + size emitted
/// in the ProveIR body (NOT the extended stream), so we can see whether
/// SHA-256's sub-component arrays (`sha256compression_0.inp`, etc.) get
/// pre-declared.
#[test]
fn dump_witness_array_decls_class_b() {
    use ir_forge::types::CircuitNode;

    fn count_decls(name: &str, fixture: &str) {
        println!("\n== {name} witness-array-decls ==");
        let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap();
        let path = manifest_dir.join(fixture);
        let lib_dirs = vec![
            manifest_dir.join("test/circomlib"),
            manifest_dir.join("test/circomlib/circuits"),
        ];
        if !path.exists() {
            println!("FIXTURE MISSING");
            return;
        }
        let result = match compile_file_with_frontend(&path, &lib_dirs, Frontend::Lysis) {
            Ok(r) => r,
            Err(e) => {
                println!("compile failed: {e}");
                return;
            }
        };

        // Walk the ProveIR body for WitnessArrayDecl
        fn walk_decls(nodes: &[CircuitNode], depth: usize) -> Vec<(String, String)> {
            let mut out = Vec::new();
            let pad = "  ".repeat(depth);
            for n in nodes {
                match n {
                    CircuitNode::WitnessArrayDecl { name, size, .. } => {
                        out.push((name.clone(), format!("{pad}{size:?}")));
                    }
                    CircuitNode::For { body, .. } => {
                        out.extend(walk_decls(body, depth + 1));
                    }
                    CircuitNode::If {
                        then_body,
                        else_body,
                        ..
                    } => {
                        out.extend(walk_decls(then_body, depth + 1));
                        out.extend(walk_decls(else_body, depth + 1));
                    }
                    _ => {}
                }
            }
            out
        }
        let decls = walk_decls(&result.prove_ir.body, 0);
        println!("Template body has {} WitnessArrayDecl nodes", decls.len());
        for (name, sizestr) in decls.iter().take(40) {
            println!("  {sizestr}WitnessArrayDecl name={name}");
        }
        if decls.len() > 40 {
            println!("  ... +{} more", decls.len() - 40);
        }
    }

    count_decls("Pedersen(8)", "test/circomlib/pedersen_test.circom");
    count_decls("Sha256(64)", "test/circomlib/sha256_test.circom");
    count_decls("LessThan(8)", "test/circom/lessthan_8.circom");
    count_decls("Pedersen_old(8)", "test/circomlib/pedersen_old_test.circom");
}
