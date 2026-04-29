//! Discriminating-template inspection for Bug Class A.
//!
//! Dumps the ExtendedInstruction stream produced by
//! `instantiate_with_outputs_extended` for a handful of templates that
//! were classified during the cross-path baseline as either failing
//! (Bug Class A) or passing-byte-identical. The goal is to validate
//! the model that the instantiator's `var`-accumulator-escape pattern
//! is the bug — i.e. that all *failing* templates have a `var` updated
//! inside a rolled `LoopUnroll` and read after it, and *passing*
//! templates do not.
//!
//! Not a permanent test — purely a diagnostic for
//! `.claude/plans/cross-path-baseline-2026-04-28/fix-class-a.md`.
//!
//! Run: `cargo test --release --test bug_class_a_discriminate -- --nocapture`

use std::collections::{HashMap, HashSet};

use ir_core::SsaVar;
use ir_forge::extended::ExtendedInstruction;
use memory::{Bn254Fr, FieldElement};

use circom::{compile_file_with_frontend, Frontend};

fn fmt_var(v: SsaVar) -> String {
    format!("%{}", v.0)
}

#[derive(Default)]
struct Scopes {
    // Map of SsaVar → "outer" | "inside_loop_<n>"; only tracks loop-local defs
    inside_loop: HashSet<u32>,
    outer_defs: HashSet<u32>,
    // (use_var, where_used_scope, where_def_scope)
    cross_loop_uses: Vec<(u32, String, String)>,
}

fn record_def(v: SsaVar, in_loop: bool, scopes: &mut Scopes) {
    if in_loop {
        scopes.inside_loop.insert(v.0);
    } else {
        scopes.outer_defs.insert(v.0);
    }
}

fn record_use(v: SsaVar, in_loop: bool, scopes: &mut Scopes) {
    if !in_loop && scopes.inside_loop.contains(&v.0) {
        // Used outside, but defined inside a loop → CROSS-LOOP USE
        scopes
            .cross_loop_uses
            .push((v.0, "outer".to_string(), "loop".to_string()));
    }
}

fn walk<F: memory::FieldBackend>(
    body: &[ExtendedInstruction<F>],
    in_loop_depth: usize,
    scopes: &mut Scopes,
    indent: usize,
) {
    let pad = " ".repeat(indent);
    for (i, ext) in body.iter().enumerate() {
        let in_loop = in_loop_depth > 0;
        match ext {
            ExtendedInstruction::Plain(inst) => {
                let res = inst.result_var();
                record_def(res, in_loop, scopes);
                for v in inst.extra_result_vars() {
                    record_def(*v, in_loop, scopes);
                }
                for u in inst.operands() {
                    record_use(u, in_loop, scopes);
                }
                let kind = format!("{:?}", inst);
                let kind_short = kind.split_whitespace().next().unwrap_or("?").to_string();
                let uses: Vec<String> = inst.operands().into_iter().map(fmt_var).collect();
                println!(
                    "{pad}[{i:>3}] Plain        def=%{:<3} uses={:<26} | {}",
                    res.0,
                    uses.join(","),
                    kind_short
                );
            }
            ExtendedInstruction::TemplateBody {
                id,
                frame_size,
                n_params,
                captures,
                body: inner,
            } => {
                println!(
                    "{pad}[{i:>3}] TemplateBody id={:?} frame={} params={} captures={:?}",
                    id, frame_size, n_params, captures
                );
                walk(inner, in_loop_depth, scopes, indent + 2);
            }
            ExtendedInstruction::TemplateCall {
                template_id,
                captures,
                outputs,
            } => {
                println!(
                    "{pad}[{i:>3}] TemplateCall id={:?} caps={:?} outs={:?}",
                    template_id, captures, outputs
                );
                for o in outputs {
                    record_def(*o, in_loop, scopes);
                }
                for c in captures {
                    record_use(*c, in_loop, scopes);
                }
            }
            ExtendedInstruction::LoopUnroll {
                iter_var,
                start,
                end,
                body: inner,
            } => {
                println!(
                    "{pad}[{i:>3}] LoopUnroll   iter=%{} range=[{}..{}]",
                    iter_var.0, start, end
                );
                record_def(*iter_var, in_loop, scopes);
                walk(inner, in_loop_depth + 1, scopes, indent + 2);
            }
            ExtendedInstruction::SymbolicIndexedEffect {
                array_slots,
                index_var,
                value_var,
                ..
            } => {
                let slots: Vec<String> = array_slots.iter().map(|v| fmt_var(*v)).collect();
                println!(
                    "{pad}[{i:>3}] SymIndEff    slots=[{}] idx=%{}",
                    slots.join(","),
                    index_var.0
                );
                record_use(*index_var, in_loop, scopes);
                if let Some(v) = value_var {
                    record_use(*v, in_loop, scopes);
                }
                for s in array_slots {
                    record_def(*s, in_loop, scopes);
                }
            }
            ExtendedInstruction::SymbolicArrayRead {
                result_var,
                array_slots,
                index_var,
                ..
            } => {
                let slots: Vec<String> = array_slots.iter().map(|v| fmt_var(*v)).collect();
                println!(
                    "{pad}[{i:>3}] SymArrRead   res=%{} slots=[{}] idx=%{}",
                    result_var.0,
                    slots.join(","),
                    index_var.0
                );
                record_def(*result_var, in_loop, scopes);
                record_use(*index_var, in_loop, scopes);
                for s in array_slots {
                    record_use(*s, in_loop, scopes);
                }
            }
            ExtendedInstruction::SymbolicShift {
                result_var,
                operand_var,
                shift_var,
                ..
            } => {
                println!(
                    "{pad}[{i:>3}] SymShift     res=%{} op=%{} amt=%{}",
                    result_var.0, operand_var.0, shift_var.0
                );
                record_def(*result_var, in_loop, scopes);
                record_use(*operand_var, in_loop, scopes);
                record_use(*shift_var, in_loop, scopes);
            }
        }
    }
}

fn try_dump(name: &str, fixture: &str, captures_kv: &[(&str, u64)]) {
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
                println!("instantiate_extended failed: {e}");
                return;
            }
        };

    println!(
        "body len: {}, next_var: %{}",
        extended.body.len(),
        extended.next_var
    );
    let mut scopes = Scopes::default();
    walk(&extended.body, 0, &mut scopes, 0);

    println!("\n-- Scope analysis --");
    println!(
        "vars defined inside-some-loop: {}",
        scopes.inside_loop.len()
    );
    println!("vars defined outer:            {}", scopes.outer_defs.len());
    if scopes.cross_loop_uses.is_empty() {
        println!("CROSS-LOOP USES: none — pattern is INSIDE-LOOP-ONLY");
    } else {
        println!(
            "CROSS-LOOP USES (BUG CLASS A pattern): {} occurrence(s)",
            scopes.cross_loop_uses.len()
        );
        for (v, used_scope, def_scope) in &scopes.cross_loop_uses {
            println!("  %{v} defined in {def_scope}, used in {used_scope}");
        }
    }

    // Try the walker
    let walker_result =
        prove_ir.instantiate_lysis_with_outputs::<Bn254Fr>(&captures, &output_names);
    match walker_result {
        Ok(prog) => println!("Walker: OK ({} instructions)", prog.instructions().len()),
        Err(e) => println!("Walker: FAIL — {e}"),
    }
}

#[test]
fn dump_discriminating_templates() {
    // Confirmed-failing (Bug Class A): Num2Bits has the canonical
    // var-accumulator-escapes-loop pattern.
    try_dump("Num2Bits(8)", "test/circom/num2bits_8.circom", &[]);

    // Suspected-failing: BinSum has the SAME pattern as Num2Bits
    // (`var lin = 0; lin += a[i]*e2; ...; lin === lout;`). If the
    // model is right, this MUST also fail with the same shape.
    try_dump("BinSum(4)", "test/circom/binsum.circom", &[]);

    // Suspected-passing: IsZero has no loop at all.
    try_dump("IsZero()", "test/circom/iszero.circom", &[]);

    // Suspected-passing: MiMCSponge has loop-local var ops only
    // (`var t; t = ...; xL[i] <== aux + t4[i]*t;`) — `t` is reassigned
    // each iteration but never read after the loop. Per the baseline,
    // this passes byte-identical under Lysis.
    try_dump(
        "MiMCSponge(2,220,1)",
        "test/circomlib/mimcsponge_test.circom",
        &[],
    );

    // Pedersen_old: per the baseline this passes count-equal under
    // Lysis (vars 46 vs 54, +8 — which the baseline characterises as
    // ordering-only divergence, not Bug Class A).
    if std::path::Path::new(
        "/home/eddndev/dev/achronyme/achronyme/test/circomlib/pedersen_old_test.circom",
    )
    .exists()
    {
        try_dump(
            "Pedersen_old(8)",
            "test/circomlib/pedersen_old_test.circom",
            &[],
        );
    }
}
