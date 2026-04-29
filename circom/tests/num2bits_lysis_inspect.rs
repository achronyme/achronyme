//! Inspection test for the Num2Bits Lysis bug.
//!
//! Dumps the ExtendedInstruction stream produced by
//! `instantiate_with_outputs_extended` so we can trace exactly which
//! SsaVar `%18` is — i.e. which instruction *uses* it and which
//! instruction *should* have defined it.
//!
//! Not a permanent test — purely a diagnostic.
//! Run: `cargo test --release --test num2bits_lysis_inspect -- --nocapture`

use std::collections::{HashMap, HashSet};

use ir_core::{Instruction, SsaVar};
use ir_forge::extended::ExtendedInstruction;
use memory::{Bn254Fr, FieldElement};

use circom::{compile_file_with_frontend, Frontend};

fn fmt_var(v: SsaVar) -> String {
    format!("%{}", v.0)
}

fn dump_ext<F: memory::FieldBackend>(
    body: &[ExtendedInstruction<F>],
    indent: usize,
    counters: &mut Counters,
) {
    let pad = " ".repeat(indent);
    for (i, ext) in body.iter().enumerate() {
        match ext {
            ExtendedInstruction::Plain(inst) => {
                let res = inst.result_var();
                let extras = inst.extra_result_vars();
                let mut defs = vec![fmt_var(res)];
                for v in extras {
                    defs.push(fmt_var(*v));
                }
                let uses: Vec<String> = inst.operands().into_iter().map(fmt_var).collect();
                let kind = inst_kind(inst);
                println!(
                    "{pad}[{i:>3}] Plain         def={:<12} uses={:<32} | {}",
                    defs.join(","),
                    uses.join(","),
                    kind,
                );
                counters.plain += 1;
                for d in &defs {
                    counters.defs.insert(d.clone());
                }
                for u in &uses {
                    counters.uses.insert(u.to_string());
                }
            }
            ExtendedInstruction::TemplateBody {
                id,
                frame_size,
                n_params,
                captures,
                body: inner,
            } => {
                let cap_str: Vec<String> = captures.iter().copied().map(fmt_var).collect();
                println!(
                    "{pad}[{i:>3}] TemplateBody  id={:?} frame={} params={} captures=[{}]",
                    id,
                    frame_size,
                    n_params,
                    cap_str.join(","),
                );
                dump_ext(inner, indent + 2, counters);
            }
            ExtendedInstruction::TemplateCall {
                template_id,
                captures,
                outputs,
            } => {
                let cap: Vec<String> = captures.iter().copied().map(fmt_var).collect();
                let out: Vec<String> = outputs.iter().copied().map(fmt_var).collect();
                println!(
                    "{pad}[{i:>3}] TemplateCall  id={:?} caps=[{}] outs=[{}]",
                    template_id,
                    cap.join(","),
                    out.join(","),
                );
                for o in &out {
                    counters.defs.insert(o.clone());
                }
                for c in &cap {
                    counters.uses.insert(c.clone());
                }
            }
            ExtendedInstruction::LoopUnroll {
                iter_var,
                start,
                end,
                body: inner,
            } => {
                println!(
                    "{pad}[{i:>3}] LoopUnroll    iter={} range=[{}..{}]",
                    fmt_var(*iter_var),
                    start,
                    end,
                );
                counters.defs.insert(fmt_var(*iter_var));
                dump_ext(inner, indent + 2, counters);
            }
            ExtendedInstruction::SymbolicIndexedEffect {
                kind,
                array_slots,
                index_var,
                value_var,
                ..
            } => {
                let slots: Vec<String> = array_slots.iter().copied().map(fmt_var).collect();
                let val = value_var
                    .map(fmt_var)
                    .unwrap_or_else(|| "<witness>".to_string());
                println!(
                    "{pad}[{i:>3}] SymIndEff     kind={:?} slots=[{}] idx={} val={}",
                    kind,
                    slots.join(","),
                    fmt_var(*index_var),
                    val,
                );
                counters.uses.insert(fmt_var(*index_var));
                if let Some(v) = value_var {
                    counters.uses.insert(fmt_var(*v));
                }
                // slots are reads or fresh witness; record as both — they're the targets
                for s in &slots {
                    counters.defs.insert(s.clone());
                }
            }
            ExtendedInstruction::SymbolicArrayRead {
                result_var,
                array_slots,
                index_var,
                ..
            } => {
                let slots: Vec<String> = array_slots.iter().copied().map(fmt_var).collect();
                println!(
                    "{pad}[{i:>3}] SymArrRead    res={} slots=[{}] idx={}",
                    fmt_var(*result_var),
                    slots.join(","),
                    fmt_var(*index_var),
                );
                counters.defs.insert(fmt_var(*result_var));
                counters.uses.insert(fmt_var(*index_var));
                for s in &slots {
                    counters.uses.insert(s.clone());
                }
            }
            ExtendedInstruction::SymbolicShift {
                result_var,
                operand_var,
                shift_var,
                num_bits,
                direction,
                ..
            } => {
                println!(
                    "{pad}[{i:>3}] SymShift      res={} op={} amt={} bits={} dir={:?}",
                    fmt_var(*result_var),
                    fmt_var(*operand_var),
                    fmt_var(*shift_var),
                    num_bits,
                    direction,
                );
                counters.defs.insert(fmt_var(*result_var));
                counters.uses.insert(fmt_var(*operand_var));
                counters.uses.insert(fmt_var(*shift_var));
            }
        }
    }
}

fn inst_kind<F: memory::FieldBackend>(inst: &Instruction<F>) -> String {
    // Cheap discriminator string; format!{:?} would dump full body, too verbose
    let dbg = format!("{:?}", inst);
    dbg.split_whitespace().next().unwrap_or("?").to_string()
}

#[derive(Default)]
struct Counters {
    plain: usize,
    defs: std::collections::BTreeSet<String>,
    uses: std::collections::BTreeSet<String>,
}

#[test]
fn dump_num2bits_lysis_extended_stream() {
    let manifest_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap();
    let path = manifest_dir.join("test/circom/num2bits_8.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];
    assert!(path.exists(), "fixture missing: {}", path.display());

    let result = compile_file_with_frontend(&path, &lib_dirs, Frontend::Lysis)
        .expect("compile_file_with_frontend(Lysis) should succeed (it's instantiate that fails)");
    let prove_ir = result.prove_ir;
    let captures: HashMap<String, FieldElement<Bn254Fr>> = result
        .capture_values
        .into_iter()
        .map(|(k, v)| (k, FieldElement::<Bn254Fr>::from_u64(v)))
        .collect();
    let output_names: HashSet<String> = result.output_names.into_iter().collect();

    println!("== captures (template params) ==");
    for (k, v) in &captures {
        println!("  {k} = {:?}", v);
    }
    println!("== output_names ==");
    for n in &output_names {
        println!("  {n}");
    }

    let extended = prove_ir
        .instantiate_with_outputs_extended::<Bn254Fr>(&captures, &output_names)
        .expect("instantiate_with_outputs_extended should succeed");

    println!(
        "\n== ExtendedIrProgram body ({} instructions) ==",
        extended.body.len()
    );
    println!("== next_var = %{} ==\n", extended.next_var);

    let mut counters = Counters::default();
    dump_ext(&extended.body, 0, &mut counters);

    println!("\n== Summary ==");
    println!("plain count: {}", counters.plain);
    println!("defs ({}): {:?}", counters.defs.len(), counters.defs);
    println!("uses ({}): {:?}", counters.uses.len(), counters.uses);

    let undefined: Vec<&String> = counters.uses.difference(&counters.defs).collect();
    println!(
        "\n== Used but never defined (would trip the walker): {:?}",
        undefined
    );

    // Now actually run the walker and see what it says
    println!("\n== Walker run ==");
    let walker_result =
        prove_ir.instantiate_lysis_with_outputs::<Bn254Fr>(&captures, &output_names);
    match walker_result {
        Ok(prog) => println!(
            "Walker succeeded with {} instructions",
            prog.instructions().len()
        ),
        Err(e) => println!("Walker failed: {e}"),
    }
}
