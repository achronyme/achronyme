//! Diagnostic-only: count `Input` instructions per side of the
//! cross-path baseline for the 7 slack-divergent templates.
//!
//! Goal: discriminate "orphan witness Input wires" hypothesis (Lysis
//! emits extra `Input` instructions for sub-component arrays that no
//! constraint references) from "pure wire-renumbering" (same Input
//! count, just different SsaVar order).
//!
//! Outputs a structured table on stderr with --nocapture. Not gated.

use constraints::r1cs::LinearCombination;
use std::collections::{HashMap, HashSet};
use std::path::Path;
use zkc::r1cs_backend::R1CSCompiler;

use circom::Frontend;
use ir::passes::canonicalize_ssa;
use ir::types::{Instruction, IrProgram, Visibility};
use memory::{Bn254Fr, FieldElement};

#[derive(Debug, Default)]
struct Counts {
    public: usize,
    witness: usize,
    total_instr: usize,
    /// Names of all `Input(Witness)` instructions, in emission order.
    witness_names: Vec<String>,
}

fn count_inputs(program: &IrProgram<Bn254Fr>) -> Counts {
    let mut c = Counts::default();
    for inst in program.iter() {
        c.total_instr += 1;
        if let Instruction::Input {
            name, visibility, ..
        } = inst
        {
            match visibility {
                Visibility::Public => c.public += 1,
                Visibility::Witness => {
                    c.witness += 1;
                    c.witness_names.push(name.clone());
                }
            }
        }
    }
    c
}

fn run_one(name: &str, file: &str, captures: HashMap<String, FieldElement<Bn254Fr>>) {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join(file);
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    eprintln!("\n=== {name} ===");
    for fe in [Frontend::Legacy, Frontend::Lysis] {
        let result = match circom::compile_file_with_frontend(&path, &lib_dirs, fe) {
            Ok(r) => r,
            Err(e) => {
                eprintln!("  [{fe:?}] compile failed: {e}");
                continue;
            }
        };
        let fe_caps: HashMap<String, FieldElement<Bn254Fr>> = result
            .capture_values
            .iter()
            .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
            .collect();
        let merged_caps: HashMap<String, FieldElement<Bn254Fr>> = fe_caps
            .into_iter()
            .chain(captures.iter().map(|(k, v)| (k.clone(), *v)))
            .collect();

        let program: IrProgram<Bn254Fr> = match fe {
            Frontend::Legacy => result
                .prove_ir
                .instantiate_with_outputs::<Bn254Fr>(&merged_caps, &result.output_names)
                .expect("legacy instantiate failed"),
            Frontend::Lysis => result
                .prove_ir
                .instantiate_lysis_with_outputs::<Bn254Fr>(&merged_caps, &result.output_names)
                .expect("lysis instantiate failed"),
        };
        // Pre-optimize (raw lift) to expose orphan witness inputs that
        // const-fold/DCE would later prune. We want the unoptimized count
        // to characterise the slack source.
        let pre_program = canonicalize_ssa(&program);
        let pre = count_inputs(&pre_program);

        // Post-optimize: this is what cross_path_baseline measures.
        let mut opt_program = program;
        ir::passes::optimize(&mut opt_program);
        let opt_program = canonicalize_ssa(&opt_program);
        let post = count_inputs(&opt_program);

        eprintln!(
            "  [{fe:?}] PRE-opt:  pub={:>4} witness={:>4} total_instr={:>6}",
            pre.public, pre.witness, pre.total_instr
        );
        eprintln!(
            "  [{fe:?}] POST-opt: pub={:>4} witness={:>4} total_instr={:>6}",
            post.public, post.witness, post.total_instr
        );

        // Compile to R1CS, then identify orphan witnesses
        // (Inputs whose SsaVar is never referenced by any constraint).
        let mut compiler = R1CSCompiler::<Bn254Fr>::new();
        compiler
            .compile_ir(&opt_program)
            .expect("R1CS compile failed");
        let _ = compiler.optimize_r1cs();

        // Build set of wires referenced by any A/B/C lc.
        let mut referenced: HashSet<usize> = HashSet::new();
        for c in compiler.cs.constraints() {
            for term in c.a.simplify().terms() {
                referenced.insert(term.0.index());
            }
            for term in c.b.simplify().terms() {
                referenced.insert(term.0.index());
            }
            for term in c.c.simplify().terms() {
                referenced.insert(term.0.index());
            }
        }

        // Walk the IR program & identify which witness Inputs are not
        // referenced. We need the ssa-var-to-wire mapping; the R1CS
        // compiler routes Input.result → wire 1:1 so the SsaVar.index
        // matches the wire-id (modulo wire 0 being the constant 1).
        let mut orphan_names: Vec<String> = Vec::new();
        for inst in opt_program.iter() {
            if let Instruction::Input {
                result,
                name,
                visibility: Visibility::Witness,
            } = inst
            {
                if !referenced.contains(&(result.0 as usize)) {
                    orphan_names.push(name.clone());
                }
            }
        }

        let post_constraints = compiler.cs.num_constraints();
        let post_vars = compiler.cs.num_variables();
        eprintln!(
            "  [{fe:?}] R1CS post-O1: vars={:>4} constraints={:>5} orphan_witnesses={:>4}",
            post_vars,
            post_constraints,
            orphan_names.len()
        );
        if !orphan_names.is_empty() {
            let display: Vec<&String> = orphan_names.iter().take(8).collect();
            eprintln!("  [{fe:?}]   orphan sample: {display:?}");
        }
        // Silence unused.
        let _: &dyn Fn() = &|| {
            let _ = LinearCombination::<Bn254Fr>::default();
        };
    }
}

#[test]
fn cross_path_input_audit() {
    type TemplateRow<'a> = (&'a str, &'a str, Vec<(&'a str, u64)>);
    let templates: Vec<TemplateRow> = vec![
        (
            "LessThan(8)",
            "test/circom/lessthan_8.circom",
            vec![("in_0", 3), ("in_1", 10)],
        ),
        (
            "Pedersen(8)",
            "test/circomlib/pedersen_test.circom",
            (0..8)
                .map(|i| (Box::leak(format!("in_{i}").into_boxed_str()) as &str, i % 2))
                .collect(),
        ),
        (
            "EscalarMulFix(253)",
            "test/circomlib/escalarmulfix_test.circom",
            (0..253)
                .map(|i| (Box::leak(format!("e_{i}").into_boxed_str()) as &str, 0))
                .collect(),
        ),
        (
            "Poseidon(2)",
            "test/circomlib/poseidon_test.circom",
            vec![("inputs_0", 1), ("inputs_1", 2)],
        ),
        (
            "MiMCSponge(2,220,1)",
            "test/circomlib/mimcsponge_test.circom",
            vec![("ins_0", 1), ("ins_1", 2), ("k", 0)],
        ),
        (
            "Pedersen_old(8)",
            "test/circomlib/pedersen_old_test.circom",
            (0..8)
                .map(|i| (Box::leak(format!("in_{i}").into_boxed_str()) as &str, i % 2))
                .collect(),
        ),
    ];
    // EscalarMulAny separately since it needs e_0..e_253 + p_0,p_1.
    let mut ema: Vec<(&str, u64)> = (0..254)
        .map(|i| (Box::leak(format!("e_{i}").into_boxed_str()) as &str, 0))
        .collect();
    ema.push(("p_0", 0));
    ema.push(("p_1", 1));
    let mut all = templates;
    all.push((
        "EscalarMulAny(254)",
        "test/circomlib/escalarmulany254_test.circom",
        ema,
    ));

    for (name, file, caps) in all {
        let m: HashMap<String, FieldElement<Bn254Fr>> = caps
            .into_iter()
            .map(|(k, v)| (k.to_string(), FieldElement::<Bn254Fr>::from_u64(v)))
            .collect();
        run_one(name, file, m);
    }
}
