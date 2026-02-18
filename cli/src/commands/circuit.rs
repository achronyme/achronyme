use std::collections::HashMap;
use std::fs;

use anyhow::{Context, Result};

use compiler::plonkish_backend::{PlonkishCompiler, PlonkishWitnessGenerator};
use compiler::r1cs_backend::R1CSCompiler;
use compiler::witness_gen::WitnessGenerator;
use constraints::{write_r1cs, write_wtns};
use ir::IrLowering;
use memory::FieldElement;

/// Parse an `--inputs` string like `"out=42,a=6,b=0x07"` into a map.
fn parse_inputs(raw: &str) -> Result<HashMap<String, FieldElement>> {
    let mut map = HashMap::new();
    for pair in raw.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let (name, val_str) = pair
            .split_once('=')
            .context(format!("invalid input pair: {pair:?} (expected name=value)"))?;
        let val = if val_str.starts_with("0x") || val_str.starts_with("0X") {
            FieldElement::from_hex_str(val_str)
                .context(format!("invalid hex value for {name:?}: {val_str:?}"))?
        } else {
            FieldElement::from_decimal_str(val_str)
                .context(format!("invalid decimal value for {name:?}: {val_str:?}"))?
        };
        map.insert(name.to_string(), val);
    }
    Ok(map)
}

pub fn circuit_command(
    path: &str,
    r1cs_path: &str,
    wtns_path: &str,
    public: &[String],
    witness: &[String],
    inputs: Option<&str>,
    no_optimize: bool,
    backend: &str,
) -> Result<()> {
    let source = fs::read_to_string(path)
        .with_context(|| format!("cannot read source file: {path}"))?;

    // 1. Lower to IR — self-contained or CLI-provided declarations
    let mut program = if public.is_empty() && witness.is_empty() {
        let (_, _, prog) = IrLowering::lower_self_contained(&source)
            .map_err(|e| anyhow::anyhow!("IR lowering error: {e:?}"))?;
        prog
    } else {
        let pub_refs: Vec<&str> = public.iter().map(|s| s.as_str()).collect();
        let wit_refs: Vec<&str> = witness.iter().map(|s| s.as_str()).collect();
        IrLowering::lower_circuit(&source, &pub_refs, &wit_refs)
            .map_err(|e| anyhow::anyhow!("IR lowering error: {e:?}"))?
    };

    // 2. Optimize (unless --no-optimize)
    if !no_optimize {
        ir::passes::optimize(&mut program);
    }

    // 3. Analyze for under-constrained inputs
    let warnings = ir::passes::analyze(&program);
    for w in &warnings {
        eprintln!("warning: {w}");
    }

    match backend {
        "r1cs" => run_r1cs_pipeline(&program, r1cs_path, wtns_path, inputs),
        "plonkish" => run_plonkish_pipeline(&program, inputs),
        _ => Err(anyhow::anyhow!(
            "unknown backend `{backend}` (use \"r1cs\" or \"plonkish\")"
        )),
    }
}

fn run_r1cs_pipeline(
    program: &ir::IrProgram,
    r1cs_path: &str,
    wtns_path: &str,
    inputs: Option<&str>,
) -> Result<()> {
    let mut compiler = R1CSCompiler::new();
    compiler
        .compile_ir(program)
        .map_err(|e| anyhow::anyhow!("R1CS compilation error: {e:?}"))?;

    let r1cs_data = write_r1cs(&compiler.cs);
    fs::write(r1cs_path, &r1cs_data)
        .with_context(|| format!("cannot write {r1cs_path}"))?;
    eprintln!(
        "wrote {} ({} constraints, {} wires, {} bytes)",
        r1cs_path,
        compiler.cs.num_constraints(),
        compiler.cs.num_variables(),
        r1cs_data.len(),
    );

    if let Some(raw_inputs) = inputs {
        let input_map = parse_inputs(raw_inputs)?;

        let wg = WitnessGenerator::from_compiler(&compiler);
        let witness_vec = wg
            .generate(&input_map)
            .map_err(|e| anyhow::anyhow!("witness generation error: {e}"))?;

        compiler
            .cs
            .verify(&witness_vec)
            .map_err(|idx| anyhow::anyhow!("witness verification failed at constraint {idx}"))?;

        let wtns_data = write_wtns(&witness_vec);
        fs::write(wtns_path, &wtns_data)
            .with_context(|| format!("cannot write {wtns_path}"))?;
        eprintln!(
            "wrote {} ({} values, {} bytes) — verified OK",
            wtns_path,
            witness_vec.len(),
            wtns_data.len(),
        );
    }

    Ok(())
}

fn run_plonkish_pipeline(program: &ir::IrProgram, inputs: Option<&str>) -> Result<()> {
    let mut compiler = PlonkishCompiler::new();
    compiler
        .compile_ir(program)
        .map_err(|e| anyhow::anyhow!("Plonkish compilation error: {e}"))?;

    eprintln!(
        "plonkish: {} rows, {} copies, {} lookups",
        compiler.num_circuit_rows(),
        compiler.system.copies.len(),
        compiler.system.lookups.len(),
    );

    if let Some(raw_inputs) = inputs {
        let input_map = parse_inputs(raw_inputs)?;
        let wg = PlonkishWitnessGenerator::from_compiler(&compiler);
        wg.generate(&input_map, &mut compiler.system.assignments)
            .map_err(|e| anyhow::anyhow!("Plonkish witness generation error: {e}"))?;
        compiler
            .system
            .verify()
            .map_err(|e| anyhow::anyhow!("Plonkish verification error: {e}"))?;
        eprintln!("plonkish verification: OK");
    }

    Ok(())
}
