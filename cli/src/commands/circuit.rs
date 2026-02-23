use std::collections::HashMap;
use std::fs;

use anyhow::{Context, Result};

use compiler::plonkish_backend::PlonkishCompiler;
use compiler::r1cs_backend::R1CSCompiler;
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
        let (name, val_str) = pair.split_once('=').context(format!(
            "invalid input pair: {pair:?} (expected name=value)"
        ))?;
        let val = if val_str.starts_with("0x") || val_str.starts_with("0X") {
            FieldElement::from_hex_str(val_str)
                .context(format!("invalid hex value for {name:?}: {val_str:?}"))?
        } else if let Some(digits) = val_str.strip_prefix('-') {
            let abs = FieldElement::from_decimal_str(digits)
                .context(format!("invalid decimal value for {name:?}: {val_str:?}"))?;
            abs.neg()
        } else {
            FieldElement::from_decimal_str(val_str)
                .context(format!("invalid decimal value for {name:?}: {val_str:?}"))?
        };
        map.insert(name.to_string(), val);
    }
    Ok(map)
}

#[allow(clippy::too_many_arguments)]
pub fn circuit_command(
    path: &str,
    r1cs_path: &str,
    wtns_path: &str,
    public: &[String],
    witness: &[String],
    inputs: Option<&str>,
    no_optimize: bool,
    backend: &str,
    prove: bool,
    solidity_path: Option<&str>,
) -> Result<()> {
    let source =
        fs::read_to_string(path).with_context(|| format!("cannot read source file: {path}"))?;

    // 1. Lower to IR — self-contained or CLI-provided declarations
    let mut program = if public.is_empty() && witness.is_empty() {
        let (_, _, prog) = IrLowering::lower_self_contained(&source)
            .map_err(|e| anyhow::anyhow!("IR lowering error: {e}"))?;
        prog
    } else {
        let pub_refs: Vec<&str> = public.iter().map(|s| s.as_str()).collect();
        let wit_refs: Vec<&str> = witness.iter().map(|s| s.as_str()).collect();
        IrLowering::lower_circuit(&source, &pub_refs, &wit_refs)
            .map_err(|e| anyhow::anyhow!("IR lowering error: {e}"))?
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

    if solidity_path.is_some() && backend != "r1cs" {
        return Err(anyhow::anyhow!(
            "--solidity is only supported with the r1cs backend"
        ));
    }

    match backend {
        "r1cs" => run_r1cs_pipeline(&program, r1cs_path, wtns_path, inputs, solidity_path),
        "plonkish" => run_plonkish_pipeline(&program, inputs, prove),
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
    solidity_path: Option<&str>,
) -> Result<()> {
    let mut compiler = R1CSCompiler::new();
    let proven = ir::passes::bool_prop::compute_proven_boolean(program);
    compiler.set_proven_boolean(proven);

    if let Some(raw_inputs) = inputs {
        let input_map = parse_inputs(raw_inputs)?;

        // Unified: compile + witness in one pass (with early IR evaluation)
        let witness_vec = compiler
            .compile_ir_with_witness(program, &input_map)
            .map_err(|e| anyhow::anyhow!("R1CS compilation error: {e}"))?;

        compiler
            .cs
            .verify(&witness_vec)
            .map_err(|idx| anyhow::anyhow!("witness verification failed at constraint {idx}"))?;

        let r1cs_data = write_r1cs(&compiler.cs);
        fs::write(r1cs_path, &r1cs_data).with_context(|| format!("cannot write {r1cs_path}"))?;
        eprintln!(
            "wrote {} ({} constraints, {} wires, {} bytes)",
            r1cs_path,
            compiler.cs.num_constraints(),
            compiler.cs.num_variables(),
            r1cs_data.len(),
        );

        let wtns_data = write_wtns(&witness_vec);
        fs::write(wtns_path, &wtns_data).with_context(|| format!("cannot write {wtns_path}"))?;
        eprintln!(
            "wrote {} ({} values, {} bytes) — verified OK",
            wtns_path,
            witness_vec.len(),
            wtns_data.len(),
        );
    } else {
        // No inputs: compile constraints only
        compiler
            .compile_ir(program)
            .map_err(|e| anyhow::anyhow!("R1CS compilation error: {e}"))?;

        let r1cs_data = write_r1cs(&compiler.cs);
        fs::write(r1cs_path, &r1cs_data).with_context(|| format!("cannot write {r1cs_path}"))?;
        eprintln!(
            "wrote {} ({} constraints, {} wires, {} bytes)",
            r1cs_path,
            compiler.cs.num_constraints(),
            compiler.cs.num_variables(),
            r1cs_data.len(),
        );
    }

    // Generate Solidity verifier if requested
    if let Some(sol_path) = solidity_path {
        let cache_dir = std::env::var("HOME")
            .map(|h| std::path::PathBuf::from(h).join(".achronyme").join("cache"))
            .unwrap_or_else(|_| std::path::PathBuf::from("/tmp/achronyme/cache"));

        let vk = crate::groth16::setup_vk_only(&compiler.cs, &cache_dir)
            .map_err(|e| anyhow::anyhow!("Groth16 setup failed: {e}"))?;

        let sol_source = crate::solidity::generate_solidity_verifier(&vk);
        fs::write(sol_path, &sol_source).with_context(|| format!("cannot write {sol_path}"))?;
        eprintln!("wrote {} (Solidity Groth16 verifier)", sol_path);
    }

    Ok(())
}

fn run_plonkish_pipeline(program: &ir::IrProgram, inputs: Option<&str>, prove: bool) -> Result<()> {
    let mut compiler = PlonkishCompiler::new();
    let proven = ir::passes::bool_prop::compute_proven_boolean(program);
    compiler.set_proven_boolean(proven);

    if let Some(raw_inputs) = inputs {
        let input_map = parse_inputs(raw_inputs)?;

        // Unified: compile + witness in one pass (with early IR evaluation)
        compiler
            .compile_ir_with_witness(program, &input_map)
            .map_err(|e| anyhow::anyhow!("Plonkish compilation error: {e}"))?;

        eprintln!(
            "plonkish: {} rows, {} copies, {} lookups",
            compiler.num_circuit_rows(),
            compiler.system.copies.len(),
            compiler.system.lookups.len(),
        );

        compiler
            .system
            .verify()
            .map_err(|e| anyhow::anyhow!("Plonkish verification error: {e}"))?;
        eprintln!("plonkish verification: OK");

        if prove {
            let cache_dir = std::env::var("HOME")
                .map(|h| std::path::PathBuf::from(h).join(".achronyme").join("cache"))
                .unwrap_or_else(|_| std::path::PathBuf::from("/tmp/achronyme/cache"));

            let result = crate::halo2_proof::generate_plonkish_proof(compiler, &cache_dir)
                .map_err(|e| anyhow::anyhow!("Plonkish proof generation error: {e}"))?;

            match result {
                vm::ProveResult::Proof {
                    proof_json,
                    public_json,
                    vkey_json,
                } => {
                    fs::write("proof.json", &proof_json).context("cannot write proof.json")?;
                    fs::write("public.json", &public_json).context("cannot write public.json")?;
                    fs::write("vkey.json", &vkey_json).context("cannot write vkey.json")?;
                    eprintln!("wrote proof.json, public.json, vkey.json");
                }
                vm::ProveResult::VerifiedOnly => {
                    eprintln!("plonkish proof generation: verified only (no proof output)");
                }
            }
        }
    } else {
        if prove {
            return Err(anyhow::anyhow!("--prove requires --inputs"));
        }

        compiler
            .compile_ir(program)
            .map_err(|e| anyhow::anyhow!("Plonkish compilation error: {e}"))?;

        eprintln!(
            "plonkish: {} rows, {} copies, {} lookups",
            compiler.num_circuit_rows(),
            compiler.system.copies.len(),
            compiler.system.lookups.len(),
        );
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_inputs_positive_decimal() {
        let map = parse_inputs("x=42,y=0").unwrap();
        assert_eq!(map["x"], FieldElement::from_u64(42));
        assert_eq!(map["y"], FieldElement::ZERO);
    }

    #[test]
    fn parse_inputs_negative_decimal() {
        let map = parse_inputs("x=-1").unwrap();
        // -1 mod p = p - 1
        assert_eq!(map["x"], FieldElement::from_u64(1).neg());
    }

    #[test]
    fn parse_inputs_negative_large() {
        let map = parse_inputs("a=-42,b=7").unwrap();
        assert_eq!(map["a"], FieldElement::from_u64(42).neg());
        assert_eq!(map["b"], FieldElement::from_u64(7));
    }

    #[test]
    fn parse_inputs_hex() {
        let map = parse_inputs("x=0xFF").unwrap();
        assert_eq!(map["x"], FieldElement::from_u64(255));
    }

    #[test]
    fn parse_inputs_empty_pair_skipped() {
        let map = parse_inputs("x=1,,y=2").unwrap();
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn parse_inputs_invalid_pair_errors() {
        assert!(parse_inputs("no_equals").is_err());
    }
}
