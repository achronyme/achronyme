use std::collections::HashMap;
use std::fs;

use anyhow::{Context, Result};
use constraints::PoseidonParamsProvider;
use memory::{FieldBackend, FieldElement};
use zkc::plonkish_backend::PlonkishCompiler;

use super::bn254::Bn254Ops;
use crate::style::{format_number, Styler};

#[allow(clippy::too_many_arguments)]
pub(super) fn run_plonkish_pipeline<F: FieldBackend + PoseidonParamsProvider + Bn254Ops>(
    program: &ir::IrProgram<F>,
    inputs: Option<&HashMap<String, FieldElement<F>>>,
    prove: bool,
    plonkish_json_path: Option<&str>,
    source_dir: &std::path::Path,
    style: &Styler,
    verbose: bool,
    proven: &std::collections::HashSet<ir::SsaVar>,
) -> Result<()> {
    let mut compiler = PlonkishCompiler::<F>::new();
    compiler.set_proven_boolean(proven.clone());

    if let Some(input_map) = inputs {
        // Unified: compile + witness in one pass (with early IR evaluation)
        compiler
            .compile_ir_with_witness(program, input_map)
            .map_err(|e| anyhow::anyhow!("Plonkish compilation error: {e}"))?;

        compiler
            .system
            .verify()
            .map_err(|e| anyhow::anyhow!("Plonkish verification error: {e}"))?;

        if verbose {
            eprintln!();
            eprintln!("{}:", style.success("Plonkish generated"));
            eprintln!(
                "    Rows:    {}",
                style.bold(&format_number(compiler.num_circuit_rows()))
            );
            eprintln!(
                "    Copies:  {}",
                format_number(compiler.system.copies.len())
            );
            eprintln!(
                "    Lookups: {}",
                format_number(compiler.system.lookups.len())
            );
            eprintln!("    Verification: {}", style.green("OK"));
        } else {
            eprintln!(
                "plonkish: {} rows, {} copies, {} lookups",
                compiler.num_circuit_rows(),
                compiler.system.copies.len(),
                compiler.system.lookups.len(),
            );
            eprintln!("plonkish verification: OK");
        }

        // Export Plonkish circuit + witness to JSON if requested
        if let Some(json_path) = plonkish_json_path {
            let json = constraints::write_plonkish_json(&compiler.system);
            fs::write(json_path, &json).with_context(|| format!("cannot write {json_path}"))?;
            if verbose {
                eprintln!(
                    "    Wrote {} {}",
                    style.bold(json_path),
                    style.dim("(Plonkish JSON export)")
                );
            } else {
                eprintln!("wrote {} (Plonkish JSON export)", json_path);
            }
        }

        if prove {
            let cache_dir = crate::cache_dir();

            let result = F::halo2_proof(compiler, &cache_dir)
                .map_err(|e| anyhow::anyhow!("Plonkish proof generation error: {e}"))?;

            match result {
                akron::ProveResult::Proof {
                    proof_json,
                    public_json,
                    vkey_json,
                } => {
                    let proof_path = source_dir.join("proof.json");
                    let public_path = source_dir.join("public.json");
                    let vkey_path = source_dir.join("vkey.json");
                    fs::write(&proof_path, &proof_json)
                        .with_context(|| format!("cannot write {}", proof_path.display()))?;
                    fs::write(&public_path, &public_json)
                        .with_context(|| format!("cannot write {}", public_path.display()))?;
                    fs::write(&vkey_path, &vkey_json)
                        .with_context(|| format!("cannot write {}", vkey_path.display()))?;
                    if verbose {
                        eprintln!(
                            "\n{} {}",
                            style.success("Proof generated"),
                            style.dim("(PlonK/halo2)")
                        );
                        eprintln!(
                            "    Wrote {}",
                            style.bold(&proof_path.display().to_string())
                        );
                        eprintln!(
                            "    Wrote {}",
                            style.bold(&public_path.display().to_string())
                        );
                        eprintln!("    Wrote {}", style.bold(&vkey_path.display().to_string()));
                    } else {
                        eprintln!(
                            "wrote {}, {}, {}",
                            proof_path.display(),
                            public_path.display(),
                            vkey_path.display()
                        );
                    }
                }
                akron::ProveResult::VerifiedOnly => {
                    if verbose {
                        eprintln!("\n{}", style.green("Proof verified (no proof output)"));
                    } else {
                        eprintln!("plonkish proof generation: verified only (no proof output)");
                    }
                }
            }
        }
    } else {
        if prove {
            return Err(anyhow::anyhow!("--prove requires --inputs or --input-file"));
        }

        compiler
            .compile_ir(program)
            .map_err(|e| anyhow::anyhow!("Plonkish compilation error: {e}"))?;

        if verbose {
            eprintln!();
            eprintln!("{}:", style.success("Plonkish generated"));
            eprintln!(
                "    Rows:    {}",
                style.bold(&format_number(compiler.num_circuit_rows()))
            );
            eprintln!(
                "    Copies:  {}",
                format_number(compiler.system.copies.len())
            );
            eprintln!(
                "    Lookups: {}",
                format_number(compiler.system.lookups.len())
            );
        } else {
            eprintln!(
                "plonkish: {} rows, {} copies, {} lookups",
                compiler.num_circuit_rows(),
                compiler.system.copies.len(),
                compiler.system.lookups.len(),
            );
        }

        // Export Plonkish circuit to JSON if requested (no witness in this path)
        if let Some(json_path) = plonkish_json_path {
            let json = constraints::write_plonkish_json(&compiler.system);
            fs::write(json_path, &json).with_context(|| format!("cannot write {json_path}"))?;
            if verbose {
                eprintln!(
                    "    Wrote {} {}",
                    style.bold(json_path),
                    style.dim("(Plonkish JSON export, no witness)")
                );
            } else {
                eprintln!("wrote {} (Plonkish JSON export, no witness)", json_path);
            }
        }
    }

    Ok(())
}
