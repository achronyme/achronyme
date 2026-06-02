use std::collections::HashMap;
use std::fs;

use anyhow::{Context, Result};
use constraints::PoseidonParamsProvider;
use constraints::{write_r1cs, write_wtns};
use memory::field::PrimeId;
use memory::{FieldBackend, FieldElement};
use zkc::r1cs_backend::R1CSCompiler;

use super::bn254::Bn254Ops;
use crate::style::{format_number, Styler};

#[allow(clippy::too_many_arguments)]
pub(super) fn run_r1cs_pipeline<F: FieldBackend + PoseidonParamsProvider + Bn254Ops>(
    program: &ir::IrProgram<F>,
    r1cs_path: &str,
    wtns_path: &str,
    inputs: Option<&HashMap<String, FieldElement<F>>>,
    prime_id: PrimeId,
    solidity_path: Option<&str>,
    style: &Styler,
    verbose: bool,
    no_optimize: bool,
    proven: &std::collections::HashSet<ir::SsaVar>,
) -> Result<()> {
    let mut compiler = R1CSCompiler::<F>::new();
    compiler.prime_id = prime_id;
    compiler.set_proven_boolean(proven.clone());

    // Count public/witness inputs from IR
    let n_public = program
        .iter()
        .filter(|i| {
            matches!(
                i,
                ir::Instruction::Input {
                    visibility: ir::Visibility::Public,
                    ..
                }
            )
        })
        .count();
    let n_witness = program
        .iter()
        .filter(|i| {
            matches!(
                i,
                ir::Instruction::Input {
                    visibility: ir::Visibility::Witness,
                    ..
                }
            )
        })
        .count();

    if let Some(input_map) = inputs {
        // Unified: compile + witness in one pass (with early IR evaluation)
        let mut witness_vec = compiler
            .compile_ir_with_witness(program, input_map)
            .map_err(|e| anyhow::anyhow!("R1CS compilation error: {e}"))?;

        // R1CS linear constraint elimination
        if !no_optimize {
            let r1cs_stats = compiler.optimize_r1cs();
            if verbose && r1cs_stats.variables_eliminated > 0 {
                eprintln!(
                    "    {}: {} → {} constraints ({} linear eliminated)",
                    style.cyan("R1CS opt"),
                    r1cs_stats.constraints_before,
                    r1cs_stats.constraints_after,
                    r1cs_stats.variables_eliminated,
                );
            }
            // Re-fill substituted wires in the witness
            if let Some(subs) = &compiler.substitution_map {
                for (var_idx, lc) in subs {
                    witness_vec[*var_idx] = lc
                        .evaluate(&witness_vec)
                        .map_err(|e| anyhow::anyhow!("witness fixup failed: {e}"))?;
                }
            }
        }

        if let Err(e) = compiler.cs.verify(&witness_vec) {
            let mut msg = format!("witness verification failed: {e}");
            if let constraints::r1cs::ConstraintError::ConstraintUnsatisfied(idx) = &e {
                if let Some(origin) = compiler.constraint_origins.get(*idx) {
                    let inst = &program.instructions()[origin.ir_index];
                    msg = format!("constraint {idx} unsatisfied in: {inst}");
                    if let Some(name) = program.get_name(origin.result_var) {
                        msg.push_str(&format!("  (variable: {name})"));
                    }
                    if let Some(span) = program.get_span(origin.result_var) {
                        let file = span
                            .file
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_default();
                        msg.push_str(&format!(
                            "\n    --> {}:{}:{}",
                            file, span.line_start, span.col_start
                        ));
                    }
                    // Show assert message if the instruction has one
                    match inst {
                        ir::Instruction::AssertEq {
                            message: Some(m), ..
                        }
                        | ir::Instruction::Assert {
                            message: Some(m), ..
                        } => {
                            msg.push_str(&format!("\n    message: {m}"));
                        }
                        _ => {}
                    }
                }
            }
            return Err(anyhow::anyhow!("{msg}"));
        }

        let r1cs_data = write_r1cs(&compiler.cs, prime_id);
        fs::write(r1cs_path, &r1cs_data).with_context(|| format!("cannot write {r1cs_path}"))?;

        let wtns_data = write_wtns(&witness_vec, prime_id);
        fs::write(wtns_path, &wtns_data).with_context(|| format!("cannot write {wtns_path}"))?;

        if verbose {
            eprintln!();
            eprintln!("{}:", style.success("R1CS generated"));
            let nc = compiler.cs.num_constraints();
            eprintln!("    Constraints:    {}", style.bold(&format_number(nc)));
            // Show Poseidon efficiency note if circuit uses Poseidon
            let has_poseidon = program
                .iter()
                .any(|i| matches!(i, ir::Instruction::PoseidonHash { .. }));
            if has_poseidon {
                eprintln!(
                    "    {}",
                    style.dim("Poseidon: 362 constraints (Circom: 517 — 30% more efficient)")
                );
            }
            eprintln!("    Public inputs:  {}", n_public);
            eprintln!("    Private inputs: {}", n_witness);
            eprintln!(
                "    Wrote {} ({} bytes)",
                style.bold(r1cs_path),
                format_number(r1cs_data.len())
            );
            eprintln!(
                "    Wrote {} ({} bytes) {} {}",
                style.bold(wtns_path),
                format_number(wtns_data.len()),
                style.dim("—"),
                style.green("verified OK")
            );
        } else {
            eprintln!(
                "wrote {} ({} constraints, {} wires, {} bytes)",
                r1cs_path,
                compiler.cs.num_constraints(),
                compiler.cs.num_variables(),
                r1cs_data.len(),
            );
            eprintln!(
                "wrote {} ({} values, {} bytes) — verified OK",
                wtns_path,
                witness_vec.len(),
                wtns_data.len(),
            );
        }
    } else {
        // No inputs: compile constraints only
        compiler
            .compile_ir(program)
            .map_err(|e| anyhow::anyhow!("R1CS compilation error: {e}"))?;

        // R1CS linear constraint elimination
        if !no_optimize {
            let r1cs_stats = compiler.optimize_r1cs();
            if verbose && r1cs_stats.variables_eliminated > 0 {
                eprintln!(
                    "    {}: {} → {} constraints ({} linear eliminated)",
                    style.cyan("R1CS opt"),
                    r1cs_stats.constraints_before,
                    r1cs_stats.constraints_after,
                    r1cs_stats.variables_eliminated,
                );
            }
        }

        let r1cs_data = write_r1cs(&compiler.cs, prime_id);
        fs::write(r1cs_path, &r1cs_data).with_context(|| format!("cannot write {r1cs_path}"))?;

        if verbose {
            eprintln!();
            eprintln!("{}:", style.success("R1CS generated"));
            eprintln!(
                "    Constraints:    {}",
                style.bold(&format_number(compiler.cs.num_constraints()))
            );
            eprintln!("    Public inputs:  {}", n_public);
            eprintln!("    Private inputs: {}", n_witness);
            eprintln!(
                "    Wrote {} ({} bytes)",
                style.bold(r1cs_path),
                format_number(r1cs_data.len())
            );
        } else {
            eprintln!(
                "wrote {} ({} constraints, {} wires, {} bytes)",
                r1cs_path,
                compiler.cs.num_constraints(),
                compiler.cs.num_variables(),
                r1cs_data.len(),
            );
        }
    }

    // Generate Solidity verifier if requested (BN254-only, validated by caller)
    if let Some(sol_path) = solidity_path {
        let cache_dir = crate::cache_dir();

        let sol_source =
            F::solidity_from_cs(&compiler.cs, &cache_dir).map_err(|e| anyhow::anyhow!("{e}"))?;

        fs::write(sol_path, &sol_source).with_context(|| format!("cannot write {sol_path}"))?;

        if verbose {
            eprintln!(
                "    Wrote {} {}",
                style.bold(sol_path),
                style.dim("(Solidity Groth16 verifier)")
            );
        } else {
            eprintln!("wrote {} (Solidity Groth16 verifier)", sol_path);
        }
    }

    Ok(())
}
