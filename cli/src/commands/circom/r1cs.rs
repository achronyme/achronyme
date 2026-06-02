use std::collections::HashMap;
use std::fs;

use anyhow::{Context, Result};
use constraints::PoseidonParamsProvider;
use constraints::{write_r1cs, write_wtns};
use memory::field::PrimeId;
use memory::{FieldBackend, FieldElement};
use zkc::r1cs_backend::R1CSCompiler;

use crate::style::{format_number, Styler};

#[allow(clippy::too_many_arguments)]
pub(super) fn run_r1cs_pipeline<F: FieldBackend + PoseidonParamsProvider>(
    program: &ir::IrProgram<F>,
    r1cs_path: &str,
    wtns_path: &str,
    inputs: Option<&HashMap<String, FieldElement<F>>>,
    prime_id: PrimeId,
    prove: bool,
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
            let nc = compiler.cs.num_constraints();
            eprintln!();
            eprintln!("{}:", style.success("R1CS generated"));
            eprintln!("    Constraints:    {}", style.bold(&format_number(nc)));
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

        // Generate Groth16 proof if requested (BN254 only)
        if prove {
            if F::PRIME_ID != PrimeId::Bn254 {
                return Err(anyhow::anyhow!(
                    "--prove is only supported with BN254 (default prime)"
                ));
            }
            let cache_dir = crate::cache_dir();
            // The proving API takes the default type parameter (Bn254Fr).
            // Since we validated F == Bn254Fr above, this cast is safe.
            let cs_bn254 = unsafe {
                &*(&compiler.cs as *const constraints::r1cs::ConstraintSystem<F>
                    as *const constraints::r1cs::ConstraintSystem<memory::Bn254Fr>)
            };
            let wit_bn254 = unsafe {
                std::slice::from_raw_parts(
                    witness_vec.as_ptr() as *const FieldElement<memory::Bn254Fr>,
                    witness_vec.len(),
                )
            };
            let result = proving::groth16_bn254::generate_proof(cs_bn254, wit_bn254, &cache_dir)
                .map_err(|e| anyhow::anyhow!("proof generation failed: {e}"))?;

            if let akron::ProveResult::Proof {
                proof_json,
                public_json,
                vkey_json,
            } = result
            {
                let out_dir = path_stem(r1cs_path);
                let proof_path = out_dir.join("proof.json");
                let public_path = out_dir.join("public.json");
                let vkey_path = out_dir.join("vkey.json");
                fs::write(&proof_path, &proof_json)?;
                fs::write(&public_path, &public_json)?;
                fs::write(&vkey_path, &vkey_json)?;

                if verbose {
                    eprintln!(
                        "\n{} {}",
                        style.success("Proof generated"),
                        style.dim("(Groth16)")
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
        }
    } else {
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

    // Solidity verifier (BN254-only, same cast pattern as proof generation)
    if let Some(sol_path) = solidity_path {
        if F::PRIME_ID != PrimeId::Bn254 {
            return Err(anyhow::anyhow!("--solidity is only supported with BN254"));
        }
        let cache_dir = crate::cache_dir();
        let cs_bn254 = unsafe {
            &*(&compiler.cs as *const constraints::r1cs::ConstraintSystem<F>
                as *const constraints::r1cs::ConstraintSystem<memory::Bn254Fr>)
        };
        let vk = proving::groth16_bn254::setup_vk_only(cs_bn254, &cache_dir)
            .map_err(|e| anyhow::anyhow!("Groth16 setup failed: {e}"))?;
        let sol_source = proving::solidity::generate_solidity_verifier(&vk);
        fs::write(sol_path, &sol_source).with_context(|| format!("cannot write {sol_path}"))?;
        if verbose {
            eprintln!(
                "    Wrote {} {}",
                style.bold(sol_path),
                style.dim("(Solidity Groth16 verifier)")
            );
        }
    }

    Ok(())
}

fn path_stem(path: &str) -> &std::path::Path {
    std::path::Path::new(path)
        .parent()
        .unwrap_or(std::path::Path::new("."))
}
