use std::collections::HashMap;
use std::fs;

use anyhow::{Context, Result};
use constraints::PoseidonParamsProvider;
use constraints::{write_r1cs, write_wtns};
use memory::field::PrimeId;
use memory::{FieldBackend, FieldElement};
use zkc::r1cs_backend::R1CSCompiler;
use zkc::witness::WitnessGenerator;

use crate::style::{format_number, Styler};

/// Compiled-circuit artifact for proving the same circuit repeatedly:
/// the optimized constraint system plus the pristine witness-op trace
/// captured as a [`WitnessGenerator`]. Each extra input set replays the
/// trace and skips every compile phase — instantiation, IR optimization,
/// constraint emission, and R1CS optimization all happen once.
pub(super) struct ReusableProver<F: FieldBackend = memory::Bn254Fr> {
    cs: constraints::r1cs::ConstraintSystem<F>,
    prime_id: PrimeId,
    generator: WitnessGenerator<F>,
}

/// Produce a witness (and optionally a Groth16 proof) for one more
/// input set over an already-compiled circuit. Output files are
/// suffixed with `label` so repeated runs do not clobber each other.
#[allow(clippy::too_many_arguments)]
pub(super) fn run_r1cs_repeat<F: FieldBackend + PoseidonParamsProvider>(
    prover: &ReusableProver<F>,
    all_inputs: &HashMap<String, FieldElement<F>>,
    memo: &mut artik::ArtikMemo<F>,
    label: &str,
    r1cs_path: &str,
    wtns_path: &str,
    prove: bool,
    style: &Styler,
    verbose: bool,
) -> Result<()> {
    let witness_vec = prover
        .generator
        .generate_with_memo(all_inputs, memo)
        .map_err(|e| anyhow::anyhow!("witness generation failed for `{label}`: {e}"))?;
    prover
        .cs
        .verify(&witness_vec)
        .map_err(|e| anyhow::anyhow!("witness verification failed for `{label}`: {e}"))?;

    let out_wtns = suffixed_path(wtns_path, label);
    let wtns_data = write_wtns(&witness_vec, prover.prime_id);
    fs::write(&out_wtns, &wtns_data).with_context(|| format!("cannot write {out_wtns}"))?;
    if verbose {
        eprintln!(
            "{} `{}` — wrote {} ({} values) {} {}",
            style.success("Reused circuit for"),
            label,
            style.bold(&out_wtns),
            format_number(witness_vec.len()),
            style.dim("—"),
            style.green("verified OK")
        );
    } else {
        eprintln!(
            "wrote {} ({} values) — verified OK",
            out_wtns,
            witness_vec.len()
        );
    }

    if prove {
        if F::PRIME_ID != PrimeId::Bn254 {
            return Err(anyhow::anyhow!(
                "--prove is only supported with BN254 (default prime)"
            ));
        }
        let cache_dir = crate::cache_dir();
        let result = generate_bn254_proof(&prover.cs, &witness_vec, &cache_dir)
            .map_err(|e| anyhow::anyhow!("proof generation failed for `{label}`: {e}"))?;

        if let akron::ProveResult::Proof {
            proof_json,
            public_json,
            ..
        } = result
        {
            let out_dir = path_stem(r1cs_path);
            let proof_path = out_dir.join(format!("proof.{label}.json"));
            let public_path = out_dir.join(format!("public.{label}.json"));
            fs::write(&proof_path, &proof_json)?;
            fs::write(&public_path, &public_json)?;
            if verbose {
                eprintln!(
                    "    Wrote {} and {}",
                    style.bold(&proof_path.display().to_string()),
                    style.bold(&public_path.display().to_string())
                );
            } else {
                eprintln!("wrote {}, {}", proof_path.display(), public_path.display());
            }
        }
    }

    Ok(())
}

/// `out.wtns` + `sig2` → `out.sig2.wtns` (next to the original path).
fn suffixed_path(base: &str, label: &str) -> String {
    let p = std::path::Path::new(base);
    let stem = p.file_stem().and_then(|s| s.to_str()).unwrap_or("out");
    let ext = p.extension().and_then(|s| s.to_str()).unwrap_or("");
    let name = if ext.is_empty() {
        format!("{stem}.{label}")
    } else {
        format!("{stem}.{label}.{ext}")
    };
    p.with_file_name(name).to_string_lossy().into_owned()
}

/// Groth16 proof over a BN254-validated system. The proving API takes the
/// default type parameter (Bn254Fr); callers must have checked
/// `F::PRIME_ID == PrimeId::Bn254`, which makes the cast safe.
fn generate_bn254_proof<F: FieldBackend>(
    cs: &constraints::r1cs::ConstraintSystem<F>,
    witness_vec: &[FieldElement<F>],
    cache_dir: &std::path::Path,
) -> std::result::Result<akron::ProveResult, String> {
    let cs_bn254 = unsafe {
        &*(cs as *const constraints::r1cs::ConstraintSystem<F>
            as *const constraints::r1cs::ConstraintSystem<memory::Bn254Fr>)
    };
    let wit_bn254 = unsafe {
        std::slice::from_raw_parts(
            witness_vec.as_ptr() as *const FieldElement<memory::Bn254Fr>,
            witness_vec.len(),
        )
    };
    proving::groth16_bn254::generate_proof(cs_bn254, wit_bn254, cache_dir)
}

#[allow(clippy::too_many_arguments)]
pub(super) fn run_r1cs_pipeline<F, H>(
    program: ir::IrProgram<F>,
    r1cs_path: &str,
    wtns_path: &str,
    walk_hints: H,
    prime_id: PrimeId,
    prove: bool,
    solidity_path: Option<&str>,
    style: &Styler,
    verbose: bool,
    no_optimize: bool,
    proven: &std::collections::HashSet<ir::SsaVar>,
    want_reusable: bool,
) -> Result<Option<ReusableProver<F>>>
where
    F: FieldBackend + PoseidonParamsProvider,
    H: FnOnce(&mut artik::ArtikMemo<F>) -> Result<HashMap<String, FieldElement<F>>>,
{
    let mut compiler = R1CSCompiler::<F>::new();
    compiler.prime_id = prime_id;
    compiler.set_proven_boolean(proven.clone());
    // The explicit `cs.verify` below validates the witness (with
    // constraint-origin diagnostics), so the costly up-front IR
    // evaluation inside the witness fill is redundant.
    compiler.set_skip_eval_validation(true);

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

    // Emit constraints, then shed everything later stages do not read.
    // The IR program is multi-GB on large circuits and is dead after
    // emission; it is kept only when its verify-failure diagnostics
    // (constraint origin -> IR instruction) can still fire, i.e. when the
    // optimizer that clears constraint origins is not about to run.
    let mut program = Some(program);
    compiler
        .compile_ir(program.as_ref().expect("program present before emission"))
        .map_err(|e| anyhow::anyhow!("R1CS compilation error: {e}"))?;
    compiler.release_emission_state();
    if prove && !no_optimize {
        program = None;
    }

    // The hint walk runs after emission, so the multi-million-entry
    // input/hint env never coexists with the materialized IR and the
    // emission working set. The Artik executions it performs are handed
    // to the fill, which re-runs the same big-integer programs.
    let mut artik_memo = artik::ArtikMemo::<F>::new();
    let input_map = walk_hints(&mut artik_memo)?;
    compiler.set_artik_memo(artik_memo);

    let (witness_vec, generator) = {
        let mut witness_vec = compiler
            .fill_witness(&input_map)
            .map_err(|e| anyhow::anyhow!("R1CS compilation error: {e}"))?;
        // The merged input/hint env is read only by the fill above.
        drop(input_map);

        // A single-shot run never replays the witness-op trace after the
        // fill; shed it (and the Artik cache) before the optimizer's
        // transient peak. Multi-input runs keep both for the
        // `WitnessGenerator` captured below.
        if !want_reusable {
            compiler.witness_ops = Default::default();
            let _ = compiler.take_artik_memo();
        }

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
                if let (Some(origin), Some(program)) =
                    (compiler.constraint_origins.get(*idx), program.as_ref())
                {
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

        // The witness-op trace stays pristine through optimize_r1cs, so the
        // generator captured here replays correctly for any further input set.
        let generator = want_reusable.then(|| WitnessGenerator::from_compiler(&compiler));
        (witness_vec, generator)
    };

    // Proof generation and file output need only the constraint system and
    // the witness; the compiler's remaining working set (witness-op trace,
    // Artik caches, substitution map, name tables) is shed here, before the
    // memory-heavy SNARK setup.
    drop(program);
    let cs = compiler.into_constraint_system();

    // The serialized artifact buffers are dropped as soon as they hit
    // disk; only their byte counts survive for reporting. Keeping them
    // alive would add two witness-scale buffers to the proving peak.
    let r1cs_data = write_r1cs(&cs, prime_id);
    fs::write(r1cs_path, &r1cs_data).with_context(|| format!("cannot write {r1cs_path}"))?;
    let r1cs_bytes = r1cs_data.len();
    drop(r1cs_data);

    {
        let witness_vec = &witness_vec;
        let wtns_data = write_wtns(witness_vec, prime_id);
        fs::write(wtns_path, &wtns_data).with_context(|| format!("cannot write {wtns_path}"))?;
        let wtns_bytes = wtns_data.len();
        drop(wtns_data);

        if verbose {
            let nc = cs.num_constraints();
            eprintln!();
            eprintln!("{}:", style.success("R1CS generated"));
            eprintln!("    Constraints:    {}", style.bold(&format_number(nc)));
            eprintln!("    Public inputs:  {}", n_public);
            eprintln!("    Private inputs: {}", n_witness);
            eprintln!(
                "    Wrote {} ({} bytes)",
                style.bold(r1cs_path),
                format_number(r1cs_bytes)
            );
            eprintln!(
                "    Wrote {} ({} bytes) {} {}",
                style.bold(wtns_path),
                format_number(wtns_bytes),
                style.dim("—"),
                style.green("verified OK")
            );
        } else {
            eprintln!(
                "wrote {} ({} constraints, {} wires, {} bytes)",
                r1cs_path,
                cs.num_constraints(),
                cs.num_variables(),
                r1cs_bytes,
            );
            eprintln!(
                "wrote {} ({} values, {} bytes) — verified OK",
                wtns_path,
                witness_vec.len(),
                wtns_bytes,
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
            let result = generate_bn254_proof(&cs, witness_vec, &cache_dir)
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
    }

    // Solidity verifier (BN254-only, same cast pattern as proof generation)
    if let Some(sol_path) = solidity_path {
        if F::PRIME_ID != PrimeId::Bn254 {
            return Err(anyhow::anyhow!("--solidity is only supported with BN254"));
        }
        let cache_dir = crate::cache_dir();
        let cs_bn254 = unsafe {
            &*(&cs as *const constraints::r1cs::ConstraintSystem<F>
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

    Ok(generator.map(|generator| ReusableProver {
        cs,
        prime_id,
        generator,
    }))
}

fn path_stem(path: &str) -> &std::path::Path {
    std::path::Path::new(path)
        .parent()
        .unwrap_or(std::path::Path::new("."))
}
