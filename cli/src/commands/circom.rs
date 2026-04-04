//! `ach circom` — compile a `.circom` file and optionally generate a proof.
//!
//! Runs the Circom frontend pipeline:
//! 1. Parse `.circom` source → Circom AST
//! 2. Constraint analysis (E100: under-constrained signals)
//! 3. Lower main template → ProveIR
//! 4. Instantiate ProveIR with input values → SSA IR
//! 5. Optimize → R1CS/Plonkish → proof
//!
//! Reuses the same backend pipeline as `ach circuit`.

use std::collections::HashMap;
use std::fs;

use anyhow::{Context, Result};

use compiler::r1cs_backend::R1CSCompiler;
use constraints::PoseidonParamsProvider;
use constraints::{write_r1cs, write_wtns};
use memory::field::PrimeId;
use memory::{FieldBackend, FieldElement};

use super::ErrorFormat;
use crate::style::{format_number, Styler};

// ---------------------------------------------------------------------------
// BN254-specific operations (same trait as circuit.rs)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// No trait-based proof dispatch needed: proof generation uses the concrete
// BN254 functions directly (BLS12-381 proof support deferred).
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Input parsing (reused from circuit.rs patterns)
// ---------------------------------------------------------------------------

fn parse_inputs<F: FieldBackend>(raw: &str) -> Result<HashMap<String, FieldElement<F>>> {
    let mut map = HashMap::new();
    for pair in raw.split(',') {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        let (name, val_str) = pair.split_once('=').context(format!(
            "invalid input pair: {pair:?} (expected name=value)"
        ))?;
        let val = parse_field_value::<F>(name, val_str)?;
        map.insert(name.to_string(), val);
    }
    Ok(map)
}

fn parse_field_value<F: FieldBackend>(name: &str, val_str: &str) -> Result<FieldElement<F>> {
    let val_str = val_str.trim();
    if val_str.starts_with("0x") || val_str.starts_with("0X") {
        FieldElement::<F>::from_hex_str(val_str)
            .context(format!("invalid hex value for `{name}`: {val_str:?}"))
    } else if let Some(digits) = val_str.strip_prefix('-') {
        let abs = FieldElement::<F>::from_decimal_str(digits)
            .context(format!("invalid decimal value for `{name}`: {val_str:?}"))?;
        Ok(abs.neg())
    } else {
        FieldElement::<F>::from_decimal_str(val_str)
            .context(format!("invalid decimal value for `{name}`: {val_str:?}"))
    }
}

fn parse_inputs_toml<F: FieldBackend>(path: &str) -> Result<HashMap<String, FieldElement<F>>> {
    let content =
        fs::read_to_string(path).with_context(|| format!("cannot read input file: {path}"))?;
    let table: toml::Table = content
        .parse()
        .with_context(|| format!("invalid TOML in {path}"))?;

    let mut map = HashMap::new();
    for (key, value) in &table {
        match value {
            toml::Value::String(s) => {
                map.insert(key.clone(), parse_field_value::<F>(key, s)?);
            }
            toml::Value::Integer(n) => {
                let fe = if *n < 0 {
                    FieldElement::<F>::from_decimal_str(&n.unsigned_abs().to_string())
                        .context(format!("invalid integer for `{key}`: {n}"))?
                        .neg()
                } else {
                    FieldElement::<F>::from_u64(*n as u64)
                };
                map.insert(key.clone(), fe);
            }
            toml::Value::Array(arr) => {
                for (i, elem) in arr.iter().enumerate() {
                    let elem_name = format!("{key}_{i}");
                    match elem {
                        toml::Value::String(s) => {
                            map.insert(elem_name.clone(), parse_field_value::<F>(&elem_name, s)?);
                        }
                        toml::Value::Integer(n) => {
                            let fe = if *n < 0 {
                                FieldElement::<F>::from_decimal_str(&n.unsigned_abs().to_string())
                                    .context(format!("invalid integer for `{elem_name}`: {n}"))?
                                    .neg()
                            } else {
                                FieldElement::<F>::from_u64(*n as u64)
                            };
                            map.insert(elem_name, fe);
                        }
                        _ => {
                            return Err(anyhow::anyhow!(
                                "array element {key}[{i}] must be a string or integer"
                            ));
                        }
                    }
                }
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "input `{key}` must be a string, integer, or array"
                ));
            }
        }
    }
    Ok(map)
}

// ---------------------------------------------------------------------------
// Command entry point
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub fn circom_command(
    path: &str,
    r1cs_path: &str,
    wtns_path: &str,
    inputs: Option<&str>,
    input_file: Option<&str>,
    no_optimize: bool,
    backend: &str,
    prime_id: PrimeId,
    prove: bool,
    solidity_path: Option<&str>,
    circuit_stats: bool,
    lib_dirs: &[String],
    error_format: ErrorFormat,
) -> Result<()> {
    if !matches!(backend, "r1cs" | "plonkish") {
        return Err(anyhow::anyhow!(
            "unknown backend `{backend}` (use \"r1cs\" or \"plonkish\")"
        ));
    }

    if inputs.is_some() && input_file.is_some() {
        return Err(anyhow::anyhow!(
            "--inputs and --input-file are mutually exclusive"
        ));
    }

    match prime_id {
        PrimeId::Bn254 => circom_command_inner::<memory::Bn254Fr>(
            path,
            r1cs_path,
            wtns_path,
            inputs,
            input_file,
            no_optimize,
            backend,
            prime_id,
            prove,
            solidity_path,
            circuit_stats,
            lib_dirs,
            error_format,
        ),
        PrimeId::Bls12_381 => circom_command_inner::<memory::Bls12_381Fr>(
            path,
            r1cs_path,
            wtns_path,
            inputs,
            input_file,
            no_optimize,
            backend,
            prime_id,
            prove,
            solidity_path,
            circuit_stats,
            lib_dirs,
            error_format,
        ),
        other => Err(anyhow::anyhow!(
            "prime `{}` is not supported for Circom compilation (use bn254 or bls12-381)",
            other.name()
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn circom_command_inner<F: FieldBackend + PoseidonParamsProvider>(
    path: &str,
    r1cs_path: &str,
    wtns_path: &str,
    inputs: Option<&str>,
    input_file: Option<&str>,
    no_optimize: bool,
    backend: &str,
    prime_id: PrimeId,
    prove: bool,
    solidity_path: Option<&str>,
    circuit_stats: bool,
    lib_dirs: &[String],
    error_format: ErrorFormat,
) -> Result<()> {
    let mut resolved_inputs: Option<HashMap<String, FieldElement<F>>> = if let Some(raw) = inputs {
        Some(parse_inputs::<F>(raw)?)
    } else if let Some(toml_path) = input_file {
        Some(parse_inputs_toml::<F>(toml_path)?)
    } else {
        None
    };

    let style = Styler::from_env(&error_format);
    let verbose = style.is_verbose(&error_format);

    let file_path = std::path::Path::new(path);
    let file_name = file_path
        .file_name()
        .unwrap_or(std::ffi::OsStr::new(path))
        .to_string_lossy();

    if verbose {
        eprintln!(
            "{} {} {}",
            style.success("Compiling"),
            style.bold(&format!("{file_name}")),
            style.dim("(Circom frontend)")
        );
    }

    // 1. Compile .circom to ProveIR via Circom frontend (with include resolution)
    let lib_paths: Vec<std::path::PathBuf> =
        lib_dirs.iter().map(std::path::PathBuf::from).collect();
    let compile_result =
        circom::compile_file(file_path, &lib_paths).map_err(|e| anyhow::anyhow!("{e}"))?;
    let prove_ir = compile_result.prove_ir;
    let capture_values = compile_result.capture_values;

    if verbose {
        let n_pub = prove_ir.public_inputs.len();
        let n_wit = prove_ir.witness_inputs.len();
        let n_body = prove_ir.body.len();
        eprintln!(
            "    {}: {} public, {} witness, {} nodes",
            style.cyan("ProveIR"),
            n_pub,
            n_wit,
            n_body
        );
    }

    // 2. Compute witness hints (off-circuit evaluation of `<--` expressions)
    // The hints compute signal values from user inputs using off-circuit arithmetic.
    let user_inputs: HashMap<String, FieldElement<F>> = resolved_inputs.clone().unwrap_or_default();
    let witness_values = circom::witness::compute_witness_hints_with_captures::<F>(
        &prove_ir,
        &user_inputs,
        &capture_values,
    )
    .map_err(|e| anyhow::anyhow!("witness computation failed: {e}"))?;

    // Merge user inputs + computed witness hints for R1CS
    let mut all_inputs = resolved_inputs.clone().unwrap_or_default();
    all_inputs.extend(witness_values);
    resolved_inputs = Some(all_inputs);

    // Instantiate ProveIR → SSA IR with captures from main component args
    let fe_captures: HashMap<String, FieldElement<F>> = capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<F>::from_u64(*v)))
        .collect();
    let mut program = prove_ir
        .instantiate(&fe_captures)
        .map_err(|e| anyhow::anyhow!("ProveIR instantiation error: {e}"))?;

    if verbose {
        eprintln!(
            "    {}: {} instructions",
            style.cyan("IR"),
            program.instructions.len()
        );
    }

    // 3. Optimize
    if !no_optimize {
        let stats = ir::passes::optimize(&mut program);
        let eliminated = stats.const_fold_converted + stats.dce_eliminated;
        if verbose && eliminated > 0 {
            eprintln!("    {}: {} eliminated", style.cyan("Optimized"), eliminated,);
        }
    }

    // 4. Analysis
    let warnings = ir::passes::analyze(&program);
    for w in &warnings {
        eprintln!("warning: {w}");
    }

    let proven = ir::passes::bool_prop::compute_proven_boolean(&program);

    // Circuit stats
    if circuit_stats {
        let name = std::path::Path::new(path)
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned());
        let stats = ir::stats::CircuitStats::from_program(&program, &proven, name.as_deref());
        eprintln!("{stats}");
    }

    // 5. Backend compilation
    match backend {
        "r1cs" => run_r1cs_pipeline(
            &program,
            r1cs_path,
            wtns_path,
            resolved_inputs.as_ref(),
            prime_id,
            prove,
            solidity_path,
            &style,
            verbose,
            &proven,
        ),
        "plonkish" => {
            eprintln!("plonkish backend for Circom: not yet implemented");
            Ok(())
        }
        _ => unreachable!(),
    }
}

#[allow(clippy::too_many_arguments)]
fn run_r1cs_pipeline<F: FieldBackend + PoseidonParamsProvider>(
    program: &ir::IrProgram<F>,
    r1cs_path: &str,
    wtns_path: &str,
    inputs: Option<&HashMap<String, FieldElement<F>>>,
    prime_id: PrimeId,
    prove: bool,
    solidity_path: Option<&str>,
    style: &Styler,
    verbose: bool,
    proven: &std::collections::HashSet<ir::SsaVar>,
) -> Result<()> {
    let mut compiler = R1CSCompiler::<F>::new();
    compiler.prime_id = prime_id;
    compiler.set_proven_boolean(proven.clone());

    if let Some(input_map) = inputs {
        let witness_vec = compiler
            .compile_ir_with_witness(program, input_map)
            .map_err(|e| anyhow::anyhow!("R1CS compilation error: {e}"))?;

        if let Err(e) = compiler.cs.verify(&witness_vec) {
            return Err(anyhow::anyhow!("witness verification failed: {e}"));
        }

        let r1cs_data = write_r1cs(&compiler.cs, prime_id);
        fs::write(r1cs_path, &r1cs_data).with_context(|| format!("cannot write {r1cs_path}"))?;

        let wtns_data = write_wtns(&witness_vec, prime_id);
        fs::write(wtns_path, &wtns_data).with_context(|| format!("cannot write {wtns_path}"))?;

        if verbose {
            let nc = compiler.cs.num_constraints();
            eprintln!();
            eprintln!("{}:", style.success("R1CS generated"));
            eprintln!("    Constraints: {}", style.bold(&format_number(nc)));
            eprintln!(
                "    Wrote {} ({} bytes)",
                style.bold(r1cs_path),
                format_number(r1cs_data.len())
            );
            eprintln!(
                "    Wrote {} ({} bytes) — {}",
                style.bold(wtns_path),
                format_number(wtns_data.len()),
                style.green("verified OK")
            );
        } else {
            eprintln!(
                "wrote {} ({} constraints), {} — verified OK",
                r1cs_path,
                compiler.cs.num_constraints(),
                wtns_path,
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

            if let vm::ProveResult::Proof {
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

        let r1cs_data = write_r1cs(&compiler.cs, prime_id);
        fs::write(r1cs_path, &r1cs_data).with_context(|| format!("cannot write {r1cs_path}"))?;

        if verbose {
            eprintln!();
            eprintln!("{}:", style.success("R1CS generated"));
            eprintln!(
                "    Constraints: {}",
                style.bold(&format_number(compiler.cs.num_constraints()))
            );
            eprintln!(
                "    Wrote {} ({} bytes)",
                style.bold(r1cs_path),
                format_number(r1cs_data.len())
            );
        } else {
            eprintln!(
                "wrote {} ({} constraints)",
                r1cs_path,
                compiler.cs.num_constraints(),
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
