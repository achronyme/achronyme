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

use compiler::plonkish_backend::PlonkishCompiler;
use compiler::r1cs_backend::R1CSCompiler;
use constraints::PoseidonParamsProvider;
use constraints::{write_r1cs, write_wtns};
use memory::field::PrimeId;
use memory::{FieldBackend, FieldElement};

use super::ErrorFormat;
use crate::style::{format_number, Styler};

// ---------------------------------------------------------------------------
// Input parsing
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
    plonkish_json_path: Option<&str>,
    dump_ir: bool,
    circuit_stats: bool,
    lib_dirs: &[String],
    error_format: ErrorFormat,
) -> Result<()> {
    // Validate flag combinations early
    if solidity_path.is_some() && backend != "r1cs" {
        return Err(anyhow::anyhow!(
            "--solidity is only supported with the r1cs backend"
        ));
    }

    if solidity_path.is_some() && prime_id != PrimeId::Bn254 {
        return Err(anyhow::anyhow!(
            "--solidity is only supported with BN254 (EVM precompiles require alt_bn128)"
        ));
    }

    if plonkish_json_path.is_some() && backend != "plonkish" {
        return Err(anyhow::anyhow!(
            "--plonkish-json is only supported with the plonkish backend"
        ));
    }

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
            plonkish_json_path,
            dump_ir,
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
            plonkish_json_path,
            dump_ir,
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
    plonkish_json_path: Option<&str>,
    dump_ir: bool,
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
    // Read source for diagnostic rendering (best-effort; needed for both errors and warnings)
    let source = std::fs::read_to_string(file_path).unwrap_or_default();
    let compile_result = circom::compile_file(file_path, &lib_paths).map_err(|e| {
        let diags = e.to_diagnostics();
        for diag in &diags {
            super::emit_diagnostic(diag, &source, error_format);
        }
        anyhow::anyhow!("circom compilation failed with {} error(s)", diags.len())
    })?;

    // Render warnings with the same diagnostic renderer used for the rest of Achronyme
    for warning in &compile_result.warnings {
        super::emit_diagnostic(warning, &source, error_format);
    }

    let prove_ir = compile_result.prove_ir;
    let output_names = compile_result.output_names;
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
        .instantiate_with_outputs(&fe_captures, &output_names)
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
        let eliminated = stats.const_fold_converted
            + stats.dce_eliminated
            + stats.tautological_asserts_eliminated;
        if verbose && eliminated > 0 {
            let mut parts = Vec::new();
            if stats.const_fold_converted > 0 {
                parts.push("constant folding");
            }
            if stats.dce_eliminated > 0 {
                parts.push("DCE");
            }
            let taut_msg;
            if stats.tautological_asserts_eliminated > 0 {
                taut_msg = format!(
                    "{} tautological asserts",
                    stats.tautological_asserts_eliminated
                );
                parts.push(&taut_msg);
            }
            eprintln!(
                "    {}: {} eliminated ({})",
                style.cyan("Optimized"),
                eliminated,
                parts.join(" + ")
            );
        }

        // W003: warn about unbounded comparisons (~761 constraints each)
        if !stats.bound_inference.unbounded.is_empty() {
            for &(_, lhs, rhs) in &stats.bound_inference.unbounded {
                let lhs_name = program.get_name(lhs).unwrap_or("%?");
                let rhs_name = program.get_name(rhs).unwrap_or("%?");
                eprintln!(
                    "{}: unbounded comparison between `{}` and `{}` uses ~761 constraints",
                    style.warning("warning[W003]"),
                    lhs_name,
                    rhs_name,
                );
                eprintln!(
                    "  {} add range_check({}, 64) and range_check({}, 64) to reduce to ~67",
                    style.cyan("help:"),
                    lhs_name,
                    rhs_name,
                );
            }
        }

        // Show bit-pattern detection info
        if verbose && stats.bit_pattern_bounds > 0 {
            eprintln!(
                "    {}: {} bound(s) inferred from bit patterns ({} boolean vars detected)",
                style.cyan("BitPattern"),
                stats.bit_pattern_bounds,
                stats.bit_pattern_booleans,
            );
        }

        // Show bound inference optimization info
        if verbose && stats.bound_inference.rewritten > 0 {
            eprintln!(
                "    {}: {} comparison(s) optimized via IsLtBounded",
                style.cyan("Bounds"),
                stats.bound_inference.rewritten,
            );
        }
    }

    // 4. If --dump-ir, print the IR and exit
    if dump_ir {
        println!("== Circuit IR for {} ==\n", path);
        print!("{program}");
        let n = program.instructions.len();
        let n_inputs = program
            .instructions
            .iter()
            .filter(|i| matches!(i, ir::Instruction::Input { .. }))
            .count();
        let n_constraints = program
            .instructions
            .iter()
            .filter(|i| i.has_side_effects() && !matches!(i, ir::Instruction::Input { .. }))
            .count();
        eprintln!("{n} instructions, {n_inputs} inputs, {n_constraints} constraints");
        return Ok(());
    }

    // 5. Analyze for under-constrained inputs
    let warnings = ir::passes::analyze(&program);
    for w in &warnings {
        let span = w
            .span()
            .cloned()
            .unwrap_or_else(|| compiler::diagnostic::SpanRange::point(0, 0, 0));
        let diag = compiler::Diagnostic::warning(w.to_string(), span);
        super::emit_diagnostic(&diag, &source, error_format);
    }

    // Bool propagation
    let proven = ir::passes::bool_prop::compute_proven_boolean(&program);
    if verbose && !proven.is_empty() {
        eprintln!(
            "    {}: {} proven",
            style.cyan("Boolean propagation"),
            proven.len()
        );
    }

    // Circuit stats profiler
    if circuit_stats {
        let name = std::path::Path::new(path)
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned());
        let stats = ir::stats::CircuitStats::from_program(&program, &proven, name.as_deref());
        eprintln!("{stats}");
    }

    // 6. Backend compilation
    let source_dir = file_path
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .to_path_buf();

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
            no_optimize,
            &proven,
        ),
        "plonkish" => run_plonkish_pipeline(
            &program,
            resolved_inputs.as_ref(),
            prove,
            plonkish_json_path,
            &source_dir,
            &style,
            verbose,
            &proven,
        ),
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
    no_optimize: bool,
    proven: &std::collections::HashSet<ir::SsaVar>,
) -> Result<()> {
    let mut compiler = R1CSCompiler::<F>::new();
    compiler.prime_id = prime_id;
    compiler.set_proven_boolean(proven.clone());

    // Count public/witness inputs from IR
    let n_public = program
        .instructions
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
        .instructions
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
                    let inst = &program.instructions[origin.ir_index];
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

#[allow(clippy::too_many_arguments)]
fn run_plonkish_pipeline<F: FieldBackend + PoseidonParamsProvider>(
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
            if F::PRIME_ID != PrimeId::Bn254 {
                return Err(anyhow::anyhow!(
                    "--prove with plonkish backend is only supported with BN254"
                ));
            }
            let cache_dir = crate::cache_dir();
            // Safe cast: validated F == Bn254Fr above
            let compiler_bn254 = unsafe {
                std::mem::transmute::<PlonkishCompiler<F>, PlonkishCompiler<memory::Bn254Fr>>(
                    compiler,
                )
            };
            let result = proving::halo2_proof::generate_plonkish_proof(compiler_bn254, &cache_dir)
                .map_err(|e| anyhow::anyhow!("Plonkish proof generation error: {e}"))?;

            match result {
                vm::ProveResult::Proof {
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
                vm::ProveResult::VerifiedOnly => {
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
    }

    Ok(())
}

fn path_stem(path: &str) -> &std::path::Path {
    std::path::Path::new(path)
        .parent()
        .unwrap_or(std::path::Path::new("."))
}
