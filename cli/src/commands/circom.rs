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

use anyhow::Result;

use constraints::PoseidonParamsProvider;
use memory::field::PrimeId;
use memory::{FieldBackend, FieldElement};

use super::ErrorFormat;
use crate::style::Styler;

mod input;
mod plonkish;
mod r1cs;

use input::{parse_inputs, parse_inputs_toml};
use plonkish::run_plonkish_pipeline;
use r1cs::{run_r1cs_pipeline, run_r1cs_repeat};

// ---------------------------------------------------------------------------
// Command entry point
// ---------------------------------------------------------------------------

#[allow(clippy::too_many_arguments)]
pub fn circom_command(
    path: &str,
    r1cs_path: &str,
    wtns_path: &str,
    inputs: Option<&str>,
    input_files: &[String],
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

    if inputs.is_some() && !input_files.is_empty() {
        return Err(anyhow::anyhow!(
            "--inputs and --input-file are mutually exclusive"
        ));
    }

    if input_files.len() > 1 {
        if backend != "r1cs" {
            return Err(anyhow::anyhow!(
                "multiple --input-file values are only supported with the r1cs backend"
            ));
        }
        if dump_ir {
            return Err(anyhow::anyhow!(
                "--dump-ir cannot be combined with multiple --input-file values"
            ));
        }
    }

    match prime_id {
        PrimeId::Bn254 => circom_command_inner::<memory::Bn254Fr>(
            path,
            r1cs_path,
            wtns_path,
            inputs,
            input_files,
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
            input_files,
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
    input_files: &[String],
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
    } else if let Some(toml_path) = input_files.first() {
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

    // 1. Compile .circom to ProveIR via Circom frontend (with include resolution).
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

    // 2. Compute witness hints (off-circuit evaluation of `<--` expressions).
    // The Artik cache is handed to the R1CS fill below, which re-runs the
    // same big-integer programs: identical (program, inputs) pairs become
    // content-addressed hits.
    let user_inputs: HashMap<String, FieldElement<F>> = resolved_inputs.clone().unwrap_or_default();
    let mut artik_memo = artik::ArtikMemo::<F>::new();
    let witness_values = circom::witness::compute_witness_hints_with_captures_memo::<F>(
        &prove_ir,
        &user_inputs,
        &capture_values,
        &mut artik_memo,
    )
    .map_err(|e| anyhow::anyhow!("witness computation failed: {e}"))?;

    // Merge user inputs + computed witness hints for R1CS
    let mut all_inputs = resolved_inputs.clone().unwrap_or_default();
    all_inputs.extend(witness_values);
    resolved_inputs = Some(all_inputs);

    // Instantiate ProveIR → SSA IR with captures from main component args (Lysis path).
    let fe_captures: HashMap<String, FieldElement<F>> = capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<F>::from_u64(*v)))
        .collect();
    let mut program = prove_ir
        .instantiate_lysis_with_outputs(&fe_captures, &output_names)
        .map_err(|e| anyhow::anyhow!("ProveIR Lysis instantiation error: {e}"))?;

    if verbose {
        eprintln!("    {}: {} instructions", style.cyan("IR"), program.len());
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
        let n = program.len();
        let n_inputs = program
            .iter()
            .filter(|i| matches!(i, ir::Instruction::Input { .. }))
            .count();
        let n_constraints = program
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
            .unwrap_or_else(|| diagnostics::SpanRange::point(0, 0, 0));
        let diag = diagnostics::Diagnostic::warning(w.to_string(), span);
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
        "r1cs" => {
            let want_reusable = input_files.len() > 1;
            let prover = run_r1cs_pipeline(
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
                want_reusable,
                artik_memo,
            )?;

            // Extra input files reuse the compiled circuit: only the
            // per-input work runs (hint walk, witness replay, verify,
            // proof) — no recompilation.
            if let Some(prover) = prover {
                for toml_path in &input_files[1..] {
                    let label = std::path::Path::new(toml_path)
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("input")
                        .to_string();
                    let user_inputs = parse_inputs_toml::<F>(toml_path)?;
                    let mut memo = artik::ArtikMemo::<F>::new();
                    let witness_values = circom::witness::compute_witness_hints_with_captures_memo(
                        &prove_ir,
                        &user_inputs,
                        &capture_values,
                        &mut memo,
                    )
                    .map_err(|e| {
                        anyhow::anyhow!("witness computation failed for `{label}`: {e}")
                    })?;
                    let mut all_inputs = user_inputs;
                    all_inputs.extend(witness_values);
                    run_r1cs_repeat(
                        &prover,
                        &all_inputs,
                        &mut memo,
                        &label,
                        r1cs_path,
                        wtns_path,
                        prove,
                        &style,
                        verbose,
                    )?;
                }
            }
            Ok(())
        }
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
