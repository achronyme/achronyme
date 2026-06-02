use std::collections::HashMap;
use std::fs;

use anyhow::{Context, Result};
use constraints::PoseidonParamsProvider;
use ir_forge::ProveIrCompiler;
use memory::field::PrimeId;
use memory::{FieldBackend, FieldElement};

use super::super::ErrorFormat;
use super::bn254::Bn254Ops;
use super::inputs::{parse_inputs, parse_inputs_toml};
use super::plonkish::run_plonkish_pipeline;
use super::r1cs::run_r1cs_pipeline;
use crate::style::Styler;

#[allow(clippy::too_many_arguments)]
pub fn circuit_command(
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
    error_format: ErrorFormat,
) -> Result<()> {
    // 0. Validate flag combinations early (before expensive IR lowering)
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

    // Dispatch on prime_id: one match at the CLI boundary, generics carry
    // the concrete field type through the rest of the pipeline.
    match prime_id {
        PrimeId::Bn254 => circuit_command_inner::<memory::Bn254Fr>(
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
            error_format,
        ),
        PrimeId::Bls12_381 => circuit_command_inner::<memory::Bls12_381Fr>(
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
            error_format,
        ),
        PrimeId::Goldilocks => circuit_command_inner::<memory::GoldilocksFr>(
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
            error_format,
        ),
        other => Err(anyhow::anyhow!(
            "prime `{}` is not supported for circuit compilation",
            other.name()
        )),
    }
}

#[allow(clippy::too_many_arguments)]
fn circuit_command_inner<F: FieldBackend + PoseidonParamsProvider + Bn254Ops>(
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
    error_format: ErrorFormat,
) -> Result<()> {
    // Resolve inputs from either --inputs or --input-file into a unified map.
    let resolved_inputs: Option<HashMap<String, FieldElement<F>>> = if let Some(raw) = inputs {
        Some(parse_inputs::<F>(raw)?)
    } else if let Some(toml_path) = input_file {
        Some(parse_inputs_toml::<F>(toml_path)?)
    } else {
        None
    };

    let style = Styler::from_env(&error_format);
    let verbose = style.is_verbose(&error_format);

    let source =
        fs::read_to_string(path).with_context(|| format!("cannot read source file: {path}"))?;

    let source_dir = std::path::Path::new(path)
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .to_path_buf();

    let render_prove_ir_error = |e: ir_forge::ProveIrError| -> anyhow::Error {
        let diag = e.to_diagnostic();
        let rendered = super::super::render_diagnostic(&diag, &source, error_format);
        anyhow::anyhow!("{rendered}")
    };

    let render_lysis_instantiate_error = |e: ir_forge::LysisInstantiateError| -> anyhow::Error {
        match e {
            ir_forge::LysisInstantiateError::Instantiate(inner) => render_prove_ir_error(inner),
            other => anyhow::anyhow!("{other}"),
        }
    };

    let file_name = std::path::Path::new(path)
        .file_name()
        .unwrap_or(std::ffi::OsStr::new(path))
        .to_string_lossy();

    if verbose {
        eprintln!(
            "{} {}",
            style.success("Compiling"),
            style.bold(&format!("{file_name}..."))
        );
    }

    // 1. Compile to ProveIR and instantiate to IR SSA via Lysis.
    let source_path = std::path::Path::new(path);
    let prove_ir = ProveIrCompiler::<F>::compile_circuit(&source, Some(source_path))
        .map_err(render_prove_ir_error)?;
    let mut program = prove_ir
        .instantiate_lysis(&std::collections::HashMap::new())
        .map_err(render_lysis_instantiate_error)?;

    if verbose {
        eprintln!("    {}: {} instructions", style.cyan("IR"), program.len());
    }

    // 2. Optimize (unless --no-optimize)
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

    // 3. If --dump-ir, print the IR and exit
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

    // 4. Analyze for under-constrained inputs
    let warnings = ir::passes::analyze(&program);
    for w in &warnings {
        let span = w
            .span()
            .cloned()
            .unwrap_or_else(|| diagnostics::SpanRange::point(0, 0, 0));
        let diag = diagnostics::Diagnostic::warning(w.to_string(), span);
        super::super::emit_diagnostic(&diag, &source, error_format);
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

    match backend {
        "r1cs" => run_r1cs_pipeline(
            &program,
            r1cs_path,
            wtns_path,
            resolved_inputs.as_ref(),
            prime_id,
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
        // Unreachable: backend validated at the top of this function
        _ => unreachable!(),
    }
}
