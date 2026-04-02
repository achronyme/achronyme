use std::collections::HashMap;
use std::fs;

use anyhow::{Context, Result};

use compiler::plonkish_backend::PlonkishCompiler;
use compiler::r1cs_backend::R1CSCompiler;
use constraints::PoseidonParamsProvider;
use constraints::{write_r1cs, write_wtns};
use ir::prove_ir::ProveIrCompiler;
use memory::field::PrimeId;
use memory::{FieldBackend, FieldElement};

use super::ErrorFormat;
use crate::style::{format_number, Styler};

// ---------------------------------------------------------------------------
// Trait for BN254-specific operations in generic circuit context.
//
// Solidity verifier generation and halo2 PlonK proof generation are inherently
// BN254-only (EVM precompiles, halo2 library). Flag validation in
// `circuit_command` guarantees these paths only run with BN254, but the generic
// `F` parameter doesn't carry that information. This trait bridges the gap.
// ---------------------------------------------------------------------------

trait Bn254Ops: FieldBackend + PoseidonParamsProvider + Sized {
    fn solidity_from_cs(
        _cs: &constraints::r1cs::ConstraintSystem<Self>,
        _cache_dir: &std::path::Path,
    ) -> Result<String, String> {
        Err(format!(
            "Solidity not supported for {}",
            Self::PRIME_ID.name()
        ))
    }

    fn halo2_proof(
        _compiler: PlonkishCompiler<Self>,
        _cache_dir: &std::path::Path,
    ) -> Result<vm::ProveResult, String> {
        Err(format!("halo2 not supported for {}", Self::PRIME_ID.name()))
    }
}

impl Bn254Ops for memory::Bn254Fr {
    fn solidity_from_cs(
        cs: &constraints::r1cs::ConstraintSystem<Self>,
        cache_dir: &std::path::Path,
    ) -> Result<String, String> {
        let vk = proving::groth16_bn254::setup_vk_only(cs, cache_dir)
            .map_err(|e| format!("Groth16 setup failed: {e}"))?;
        Ok(proving::solidity::generate_solidity_verifier(&vk))
    }

    fn halo2_proof(
        compiler: PlonkishCompiler<Self>,
        cache_dir: &std::path::Path,
    ) -> Result<vm::ProveResult, String> {
        proving::halo2_proof::generate_plonkish_proof(compiler, cache_dir)
    }
}

impl Bn254Ops for memory::Bls12_381Fr {}

/// Parse an `--inputs` string like `"out=42,a=6,b=0x07"` into a map.
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
        let val = if val_str.starts_with("0x") || val_str.starts_with("0X") {
            FieldElement::<F>::from_hex_str(val_str)
                .context(format!("invalid hex value for {name:?}: {val_str:?}"))?
        } else if let Some(digits) = val_str.strip_prefix('-') {
            let abs = FieldElement::<F>::from_decimal_str(digits)
                .context(format!("invalid decimal value for {name:?}: {val_str:?}"))?;
            abs.neg()
        } else {
            FieldElement::<F>::from_decimal_str(val_str)
                .context(format!("invalid decimal value for {name:?}: {val_str:?}"))?
        };
        map.insert(name.to_string(), val);
    }
    Ok(map)
}

/// Parse a string value into a FieldElement (decimal, negative decimal, or hex).
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

/// Parse a TOML input file into a flat map of name → FieldElement.
///
/// Scalars:  `name = "42"` or `name = "0xFF"`
/// Arrays:   `path = ["2", "3"]` → expands to `path_0 = 2, path_1 = 3`
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
                let fe = parse_field_value::<F>(key, s)?;
                map.insert(key.clone(), fe);
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
                            let fe = parse_field_value::<F>(&elem_name, s)?;
                            map.insert(elem_name, fe);
                        }
                        toml::Value::Integer(n) => {
                            let fe = if *n < 0 {
                                FieldElement::<F>::from_decimal_str(&n.unsigned_abs().to_string())
                                    .context(format!(
                                        "invalid integer for `{elem_name}`: {n}"
                                    ))?
                                    .neg()
                            } else {
                                FieldElement::<F>::from_u64(*n as u64)
                            };
                            map.insert(elem_name, fe);
                        }
                        _ => {
                            return Err(anyhow::anyhow!(
                                "array element {key}[{i}] must be a string or integer, got {elem}"
                            ));
                        }
                    }
                }
            }
            _ => {
                return Err(anyhow::anyhow!(
                    "input `{key}` must be a string, integer, or array of strings/integers"
                ));
            }
        }
    }
    Ok(map)
}

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

    let render_prove_ir_error = |e: ir::ProveIrError| -> anyhow::Error {
        let diag = e.to_diagnostic();
        let rendered = super::render_diagnostic(&diag, &source, error_format);
        anyhow::anyhow!("{rendered}")
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

    // 1. Compile to ProveIR and instantiate to IR SSA.
    let source_path = std::path::Path::new(path);
    let mut program = ProveIrCompiler::<F>::compile_circuit(&source, Some(source_path))
        .and_then(|prove_ir| prove_ir.instantiate(&std::collections::HashMap::new()))
        .map_err(render_prove_ir_error)?;

    if verbose {
        eprintln!(
            "    {}: {} instructions",
            style.cyan("IR"),
            program.instructions.len()
        );
    }

    // 2. Optimize (unless --no-optimize)
    if !no_optimize {
        let stats = ir::passes::optimize(&mut program);
        let eliminated = stats.const_fold_converted + stats.dce_eliminated;
        if verbose && eliminated > 0 {
            let mut parts = Vec::new();
            if stats.const_fold_converted > 0 {
                parts.push("constant folding");
            }
            if stats.dce_eliminated > 0 {
                parts.push("DCE");
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

    // 4. Analyze for under-constrained inputs
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

#[allow(clippy::too_many_arguments)]
fn run_r1cs_pipeline<F: FieldBackend + PoseidonParamsProvider + Bn254Ops>(
    program: &ir::IrProgram<F>,
    r1cs_path: &str,
    wtns_path: &str,
    inputs: Option<&HashMap<String, FieldElement<F>>>,
    prime_id: PrimeId,
    solidity_path: Option<&str>,
    style: &Styler,
    verbose: bool,
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
        // Unified: compile + witness in one pass (with early IR evaluation)
        let witness_vec = compiler
            .compile_ir_with_witness(program, input_map)
            .map_err(|e| anyhow::anyhow!("R1CS compilation error: {e}"))?;

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
                .instructions
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

        let sol_source = F::solidity_from_cs(&compiler.cs, &cache_dir)
            .map_err(|e| anyhow::anyhow!("{e}"))?;

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

#[allow(clippy::too_many_arguments)]
fn run_plonkish_pipeline<F: FieldBackend + PoseidonParamsProvider + Bn254Ops>(
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

#[cfg(test)]
mod tests {
    use super::*;

    // Type alias to constrain F = Bn254Fr in tests (avoids turbofish noise).
    type Fe = FieldElement;

    #[test]
    fn parse_inputs_positive_decimal() {
        let map: HashMap<String, Fe> = parse_inputs("x=42,y=0").unwrap();
        assert_eq!(map["x"], Fe::from_u64(42));
        assert_eq!(map["y"], Fe::ZERO);
    }

    #[test]
    fn parse_inputs_negative_decimal() {
        let map: HashMap<String, Fe> = parse_inputs("x=-1").unwrap();
        // -1 mod p = p - 1
        assert_eq!(map["x"], Fe::from_u64(1).neg());
    }

    #[test]
    fn parse_inputs_negative_large() {
        let map: HashMap<String, Fe> = parse_inputs("a=-42,b=7").unwrap();
        assert_eq!(map["a"], Fe::from_u64(42).neg());
        assert_eq!(map["b"], Fe::from_u64(7));
    }

    #[test]
    fn parse_inputs_hex() {
        let map: HashMap<String, Fe> = parse_inputs("x=0xFF").unwrap();
        assert_eq!(map["x"], Fe::from_u64(255));
    }

    #[test]
    fn parse_inputs_empty_pair_skipped() {
        let map: HashMap<String, Fe> = parse_inputs("x=1,,y=2").unwrap();
        assert_eq!(map.len(), 2);
    }

    #[test]
    fn parse_inputs_invalid_pair_errors() {
        assert!(parse_inputs::<memory::Bn254Fr>("no_equals").is_err());
    }

    // --- parse_inputs_toml tests ---

    fn write_toml(content: &str) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut f = tempfile::NamedTempFile::with_suffix(".toml").unwrap();
        f.write_all(content.as_bytes()).unwrap();
        f.flush().unwrap();
        f
    }

    #[test]
    fn toml_scalar_string() {
        let f = write_toml("x = \"42\"\ny = \"0xFF\"");
        let map: HashMap<String, Fe> = parse_inputs_toml(f.path().to_str().unwrap()).unwrap();
        assert_eq!(map["x"], Fe::from_u64(42));
        assert_eq!(map["y"], Fe::from_u64(255));
    }

    #[test]
    fn toml_scalar_integer() {
        let f = write_toml("x = 42\ny = 0");
        let map: HashMap<String, Fe> = parse_inputs_toml(f.path().to_str().unwrap()).unwrap();
        assert_eq!(map["x"], Fe::from_u64(42));
        assert_eq!(map["y"], Fe::ZERO);
    }

    #[test]
    fn toml_negative_string() {
        let f = write_toml("x = \"-1\"");
        let map: HashMap<String, Fe> = parse_inputs_toml(f.path().to_str().unwrap()).unwrap();
        assert_eq!(map["x"], Fe::from_u64(1).neg());
    }

    #[test]
    fn toml_negative_integer() {
        let f = write_toml("x = -42");
        let map: HashMap<String, Fe> = parse_inputs_toml(f.path().to_str().unwrap()).unwrap();
        assert_eq!(map["x"], Fe::from_u64(42).neg());
    }

    #[test]
    fn toml_array_expands_to_indexed() {
        let f = write_toml("path = [\"10\", \"20\", \"30\"]");
        let map: HashMap<String, Fe> = parse_inputs_toml(f.path().to_str().unwrap()).unwrap();
        assert_eq!(map.len(), 3);
        assert_eq!(map["path_0"], Fe::from_u64(10));
        assert_eq!(map["path_1"], Fe::from_u64(20));
        assert_eq!(map["path_2"], Fe::from_u64(30));
    }

    #[test]
    fn toml_array_integer_elements() {
        let f = write_toml("indices = [0, 1, 0]");
        let map: HashMap<String, Fe> = parse_inputs_toml(f.path().to_str().unwrap()).unwrap();
        assert_eq!(map.len(), 3);
        assert_eq!(map["indices_0"], Fe::ZERO);
        assert_eq!(map["indices_1"], Fe::ONE);
        assert_eq!(map["indices_2"], Fe::ZERO);
    }

    #[test]
    fn toml_mixed_scalars_and_arrays() {
        let f = write_toml("root = \"999\"\nleaf = \"1\"\npath = [\"2\", \"3\"]");
        let map: HashMap<String, Fe> = parse_inputs_toml(f.path().to_str().unwrap()).unwrap();
        assert_eq!(map.len(), 4);
        assert_eq!(map["root"], Fe::from_u64(999));
        assert_eq!(map["leaf"], Fe::ONE);
        assert_eq!(map["path_0"], Fe::from_u64(2));
        assert_eq!(map["path_1"], Fe::from_u64(3));
    }

    #[test]
    fn toml_invalid_type_rejected() {
        let f = write_toml("x = true");
        assert!(parse_inputs_toml::<memory::Bn254Fr>(f.path().to_str().unwrap()).is_err());
    }

    #[test]
    fn toml_file_not_found() {
        assert!(parse_inputs_toml::<memory::Bn254Fr>("/tmp/nonexistent_ach_inputs.toml").is_err());
    }
}
