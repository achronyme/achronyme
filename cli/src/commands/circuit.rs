use std::collections::HashMap;
use std::fs;

use anyhow::{Context, Result};

use compiler::plonkish_backend::PlonkishCompiler;
use compiler::r1cs_backend::R1CSCompiler;
use constraints::{write_r1cs, write_wtns};
use ir::prove_ir::ProveIrCompiler;
use ir::{IrLowering, ProveIrError};
use memory::FieldElement;

use super::ErrorFormat;
use crate::style::{format_number, Styler};

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
    plonkish_json_path: Option<&str>,
    dump_ir: bool,
    circuit_stats: bool,
    error_format: ErrorFormat,
) -> Result<()> {
    let _ = circuit_stats; // TODO: will be used in next commit
    // 0. Validate flag combinations early (before expensive IR lowering)
    if solidity_path.is_some() && backend != "r1cs" {
        return Err(anyhow::anyhow!(
            "--solidity is only supported with the r1cs backend"
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

    let style = Styler::from_env(&error_format);
    let verbose = style.is_verbose(&error_format);

    let source =
        fs::read_to_string(path).with_context(|| format!("cannot read source file: {path}"))?;

    let source_dir = std::path::Path::new(path)
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .to_path_buf();

    let render_ir_error = |e: ir::error::IrError| -> anyhow::Error {
        let diag = e.to_diagnostic();
        let rendered = super::render_diagnostic(&diag, &source, error_format);
        anyhow::anyhow!("{rendered}")
    };

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
    //    ProveIR pipeline handles all circuit constructs except imports.
    //    Falls back to IrLowering for circuits that use imports (until ProveIR
    //    adds import support).
    let compile_source = if public.is_empty() && witness.is_empty() {
        source.clone()
    } else {
        // CLI-declared: prepend public/witness declarations to source
        let mut header = String::new();
        for spec in public {
            header.push_str(&format!("public {spec}\n"));
        }
        for spec in witness {
            header.push_str(&format!("witness {spec}\n"));
        }
        header.push_str(&source);
        header
    };

    let mut program = match ProveIrCompiler::compile_circuit(&compile_source) {
        Ok(prove_ir) => prove_ir
            .instantiate(&std::collections::HashMap::new())
            .map_err(render_prove_ir_error)?,
        Err(ProveIrError::ImportsNotSupported { .. }) => {
            // Fallback to IrLowering for imports (not yet supported in ProveIR).
            // TODO: remove this fallback once ProveIR supports imports.
            if public.is_empty() && witness.is_empty() {
                let (_, _, prog) =
                    IrLowering::lower_self_contained_with_base(&source, source_dir.clone())
                        .map_err(render_ir_error)?;
                prog
            } else {
                let pub_refs: Vec<&str> = public.iter().map(|s| s.as_str()).collect();
                let wit_refs: Vec<&str> = witness.iter().map(|s| s.as_str()).collect();
                IrLowering::lower_circuit_with_base(
                    &source,
                    &pub_refs,
                    &wit_refs,
                    source_dir.clone(),
                )
                .map_err(render_ir_error)?
            }
        }
        Err(e) => return Err(render_prove_ir_error(e)),
    };

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

    match backend {
        "r1cs" => run_r1cs_pipeline(
            &program,
            r1cs_path,
            wtns_path,
            inputs,
            solidity_path,
            &style,
            verbose,
            &proven,
        ),
        "plonkish" => run_plonkish_pipeline(
            &program,
            inputs,
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
fn run_r1cs_pipeline(
    program: &ir::IrProgram,
    r1cs_path: &str,
    wtns_path: &str,
    inputs: Option<&str>,
    solidity_path: Option<&str>,
    style: &Styler,
    verbose: bool,
    proven: &std::collections::HashSet<ir::SsaVar>,
) -> Result<()> {
    let mut compiler = R1CSCompiler::new();
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

        let wtns_data = write_wtns(&witness_vec);
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

        let r1cs_data = write_r1cs(&compiler.cs);
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

    // Generate Solidity verifier if requested
    if let Some(sol_path) = solidity_path {
        let cache_dir = crate::cache_dir();

        let vk = crate::groth16::setup_vk_only(&compiler.cs, &cache_dir)
            .map_err(|e| anyhow::anyhow!("Groth16 setup failed: {e}"))?;

        let sol_source = crate::solidity::generate_solidity_verifier(&vk);
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
fn run_plonkish_pipeline(
    program: &ir::IrProgram,
    inputs: Option<&str>,
    prove: bool,
    plonkish_json_path: Option<&str>,
    source_dir: &std::path::Path,
    style: &Styler,
    verbose: bool,
    proven: &std::collections::HashSet<ir::SsaVar>,
) -> Result<()> {
    let mut compiler = PlonkishCompiler::new();
    compiler.set_proven_boolean(proven.clone());

    if let Some(raw_inputs) = inputs {
        let input_map = parse_inputs(raw_inputs)?;

        // Unified: compile + witness in one pass (with early IR evaluation)
        compiler
            .compile_ir_with_witness(program, &input_map)
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

            let result = crate::halo2_proof::generate_plonkish_proof(compiler, &cache_dir)
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
            return Err(anyhow::anyhow!("--prove requires --inputs"));
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
