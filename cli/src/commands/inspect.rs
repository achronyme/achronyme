use std::collections::HashMap;
use std::fs;

use anyhow::{Context, Result};

use ir::inspector::build_inspector_graph;
use ir::SsaVar;
use ir_forge::ProveIrCompiler;
use memory::FieldElement;
use zkc::r1cs_backend::R1CSCompiler;

use super::ErrorFormat;

/// Embedded inspector frontend — served as the index page.
const INSPECTOR_HTML: &str = include_str!("../inspector.html");

mod prove_block;

#[allow(clippy::too_many_arguments)]
pub fn inspect_command(
    path: &str,
    inputs: Option<&str>,
    input_file: Option<&str>,
    prove_block: Option<&str>,
    port: u16,
    bind: &str,
    no_open: bool,
    error_format: ErrorFormat,
) -> Result<()> {
    if inputs.is_some() && input_file.is_some() {
        return Err(anyhow::anyhow!(
            "--inputs and --input-file are mutually exclusive"
        ));
    }

    let source =
        fs::read_to_string(path).with_context(|| format!("cannot read source file: {path}"))?;

    let graph_json = if let Some(target_name) = prove_block {
        // ── VM path: run program, intercept the named prove block ──
        prove_block::inspect_prove_block(path, &source, target_name, error_format)?
    } else {
        // ── Standalone circuit path ──
        let resolved_inputs = resolve_inputs(inputs, input_file)?;
        inspect_circuit(&source, path, resolved_inputs.as_ref(), error_format)?
    };

    serve_inspector(&graph_json, port, bind, no_open)
}

// ── Standalone circuit inspection ──

fn inspect_circuit(
    source: &str,
    path: &str,
    inputs: Option<&HashMap<String, FieldElement>>,
    error_format: ErrorFormat,
) -> Result<String> {
    let source_path = std::path::Path::new(path);

    let render_error = |e: ir_forge::ProveIrError| -> anyhow::Error {
        let diag = e.to_diagnostic();
        let rendered = super::render_diagnostic(&diag, source, error_format);
        anyhow::anyhow!("{rendered}")
    };

    let render_lysis_error = |e: ir_forge::LysisInstantiateError| -> anyhow::Error {
        match e {
            ir_forge::LysisInstantiateError::Instantiate(inner) => render_error(inner),
            other => anyhow::anyhow!("{other}"),
        }
    };

    let prove_ir = ProveIrCompiler::<memory::Bn254Fr>::compile_circuit(source, Some(source_path))
        .map_err(render_error)?;
    let prove_ir_text = format!("{prove_ir}");
    let circuit_name = prove_ir.name.clone();

    let mut program = prove_ir
        .instantiate_lysis(&std::collections::HashMap::new())
        .map_err(render_lysis_error)?;

    ir::passes::optimize(&mut program);

    let (witness_values, eval_failures): (HashMap<SsaVar, FieldElement>, Vec<usize>) =
        if let Some(input_map) = inputs {
            ir::eval::evaluate_lenient(&program, input_map)
        } else {
            (HashMap::new(), Vec::new())
        };

    let proven = ir::passes::bool_prop::compute_proven_boolean(&program);
    let mut compiler = R1CSCompiler::new();
    compiler.set_proven_boolean(proven);

    let mut failed_nodes: HashMap<usize, Option<String>> = HashMap::new();
    let mut constraint_counts: HashMap<usize, usize> = HashMap::new();

    for idx in &eval_failures {
        let msg = extract_assert_message(&program.instructions()[*idx]);
        failed_nodes.insert(*idx, msg);
    }

    if let Some(input_map) = inputs {
        match compiler.compile_ir_with_witness(&program, input_map) {
            Ok(witness_vec) => {
                for origin in &compiler.constraint_origins {
                    *constraint_counts.entry(origin.ir_index).or_insert(0) += 1;
                }
                if let Err(constraints::r1cs::ConstraintError::ConstraintUnsatisfied(idx)) =
                    compiler.cs.verify(&witness_vec)
                {
                    if let Some(origin) = compiler.constraint_origins.get(idx) {
                        let msg = extract_assert_message(&program.instructions()[origin.ir_index]);
                        failed_nodes.insert(origin.ir_index, msg);
                    }
                }
            }
            Err(e) => eprintln!("warning: R1CS compilation failed: {e}"),
        }
    } else if compiler.compile_ir(&program).is_ok() {
        for origin in &compiler.constraint_origins {
            *constraint_counts.entry(origin.ir_index).or_insert(0) += 1;
        }
    }

    let graph = build_inspector_graph(
        &program,
        &witness_values,
        &failed_nodes,
        &constraint_counts,
        Some(source.to_string()),
        Some(prove_ir_text),
        circuit_name.as_deref(),
    );
    serde_json::to_string(&graph).context("failed to serialize inspector graph")
}

// ── HTTP server ──

fn serve_inspector(graph_json: &str, port: u16, bind: &str, no_open: bool) -> Result<()> {
    let addr = format!("{bind}:{port}");
    let server =
        tiny_http::Server::http(&addr).map_err(|e| anyhow::anyhow!("cannot start server: {e}"))?;

    // Warn if the user opted into a non-loopback bind: the inspector serves
    // witness values, source, and the full DAG with no authentication.
    let is_loopback = bind == "127.0.0.1" || bind == "localhost" || bind == "::1";
    if !is_loopback {
        eprintln!(
            "warning: inspector bound to {bind} (non-loopback). \
             It serves witness values and source without auth — \
             anyone who can reach this host on port {port} can read them."
        );
    }

    let url = format!("http://{bind}:{port}");
    eprintln!("Inspector running at {url}");
    eprintln!("Press Ctrl+C to stop.");

    if !no_open {
        let _ = open::that(&url);
    }

    let json = graph_json.to_string();
    loop {
        let request = match server.recv() {
            Ok(r) => r,
            Err(_) => break,
        };

        let (content_type, body) = match request.url() {
            "/" => ("text/html; charset=utf-8", INSPECTOR_HTML.to_string()),
            "/api/graph" => ("application/json", json.clone()),
            _ => {
                let resp = tiny_http::Response::from_string("404")
                    .with_status_code(tiny_http::StatusCode(404));
                let _ = request.respond(resp);
                continue;
            }
        };

        let resp = tiny_http::Response::from_string(&body)
            .with_header(
                tiny_http::Header::from_bytes("Content-Type", content_type).expect("valid header"),
            )
            .with_header(
                // `no-store` (vs `no-cache`) forbids any intermediate proxy
                // from stashing the response at all. The inspector serves
                // live witness values and source — a cached copy in a
                // shared proxy could leak one user's circuit to another.
                tiny_http::Header::from_bytes("Cache-Control", "no-store").expect("valid header"),
            );
        let _ = request.respond(resp);
    }

    Ok(())
}

// ── Helpers ──

fn extract_assert_message(inst: &ir::Instruction) -> Option<String> {
    match inst {
        ir::Instruction::AssertEq {
            message: Some(m), ..
        }
        | ir::Instruction::Assert {
            message: Some(m), ..
        } => Some(m.clone()),
        _ => None,
    }
}

fn resolve_inputs(
    inputs: Option<&str>,
    input_file: Option<&str>,
) -> Result<Option<HashMap<String, FieldElement>>> {
    if let Some(raw) = inputs {
        Ok(Some(parse_inputs(raw)?))
    } else if let Some(toml_path) = input_file {
        Ok(Some(parse_inputs_toml(toml_path)?))
    } else {
        Ok(None)
    }
}

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
        map.insert(name.to_string(), parse_field_value(name, val_str)?);
    }
    Ok(map)
}

fn parse_field_value(name: &str, val_str: &str) -> Result<FieldElement> {
    let val_str = val_str.trim();
    if val_str.starts_with("0x") || val_str.starts_with("0X") {
        FieldElement::from_hex_str(val_str)
            .context(format!("invalid hex value for `{name}`: {val_str:?}"))
    } else if let Some(digits) = val_str.strip_prefix('-') {
        Ok(FieldElement::from_decimal_str(digits)
            .context(format!("invalid decimal value for `{name}`: {val_str:?}"))?
            .neg())
    } else {
        FieldElement::from_decimal_str(val_str)
            .context(format!("invalid decimal value for `{name}`: {val_str:?}"))
    }
}

fn parse_inputs_toml(path: &str) -> Result<HashMap<String, FieldElement>> {
    let content =
        fs::read_to_string(path).with_context(|| format!("cannot read input file: {path}"))?;
    let table: toml::Table = content
        .parse()
        .with_context(|| format!("invalid TOML in {path}"))?;
    let mut map = HashMap::new();
    for (key, value) in &table {
        match value {
            toml::Value::String(s) => {
                map.insert(key.clone(), parse_field_value(key, s)?);
            }
            toml::Value::Integer(n) => {
                let fe = if *n < 0 {
                    FieldElement::from_decimal_str(&n.unsigned_abs().to_string())
                        .context(format!("invalid integer for `{key}`: {n}"))?
                        .neg()
                } else {
                    FieldElement::from_u64(*n as u64)
                };
                map.insert(key.clone(), fe);
            }
            toml::Value::Array(arr) => {
                for (i, elem) in arr.iter().enumerate() {
                    let elem_name = format!("{key}_{i}");
                    match elem {
                        toml::Value::String(s) => {
                            map.insert(elem_name.clone(), parse_field_value(&elem_name, s)?);
                        }
                        toml::Value::Integer(n) => {
                            let fe = if *n < 0 {
                                FieldElement::from_decimal_str(&n.unsigned_abs().to_string())
                                    .context(format!("invalid integer for `{elem_name}`: {n}"))?
                                    .neg()
                            } else {
                                FieldElement::from_u64(*n as u64)
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
