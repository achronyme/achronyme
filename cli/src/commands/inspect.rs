use std::cell::RefCell;
use std::collections::HashMap;
use std::fs;
use std::rc::Rc;

use anyhow::{Context, Result};

use akron::{ProveError, ProveHandler, ProveResult, VerifyHandler};
use compiler::r1cs_backend::R1CSCompiler;
use ir::inspector::{build_inspector_graph, InspectorGraph};
use ir::prove_ir::ProveIrCompiler;
use ir::SsaVar;
use memory::FieldElement;

use super::ErrorFormat;

/// Embedded inspector frontend — served as the index page.
const INSPECTOR_HTML: &str = include_str!("../inspector.html");

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
        inspect_prove_block(path, &source, target_name, error_format)?
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

    let render_error = |e: ir::ProveIrError| -> anyhow::Error {
        let diag = e.to_diagnostic();
        let rendered = super::render_diagnostic(&diag, source, error_format);
        anyhow::anyhow!("{rendered}")
    };

    let prove_ir = ProveIrCompiler::<memory::Bn254Fr>::compile_circuit(source, Some(source_path))
        .map_err(render_error)?;
    let prove_ir_text = format!("{prove_ir}");
    let circuit_name = prove_ir.name.clone();

    let mut program = prove_ir
        .instantiate(&std::collections::HashMap::new())
        .map_err(render_error)?;

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

// ── VM prove block inspection ──

fn inspect_prove_block(
    path: &str,
    source: &str,
    target_name: &str,
    error_format: ErrorFormat,
) -> Result<String> {
    let source_path = std::path::Path::new(path);

    // Compile program
    let mut compiler = super::new_compiler();
    compiler.base_path = Some(
        source_path
            .parent()
            .unwrap_or(std::path::Path::new("."))
            .to_path_buf(),
    );
    if let Ok(canonical) = source_path.canonicalize() {
        compiler.compiling_modules.insert(canonical);
    }
    let bytecode = compiler.compile(source).map_err(|e| {
        let rendered = super::render_compile_error(&e, source, error_format);
        anyhow::anyhow!("{rendered}")
    })?;
    super::print_warnings(&mut compiler, source, error_format);

    // Set up VM with inspector handler
    let handler = Rc::new(InspectorProveHandler::new(
        target_name.to_string(),
        source.to_string(),
    ));
    let mut vm = akron::VM::new();
    super::register_std_modules(&mut vm)?;
    vm.prove_handler = Some(Box::new(SharedInspectorHandler(Rc::clone(&handler))));
    vm.verify_handler = Some(Box::new(SharedInspectorHandler(Rc::clone(&handler))));

    // Transfer compiler data to VM (mirrors run.rs setup)
    vm.import_strings(compiler.interner.strings);
    vm.heap.import_bytes(compiler.bytes_interner.blobs);
    let field_map = vm.heap.import_fields(compiler.field_interner.fields)?;
    let bigint_map = vm.heap.import_bigints(compiler.bigint_interner.bigints)?;
    for proto in &mut compiler.prototypes {
        remap_field_handles(&mut proto.constants, &field_map);
        remap_bigint_handles(&mut proto.constants, &bigint_map);
    }

    let main_func = compiler
        .compilers
        .last()
        .ok_or_else(|| anyhow::anyhow!("compiler has no main function"))?;

    for proto in &compiler.prototypes {
        let handle = vm.heap.alloc_function(proto.clone())?;
        vm.prototypes.push(handle);
    }

    let mut main_constants = main_func.constants.clone();
    remap_field_handles(&mut main_constants, &field_map);
    remap_bigint_handles(&mut main_constants, &bigint_map);

    let func = memory::Function {
        name: "main".to_string(),
        arity: 0,
        chunk: bytecode,
        constants: main_constants,
        max_slots: main_func.max_slots,
        upvalue_info: vec![],
        line_info: main_func.line_info.clone(),
    };
    let func_idx = vm.heap.alloc_function(func)?;
    let closure_idx = vm.heap.alloc_closure(memory::Closure {
        function: func_idx,
        upvalues: vec![],
    })?;

    vm.frames.push(akron::CallFrame {
        closure: closure_idx,
        ip: 0,
        base: 0,
        dest_reg: 0,
    });

    // Run program — inspector handler will intercept the target prove block
    let _ = vm.interpret(); // errors from non-target prove blocks are ok

    // Extract graph
    let graph = handler.take_graph().ok_or_else(|| {
        anyhow::anyhow!(
            "prove block `{target_name}` was not found during execution.\n\
             Available prove blocks execute in order — ensure the program reaches it."
        )
    })?;

    serde_json::to_string(&graph).context("failed to serialize inspector graph")
}

// ── InspectorProveHandler: intercepts a named prove block ──

struct InspectorProveHandler {
    target_name: String,
    source_code: String,
    captured_graph: RefCell<Option<InspectorGraph>>,
}

impl InspectorProveHandler {
    fn new(target_name: String, source_code: String) -> Self {
        Self {
            target_name,
            source_code,
            captured_graph: RefCell::new(None),
        }
    }

    fn take_graph(&self) -> Option<InspectorGraph> {
        self.captured_graph.borrow_mut().take()
    }
}

impl ProveHandler for InspectorProveHandler {
    fn execute_prove_ir(
        &self,
        prove_ir_bytes: &[u8],
        scope_values: &HashMap<String, FieldElement>,
    ) -> Result<ProveResult, ProveError> {
        let (prove_ir, _prime_id) = ir::prove_ir::ProveIR::from_bytes(prove_ir_bytes)
            .map_err(|e| ProveError::IrLowering(format!("ProveIR deserialization: {e}")))?;

        let name = prove_ir.name.as_deref().unwrap_or("");

        // If this isn't the target, skip (return nil)
        if name != self.target_name {
            return Ok(ProveResult::VerifiedOnly);
        }

        // ── This is the target prove block — build inspector graph ──
        let prove_ir_text = format!("{prove_ir}");
        let circuit_name = prove_ir.name.clone();

        let mut program = prove_ir
            .instantiate(scope_values)
            .map_err(|e| ProveError::IrLowering(format!("{e}")))?;

        ir::passes::optimize(&mut program);

        // Build input map (same logic as DefaultProveHandler)
        let mut inputs = HashMap::new();
        for input in prove_ir
            .public_inputs
            .iter()
            .chain(prove_ir.witness_inputs.iter())
        {
            match &input.array_size {
                Some(ir::prove_ir::ArraySize::Literal(n)) => {
                    for i in 0..*n {
                        let elem_name = format!("{}_{i}", input.name);
                        if let Some(fe) = scope_values.get(&elem_name) {
                            inputs.insert(elem_name, *fe);
                        }
                    }
                }
                None => {
                    if let Some(fe) = scope_values.get(&input.name) {
                        inputs.insert(input.name.clone(), *fe);
                    }
                }
                Some(ir::prove_ir::ArraySize::Capture(_)) => {}
            }
        }
        for cap in &prove_ir.captures {
            if let Some(fe) = scope_values.get(&cap.name) {
                inputs.insert(cap.name.clone(), *fe);
            }
        }

        // Evaluate leniently
        let (witness_values, eval_failures) = ir::eval::evaluate_lenient(&program, &inputs);

        // R1CS for constraint counts
        let proven = ir::passes::bool_prop::compute_proven_boolean(&program);
        let mut r1cs_compiler = RCSCompilerWrapper::new(proven);
        let (failed_nodes, constraint_counts) =
            r1cs_compiler.compile_and_check(&program, &inputs, &eval_failures);

        let graph = build_inspector_graph(
            &program,
            &witness_values,
            &failed_nodes,
            &constraint_counts,
            Some(self.source_code.clone()),
            Some(prove_ir_text),
            circuit_name.as_deref(),
        );

        *self.captured_graph.borrow_mut() = Some(graph);

        // Return VerifiedOnly so the VM continues (no proof generated)
        Ok(ProveResult::VerifiedOnly)
    }
}

impl VerifyHandler for InspectorProveHandler {
    fn verify_proof(&self, _proof: &memory::ProofObject) -> Result<bool, String> {
        Ok(true) // no-op in inspector mode
    }
}

/// Wrapper to share InspectorProveHandler.
struct SharedInspectorHandler(Rc<InspectorProveHandler>);

impl ProveHandler for SharedInspectorHandler {
    fn execute_prove_ir(
        &self,
        prove_ir_bytes: &[u8],
        scope_values: &HashMap<String, FieldElement>,
    ) -> Result<ProveResult, ProveError> {
        self.0.execute_prove_ir(prove_ir_bytes, scope_values)
    }
}

impl VerifyHandler for SharedInspectorHandler {
    fn verify_proof(&self, proof: &memory::ProofObject) -> Result<bool, String> {
        self.0.verify_proof(proof)
    }
}

// ── R1CS helper (shared logic) ──

struct RCSCompilerWrapper {
    compiler: R1CSCompiler,
}

impl RCSCompilerWrapper {
    fn new(proven: std::collections::HashSet<ir::SsaVar>) -> Self {
        let mut compiler = R1CSCompiler::new();
        compiler.set_proven_boolean(proven);
        Self { compiler }
    }

    fn compile_and_check(
        &mut self,
        program: &ir::IrProgram,
        inputs: &HashMap<String, FieldElement>,
        eval_failures: &[usize],
    ) -> (HashMap<usize, Option<String>>, HashMap<usize, usize>) {
        let mut failed_nodes: HashMap<usize, Option<String>> = HashMap::new();
        let mut constraint_counts: HashMap<usize, usize> = HashMap::new();

        for idx in eval_failures {
            let msg = extract_assert_message(&program.instructions()[*idx]);
            failed_nodes.insert(*idx, msg);
        }

        match self.compiler.compile_ir_with_witness(program, inputs) {
            Ok(witness_vec) => {
                for origin in &self.compiler.constraint_origins {
                    *constraint_counts.entry(origin.ir_index).or_insert(0) += 1;
                }
                if let Err(constraints::r1cs::ConstraintError::ConstraintUnsatisfied(idx)) =
                    self.compiler.cs.verify(&witness_vec)
                {
                    if let Some(origin) = self.compiler.constraint_origins.get(idx) {
                        let msg = extract_assert_message(&program.instructions()[origin.ir_index]);
                        failed_nodes.insert(origin.ir_index, msg);
                    }
                }
            }
            Err(_) => {
                // Fallback: just compile for constraint counts
                let mut fallback = R1CSCompiler::new();
                if fallback.compile_ir(program).is_ok() {
                    for origin in &fallback.constraint_origins {
                        *constraint_counts.entry(origin.ir_index).or_insert(0) += 1;
                    }
                }
            }
        }

        (failed_nodes, constraint_counts)
    }
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

// ── VM data transfer helpers (reused from run.rs) ──

use super::run::{remap_bigint_handles, remap_field_handles};
