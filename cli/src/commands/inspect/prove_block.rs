use std::cell::RefCell;
use std::collections::HashMap;
use std::rc::Rc;

use anyhow::{Context, Result};

use akron::{ProveError, ProveHandler, ProveResult, VerifyHandler};
use ir::inspector::{build_inspector_graph, InspectorGraph};
use memory::FieldElement;
use zkc::r1cs_backend::R1CSCompiler;

use super::super::run::{remap_bigint_handles, remap_field_handles};
use super::super::ErrorFormat;

// ── VM prove block inspection ──

pub(super) fn inspect_prove_block(
    path: &str,
    source: &str,
    target_name: &str,
    error_format: ErrorFormat,
) -> Result<String> {
    let source_path = std::path::Path::new(path);

    // Compile program
    let mut compiler = super::super::new_compiler();
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
        let rendered = super::super::render_compile_error(&e, source, error_format);
        anyhow::anyhow!("{rendered}")
    })?;
    super::super::print_warnings(&mut compiler, source, error_format);

    // Set up VM with inspector handler
    let handler = Rc::new(InspectorProveHandler::new(
        target_name.to_string(),
        source.to_string(),
    ));
    let mut vm = akron::VM::new();
    super::super::register_std_modules(&mut vm)?;
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
        let (prove_ir, _prime_id) = ir_forge::ProveIR::from_bytes(prove_ir_bytes)
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
            .instantiate_lysis(scope_values)
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
                Some(ir_forge::ArraySize::Literal(n)) => {
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
                Some(ir_forge::ArraySize::Capture(_)) => {}
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
            let msg = super::extract_assert_message(&program.instructions()[*idx]);
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
                        let msg =
                            super::extract_assert_message(&program.instructions()[origin.ir_index]);
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
