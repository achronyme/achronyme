// ---------------------------------------------------------------------------
// Capturing prove handler: records inputs + returns VerifiedOnly so the
// VM keeps running.
// ---------------------------------------------------------------------------

use super::examples::Example;
use super::*;

#[derive(Clone)]
pub(crate) struct Capture {
    /// Sequence number, in source-evaluation order. Stable across runs
    /// because the Akron VM is single-threaded.
    pub(crate) seq: usize,
    /// `Some(name)` when the user wrote `prove name(...)`, else `None`.
    pub(crate) name: Option<String>,
    /// Raw ProveIR bytes (deserialize via `ProveIR::from_bytes`).
    bytes: Vec<u8>,
    /// All in-scope FieldElement values at the moment of the Prove
    /// opcode. Includes captures, public/witness inputs, array
    /// elements (`{name}_{i}`).
    scope: HashMap<String, FieldElement<F>>,
}

#[derive(Default)]
struct CapturingProveHandler {
    captured: RefCell<Vec<Capture>>,
}

impl ProveHandler for CapturingProveHandler {
    fn execute_prove_ir(
        &self,
        prove_ir_bytes: &[u8],
        scope_values: &HashMap<String, FieldElement<F>>,
    ) -> Result<ProveResult, ProveError> {
        let name = ProveIR::from_bytes(prove_ir_bytes)
            .ok()
            .and_then(|(p, _)| p.name);
        let mut buf = self.captured.borrow_mut();
        let seq = buf.len();
        buf.push(Capture {
            seq,
            name,
            bytes: prove_ir_bytes.to_vec(),
            scope: scope_values.clone(),
        });
        Ok(ProveResult::VerifiedOnly)
    }
}

/// Shared wrapper so we can stash the same handler in both
/// `vm.prove_handler` and `vm.verify_handler` slots.
struct SharedCapturing(Rc<CapturingProveHandler>);

impl ProveHandler for SharedCapturing {
    fn execute_prove_ir(
        &self,
        prove_ir_bytes: &[u8],
        scope_values: &HashMap<String, FieldElement<F>>,
    ) -> Result<ProveResult, ProveError> {
        self.0.execute_prove_ir(prove_ir_bytes, scope_values)
    }
}

impl akron::VerifyHandler for SharedCapturing {
    fn verify_proof(&self, _proof: &memory::ProofObject) -> Result<bool, String> {
        Ok(true)
    }
}

// ---------------------------------------------------------------------------
// Per-row outcome
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub(crate) struct RowOutcome {
    pub(crate) file: String,
    pub(crate) block: String,
    /// `Some` when instantiate_lysis + R1CS compile succeeded.
    pub(crate) baseline: Option<FrozenBaseline>,
    pub(crate) wall_clock: Duration,
    /// Set when an unrecoverable error short-circuits the row.
    pub(crate) error: Option<String>,
}

// ---------------------------------------------------------------------------
// Compile + VM run a single .ach example.
// Returns the captured prove blocks, or an error string.
// ---------------------------------------------------------------------------

pub(crate) fn run_example_capture(
    example: &Example,
    workspace_root: &Path,
) -> Result<Vec<Capture>, String> {
    let abs_path = workspace_root.join(example.rel_path);
    let source = std::fs::read_to_string(&abs_path)
        .map_err(|e| format!("read {}: {e}", abs_path.display()))?;

    let mut compiler = new_compiler();
    compiler.prime_id = memory::field::PrimeId::Bn254;
    compiler.base_path = Some(abs_path.parent().unwrap_or(Path::new(".")).to_path_buf());
    compiler.circom_lib_dirs = example
        .circom_libs
        .iter()
        .map(|s| workspace_root.join(s))
        .collect();
    if let Ok(canonical) = abs_path.canonicalize() {
        compiler.compiling_modules.insert(canonical);
    }

    let bytecode = compiler
        .compile(&source)
        .map_err(|e| format!("compile error: {e:?}"))?;

    let mut vm = VM::new();
    register_std_modules(&mut vm).map_err(|e| format!("register_std_modules: {e:?}"))?;

    let handler = Rc::new(CapturingProveHandler::default());
    vm.prove_handler = Some(Box::new(SharedCapturing(Rc::clone(&handler))));
    vm.verify_handler = Some(Box::new(SharedCapturing(Rc::clone(&handler))));

    vm.import_strings(compiler.interner.strings);
    vm.heap.import_bytes(compiler.bytes_interner.blobs);
    vm.heap
        .import_circom_handles(std::mem::take(&mut compiler.circom_handle_interner.handles));
    vm.circom_handler = Some(Box::new(
        cli::circom_handler::DefaultCircomWitnessHandler::new(
            compiler.circom_library_registry.take_libraries(),
        ),
    ));

    let field_map = vm
        .heap
        .import_fields(compiler.field_interner.fields)
        .map_err(|e| format!("import_fields: {e:?}"))?;
    let bigint_map = vm
        .heap
        .import_bigints(compiler.bigint_interner.bigints)
        .map_err(|e| format!("import_bigints: {e:?}"))?;
    for proto in &mut compiler.prototypes {
        cli::commands::run::remap_field_handles(&mut proto.constants, &field_map);
        cli::commands::run::remap_bigint_handles(&mut proto.constants, &bigint_map);
    }

    let main_func = compiler
        .compilers
        .last()
        .ok_or_else(|| "compiler has no main function".to_string())?;

    for proto in &compiler.prototypes {
        let h = vm
            .heap
            .alloc_function(proto.clone())
            .map_err(|e| format!("alloc_function: {e:?}"))?;
        vm.prototypes.push(h);
    }

    let mut main_constants = main_func.constants.clone();
    cli::commands::run::remap_field_handles(&mut main_constants, &field_map);
    cli::commands::run::remap_bigint_handles(&mut main_constants, &bigint_map);

    let func = Function {
        name: "main".to_string(),
        arity: 0,
        chunk: bytecode,
        constants: main_constants,
        max_slots: main_func.max_slots,
        upvalue_info: vec![],
        line_info: main_func.line_info.clone(),
    };

    let func_idx = vm
        .heap
        .alloc_function(func)
        .map_err(|e| format!("alloc main: {e:?}"))?;
    let closure_idx = vm
        .heap
        .alloc_closure(memory::Closure {
            function: func_idx,
            upvalues: vec![],
        })
        .map_err(|e| format!("alloc_closure: {e:?}"))?;

    vm.frames.push(CallFrame {
        closure: closure_idx,
        ip: 0,
        base: 0,
        dest_reg: 0,
    });

    vm.interpret().map_err(|e| format!("vm interpret: {e}"))?;

    drop(vm);
    let captures = std::mem::take(&mut *handler.captured.borrow_mut());
    Ok(captures)
}

// ---------------------------------------------------------------------------
// Replay one captured prove block through Lysis. Compute frozen baseline.
// ---------------------------------------------------------------------------

pub(crate) fn replay_one(capture: &Capture, file_label: &str) -> RowOutcome {
    let started = Instant::now();
    let block_name = capture
        .name
        .clone()
        .unwrap_or_else(|| format!("(anonymous #{})", capture.seq));

    let prove_ir = match ProveIR::from_bytes(&capture.bytes) {
        Ok((p, _prime)) => p,
        Err(e) => {
            return RowOutcome {
                file: file_label.into(),
                block: block_name,
                baseline: None,
                wall_clock: started.elapsed(),
                error: Some(format!("ProveIR::from_bytes: {e}")),
            };
        }
    };

    let captures_map = collect_captures(&prove_ir, &capture.scope);

    let mut program = match prove_ir.instantiate_lysis::<F>(&captures_map) {
        Ok(p) => p,
        Err(e) => {
            return RowOutcome {
                file: file_label.into(),
                block: block_name,
                baseline: None,
                wall_clock: started.elapsed(),
                error: Some(format!("instantiate_lysis: {e}")),
            };
        }
    };

    ir::passes::optimize(&mut program);

    let baseline = compute_frozen_baseline(&program);

    RowOutcome {
        file: file_label.into(),
        block: block_name,
        baseline: Some(baseline),
        wall_clock: started.elapsed(),
        error: None,
    }
}

/// Build the captures map for `instantiate_lysis` by selecting just
/// the names the ProveIR template declares as captures (scalar +
/// per-element of capture_arrays). The VM scope contains everything
/// in scope at the prove site; `instantiate_lysis` validates that we
/// passed exactly the declared captures (extra keys are ignored).
fn collect_captures(
    prove_ir: &ProveIR,
    scope: &HashMap<String, FieldElement<F>>,
) -> HashMap<String, FieldElement<F>> {
    let mut out: HashMap<String, FieldElement<F>> = HashMap::new();
    for cap in &prove_ir.captures {
        if let Some(v) = scope.get(&cap.name) {
            out.insert(cap.name.clone(), *v);
        }
    }
    for arr in &prove_ir.capture_arrays {
        for i in 0..arr.size {
            let elem = format!("{}_{i}", arr.name);
            if let Some(v) = scope.get(&elem) {
                out.insert(elem, *v);
            }
        }
    }
    let _ = ArraySize::Literal(0); // pull the import in even when unused
    out
}
