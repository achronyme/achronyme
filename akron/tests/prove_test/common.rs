use akron::{CallFrame, ProveError, ProveHandler, ProveResult, VerifyHandler, VM};
use akronc::Compiler;
use memory::FieldElement;
use memory::{Function, ProofObject, Value};
use std::collections::HashMap;

/// Helper: compile and run Achronyme source, returning the VM after execution.
/// Does NOT inject a prove handler.
pub(crate) fn run_source(source: &str) -> Result<VM, String> {
    let mut compiler = Compiler::new();
    let bytecode = compiler.compile(source).map_err(|e| format!("{e:?}"))?;
    let main_func = compiler.compilers.last().expect("No main compiler");

    let mut vm = VM::new();
    vm.import_strings(compiler.interner.strings);
    vm.heap.import_bytes(compiler.bytes_interner.blobs);
    let field_map = vm
        .heap
        .import_fields(compiler.field_interner.fields)
        .expect("import_fields");

    for proto in &mut compiler.prototypes {
        remap_field_handles(&mut proto.constants, &field_map);
        let handle = vm.heap.alloc_function(proto.clone()).expect("alloc");
        vm.prototypes.push(handle);
    }

    let mut main_constants = main_func.constants.clone();
    remap_field_handles(&mut main_constants, &field_map);

    let func = Function {
        name: "main".to_string(),
        arity: 0,
        chunk: bytecode,
        constants: main_constants,
        max_slots: main_func.max_slots,
        upvalue_info: vec![],
        line_info: vec![],
    };
    let func_idx = vm.heap.alloc_function(func).expect("alloc");
    let closure_idx = vm
        .heap
        .alloc_closure(memory::Closure {
            function: func_idx,
            upvalues: vec![],
        })
        .expect("alloc");

    vm.frames.push(CallFrame {
        closure: closure_idx,
        ip: 0,
        base: 0,
        dest_reg: 0,
    });

    vm.interpret().map_err(|e| format!("{e:?}"))?;
    Ok(vm)
}

/// Helper: compile and run with the real prove handler injected.
pub(crate) fn run_source_with_prove(source: &str) -> Result<VM, String> {
    let mut compiler = Compiler::new();
    let bytecode = compiler.compile(source).map_err(|e| format!("{e:?}"))?;
    let main_func = compiler.compilers.last().expect("No main compiler");

    let mut vm = VM::new();
    vm.import_strings(compiler.interner.strings);
    vm.heap.import_bytes(compiler.bytes_interner.blobs);
    let field_map = vm
        .heap
        .import_fields(compiler.field_interner.fields)
        .expect("import_fields");

    for proto in &mut compiler.prototypes {
        remap_field_handles(&mut proto.constants, &field_map);
        let handle = vm.heap.alloc_function(proto.clone()).expect("alloc");
        vm.prototypes.push(handle);
    }

    let mut main_constants = main_func.constants.clone();
    remap_field_handles(&mut main_constants, &field_map);

    let func = Function {
        name: "main".to_string(),
        arity: 0,
        chunk: bytecode,
        constants: main_constants,
        max_slots: main_func.max_slots,
        upvalue_info: vec![],
        line_info: vec![],
    };
    let func_idx = vm.heap.alloc_function(func).expect("alloc");
    let closure_idx = vm
        .heap
        .alloc_closure(memory::Closure {
            function: func_idx,
            upvalues: vec![],
        })
        .expect("alloc");

    vm.frames.push(CallFrame {
        closure: closure_idx,
        ip: 0,
        base: 0,
        dest_reg: 0,
    });

    // Inject the real prove handler (uses IR→R1CS pipeline)
    vm.prove_handler = Some(Box::new(RealProveHandler));

    vm.interpret().map_err(|e| format!("{e:?}"))?;
    Ok(vm)
}

/// Real prove handler that uses the ProveIR → instantiate → R1CS pipeline.
struct RealProveHandler;

impl ProveHandler for RealProveHandler {
    fn execute_prove_ir(
        &self,
        prove_ir_bytes: &[u8],
        scope_values: &HashMap<String, FieldElement>,
    ) -> Result<ProveResult, ProveError> {
        use zkc::r1cs_backend::R1CSCompiler;

        let (prove_ir, _prime_id) = ir_forge::ProveIR::from_bytes(prove_ir_bytes)
            .map_err(|e| ProveError::IrLowering(format!("ProveIR: {e}")))?;

        let mut program = prove_ir
            .instantiate_lysis(scope_values)
            .map_err(|e| ProveError::IrLowering(format!("{e}")))?;

        ir::passes::optimize(&mut program);

        let mut inputs = HashMap::new();
        for input in prove_ir
            .public_inputs
            .iter()
            .chain(prove_ir.witness_inputs.iter())
        {
            if let Some(fe) = scope_values.get(&input.name) {
                inputs.insert(input.name.clone(), *fe);
            }
        }
        for cap in &prove_ir.captures {
            if let Some(fe) = scope_values.get(&cap.name) {
                inputs.insert(cap.name.clone(), *fe);
            }
        }

        let mut r1cs = R1CSCompiler::new();
        let proven = ir::passes::bool_prop::compute_proven_boolean(&program);
        r1cs.set_proven_boolean(proven);
        let witness = r1cs
            .compile_ir_with_witness(&program, &inputs)
            .map_err(|e| ProveError::Compilation(format!("{e}")))?;

        r1cs.cs
            .verify(&witness)
            .map_err(|idx| ProveError::Verification(format!("constraint {idx} failed")))?;

        Ok(ProveResult::VerifiedOnly)
    }
}
/// Mock handler that returns a Proof with fixed JSON payloads.
pub(crate) struct MockProofHandler;

impl ProveHandler for MockProofHandler {
    fn execute_prove_ir(
        &self,
        _prove_ir_bytes: &[u8],
        _scope_values: &HashMap<String, FieldElement>,
    ) -> Result<ProveResult, ProveError> {
        Ok(ProveResult::Proof {
            proof_json: r#"{"pi_a":["1","2"]}"#.to_string(),
            public_json: r#"["42"]"#.to_string(),
            vkey_json: r#"{"protocol":"groth16"}"#.to_string(),
        })
    }
}

/// Helper: compile and run with the mock proof handler.
pub(crate) fn run_source_with_mock_proof(source: &str) -> Result<VM, String> {
    let mut compiler = Compiler::new();
    let bytecode = compiler.compile(source).map_err(|e| format!("{e:?}"))?;
    let main_func = compiler.compilers.last().expect("No main compiler");

    let mut vm = VM::new();
    vm.import_strings(compiler.interner.strings);
    vm.heap.import_bytes(compiler.bytes_interner.blobs);
    let field_map = vm
        .heap
        .import_fields(compiler.field_interner.fields)
        .expect("import_fields");

    for proto in &mut compiler.prototypes {
        remap_field_handles(&mut proto.constants, &field_map);
        let handle = vm.heap.alloc_function(proto.clone()).expect("alloc");
        vm.prototypes.push(handle);
    }

    let mut main_constants = main_func.constants.clone();
    remap_field_handles(&mut main_constants, &field_map);

    let func = Function {
        name: "main".to_string(),
        arity: 0,
        chunk: bytecode,
        constants: main_constants,
        max_slots: main_func.max_slots,
        upvalue_info: vec![],
        line_info: vec![],
    };
    let func_idx = vm.heap.alloc_function(func).expect("alloc");
    let closure_idx = vm
        .heap
        .alloc_closure(memory::Closure {
            function: func_idx,
            upvalues: vec![],
        })
        .expect("alloc");

    vm.frames.push(CallFrame {
        closure: closure_idx,
        ip: 0,
        base: 0,
        dest_reg: 0,
    });

    vm.prove_handler = Some(Box::new(MockProofHandler));

    vm.interpret().map_err(|e| format!("{e:?}"))?;
    Ok(vm)
}
/// Mock verify handler that always returns true.
struct AlwaysValidVerifyHandler;

impl VerifyHandler for AlwaysValidVerifyHandler {
    fn verify_proof(&self, _proof: &ProofObject) -> Result<bool, String> {
        Ok(true)
    }
}

/// Mock verify handler that always returns false.
struct AlwaysInvalidVerifyHandler;

impl VerifyHandler for AlwaysInvalidVerifyHandler {
    fn verify_proof(&self, _proof: &ProofObject) -> Result<bool, String> {
        Ok(false)
    }
}

/// Helper: compile and run with both mock proof + mock verify handlers.
pub(crate) fn run_source_with_mock_verify(source: &str, valid: bool) -> Result<VM, String> {
    let mut compiler = Compiler::new();
    let bytecode = compiler.compile(source).map_err(|e| format!("{e:?}"))?;
    let main_func = compiler.compilers.last().expect("No main compiler");

    let mut vm = VM::new();
    vm.import_strings(compiler.interner.strings);
    vm.heap.import_bytes(compiler.bytes_interner.blobs);
    let field_map = vm
        .heap
        .import_fields(compiler.field_interner.fields)
        .expect("import_fields");

    for proto in &mut compiler.prototypes {
        remap_field_handles(&mut proto.constants, &field_map);
        let handle = vm.heap.alloc_function(proto.clone()).expect("alloc");
        vm.prototypes.push(handle);
    }

    let mut main_constants = main_func.constants.clone();
    remap_field_handles(&mut main_constants, &field_map);

    let func = Function {
        name: "main".to_string(),
        arity: 0,
        chunk: bytecode,
        constants: main_constants,
        max_slots: main_func.max_slots,
        upvalue_info: vec![],
        line_info: vec![],
    };
    let func_idx = vm.heap.alloc_function(func).expect("alloc");
    let closure_idx = vm
        .heap
        .alloc_closure(memory::Closure {
            function: func_idx,
            upvalues: vec![],
        })
        .expect("alloc");

    vm.frames.push(CallFrame {
        closure: closure_idx,
        ip: 0,
        base: 0,
        dest_reg: 0,
    });

    vm.prove_handler = Some(Box::new(MockProofHandler));
    if valid {
        vm.verify_handler = Some(Box::new(AlwaysValidVerifyHandler));
    } else {
        vm.verify_handler = Some(Box::new(AlwaysInvalidVerifyHandler));
    }

    vm.interpret().map_err(|e| format!("{e:?}"))?;
    Ok(vm)
}
pub(crate) fn remap_field_handles(constants: &mut [Value], field_map: &[u32]) {
    for val in constants.iter_mut() {
        if val.is_field() {
            let old_handle = val.as_handle().expect("Field value must have handle");
            if let Some(&new_handle) = field_map.get(old_handle as usize) {
                *val = Value::field(new_handle);
            }
        }
    }
}
