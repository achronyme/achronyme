use anyhow::{Context, Result};
use compiler::Compiler;
use memory::Function;
use std::fs;
use vm::{CallFrame, VM};

use crate::prove_handler::{DefaultProveHandler, ProveBackend};

pub fn run_file(
    path: &str,
    stress_gc: bool,
    ptau: Option<&str>,
    prove_backend: &str,
) -> Result<()> {
    if ptau.is_some() {
        eprintln!(
            "Warning: --ptau is deprecated and ignored (native Groth16 backend does not use ptau files)"
        );
    }

    let backend = match prove_backend {
        "plonkish" => ProveBackend::Plonkish,
        _ => ProveBackend::R1cs,
    };

    if path.ends_with(".achb") {
        let mut file = fs::File::open(path).context("Failed to open binary file")?;

        let mut vm = VM::new();
        vm.stress_mode = stress_gc;
        let handler = DefaultProveHandler::new(backend);
        vm.verify_handler = Some(Box::new(DefaultProveHandler::new(backend)));
        vm.prove_handler = Some(Box::new(handler));

        // Use the new secure loader
        vm.load_executable(&mut file)
            .map_err(|e| anyhow::anyhow!("Loader Error: {:?}", e))?;

        if let Err(e) = vm.interpret() {
            let msg = format_runtime_error(&vm, &e);
            return Err(anyhow::anyhow!("{}", msg));
        }

        if let Some(val) = vm.stack.last() {
            println!("Exit Status: {}", vm.val_to_string(val));
        }
        Ok(())
    } else {
        let content = fs::read_to_string(path).context("Failed to source file")?;
        let mut compiler = Compiler::new();
        let bytecode = compiler
            .compile(&content)
            .map_err(|e| anyhow::anyhow!("Compile error: {:?}", e))?;

        let mut vm = VM::new();
        vm.stress_mode = stress_gc;
        let handler = DefaultProveHandler::new(backend);
        vm.verify_handler = Some(Box::new(DefaultProveHandler::new(backend)));
        vm.prove_handler = Some(Box::new(handler));

        // Transfer strings from compiler to VM
        vm.heap.import_strings(compiler.interner.strings);

        // Transfer field literals from compiler to VM
        let field_map = vm.heap.import_fields(compiler.field_interner.fields);
        // Transfer bigint literals from compiler to VM
        let bigint_map = vm.heap.import_bigints(compiler.bigint_interner.bigints);
        // Remap field and bigint handles in constants
        for proto in &mut compiler.prototypes {
            remap_field_handles(&mut proto.constants, &field_map);
            remap_bigint_handles(&mut proto.constants, &bigint_map);
        }

        // Transfer Debug Symbols (Source Mode)
        let mut debug_map = std::collections::HashMap::new();
        for (name, idx) in &compiler.global_symbols {
            debug_map.insert(*idx, name.clone());
        }
        vm.debug_symbols = Some(debug_map);

        // Get constants and max_slots from the main function compiler
        let main_func = compiler.compilers.last().expect("No main compiler");

        // Allocate ALL prototypes on heap (flat global architecture)
        for proto in &compiler.prototypes {
            let handle = vm.heap.alloc_function(proto.clone());
            vm.prototypes.push(handle);
        }

        let mut main_constants = main_func.constants.clone();
        remap_field_handles(&mut main_constants, &field_map);
        remap_bigint_handles(&mut main_constants, &bigint_map);

        let func = Function {
            name: "main".to_string(),
            arity: 0,
            chunk: bytecode,
            constants: main_constants,
            max_slots: main_func.max_slots,
            upvalue_info: vec![],
            line_info: main_func.line_info.clone(),
        };
        let func_idx = vm.heap.alloc_function(func);
        let closure_idx = vm.heap.alloc_closure(memory::Closure {
            function: func_idx,
            upvalues: vec![],
        });

        vm.frames.push(CallFrame {
            closure: closure_idx,
            ip: 0,
            base: 0,
            dest_reg: 0, // Top-level script, unused
        });

        if let Err(e) = vm.interpret() {
            let msg = format_runtime_error(&vm, &e);
            return Err(anyhow::anyhow!("{}", msg));
        }

        if let Some(val) = vm.stack.last() {
            println!("Exit Status: {}", vm.val_to_string(val));
        }

        Ok(())
    }
}

/// Remap field literal handles from compiler-space to VM heap-space.
fn remap_field_handles(constants: &mut [memory::Value], field_map: &[u32]) {
    for val in constants.iter_mut() {
        if val.is_field() {
            let old_handle = val.as_handle().expect("Field value must have handle");
            if let Some(&new_handle) = field_map.get(old_handle as usize) {
                *val = memory::Value::field(new_handle);
            }
        }
    }
}

/// Remap BigInt literal handles from compiler-space to VM heap-space.
fn remap_bigint_handles(constants: &mut [memory::Value], bigint_map: &[u32]) {
    for val in constants.iter_mut() {
        if val.is_bigint() {
            let old_handle = val.as_handle().expect("BigInt value must have handle");
            if let Some(&new_handle) = bigint_map.get(old_handle as usize) {
                *val = memory::Value::bigint(new_handle);
            }
        }
    }
}

/// Format a runtime error with source location if available.
fn format_runtime_error(vm: &VM, err: &vm::RuntimeError) -> String {
    match &vm.last_error_location {
        Some((func_name, line)) => format!("[line {line}] in {func_name}: {err:?}"),
        None => format!("Runtime Error: {err:?}"),
    }
}
