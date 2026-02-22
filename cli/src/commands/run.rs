use anyhow::{Context, Result};
use compiler::Compiler;
use memory::Function;
use std::fs;
use vm::{CallFrame, VM};

use crate::prove_handler::DefaultProveHandler;

// Need format_value logic. It was local in runner.rs.
// I will duplicate it here or move it to a shared utils or vm method?
// Since `Value::fmt` exists (Debug), but the user wants `format_value`.
// Ideally updating `Value::Display` or similar.
// For now, I'll put `format_value` here or make it a helper in `vm` or `cli`.
// Let's put it in `vm` would be best, but I can't easily change `vm` right deeply now.
// I'll copy it here for now to avoid cross-crate dependency cycles if any (cli depends on vm, so vm can't depend on cli).
// BUT `vm` has `Value` and `VM`. `format_value` takes `&Value` and `&VM`.
// It strictly belongs in `vm` or `cli` utils.
// I'll make a private helper here for now.

pub fn run_file(path: &str, stress_gc: bool, ptau: Option<&str>) -> Result<()> {
    if ptau.is_some() {
        eprintln!("Warning: --ptau is deprecated and ignored (native Groth16 backend does not use ptau files)");
    }

    if path.ends_with(".achb") {
        let mut file = fs::File::open(path).context("Failed to open binary file")?;

        let mut vm = VM::new();
        vm.stress_mode = stress_gc;
        vm.prove_handler = Some(Box::new(DefaultProveHandler::new()));

        // Use the new secure loader
        vm.load_executable(&mut file)
            .map_err(|e| anyhow::anyhow!("Loader Error: {:?}", e))?;

        vm.interpret()
            .map_err(|e| anyhow::anyhow!("Runtime Error: {:?}", e))?;

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
        vm.prove_handler = Some(Box::new(DefaultProveHandler::new()));

        // Transfer strings from compiler to VM
        vm.heap.import_strings(compiler.interner.strings);

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

        let func = Function {
            name: "main".to_string(),
            arity: 0,
            chunk: bytecode,
            constants: main_func.constants.clone(),
            max_slots: main_func.max_slots,
            upvalue_info: vec![],
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

        vm.interpret()
            .map_err(|e| anyhow::anyhow!("Runtime Error: {:?}", e))?;

        if let Some(val) = vm.stack.last() {
            println!("Exit Status: {}", vm.val_to_string(val));
        }

        Ok(())
    }
}
