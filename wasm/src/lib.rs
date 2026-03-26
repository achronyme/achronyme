use std::cell::RefCell;

use wasm_bindgen::prelude::*;

use compiler::Compiler;
use memory::{Closure, Function, Value};
use vm::error::RuntimeError;
use vm::native::NativeObj;
use vm::{CallFrame, ValueOps, VM};

// Thread-local buffer for capturing print() output.
thread_local! {
    static OUTPUT: RefCell<Vec<String>> = RefCell::new(Vec::new());
}

/// Custom print native that writes to the thread-local buffer instead of stdout.
fn captured_print(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> {
    let mut line = String::new();
    for (i, arg) in args.iter().enumerate() {
        if i > 0 {
            line.push(' ');
        }
        line.push_str(&vm.val_to_string(arg));
    }
    OUTPUT.with(|buf| buf.borrow_mut().push(line));
    Ok(Value::nil())
}

/// Result of running an Achronyme program.
#[wasm_bindgen]
pub struct RunResult {
    success: bool,
    output: String,
    error: String,
}

#[wasm_bindgen]
impl RunResult {
    #[wasm_bindgen(getter)]
    pub fn success(&self) -> bool {
        self.success
    }

    #[wasm_bindgen(getter)]
    pub fn output(&self) -> String {
        self.output.clone()
    }

    #[wasm_bindgen(getter)]
    pub fn error(&self) -> String {
        self.error.clone()
    }
}

/// Compile and run an Achronyme source program.
///
/// Returns a `RunResult` with captured output, success status, and error message.
#[wasm_bindgen]
pub fn run(source: &str) -> RunResult {
    // Clear the output buffer
    OUTPUT.with(|buf| buf.borrow_mut().clear());

    match run_inner(source) {
        Ok(()) => {
            let output = OUTPUT.with(|buf| buf.borrow().join("\n"));
            RunResult {
                success: true,
                output,
                error: String::new(),
            }
        }
        Err(msg) => {
            let output = OUTPUT.with(|buf| buf.borrow().join("\n"));
            RunResult {
                success: false,
                output,
                error: msg,
            }
        }
    }
}

fn run_inner(source: &str) -> Result<(), String> {
    // 1. Compile
    let mut compiler = Compiler::new();
    let bytecode = compiler.compile(source).map_err(|e| format!("{e}"))?;

    // 2. Create VM
    let mut vm = VM::new();

    // 3. Replace the print native (index 0) with our captured version
    if !vm.natives.is_empty() {
        vm.natives[0] = NativeObj {
            name: "print".to_string(),
            func: captured_print,
            arity: -1,
        };
    }

    // 4. Transfer artifacts from compiler to VM
    vm.import_strings(compiler.interner.strings);
    vm.heap.import_bytes(compiler.bytes_interner.blobs);

    let field_map = vm
        .heap
        .import_fields(compiler.field_interner.fields)
        .map_err(|e| format!("field import: {e}"))?;
    let bigint_map = vm
        .heap
        .import_bigints(compiler.bigint_interner.bigints)
        .map_err(|e| format!("bigint import: {e}"))?;

    // Remap handles in prototypes
    for proto in &mut compiler.prototypes {
        remap_field_handles(&mut proto.constants, &field_map);
        remap_bigint_handles(&mut proto.constants, &bigint_map);
    }

    // 5. Allocate prototypes on heap
    for proto in &compiler.prototypes {
        let handle = vm
            .heap
            .alloc_function(proto.clone())
            .map_err(|e| format!("alloc prototype: {e}"))?;
        vm.prototypes.push(handle);
    }

    // 6. Create main function
    let main_func = compiler
        .compilers
        .last()
        .ok_or_else(|| "no main function".to_string())?;

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

    let func_idx = vm
        .heap
        .alloc_function(func)
        .map_err(|e| format!("alloc main: {e}"))?;
    let closure_idx = vm
        .heap
        .alloc_closure(Closure {
            function: func_idx,
            upvalues: vec![],
        })
        .map_err(|e| format!("alloc closure: {e}"))?;

    vm.frames.push(CallFrame {
        closure: closure_idx,
        ip: 0,
        base: 0,
        dest_reg: 0,
    });

    // 7. Execute
    vm.interpret().map_err(|e| {
        if let Some((func_name, line)) = &vm.last_error_location {
            format!("[line {line}] in {func_name}: {e}")
        } else {
            format!("Runtime error: {e}")
        }
    })
}

// --- Handle remapping (mirrors cli/src/commands/run.rs) ---

fn remap_field_handles(constants: &mut [Value], field_map: &[u32]) {
    for val in constants.iter_mut() {
        if val.is_field() {
            let old_handle = val.as_handle().expect("Field value must have handle");
            if let Some(&new_handle) = field_map.get(old_handle as usize) {
                *val = Value::field(new_handle);
            }
        }
    }
}

fn remap_bigint_handles(constants: &mut [Value], bigint_map: &[u32]) {
    for val in constants.iter_mut() {
        if val.is_bigint() {
            let old_handle = val.as_handle().expect("BigInt value must have handle");
            if let Some(&new_handle) = bigint_map.get(old_handle as usize) {
                *val = Value::bigint(new_handle);
            }
        }
    }
}
