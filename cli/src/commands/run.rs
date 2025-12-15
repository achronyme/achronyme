use anyhow::{Context, Result};
use compiler::Compiler;
use memory::{Function, Value};
use std::fs;
use vm::{CallFrame, VM};

use vm::opcode::OpCode;
use vm::opcode::instruction::decode_opcode; // Used in formatting if needed, though run_file mostly runs.

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

pub fn run_file(path: &str) -> Result<()> {
    let content = fs::read_to_string(path).unwrap_or_default();

    if path.ends_with(".achb") {
        use byteorder::{LittleEndian, ReadBytesExt};
        use std::io::Read;

        let mut file = fs::File::open(path).context("Failed to open binary file")?;

        let mut magic = [0u8; 4];
        file.read_exact(&mut magic)?;
        if &magic != b"ACH\x08" {
            return Err(anyhow::anyhow!("Invalid binary magic or version"));
        }

        let max_slots = file.read_u16::<LittleEndian>()?;

        // --- String Table ---
        let str_count = file.read_u32::<LittleEndian>()?;
        let mut strings = Vec::with_capacity(str_count as usize);

        for _ in 0..str_count {
            let len = file.read_u32::<LittleEndian>()?;
            let mut bytes = vec![0u8; len as usize];
            file.read_exact(&mut bytes)?;
            
            let s = String::from_utf8(bytes)
                .map_err(|_| anyhow::anyhow!("Invalid UTF-8 in binary"))?;
            strings.push(s);
        }

        // --- Constants ---
        let const_count = file.read_u32::<LittleEndian>()?;
        let mut constants = Vec::with_capacity(const_count as usize);
        for _ in 0..const_count {
            let tag = file.read_u8()?;
            match tag {
                0 => {
                    let n = file.read_f64::<LittleEndian>()?;
                    constants.push(Value::number(n));
                }
                1 => {
                    // Read Handle -> Create Value
                    let handle = file.read_u32::<LittleEndian>()?;
                    constants.push(Value::string(handle));
                }
                _ => return Err(anyhow::anyhow!("Unknown constant tag: {}", tag)),
            }
        }

        let code_len = file.read_u32::<LittleEndian>()?;
        let mut bytecode = Vec::with_capacity(code_len as usize);
        for _ in 0..code_len {
            bytecode.push(file.read_u32::<LittleEndian>()?);
        }

        let mut vm = VM::new();
        // Sync VM Heap
        vm.heap.import_strings(strings);

        // Try load debug symbols (Sidecar)
        let mut debug_bytes = Vec::new();
        // Read until EOF
        if file.read_to_end(&mut debug_bytes).is_ok() && !debug_bytes.is_empty() {
             vm.load_debug_section(&debug_bytes);
        }
        let func = Function {
            name: "main".to_string(),
            arity: 0,
            max_slots,
            chunk: bytecode,
            constants,
        };
        let func_idx = vm.heap.alloc_function(func);
        vm.frames.push(CallFrame {
            closure: func_idx,
            ip: 0,
            base: 0,
            dest_reg: 0, // Top-level script, unused
        });

        vm.interpret()
            .map_err(|e| anyhow::anyhow!("Runtime Error: {:?}", e))?;

        if let Some(val) = vm.stack.last() {
            println!("{}", format_value(val, &vm));
        }
        Ok(())
    } else {
        let mut compiler = Compiler::new();
        let bytecode = compiler
            .compile(&content)
            .map_err(|e| anyhow::anyhow!("Compile error: {:?}", e))?;

        let mut vm = VM::new();

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
        };
        let func_idx = vm.heap.alloc_function(func);

        vm.frames.push(CallFrame {
            closure: func_idx,
            ip: 0,
            base: 0,
            dest_reg: 0, // Top-level script, unused
        });

        vm.interpret()
            .map_err(|e| anyhow::anyhow!("Runtime Error: {:?}", e))?;

        if let Some(val) = vm.stack.last() {
            println!("{}", format_value(val, &vm));
        }

        Ok(())
    }
}

use memory::value::*;

fn format_value(val: &Value, vm: &VM) -> String {
    match val.type_tag() {
        TAG_NIL => "nil".to_string(),
        TAG_FALSE => "false".to_string(),
        TAG_TRUE => "true".to_string(),
        TAG_NUMBER => {
            let n = val.as_number().unwrap();
            if n.is_nan() {
                "NaN".to_string()
            } else if n.is_infinite() {
                if n > 0.0 {
                    "Infinity".to_string()
                } else {
                    "-Infinity".to_string()
                }
            } else {
                format!("{}", n)
            }
        }
        TAG_COMPLEX => {
            let idx = val.as_handle().unwrap();
            if let Some(c) = vm.heap.get_complex(idx) {
                if c.im.abs() < 1e-15 {
                    format!("{}", c.re)
                } else if c.re.abs() < 1e-15 {
                    if c.im == 1.0 {
                        "i".to_string()
                    } else if c.im == -1.0 {
                        "-i".to_string()
                    } else {
                        format!("{}i", c.im)
                    }
                } else if c.im >= 0.0 {
                    format!("{} + {}i", c.re, c.im)
                } else {
                    format!("{} - {}i", c.re, c.im.abs())
                }
            } else {
                format!("Complex({})", idx)
            }
        }
        TAG_STRING => {
            let handle = val.as_handle().unwrap();
            vm.heap
                .get_string(handle)
                .map(|s| s.clone())
                .unwrap_or_else(|| format!("String({})", handle))
        }
        TAG_LIST => format!("List({})", val.as_handle().unwrap()),
        TAG_MAP => format!("Map({})", val.as_handle().unwrap()),
        TAG_FUNCTION => format!("Function({})", val.as_handle().unwrap()),
        TAG_TENSOR => format!("Tensor({})", val.as_handle().unwrap()),
        _ => format!("Unknown(Bits: {:x})", val.0),
    }
}
