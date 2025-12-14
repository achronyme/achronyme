use anyhow::{Result, Context};
use std::fs;
use compiler::Compiler;
use vm::{VM, CallFrame, OpCode};
use vm::opcode::instruction::*;
use memory::{Function, Value};

pub fn run_file(path: &str) -> Result<()> {
    let content = fs::read_to_string(path).unwrap_or_default();
    
    if path.ends_with(".achb") {
        use std::io::Read;
        use byteorder::{ReadBytesExt, LittleEndian};
        
        let mut file = fs::File::open(path).context("Failed to open binary file")?;
        
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic)?;
        if &magic != b"ACH\x07" {
            return Err(anyhow::anyhow!("Invalid binary magic or version"));
        }
        
        let const_count = file.read_u32::<LittleEndian>()?;
        let mut constants = Vec::with_capacity(const_count as usize);
        for _ in 0..const_count {
            let tag = file.read_u8()?;
            match tag {
                0 => {
                    let n = file.read_f64::<LittleEndian>()?;
                    constants.push(Value::Number(n));
                }
                1 => {
                    let len = file.read_u32::<LittleEndian>()?;
                    let mut bytes = vec![0u8; len as usize];
                    file.read_exact(&mut bytes)?;
                    let s = String::from_utf8(bytes).map_err(|_| anyhow::anyhow!("Invalid UTF-8 string constant"))?;
                    constants.push(Value::String(s));
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
        let func = Function {
            name: "main".to_string(),
            arity: 0,
            chunk: bytecode,
            constants,
        };
        let func_idx = vm.heap.alloc_function(func);
        vm.frames.push(CallFrame { closure: func_idx, ip: 0, base: 0 });
        
        vm.interpret().map_err(|e| anyhow::anyhow!("Runtime Error: {:?}", e))?;
        
        if let Some(val) = vm.stack.last() {
            println!("{}", format_value(val, &vm));
        }
        Ok(())
    } else {
        let mut compiler = Compiler::new();
        // Compile using the refactored compiler which returns distinct error type
        let bytecode = compiler.compile(&content).map_err(|e| anyhow::anyhow!("Compile error: {:?}", e))?;
        
        let mut vm = VM::new();
        let func = Function {
            name: "main".to_string(),
            arity: 0,
            chunk: bytecode,
            constants: compiler.constants,
        };
        let func_idx = vm.heap.alloc_function(func);
        
        vm.frames.push(CallFrame {
            closure: func_idx,
            ip: 0,
            base: 0,
        });
        
        vm.interpret().map_err(|e| anyhow::anyhow!("Runtime Error: {:?}", e))?;
        
        if let Some(val) = vm.stack.last() {
            println!("{}", format_value(val, &vm));
        }
        
        Ok(())
    }
}

pub fn disassemble_file(path: &str) -> Result<()> {
    let content = fs::read_to_string(path).context("Failed to read file")?;
    let mut compiler = Compiler::new();
    let bytecode = compiler.compile(&content).map_err(|e| anyhow::anyhow!("Compile error: {:?}", e))?;
    
    println!("== Disassembly of {} ==", path);
    for (i, inst) in bytecode.iter().enumerate() {
        let op_byte = decode_opcode(*inst);
        let name = OpCode::from_u8(op_byte)
            .map(|op| op.name())
            .unwrap_or("UNKNOWN");
            
        let a = decode_a(*inst);
        let b = decode_b(*inst);
        let c = decode_c(*inst);
        let bx = decode_bx(*inst);
        
        match OpCode::from_u8(op_byte) {
            Some(OpCode::LoadConst) => {
                 let val = compiler.constants.get(bx as usize);
                 println!("{:04} {:<12} R{}, K[{}] ({:?})", i, name, a, bx, val);
            }
            Some(OpCode::Return) => {
                 println!("{:04} {:<12} R{}", i, name, a);
            }
            Some(OpCode::Add) | Some(OpCode::Sub) | Some(OpCode::Mul) | Some(OpCode::Div) | Some(OpCode::Pow) | Some(OpCode::NewComplex) => {
                 println!("{:04} {:<12} R{}, R{}, R{}", i, name, a, b, c);
            }
            Some(OpCode::Move) | Some(OpCode::Neg) => {
                 println!("{:04} {:<12} R{}, R{}", i, name, a, b);
            }
            _ => {
                 println!("{:04} {:<12} A={} B={} C={} Bx={}", i, name, a, b, c, bx);
            }
        }
    }
    Ok(())
}

pub fn compile_file(path: &str, output: Option<&str>) -> Result<()> {
    let content = fs::read_to_string(path).context("Failed to read file")?;
    let mut compiler = Compiler::new();
    let bytecode = compiler.compile(&content).map_err(|e| anyhow::anyhow!("Compile error: {:?}", e))?;
    
    println!("Compiled {} instructions.", bytecode.len());
    
    if let Some(out_path) = output {
        use std::io::Write;
        use byteorder::{WriteBytesExt, LittleEndian};
        
        let mut file = fs::File::create(out_path).context("Failed to create output file")?;
        
        file.write_all(b"ACH\x07")?; 
        
        file.write_u32::<LittleEndian>(compiler.constants.len() as u32)?;
        for c in &compiler.constants {
             match c {
                 Value::Number(n) => {
                     file.write_u8(0)?;
                     file.write_f64::<LittleEndian>(*n)?;
                 }
                 Value::String(s) => {
                     file.write_u8(1)?;
                     let bytes = s.as_bytes();
                     file.write_u32::<LittleEndian>(bytes.len() as u32)?;
                     file.write_all(bytes)?;
                 }
                 _ => return Err(anyhow::anyhow!("Unsupported constant type for serialization: {:?}", c)),
             }
        }
        
        file.write_u32::<LittleEndian>(bytecode.len() as u32)?;
        for inst in &bytecode {
            file.write_u32::<LittleEndian>(*inst)?;
        }
        
        println!("Saved binary to {}", out_path);
    }
    Ok(())
}

fn format_value(val: &Value, vm: &VM) -> String {
    match val {
        Value::Nil => "nil".to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => {
            if n.is_nan() {
                "NaN".to_string()
            } else if n.is_infinite() {
                if *n > 0.0 { "Infinity".to_string() } else { "-Infinity".to_string() }
            } else {
                format!("{}", n)
            }
        }
        Value::Complex(idx) => {
            if let Some(c) = vm.heap.get_complex(*idx) {
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
        Value::String(s) => s.clone(),
        Value::List(idx) => format!("List({})", idx),
        Value::Map(idx) => format!("Map({})", idx),
        Value::Function(idx) => format!("Function({})", idx),
        Value::Tensor(idx) => format!("Tensor({})", idx),
    }
}
