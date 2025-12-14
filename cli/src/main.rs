use clap::{Parser, Subcommand};
use anyhow::{Result, Context};
use std::fs;

use compiler::Compiler;
use vm::{VM, CallFrame};
use memory::Function;
use vm::opcode::{OpCode, instruction::*};

#[derive(Parser)]
#[command(name = "ach")]
#[command(about = "Achronyme CLI", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Run a source file or binary
    Run {
        /// Path to the file (.ach or .achb)
        path: String,
    },
    /// Disassemble a source file or binary
    Disassemble {
        /// Path to the file
        path: String,
    },
    /// Compile a source file to binary
    Compile {
        /// Input source file
        path: String,
        /// Output binary file (optional)
        #[arg(short, long)]
        output: Option<String>,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Run { path } => run_file(path),
        Commands::Disassemble { path } => disassemble_file(path),
        Commands::Compile { path, output } => compile_file(path, output.as_deref()),
    }
}

fn run_file(path: &str) -> Result<()> {
    // Detect binary valid magic? For now just try to parse text, if fail try binary?
    // Or check extension.
    let content = fs::read_to_string(path).unwrap_or_default(); // Might be binary
    
    // Simple heuristic: If it compiles, run it.
    // Real implementation should check magic bytes or extension.
    if path.ends_with(".achb") {
        use std::io::Read;
        use byteorder::{ReadBytesExt, LittleEndian};
        
        // Read file
        let mut file = fs::File::open(path).context("Failed to open binary file")?;
        
        // 1. Magic + Version
        let mut magic = [0u8; 4];
        file.read_exact(&mut magic)?;
        if &magic != b"ACH\x07" {
            return Err(anyhow::anyhow!("Invalid binary magic or version"));
        }
        
        // 2. Constants
        let const_count = file.read_u32::<LittleEndian>()?;
        let mut constants = Vec::with_capacity(const_count as usize);
        for _ in 0..const_count {
            let tag = file.read_u8()?;
            match tag {
                0 => {
                    let n = file.read_f64::<LittleEndian>()?;
                    constants.push(memory::Value::Number(n));
                }
                _ => return Err(anyhow::anyhow!("Unknown constant tag: {}", tag)),
            }
        }
        
        // 3. Bytecode
        let code_len = file.read_u32::<LittleEndian>()?;
        let mut bytecode = Vec::with_capacity(code_len as usize);
        for _ in 0..code_len {
            bytecode.push(file.read_u32::<LittleEndian>()?);
        }
        
        // Execute
        let mut vm = VM::new();
        let func = Function {
            name: "main".to_string(),
            arity: 0,
            chunk: bytecode,
            constants,
        };
        let func_idx = vm.heap.alloc_function(func);
        vm.frames.push(CallFrame { closure: func_idx, ip: 0, base: 0 });
        
        vm.interpret().map_err(|e| anyhow::anyhow!("Runtime Error: {}", e))?;
        
        if let Some(val) = vm.stack.last() {
            println!("Result: {:?}", val);
        }
        Ok(())
    } else {
        let mut compiler = Compiler::new();
        let bytecode = compiler.compile(&content).map_err(|e| anyhow::anyhow!(e))?;
        
        // Setup VM
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
        
        vm.interpret().map_err(|e| anyhow::anyhow!("Runtime Error: {}", e))?;
        
        // Print result if any (top of stack)
        // Only if not popped? The compiler returns R[A]. But VM pops frame? 
        // Our VM pops frame. So result is lost unless we store it or print it.
        // For testing we will print the last value on stack if stack not empty.
        if let Some(val) = vm.stack.last() {
            println!("Result: {:?}", val);
        }
        
        Ok(())
    }
}

fn disassemble_file(path: &str) -> Result<()> {
    let content = fs::read_to_string(path).context("Failed to read file")?;
    let mut compiler = Compiler::new();
    let bytecode = compiler.compile(&content).map_err(|e| anyhow::anyhow!(e))?;
    
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
        
        // Heuristic for format
        // LoadConst use ABx
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

fn compile_file(path: &str, output: Option<&str>) -> Result<()> {
    let content = fs::read_to_string(path).context("Failed to read file")?;
    let mut compiler = Compiler::new();
    let bytecode = compiler.compile(&content).map_err(|e| anyhow::anyhow!(e))?;
    
    println!("Compiled {} instructions.", bytecode.len());
    
    if let Some(out_path) = output {
        use std::io::Write;
        use byteorder::{WriteBytesExt, LittleEndian};
        
        let mut file = fs::File::create(out_path).context("Failed to create output file")?;
        
        // 1. Magic + Version
        file.write_all(b"ACH\x07")?; 
        
        // 2. Constants
        file.write_u32::<LittleEndian>(compiler.constants.len() as u32)?;
        for c in &compiler.constants {
             match c {
                 memory::Value::Number(n) => {
                     file.write_u8(0)?; // Tag 0 = Number
                     file.write_f64::<LittleEndian>(*n)?;
                 }
                 _ => return Err(anyhow::anyhow!("Unsupported constant type for serialization: {:?}", c)),
             }
        }
        
        // 3. Bytecode
        file.write_u32::<LittleEndian>(bytecode.len() as u32)?;
        for inst in &bytecode {
            file.write_u32::<LittleEndian>(*inst)?;
        }
        
        println!("Saved string binary to {}", out_path);
    }
    Ok(())
}
