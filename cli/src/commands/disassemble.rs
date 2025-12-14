use anyhow::{Context, Result};
use compiler::Compiler;
use std::fs;
use vm::opcode::{OpCode, instruction::*};

pub fn disassemble_file(path: &str) -> Result<()> {
    let content = fs::read_to_string(path).context("Failed to read file")?;
    let mut compiler = Compiler::new();
    let bytecode = compiler
        .compile(&content)
        .map_err(|e| anyhow::anyhow!("Compile error: {:?}", e))?;

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
            Some(OpCode::Add)
            | Some(OpCode::Sub)
            | Some(OpCode::Mul)
            | Some(OpCode::Div)
            | Some(OpCode::Pow)
            | Some(OpCode::NewComplex) => {
                println!("{:04} {:<12} R{}, R{}, R{}", i, name, a, b, c);
            }
            Some(OpCode::Move) | Some(OpCode::Neg) => {
                println!("{:04} {:<12} R{}, R{}", i, name, a, b);
            }
            Some(OpCode::DefGlobalLet)
            | Some(OpCode::DefGlobalVar)
            | Some(OpCode::GetGlobal)
            | Some(OpCode::SetGlobal) => {
                let val = compiler.constants.get(bx as usize);
                println!("{:04} {:<12} R{}, Name[{}] ({:?})", i, name, a, bx, val);
            }
            _ => {
                println!("{:04} {:<12} A={} B={} C={} Bx={}", i, name, a, b, c, bx);
            }
        }
    }
    Ok(())
}
