//! Bytecode debugging utilities

use crate::bytecode::FunctionPrototype;
use crate::opcode::{instruction::*, OpCode};
use std::rc::Rc;

/// Print detailed bytecode disassembly
pub fn disassemble_function(func: &FunctionPrototype, name: &str) {
    println!("\n========== Function: {} ==========", name);
    println!("Parameters: {}", func.param_count);
    println!("Registers: {}", func.register_count);
    println!("Upvalues: {}", func.upvalues.len());

    if !func.upvalues.is_empty() {
        println!("\nUpvalues:");
        for (i, upval) in func.upvalues.iter().enumerate() {
            println!("  [{}] depth={} reg={} mutable={}",
                i, upval.depth, upval.register, upval.is_mutable);
        }
    }

    println!("\nBytecode:");
    for (i, &instruction) in func.code.iter().enumerate() {
        print!("{:04}  ", i);
        disassemble_instruction(instruction, func);
    }

    // Recursively disassemble nested functions
    if !func.functions.is_empty() {
        println!("\n--- Nested Functions ---");
        for (i, nested) in func.functions.iter().enumerate() {
            disassemble_function(nested, &format!("{}.<nested-{}>", name, i));
        }
    }

    println!("========================================\n");
}

/// Disassemble a single instruction
fn disassemble_instruction(instruction: u32, func: &FunctionPrototype) {
    let opcode_byte = decode_opcode(instruction);
    let opcode = match OpCode::from_u8(opcode_byte) {
        Some(op) => op,
        None => {
            println!("UNKNOWN     opcode={} (raw: 0x{:08x})", opcode_byte, instruction);
            return;
        }
    };

    match opcode {
        OpCode::Move => {
            let a = decode_a(instruction);
            let b = decode_b(instruction);
            println!("MOVE        R{} R{}", a, b);
        }
        OpCode::LoadConst => {
            let a = decode_a(instruction);
            let bx = decode_bx(instruction);
            let const_val = func.constants.constants.get(bx as usize)
                .map(|v| format!("{:?}", v))
                .unwrap_or_else(|| "???".to_string());
            println!("LOADCONST   R{} K[{}]  ; {}", a, bx, const_val);
        }
        OpCode::LoadNull => {
            let a = decode_a(instruction);
            println!("LOADNULL    R{}", a);
        }
        OpCode::NewRecord => {
            let a = decode_a(instruction);
            println!("NEWRECORD   R{}", a);
        }
        OpCode::SetField => {
            let a = decode_a(instruction);
            let b = decode_b(instruction);
            let c = decode_c(instruction);
            let field_name = func.constants.constants.get(b as usize)
                .and_then(|v| if let crate::value::Value::String(s) = v { Some(s.as_str()) } else { None })
                .unwrap_or("???");
            println!("SETFIELD    R{} \"{}\" R{}", a, field_name, c);
        }
        OpCode::GetField => {
            let a = decode_a(instruction);
            let b = decode_b(instruction);
            let c = decode_c(instruction);
            let field_name = func.constants.constants.get(c as usize)
                .and_then(|v| if let crate::value::Value::String(s) = v { Some(s.as_str()) } else { None })
                .unwrap_or("???");
            println!("GETFIELD    R{} R{} \"{}\"", a, b, field_name);
        }
        OpCode::Closure => {
            let a = decode_a(instruction);
            let bx = decode_bx(instruction);
            println!("CLOSURE     R{} F[{}]", a, bx);
        }
        OpCode::Call => {
            let a = decode_a(instruction);
            let b = decode_b(instruction);
            let c = decode_c(instruction);
            println!("CALL        R{} R{} argc={}", a, b, c);
        }
        OpCode::TailCall => {
            let b = decode_b(instruction);
            let c = decode_c(instruction);
            println!("TAILCALL    R{} argc={}", b, c);
        }
        OpCode::Return => {
            let a = decode_a(instruction);
            println!("RETURN      R{}", a);
        }
        OpCode::GetUpvalue => {
            let a = decode_a(instruction);
            let b = decode_b(instruction);
            println!("GETUPVALUE  R{} U[{}]", a, b);
        }
        OpCode::SetUpvalue => {
            let a = decode_a(instruction);
            let b = decode_b(instruction);
            println!("SETUPVALUE  U[{}] R{}", a, b);
        }
        OpCode::Add => {
            let a = decode_a(instruction);
            let b = decode_b(instruction);
            let c = decode_c(instruction);
            println!("ADD         R{} R{} R{}", a, b, c);
        }
        OpCode::Sub => {
            let a = decode_a(instruction);
            let b = decode_b(instruction);
            let c = decode_c(instruction);
            println!("SUB         R{} R{} R{}", a, b, c);
        }
        OpCode::Mul => {
            let a = decode_a(instruction);
            let b = decode_b(instruction);
            let c = decode_c(instruction);
            println!("MUL         R{} R{} R{}", a, b, c);
        }
        OpCode::Div => {
            let a = decode_a(instruction);
            let b = decode_b(instruction);
            let c = decode_c(instruction);
            println!("DIV         R{} R{} R{}", a, b, c);
        }
        OpCode::Le => {
            let a = decode_a(instruction);
            let b = decode_b(instruction);
            let c = decode_c(instruction);
            println!("LE          R{} R{} R{}", a, b, c);
        }
        OpCode::JumpIfTrue => {
            let a = decode_a(instruction);
            let bx = decode_bx(instruction) as i16;
            println!("JUMPIFTRUE  R{} +{}", a, bx);
        }
        OpCode::JumpIfFalse => {
            let a = decode_a(instruction);
            let bx = decode_bx(instruction) as i16;
            println!("JUMPIFFALSE R{} +{}", a, bx);
        }
        OpCode::Jump => {
            let bx = decode_bx(instruction) as i16;
            println!("JUMP        +{}", bx);
        }
        OpCode::CallBuiltin => {
            let a = decode_a(instruction);
            let b = decode_b(instruction);
            let c = decode_c(instruction);
            println!("CALLBUILTIN R{} builtin={} argc={}", a, b, c);
        }
        _ => {
            println!("{:?}        (raw: 0x{:08x})", opcode, instruction);
        }
    }
}
