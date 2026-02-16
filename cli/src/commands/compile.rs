use anyhow::{Context, Result};
use compiler::Compiler;
use memory::Value;
use std::fs;
use vm::specs::{SER_TAG_NUMBER, SER_TAG_STRING, SER_TAG_NIL};

pub fn compile_file(path: &str, output: Option<&str>) -> Result<()> {
    let content = fs::read_to_string(path).context("Failed to read file")?;
    let mut compiler = Compiler::new();
    let bytecode = compiler
        .compile(&content)
        .map_err(|e| anyhow::anyhow!("Compile error: {:?}", e))?;

    println!("Compiled {} instructions.", bytecode.len());

    if let Some(out_path) = output {
        use byteorder::{LittleEndian, WriteBytesExt};
        use std::io::Write;

        let mut file = fs::File::create(out_path).context("Failed to create output file")?;

        file.write_all(b"ACH\x08")?;
        
        // Metadata
        let main_func = compiler.compilers.last().expect("No main compiler");
        file.write_u16::<LittleEndian>(main_func.max_slots)?;

        // --- String Table ---
        let strings = &compiler.interner.strings;
        file.write_u32::<LittleEndian>(strings.len() as u32)?;
        for s in strings {
            let bytes = s.as_bytes();
            file.write_u32::<LittleEndian>(bytes.len() as u32)?;
            file.write_all(bytes)?;
        }
        
        // --- Constants ---
        let main_func = compiler.compilers.last().expect("No main compiler");
        file.write_u32::<LittleEndian>(main_func.constants.len() as u32)?;
        for c in &main_func.constants {
            if let Some(n) = c.as_number() {
                file.write_u8(SER_TAG_NUMBER)?;
                file.write_f64::<LittleEndian>(n)?;
            } else if c.is_string() {
                file.write_u8(SER_TAG_STRING)?;
                // Payload is the handle
                let handle = c.as_handle().expect("String value must have handle");
                file.write_u32::<LittleEndian>(handle)?;
            } else if c.is_nil() {
                file.write_u8(SER_TAG_NIL)?;
            } else {
                return Err(anyhow::anyhow!(
                    "Unsupported constant type for serialization: {:?}",
                    c
                ));
            }
        }

        // --- Prototypes (Function Table) ---
        file.write_u32::<LittleEndian>(compiler.prototypes.len() as u32)?;
        for proto in &compiler.prototypes {
            // Name
            let name_bytes = proto.name.as_bytes();
            file.write_u32::<LittleEndian>(name_bytes.len() as u32)?;
            file.write_all(name_bytes)?;
            
            // Arity and max_slots
            file.write_u8(proto.arity)?;
            file.write_u16::<LittleEndian>(proto.max_slots)?;
            
            // Proto constants
            file.write_u32::<LittleEndian>(proto.constants.len() as u32)?;
            for c in &proto.constants {
                if let Some(n) = c.as_number() {
                    file.write_u8(SER_TAG_NUMBER)?;
                    file.write_f64::<LittleEndian>(n)?;
                } else if c.is_string() {
                    file.write_u8(SER_TAG_STRING)?;
                    let handle = c.as_handle().expect("String value must have handle");
                    file.write_u32::<LittleEndian>(handle)?;
                } else {
                    file.write_u8(SER_TAG_NIL)?;
                }
            }
            
            // Upvalue Info (New in v2)
            let upvalue_count = (proto.upvalue_info.len() / 2) as u32;
            file.write_u32::<LittleEndian>(upvalue_count)?;
            file.write_all(&proto.upvalue_info)?;

            // Proto bytecode
            file.write_u32::<LittleEndian>(proto.chunk.len() as u32)?;
            for inst in &proto.chunk {
                file.write_u32::<LittleEndian>(*inst)?;
            }
        }

        // --- Main Bytecode ---
        file.write_u32::<LittleEndian>(bytecode.len() as u32)?;
        for inst in &bytecode {
            file.write_u32::<LittleEndian>(*inst)?;
        }

        // Append Debug Symbols (Sidecar)
        let mut debug_buffer = Vec::new();
        compiler.append_debug_symbols(&mut debug_buffer);
        file.write_all(&debug_buffer)?;

        println!("Saved binary to {}", out_path);
    }
    Ok(())
}
