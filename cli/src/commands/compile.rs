use anyhow::{Context, Result};
use compiler::Compiler;
use std::fs;
use vm::specs::{SER_TAG_FIELD, SER_TAG_INT, SER_TAG_NIL, SER_TAG_STRING};

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

        file.write_all(b"ACH\x0A")?;

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

        // --- Field Table ---
        let fields = &compiler.field_interner.fields;
        file.write_u32::<LittleEndian>(fields.len() as u32)?;
        for fe in fields {
            let canonical = fe.to_canonical();
            for limb in &canonical {
                file.write_u64::<LittleEndian>(*limb)?;
            }
        }

        // --- Constants ---
        let main_func = compiler.compilers.last().expect("No main compiler");
        file.write_u32::<LittleEndian>(main_func.constants.len() as u32)?;
        for c in &main_func.constants {
            if let Some(n) = c.as_int() {
                file.write_u8(SER_TAG_INT)?;
                file.write_i64::<LittleEndian>(n)?;
            } else if c.is_string() {
                file.write_u8(SER_TAG_STRING)?;
                let handle = c.as_handle().expect("String value must have handle");
                file.write_u32::<LittleEndian>(handle)?;
            } else if c.is_field() {
                file.write_u8(SER_TAG_FIELD)?;
                let handle = c.as_handle().expect("Field value must have handle");
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
                if let Some(n) = c.as_int() {
                    file.write_u8(SER_TAG_INT)?;
                    file.write_i64::<LittleEndian>(n)?;
                } else if c.is_string() {
                    file.write_u8(SER_TAG_STRING)?;
                    let handle = c.as_handle().expect("String value must have handle");
                    file.write_u32::<LittleEndian>(handle)?;
                } else if c.is_field() {
                    file.write_u8(SER_TAG_FIELD)?;
                    let handle = c.as_handle().expect("Field value must have handle");
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
