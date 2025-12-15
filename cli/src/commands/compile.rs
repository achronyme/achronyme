use anyhow::{Context, Result};
use compiler::Compiler;
use memory::Value;
use std::fs;

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
        file.write_u16::<LittleEndian>(compiler.max_reg_touched)?;

        // --- String Table ---
        let strings = &compiler.interner.strings;
        file.write_u32::<LittleEndian>(strings.len() as u32)?;
        for s in strings {
            let bytes = s.as_bytes();
            file.write_u32::<LittleEndian>(bytes.len() as u32)?;
            file.write_all(bytes)?;
        }

        // --- Constants ---
        file.write_u32::<LittleEndian>(compiler.constants.len() as u32)?;
        for c in &compiler.constants {
            if let Some(n) = c.as_number() {
                file.write_u8(0)?;
                file.write_f64::<LittleEndian>(n)?;
            } else if c.is_string() {
                file.write_u8(1)?;
                // Payload is the handle
                let handle = c.as_handle().expect("String value must have handle");
                file.write_u32::<LittleEndian>(handle)?;
            } else {
                return Err(anyhow::anyhow!(
                    "Unsupported constant type for serialization: {:?}",
                    c
                ));
            }
        }

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
