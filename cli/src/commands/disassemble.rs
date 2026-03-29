use anyhow::{Context, Result};
use std::fs;
use vm::opcode::{instruction::*, OpCode};

use achronyme_parser::ast::*;

use super::ErrorFormat;

pub fn disassemble_file(path: &str, error_format: ErrorFormat) -> Result<()> {
    let content = fs::read_to_string(path).context("Failed to read file")?;

    // Parse AST to detect circuit mode
    let (ast, _parse_errors) = achronyme_parser::parse_program(&content);

    if has_circuit_decls(&ast.stmts) {
        // Self-contained circuit: show IR only
        disassemble_circuit(path, &content, &ast, error_format)
    } else {
        // VM mode (pure or mixed with prove blocks).
        // Prove blocks are dumped from the compiled bytecode, not re-parsed.
        disassemble_vm(path, &content, error_format)
    }
}

// ---------------------------------------------------------------------------
// Detection helpers
// ---------------------------------------------------------------------------

fn has_circuit_decls(stmts: &[Stmt]) -> bool {
    stmts.iter().any(|s| matches!(s, Stmt::CircuitDecl { .. }))
}

// ---------------------------------------------------------------------------
// Circuit IR disassembly
// ---------------------------------------------------------------------------

fn disassemble_circuit(
    path: &str,
    source: &str,
    ast: &Program,
    error_format: ErrorFormat,
) -> Result<()> {
    let source_dir = std::path::Path::new(path)
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .to_path_buf();

    // Try self-contained lowering first (works for inline circuit bodies
    // that use `public x` / `witness y` declarations directly).
    if let Ok((pub_names, wit_names, mut program)) =
        ir::IrLowering::lower_self_contained_with_base(source, source_dir.clone())
    {
        ir::passes::optimize(&mut program);
        print_circuit_ir(path, None, &pub_names, &wit_names, &program);
        return Ok(());
    }

    // Self-contained lowering failed — extract each CircuitDecl's body
    // from the source using byte-range spans and reconstruct the input
    // declarations from the typed parameters.
    let mut found = false;
    for stmt in &ast.stmts {
        if let Stmt::CircuitDecl {
            name, params, body, ..
        } = stmt
        {
            found = true;

            // Reconstruct self-contained source: param declarations + body
            let mut circuit_src = String::new();
            for p in params {
                let ta = p.type_ann.as_ref();
                let vis = ta.and_then(|t| t.visibility.as_ref());
                let role = match vis {
                    Some(Visibility::Public) => "public",
                    Some(Visibility::Witness) => "witness",
                    None => "witness", // default
                };
                // The self-contained format is: `role name` or `role name[size]`
                let array_suffix = ta
                    .and_then(|t| t.array_size.map(|sz| format!("[{sz}]")))
                    .unwrap_or_default();
                circuit_src.push_str(&format!("{} {}{}\n", role, p.name, array_suffix));
            }

            // Extract body source using span byte offsets
            {
                let start = body.span.byte_start;
                let end = body.span.byte_end;
                if start < source.len() && end <= source.len() && start < end {
                    // span covers "{ ... }", strip the braces
                    let body_src = &source[start..end];
                    let inner = body_src
                        .trim()
                        .strip_prefix('{')
                        .and_then(|s| s.strip_suffix('}'))
                        .unwrap_or(body_src);
                    circuit_src.push_str(inner);
                }
            }

            match ir::IrLowering::lower_self_contained_with_base(&circuit_src, source_dir.clone()) {
                Ok((pub_names, wit_names, mut program)) => {
                    ir::passes::optimize(&mut program);
                    print_circuit_ir(path, Some(name), &pub_names, &wit_names, &program);
                }
                Err(e) => {
                    let diag = e.to_diagnostic();
                    let rendered = super::render_diagnostic(&diag, source, error_format);
                    eprintln!("  (failed to lower circuit `{name}`: {rendered})");
                }
            }
        }
    }

    if !found {
        anyhow::bail!("no circuit declarations found in {path}");
    }
    Ok(())
}

fn print_circuit_ir(
    path: &str,
    name: Option<&str>,
    pub_names: &[String],
    wit_names: &[String],
    program: &ir::IrProgram,
) {
    match name {
        Some(n) => println!("== Circuit IR for `{}` ({}) ==", n, path),
        None => println!("== Circuit IR for {} ==", path),
    }
    println!();

    if !pub_names.is_empty() {
        println!("  public:  {}", pub_names.join(", "));
    }
    if !wit_names.is_empty() {
        println!("  witness: {}", wit_names.join(", "));
    }
    println!();

    print!("{program}");

    let n = program.instructions.len();
    let n_pub = pub_names.len();
    let n_wit = wit_names.len();
    let n_constraints = program
        .instructions
        .iter()
        .filter(|i| i.has_side_effects() && !matches!(i, ir::Instruction::Input { .. }))
        .count();
    eprintln!(
        "{n} instructions, {} inputs ({n_pub} public, {n_wit} witness), {n_constraints} constraints",
        n_pub + n_wit
    );
    println!();
}

// ---------------------------------------------------------------------------
// VM bytecode disassembly (with prove block IR dump)
// ---------------------------------------------------------------------------

fn disassemble_vm(path: &str, source: &str, error_format: ErrorFormat) -> Result<()> {
    let mut compiler = super::new_compiler();
    let bytecode = compiler.compile(source).map_err(|e| {
        let rendered = super::render_compile_error(&e, source, error_format);
        anyhow::anyhow!("{rendered}")
    })?;

    super::print_warnings(&mut compiler, source, error_format);

    let mut inv_globals = std::collections::HashMap::new();
    for (name, entry) in &compiler.global_symbols {
        inv_globals.insert(entry.index, name);
    }

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
                let main_func = compiler
                    .compilers
                    .last()
                    .ok_or_else(|| anyhow::anyhow!("compiler has no main function"))?;
                let val_opt = main_func.constants.get(bx as usize);

                let val_str = if let Some(val) = val_opt {
                    if val.is_string() {
                        let handle = val.as_handle().unwrap();
                        if let Some(s) = compiler.interner.strings.get(handle as usize) {
                            format!("\"{}\"", s)
                        } else {
                            format!("{:?}", val)
                        }
                    } else {
                        format!("{:?}", val)
                    }
                } else {
                    "None".to_string()
                };

                println!("{:04} {:<12} R{}, K[{}] ({})", i, name, a, bx, val_str);
            }
            Some(OpCode::Return) => {
                println!("{:04} {:<12} R{}", i, name, a);
            }
            Some(OpCode::Add) | Some(OpCode::Sub) | Some(OpCode::Mul) | Some(OpCode::Div)
            | Some(OpCode::Pow) => {
                println!("{:04} {:<12} R{}, R{}, R{}", i, name, a, b, c);
            }
            Some(OpCode::Move) | Some(OpCode::Neg) => {
                println!("{:04} {:<12} R{}, R{}", i, name, a, b);
            }
            Some(OpCode::DefGlobalLet)
            | Some(OpCode::DefGlobalVar)
            | Some(OpCode::GetGlobal)
            | Some(OpCode::SetGlobal) => {
                let sym_name = inv_globals.get(&bx).map(|s| s.as_str()).unwrap_or("?");
                println!(
                    "{:04} {:<12} R{}, Name[{}] ('{}')",
                    i, name, a, bx, sym_name
                );
            }
            _ => {
                println!("{:04} {:<12} A={} B={} C={} Bx={}", i, name, a, b, c, bx);
            }
        }
    }

    // ── Dump ProveIR for each PROVE instruction ─────────────────────────
    dump_prove_blocks_from_bytecode(&bytecode, &compiler);

    Ok(())
}

/// Scan compiled bytecode for PROVE instructions, deserialize the ProveIR
/// from the constant pool, and print it.
fn dump_prove_blocks_from_bytecode(bytecode: &[u32], compiler: &compiler::Compiler) {
    let main_func = match compiler.compilers.last() {
        Some(f) => f,
        None => return,
    };

    let mut block_num = 0u32;
    for (i, &inst) in bytecode.iter().enumerate() {
        if decode_opcode(inst) != OpCode::Prove.as_u8() {
            continue;
        }
        block_num += 1;
        let bx = decode_bx(inst) as usize;

        println!();
        println!("  -- ProveIR block {} (instruction {:04}) --", block_num, i);

        let Some(val) = main_func.constants.get(bx) else {
            println!("  (constant K[{bx}] not found)");
            continue;
        };

        if !val.is_bytes() {
            println!("  (constant K[{bx}] is not bytes)");
            continue;
        }

        let Some(handle) = val.as_handle() else {
            println!("  (could not extract handle from K[{bx}])");
            continue;
        };

        let Some(blob) = compiler.bytes_interner.blobs.get(handle as usize) else {
            println!("  (bytes handle {handle} not found in interner)");
            continue;
        };

        match ir::prove_ir::ProveIR::from_bytes(blob) {
            Ok(prove_ir) => print!("{prove_ir}"),
            Err(e) => println!("  (failed to deserialize ProveIR: {e})"),
        }
    }
}
