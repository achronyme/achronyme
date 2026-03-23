use anyhow::{Context, Result};
use std::fs;
use vm::opcode::{instruction::*, OpCode};

use achronyme_parser::ast::*;

use super::ErrorFormat;

pub fn disassemble_file(path: &str, error_format: ErrorFormat) -> Result<()> {
    let content = fs::read_to_string(path).context("Failed to read file")?;

    // Parse AST to detect circuit mode
    let (ast, _parse_errors) = achronyme_parser::parse_program(&content);

    let is_circuit = has_circuit_decls(&ast.stmts);
    let prove_blocks = collect_prove_blocks(&ast.stmts);

    if is_circuit {
        // Self-contained circuit: show IR only
        disassemble_circuit(path, &content, error_format)
    } else if !prove_blocks.is_empty() {
        // Mixed mode: VM bytecode + IR for each prove block
        disassemble_vm(path, &content, error_format)?;
        disassemble_prove_blocks(&prove_blocks)
    } else {
        // Pure VM: current behavior
        disassemble_vm(path, &content, error_format)
    }
}

// ---------------------------------------------------------------------------
// Detection helpers
// ---------------------------------------------------------------------------

fn has_circuit_decls(stmts: &[Stmt]) -> bool {
    stmts
        .iter()
        .any(|s| matches!(s, Stmt::PublicDecl { .. } | Stmt::WitnessDecl { .. }))
}

/// Collect `(source_text, line_number)` for every prove block in the AST.
fn collect_prove_blocks(stmts: &[Stmt]) -> Vec<(String, usize)> {
    let mut blocks = Vec::new();
    for stmt in stmts {
        collect_proves_stmt(stmt, &mut blocks);
    }
    blocks
}

fn collect_proves_stmt(stmt: &Stmt, out: &mut Vec<(String, usize)>) {
    match stmt {
        Stmt::Expr(expr) => collect_proves_expr(expr, out),
        Stmt::LetDecl { value, .. } | Stmt::MutDecl { value, .. } => {
            collect_proves_expr(value, out);
        }
        Stmt::Assignment { target, value, .. } => {
            collect_proves_expr(target, out);
            collect_proves_expr(value, out);
        }
        Stmt::FnDecl { body, .. } => collect_proves_block(body, out),
        Stmt::Print { value, .. } => collect_proves_expr(value, out),
        Stmt::Return {
            value: Some(expr), ..
        } => collect_proves_expr(expr, out),
        Stmt::Export { inner, .. } => collect_proves_stmt(inner, out),
        _ => {}
    }
}

fn collect_proves_expr(expr: &Expr, out: &mut Vec<(String, usize)>) {
    match expr {
        Expr::Prove { span, .. } => {
            out.push(("prove { ... }".to_string(), span.line_start));
        }
        Expr::BinOp { lhs, rhs, .. } => {
            collect_proves_expr(lhs, out);
            collect_proves_expr(rhs, out);
        }
        Expr::UnaryOp { operand, .. } => collect_proves_expr(operand, out),
        Expr::Call { callee, args, .. } => {
            collect_proves_expr(callee, out);
            for arg in args {
                collect_proves_expr(&arg.value, out);
            }
        }
        Expr::Index { object, index, .. } => {
            collect_proves_expr(object, out);
            collect_proves_expr(index, out);
        }
        Expr::DotAccess { object, .. } => collect_proves_expr(object, out),
        Expr::If {
            condition,
            then_block,
            else_branch,
            ..
        } => {
            collect_proves_expr(condition, out);
            collect_proves_block(then_block, out);
            if let Some(branch) = else_branch {
                match branch {
                    ElseBranch::Block(b) => collect_proves_block(b, out),
                    ElseBranch::If(e) => collect_proves_expr(e, out),
                }
            }
        }
        Expr::For { body, .. }
        | Expr::While { body, .. }
        | Expr::Forever { body, .. }
        | Expr::FnExpr { body, .. } => {
            collect_proves_block(body, out);
        }
        Expr::Block(block) => collect_proves_block(block, out),
        Expr::Array { elements, .. } => {
            for elem in elements {
                collect_proves_expr(elem, out);
            }
        }
        Expr::Map { pairs, .. } => {
            for (_, val) in pairs {
                collect_proves_expr(val, out);
            }
        }
        _ => {}
    }
}

fn collect_proves_block(block: &Block, out: &mut Vec<(String, usize)>) {
    for s in &block.stmts {
        collect_proves_stmt(s, out);
    }
}

// ---------------------------------------------------------------------------
// Circuit IR disassembly (self-contained .ach files with public/witness)
// ---------------------------------------------------------------------------

fn disassemble_circuit(path: &str, source: &str, error_format: ErrorFormat) -> Result<()> {
    let source_dir = std::path::Path::new(path)
        .parent()
        .unwrap_or(std::path::Path::new("."))
        .to_path_buf();

    let (pub_names, wit_names, mut program) =
        ir::IrLowering::lower_self_contained_with_base(source, source_dir).map_err(|e| {
            let diag = e.to_diagnostic();
            let rendered = super::render_diagnostic(&diag, source, error_format);
            anyhow::anyhow!("{rendered}")
        })?;

    ir::passes::optimize(&mut program);

    println!("== Circuit IR for {} ==", path);
    println!();

    // Inputs summary
    if !pub_names.is_empty() {
        println!("  public:  {}", pub_names.join(", "));
    }
    if !wit_names.is_empty() {
        println!("  witness: {}", wit_names.join(", "));
    }
    println!();

    // IR instructions
    print!("{program}");

    // Stats
    let n = program.instructions.len();
    let n_pub = pub_names.len();
    let n_wit = wit_names.len();
    let n_constraints = program
        .instructions
        .iter()
        .filter(|i| i.has_side_effects() && !matches!(i, ir::Instruction::Input { .. }))
        .count();
    eprintln!("{n} instructions, {} inputs ({n_pub} public, {n_wit} witness), {n_constraints} constraints", n_pub + n_wit);

    Ok(())
}

// ---------------------------------------------------------------------------
// Prove block IR dump (for mixed VM + circuit files)
// ---------------------------------------------------------------------------

fn disassemble_prove_blocks(prove_blocks: &[(String, usize)]) -> Result<()> {
    for (i, (prove_src, line)) in prove_blocks.iter().enumerate() {
        println!();
        println!(
            "  -- Circuit IR for prove block {} (line {}) --",
            i + 1,
            line
        );

        // Strip `prove` keyword — source is "prove { ... }", handler expects "{ ... }"
        let block_src = &prove_src[prove_src.find('{').unwrap_or(0)..];
        let inner = block_src
            .trim()
            .strip_prefix('{')
            .and_then(|s| s.strip_suffix('}'))
            .unwrap_or(block_src);

        match ir::IrLowering::lower_self_contained(inner) {
            Ok((_, _, mut program)) => {
                ir::passes::optimize(&mut program);
                print!("{program}");
            }
            Err(e) => {
                println!("  (failed to lower IR: {e})");
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// VM bytecode disassembly (original behavior)
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
    Ok(())
}
