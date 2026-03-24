use crate::codegen::Compiler;
use crate::control_flow::ControlFlowCompiler;
use crate::error::CompilerError;
use crate::expressions::ExpressionCompiler;
use crate::scopes::ScopeCompiler;
use crate::types::{Local, LoopContext};
use achronyme_parser::ast::*;
use memory::Value;
use vm::opcode::OpCode;

pub(super) fn enter_loop(compiler: &mut Compiler, start_label: usize) -> Result<(), CompilerError> {
    let depth = compiler.current()?.scope_depth;
    compiler.current()?.loop_stack.push(LoopContext {
        scope_depth: depth,
        start_label,
        break_jumps: Vec::new(),
    });
    Ok(())
}

pub(super) fn exit_loop(compiler: &mut Compiler) -> Result<(), CompilerError> {
    let loop_ctx = compiler
        .current()?
        .loop_stack
        .pop()
        .ok_or_else(|| CompilerError::InternalError("loop stack underflow".into()))?;
    for jump_idx in loop_ctx.break_jumps {
        compiler.patch_jump(jump_idx)?;
    }
    Ok(())
}

pub(super) fn compile_for(
    compiler: &mut Compiler,
    var: &str,
    iterable: &ForIterable,
    body: &Block,
) -> Result<u8, CompilerError> {
    let iter_src_reg = match iterable {
        ForIterable::Expr(expr) => compiler.compile_expr(expr)?,
        ForIterable::Range { start, end } => {
            // Build a list [start, start+1, ..., end-1] for the VM iterator
            let count = if *end >= *start {
                (end - start) as usize
            } else {
                0
            };
            if count > 255 {
                return Err(CompilerError::CompilerLimitation(
                    "for..in range with more than 255 iterations; use a while loop instead".into(),
                    compiler.cur_span(),
                ));
            }

            let list_reg = compiler.alloc_reg()?;
            let start_elem = compiler.current()?.reg_top;

            for i in *start..*end {
                let r = compiler.alloc_reg()?;
                let ci = compiler.add_constant(Value::int(i as i64))?;
                if ci > 0xFFFF {
                    return Err(CompilerError::TooManyConstants(compiler.cur_span()));
                }
                compiler.emit_abx(OpCode::LoadConst, r, ci as u16)?;
            }

            compiler.emit_abc(OpCode::BuildList, list_reg, start_elem, count as u8)?;

            for _ in 0..count {
                let top = compiler.current()?.reg_top - 1;
                compiler.free_reg(top)?;
            }

            list_reg
        }
    };

    let iter_reg = compiler.alloc_contiguous(2)?;
    let val_reg = iter_reg + 1;

    compiler.emit_abc(OpCode::GetIter, iter_reg, iter_src_reg, 0)?;

    let start_label = compiler.current()?.bytecode.len();
    compiler.enter_loop(start_label)?;

    let jump_exit_idx = compiler.emit_jump(OpCode::ForIter, iter_reg)?;

    compiler.begin_scope()?;
    let depth = compiler.current()?.scope_depth;
    let var_span = compiler.current_span.clone();
    compiler.current()?.locals.push(Local {
        name: var.to_string(),
        depth,
        is_captured: false,
        is_mutable: false,
        is_read: false,
        is_mutated: false,
        reg: val_reg,
        span: var_span,
        type_ann: None,
    });

    let body_target = compiler.alloc_reg()?;
    compiler.compile_block(body, body_target)?;
    compiler.free_reg(body_target)?;

    compiler.emit_abx(OpCode::Jump, 0, start_label as u16)?;

    compiler.patch_jump(jump_exit_idx)?;

    compiler.end_scope()?;

    compiler.exit_loop()?;

    compiler.free_reg(iter_reg)?;
    compiler.free_reg(iter_src_reg)?;

    let target_reg = compiler.alloc_reg()?;
    compiler.emit_abx(OpCode::LoadNil, target_reg, 0)?;
    Ok(target_reg)
}

pub(super) fn compile_forever(compiler: &mut Compiler, body: &Block) -> Result<u8, CompilerError> {
    let start_label = compiler.current()?.bytecode.len();
    compiler.enter_loop(start_label)?;

    let body_reg = compiler.alloc_reg()?;
    compiler.compile_block(body, body_reg)?;
    compiler.free_reg(body_reg)?;

    compiler.emit_abx(OpCode::Jump, 0, start_label as u16)?;

    compiler.exit_loop()?;

    let target_reg = compiler.alloc_reg()?;
    compiler.emit_abx(OpCode::LoadNil, target_reg, 0)?;
    Ok(target_reg)
}

pub(super) fn compile_while(
    compiler: &mut Compiler,
    condition: &Expr,
    body: &Block,
) -> Result<u8, CompilerError> {
    let start_label = compiler.current()?.bytecode.len();

    let cond_reg = compiler.compile_expr(condition)?;

    let jump_end = compiler.emit_jump(OpCode::JumpIfFalse, cond_reg)?;

    compiler.free_reg(cond_reg)?;

    compiler.enter_loop(start_label)?;

    let body_reg = compiler.alloc_reg()?;
    compiler.compile_block(body, body_reg)?;
    compiler.free_reg(body_reg)?;

    compiler.emit_abx(OpCode::Jump, 0, start_label as u16)?;

    compiler.patch_jump(jump_end)?;

    compiler.exit_loop()?;

    let target_reg = compiler.alloc_reg()?;
    compiler.emit_abx(OpCode::LoadNil, target_reg, 0)?;

    Ok(target_reg)
}
