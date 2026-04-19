//! Circuit boundary: `circuit name(param: Public, ...) { … }` declarations
//! and `import circuit "path" as Alias` directives.
//!
//! Both produce `global_symbols` entries whose value is a serialized ProveIR
//! blob stored in the constant pool and reloaded at runtime via `TAG_BYTES`.
//! They share `CircomImport` diagnostics, alias-conflict checks, and the
//! ProveIR → bytes encoding pipeline — hence co-located in this submodule.

use super::circom_imports;
use super::import_kind::{detect_import_kind, ImportFileKind};
use crate::codegen::Compiler;
use crate::error::{span_box, CompilerError};
use achronyme_parser::ast::*;
use memory::Value;

pub(super) fn compile_circuit_decl(
    compiler: &mut Compiler,
    name: &str,
    params: &[TypedParam],
    body: &Block,
    span: &Span,
) -> Result<(), CompilerError> {
    use achronyme_parser::ast::Visibility;
    // 1. Synthesize public/witness declarations from circuit params
    let mut stmts = Vec::new();
    for param in params {
        let ta = param.type_ann.as_ref().ok_or_else(|| {
            CompilerError::CompileError(
                format!("circuit parameter `{}` has no type annotation", param.name),
                span_box(span),
            )
        })?;
        let vis = ta.visibility.ok_or_else(|| {
            CompilerError::CompileError(
                format!(
                    "circuit parameter `{}` requires Public or Witness visibility",
                    param.name
                ),
                span_box(span),
            )
        })?;
        let decl = InputDecl {
            name: param.name.clone(),
            array_size: ta.array_size,
            type_ann: Some(ta.clone()),
        };
        match vis {
            Visibility::Public => stmts.push(Stmt::PublicDecl {
                names: vec![decl],
                span: span.clone(),
            }),
            Visibility::Witness => stmts.push(Stmt::WitnessDecl {
                names: vec![decl],
                span: span.clone(),
            }),
        }
    }
    stmts.extend(body.stmts.clone());
    let circuit_body = Block {
        stmts,
        span: body.span.clone(),
    };

    // 2. Compile to ProveIR — pass outer functions so the circuit can
    //    inline user-defined helpers from the enclosing scope, plus
    //    any circom template imports so the ProveIR compiler can
    //    resolve `Poseidon(...)(...)` / `P.Poseidon(...)(...)` calls.
    let functions = compiler
        .resolver_outer_functions
        .clone()
        .unwrap_or_else(|| compiler.fn_decl_asts.clone());
    let outer_scope = ir::prove_ir::OuterScope {
        functions,
        circom_imports: circom_imports::build_circom_imports_for_outer_scope(compiler),
        ..Default::default()
    };
    let mut prove_ir =
        ir::prove_ir::ProveIrCompiler::<memory::Bn254Fr>::compile(&circuit_body, &outer_scope)
            .map_err(|e| CompilerError::CompileError(format!("{e}"), span_box(span)))?;
    prove_ir.name = Some(name.to_string());

    // 3. Serialize to bytes
    let ir_bytes = prove_ir.to_bytes(compiler.prime_id).map_err(|e| {
        CompilerError::CompileError(format!("ProveIR serialization: {e}"), span_box(span))
    })?;

    // 4. Store bytes in constant pool and bind as global
    let handle = compiler.intern_bytes(ir_bytes);
    let val = Value::bytes(handle);
    let idx = compiler.add_constant(val)?;
    if idx > 0xFFFF {
        return Err(CompilerError::TooManyConstants(span_box(span)));
    }

    // Bind the circuit name as a global pointing to the bytes constant
    if compiler.next_global_idx == u16::MAX {
        return Err(CompilerError::TooManyConstants(span_box(span)));
    }
    let global_idx = compiler.next_global_idx;
    compiler.next_global_idx += 1;
    compiler.global_symbols.insert(
        name.to_string(),
        crate::types::GlobalEntry {
            index: global_idx,
            type_ann: None,
            is_mutable: false,
            param_names: Some(params.iter().map(|p| p.name.clone()).collect()),
        },
    );

    // Emit: load the bytes constant into a register, then define as global
    let reg = compiler.alloc_reg()?;
    compiler.emit_abx(akron::opcode::OpCode::LoadConst, reg, idx as u16)?;
    compiler.emit_abx(akron::opcode::OpCode::DefGlobalLet, reg, global_idx)?;
    compiler.free_reg(reg)?;

    Ok(())
}

pub(super) fn compile_import_circuit(
    compiler: &mut Compiler,
    path: &str,
    alias: &str,
    span: &Span,
) -> Result<(), CompilerError> {
    if detect_import_kind(path) == ImportFileKind::Circom {
        return circom_imports::full_circuit(compiler, path, alias, span);
    }

    // 1. Resolve path relative to base_path
    let base = compiler
        .base_path
        .clone()
        .unwrap_or_else(|| std::path::PathBuf::from("."));
    let full_path = base.join(path);

    if !full_path.exists() {
        return Err(CompilerError::CompileError(
            format!("circuit file not found: {}", full_path.display()),
            span_box(span),
        ));
    }

    // 2. Read circuit source
    let source = std::fs::read_to_string(&full_path).map_err(|e| {
        CompilerError::CompileError(
            format!("cannot read circuit file {}: {e}", full_path.display()),
            span_box(span),
        )
    })?;

    // 3. Compile to ProveIR via compile_circuit (self-contained)
    let mut prove_ir = ir::prove_ir::ProveIrCompiler::<memory::Bn254Fr>::compile_circuit(
        &source,
        Some(&full_path),
    )
    .map_err(|e| CompilerError::CompileError(format!("{e}"), span_box(span)))?;
    prove_ir.name = Some(alias.to_string());

    // 4. Serialize to bytes
    let ir_bytes = prove_ir.to_bytes(compiler.prime_id).map_err(|e| {
        CompilerError::CompileError(format!("ProveIR serialization: {e}"), span_box(span))
    })?;

    // 5. Store bytes in constant pool and bind alias as global
    let handle = compiler.intern_bytes(ir_bytes);
    let val = Value::bytes(handle);
    let idx = compiler.add_constant(val)?;
    if idx > 0xFFFF {
        return Err(CompilerError::TooManyConstants(span_box(span)));
    }

    if compiler.next_global_idx == u16::MAX {
        return Err(CompilerError::TooManyConstants(span_box(span)));
    }
    let global_idx = compiler.next_global_idx;
    compiler.next_global_idx += 1;
    let circuit_param_names: Vec<String> = prove_ir
        .public_inputs
        .iter()
        .chain(prove_ir.witness_inputs.iter())
        .map(|input| input.name.clone())
        .collect();
    compiler.global_symbols.insert(
        alias.to_string(),
        crate::types::GlobalEntry {
            index: global_idx,
            type_ann: None,
            is_mutable: false,
            param_names: Some(circuit_param_names),
        },
    );

    let reg = compiler.alloc_reg()?;
    compiler.emit_abx(akron::opcode::OpCode::LoadConst, reg, idx as u16)?;
    compiler.emit_abx(akron::opcode::OpCode::DefGlobalLet, reg, global_idx)?;
    compiler.free_reg(reg)?;

    Ok(())
}
