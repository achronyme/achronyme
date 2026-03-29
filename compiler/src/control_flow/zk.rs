use crate::codegen::Compiler;
use crate::error::{span_box, CompilerError};
use crate::expressions::ExpressionCompiler;
use crate::scopes::ScopeCompiler;
use achronyme_parser::ast::*;
use memory::Value;
use vm::opcode::OpCode;

/// Search all compiler scopes (locals and globals) for a variable with the
/// given name that has an array type annotation. Returns the array size if found.
fn find_array_size(compiler: &Compiler, name: &str) -> Option<usize> {
    // Search current function scope first
    if let Ok(func) = compiler.current_ref() {
        for local in func.locals.iter().rev() {
            if local.name == name {
                return local.type_ann.as_ref().and_then(|ta| ta.array_len());
            }
        }
    }
    // Search enclosing scopes (upvalue chain)
    for fc in compiler.compilers.iter().rev().skip(1) {
        for local in fc.locals.iter().rev() {
            if local.name == name {
                return local.type_ann.as_ref().and_then(|ta| ta.array_len());
            }
        }
    }
    // Search globals
    if let Some(entry) = compiler.global_symbols.get(name) {
        return entry.type_ann.as_ref().and_then(|ta| ta.array_len());
    }
    None
}

/// Check if `name` is an element of a known outer-scope array (type-directed).
///
/// Returns the parent array name if `name` matches `{parent}_{index}` where
/// `parent` is an `OuterScopeEntry::Array(n)` with `index < n`.
/// This is NOT a naming-convention heuristic — it uses the enriched outer_scope
/// as ground truth, so `player_1` won't be falsely matched.
fn find_array_parent(
    name: &str,
    outer_scope: &std::collections::HashMap<String, ir::prove_ir::OuterScopeEntry>,
) -> Option<String> {
    if let Some(pos) = name.rfind('_') {
        let parent = &name[..pos];
        let suffix = &name[pos + 1..];
        if let Ok(idx) = suffix.parse::<usize>() {
            if let Some(ir::prove_ir::OuterScopeEntry::Array(n)) = outer_scope.get(parent) {
                if idx < *n {
                    return Some(parent.to_string());
                }
            }
        }
    }
    None
}

pub(super) fn compile_prove(
    compiler: &mut Compiler,
    body: &Block,
    params: &[TypedParam],
    name: Option<&str>,
) -> Result<u8, CompilerError> {
    // 1. Collect outer scope names for ProveIR capture detection.
    //    Include locals from ALL enclosing function scopes (not just current),
    //    so that upvalue-accessible variables are visible to ProveIR.
    //    Type annotations are propagated so ProveIR knows about arrays.
    let mut outer_values: std::collections::HashMap<String, ir::prove_ir::OuterScopeEntry> =
        std::collections::HashMap::new();
    let to_scope_entry = |ta: &Option<TypeAnnotation>| -> ir::prove_ir::OuterScopeEntry {
        match ta.as_ref().and_then(|t| t.array_len()) {
            Some(n) => ir::prove_ir::OuterScopeEntry::Array(n),
            None => ir::prove_ir::OuterScopeEntry::Scalar,
        }
    };
    if let Ok(func) = compiler.current_ref() {
        for local in &func.locals {
            outer_values.insert(local.name.clone(), to_scope_entry(&local.type_ann));
        }
    }
    for fc in &compiler.compilers[..compiler.compilers.len().saturating_sub(1)] {
        for local in &fc.locals {
            outer_values
                .entry(local.name.clone())
                .or_insert_with(|| to_scope_entry(&local.type_ann));
        }
    }
    // Global symbols — read type annotations from GlobalEntry
    for (gname, gentry) in &compiler.global_symbols {
        if gentry.index >= vm::specs::USER_GLOBAL_START && !gname.contains("::") {
            outer_values
                .entry(gname.clone())
                .or_insert_with(|| to_scope_entry(&gentry.type_ann));
        }
    }

    let outer_scope = ir::prove_ir::OuterScope {
        values: outer_values,
        functions: compiler.fn_decl_asts.clone(),
    };

    // 2. If params are provided (new syntax), validate no old-style
    //    declarations in the body and synthesize PublicDecl stmts.
    let compile_body = if !params.is_empty() {
        // Validate: no old-style public/witness declarations in body
        for stmt in &body.stmts {
            if matches!(stmt, Stmt::PublicDecl { .. } | Stmt::WitnessDecl { .. }) {
                return Err(CompilerError::CompileError(
                    "cannot mix prove(...) parameter syntax with explicit \
                     public/witness declarations inside the block"
                        .into(),
                    compiler.cur_span(),
                ));
            }
        }

        // Synthesize PublicDecl stmts from typed params.
        // Read array_size from the param's type_ann, falling back to outer scope.
        let mut stmts = Vec::new();
        for param in params {
            let ta = param.type_ann.as_ref();
            let array_size = ta
                .and_then(|t| t.array_size)
                .or_else(|| find_array_size(compiler, &param.name));
            stmts.push(Stmt::PublicDecl {
                names: vec![InputDecl {
                    name: param.name.clone(),
                    array_size,
                    type_ann: ta.cloned(),
                }],
                span: body.span.clone(),
            });
        }
        stmts.extend(body.stmts.clone());
        Block {
            stmts,
            span: body.span.clone(),
        }
    } else {
        body.clone()
    };

    // 3. Compile AST Block -> ProveIR template.
    let mut prove_ir = ir::prove_ir::ProveIrCompiler::compile(&compile_body, &outer_scope)
        .map_err(|e| CompilerError::CompileError(format!("{e}"), compiler.cur_span()))?;
    prove_ir.name = name.map(|n| n.to_string());

    // 4. Build capture name list: captures + public inputs + witness inputs.
    //    All values come from the outer scope at runtime.
    //
    //    For array captures/inputs, push the ORIGINAL array name (not
    //    expanded element names) — the VM handler expands TAG_LIST values
    //    into individual scalar entries at runtime.
    let mut capture_names: Vec<String> = Vec::new();
    let mut emitted_arrays: std::collections::HashSet<String> = std::collections::HashSet::new();

    for cap in &prove_ir.captures {
        if let Some(parent) = find_array_parent(&cap.name, &outer_scope.values) {
            // Array element capture — load the parent array once
            if emitted_arrays.insert(parent.clone()) {
                capture_names.push(parent);
            }
        } else {
            capture_names.push(cap.name.clone());
        }
    }
    for input in &prove_ir.public_inputs {
        match &input.array_size {
            Some(ir::prove_ir::ArraySize::Literal(_)) => {
                // Array input from outer scope — load the whole list
                if emitted_arrays.insert(input.name.clone()) {
                    capture_names.push(input.name.clone());
                }
            }
            None => capture_names.push(input.name.clone()),
            Some(ir::prove_ir::ArraySize::Capture(_)) => {
                return Err(CompilerError::CompileError(
                    "capture-sized arrays in prove blocks are not yet supported".into(),
                    compiler.cur_span(),
                ));
            }
        }
    }
    for input in &prove_ir.witness_inputs {
        match &input.array_size {
            Some(ir::prove_ir::ArraySize::Literal(_)) => {
                if emitted_arrays.insert(input.name.clone()) {
                    capture_names.push(input.name.clone());
                }
            }
            None => capture_names.push(input.name.clone()),
            Some(ir::prove_ir::ArraySize::Capture(_)) => {
                return Err(CompilerError::CompileError(
                    "capture-sized arrays in prove blocks are not yet supported".into(),
                    compiler.cur_span(),
                ));
            }
        }
    }

    let count = capture_names.len();
    if count > 127 {
        return Err(CompilerError::CompilerLimitation(
            "prove block captures too many variables".into(),
            compiler.cur_span(),
        ));
    }

    // 4. Build capture map from scope values (same codegen as before).
    let map_reg = compiler.alloc_reg()?;

    if count > 0 {
        let start_reg = compiler.alloc_contiguous((count * 2) as u8)?;

        for (i, cap_name) in capture_names.iter().enumerate() {
            let key_reg = start_reg + (i as u8 * 2);
            let val_reg = key_reg + 1;

            let key_handle = compiler.intern_string(cap_name);
            let key_val = Value::string(key_handle);
            let key_idx = compiler.add_constant(key_val)?;
            if key_idx > 0xFFFF {
                return Err(CompilerError::TooManyConstants(compiler.cur_span()));
            }
            compiler.emit_abx(OpCode::LoadConst, key_reg, key_idx as u16)?;

            if let Some((idx, local_reg)) = compiler.resolve_local(cap_name) {
                compiler.current()?.locals[idx].is_read = true;
                compiler.emit_abc(OpCode::Move, val_reg, local_reg, 0)?;
            } else if let Some(upval_idx) =
                compiler.resolve_upvalue(compiler.compilers.len() - 1, cap_name)
            {
                compiler.emit_abx(OpCode::GetUpvalue, val_reg, upval_idx as u16)?;
            } else if let Some(global_entry) = compiler.global_symbols.get(cap_name) {
                let global_idx = global_entry.index;
                if compiler.imported_names.contains_key(cap_name) {
                    compiler.used_imported_names.insert(cap_name.to_string());
                }
                compiler.emit_abx(OpCode::GetGlobal, val_reg, global_idx)?;
            } else {
                return Err(CompilerError::CompileError(
                    format!("prove: variable `{cap_name}` not found in scope"),
                    compiler.cur_span(),
                ));
            }
        }

        compiler.emit_abc(OpCode::BuildMap, map_reg, start_reg, count as u8)?;

        for _ in 0..(count * 2) {
            let top = compiler.current()?.reg_top - 1;
            compiler.free_reg(top)?;
        }
    } else {
        let start = compiler.current()?.reg_top;
        compiler.emit_abc(OpCode::BuildMap, map_reg, start, 0)?;
    }

    // 5. Serialize ProveIR and store as bytes constant.
    let ir_bytes = prove_ir.to_bytes().map_err(|e| {
        CompilerError::CompileError(format!("ProveIR serialization: {e}"), compiler.cur_span())
    })?;
    let ir_handle = compiler.intern_bytes(ir_bytes);
    let ir_val = Value::bytes(ir_handle);
    let ir_idx = compiler.add_constant(ir_val)?;
    if ir_idx > 0xFFFF {
        return Err(CompilerError::TooManyConstants(compiler.cur_span()));
    }

    // 6. Emit Prove R[map_reg], K[ir_idx]
    compiler.emit_abx(OpCode::Prove, map_reg, ir_idx as u16)?;

    Ok(map_reg)
}

pub(super) fn compile_circuit_call(
    compiler: &mut Compiler,
    name: &str,
    args: &[(String, Expr)],
    span: &Span,
) -> Result<u8, CompilerError> {
    // 1. Resolve the circuit name to its global index (contains ProveIR bytes)
    let global_idx = compiler
        .global_symbols
        .get(name)
        .ok_or_else(|| {
            CompilerError::CompileError(format!("circuit `{name}` not found"), span_box(span))
        })?
        .index;

    // 2. Load the ProveIR bytes from the global into a register
    let ir_reg = compiler.alloc_reg()?;
    compiler.emit_abx(OpCode::GetGlobal, ir_reg, global_idx)?;

    // 3. Store the bytes as a constant (we need its index for the Prove opcode)
    //    The global already holds a Value::bytes — we need to get it into the
    //    constant pool. We load it into a register and then pass its constant
    //    index via GetGlobal. But Prove expects K[bx] = bytes constant.
    //    Approach: store the constant index at circuit-decl time, and here we
    //    look it up. Alternatively, emit the bytes constant index directly.
    //    Simplest: search constants for the bytes value matching this global.

    // Actually, the Prove opcode reads bytes from constants[bx]. We need the
    // constant index of the ProveIR bytes. Since the circuit decl stored the
    // bytes as a constant AND as a global, we can find the constant by scanning.
    // But that's fragile. Better approach: use the ir_reg to pass the bytes
    // directly to a new opcode pattern.
    //
    // Simplest working approach: the circuit call builds a map + emits Prove
    // using the same constant index the circuit decl used. We need to recover
    // that index. The global stores a Value::bytes(handle), and we interned
    // that bytes with a specific constant index.
    //
    // For now: find the bytes constant that matches. Since globals store
    // Value::bytes(handle), and the constant pool also has Value::bytes(handle)
    // with the same handle, we can find it.

    compiler.free_reg(ir_reg)?;

    // Search the constant pool for the bytes value stored at this global
    // The circuit decl stored: constants[idx] = Value::bytes(handle), global = same
    // We need `idx`.
    let ir_idx = compiler
        .current()?
        .constants
        .iter()
        .position(|c| c.is_bytes())
        .ok_or_else(|| {
            CompilerError::CompileError(
                format!("circuit `{name}` has no ProveIR constant in pool"),
                span_box(span),
            )
        })? as u16;

    // 3. Validate keyword argument names against circuit parameter names
    if let Some(entry) = compiler.global_symbols.get(name) {
        if let Some(ref declared_params) = entry.param_names {
            for (arg_name, _) in args {
                if !declared_params.contains(arg_name) {
                    let suggestion = crate::suggest::find_similar(
                        arg_name,
                        declared_params.iter().map(|s| s.as_str()),
                        2,
                    );
                    let mut msg =
                        format!("unknown keyword argument `{arg_name}` in call to `{name}`");
                    if let Some(did_you_mean) = suggestion {
                        msg.push_str(&format!("; did you mean `{did_you_mean}`?"));
                    }
                    return Err(CompilerError::CompileError(msg, span_box(span)));
                }
            }
        }
    }

    // 4. Build the keyword argument map: { "key1": val1, "key2": val2, ... }
    let count = args.len();
    if count > 127 {
        return Err(CompilerError::CompilerLimitation(
            "circuit call has too many arguments".into(),
            span_box(span),
        ));
    }

    let map_reg = compiler.alloc_reg()?;

    if count > 0 {
        let start_reg = compiler.alloc_contiguous((count * 2) as u8)?;

        for (i, (key, val_expr)) in args.iter().enumerate() {
            let key_reg = start_reg + (i as u8 * 2);
            let val_reg = key_reg + 1;

            // Key: string constant
            let key_handle = compiler.intern_string(key);
            let key_val = Value::string(key_handle);
            let key_idx = compiler.add_constant(key_val)?;
            if key_idx > 0xFFFF {
                return Err(CompilerError::TooManyConstants(span_box(span)));
            }
            compiler.emit_abx(OpCode::LoadConst, key_reg, key_idx as u16)?;

            // Value: compile expression
            let compiled_reg = compiler.compile_expr(val_expr)?;
            compiler.emit_abc(OpCode::Move, val_reg, compiled_reg, 0)?;
            compiler.free_reg(compiled_reg)?;
        }

        compiler.emit_abc(OpCode::BuildMap, map_reg, start_reg, count as u8)?;

        for _ in 0..(count * 2) {
            let top = compiler.current()?.reg_top - 1;
            compiler.free_reg(top)?;
        }
    } else {
        let start = compiler.current()?.reg_top;
        compiler.emit_abc(OpCode::BuildMap, map_reg, start, 0)?;
    }

    // 4. Emit Prove R[map_reg], K[ir_idx]
    compiler.emit_abx(OpCode::Prove, map_reg, ir_idx)?;

    Ok(map_reg)
}
