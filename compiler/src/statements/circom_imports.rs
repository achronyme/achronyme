//! Dispatch handlers for `.circom` imports in the Achronyme compiler.
//!
//! When an `.ach` file imports a `.circom` file, the three existing
//! import forms route here instead of the native module loader:
//!
//! - `import "x.circom" as P` → [`namespace`] (compile-time only,
//!   no VM bytecode)
//! - `import { T1, T2 } from "x.circom"` → [`selective`]
//!   (compile-time only)
//! - `import circuit "x.circom" as C` → [`full_circuit`] (lowers to a
//!   complete ProveIR, serializes as bytes, binds alias as a runtime
//!   global)
//!
//! These are `pub(super)` and called from the trait impl in
//! [`super`] via the [`super::detect_import_kind`] dispatch.

use std::path::Path;
use std::sync::Arc;

use achronyme_parser::ast::Span;
use memory::Value;
use vm::opcode::OpCode;

use crate::codegen::Compiler;
use crate::error::{span_box, CompilerError};

/// Dispatch point for `import "x.circom" as P` — namespace-mode
/// import of a Circom library. This is compile-time only: no VM
/// bytecode is emitted here and the alias is **not** registered as
/// a runtime global. References inside `prove {}` / `circuit {}`
/// blocks or VM expressions are resolved later by pattern-matching
/// `Call { callee: Call { ... } }` against the namespace table
/// (Phase 3).
pub(super) fn namespace(
    compiler: &mut Compiler,
    path: &str,
    alias: &str,
    span: &Span,
) -> Result<(), CompilerError> {
    // 1. Resolve path relative to the current base_path (same
    //    convention as .ach imports). Circom `include` resolution
    //    inside the library itself uses compiler.circom_lib_dirs as
    //    extra search roots.
    let base = compiler
        .base_path
        .clone()
        .unwrap_or_else(|| Path::new(".").to_path_buf());
    let resolved = base.join(path);
    if !resolved.exists() {
        return Err(CompilerError::ModuleNotFound(
            format!(
                "circom file not found: {} (resolved from {})",
                path,
                base.display()
            ),
            span_box(span),
        ));
    }
    let canonical = resolved.canonicalize().map_err(|e| {
        CompilerError::CompileError(
            format!(
                "cannot canonicalize circom path {}: {e}",
                resolved.display()
            ),
            span_box(span),
        )
    })?;

    // 2. Reject a duplicate alias with a conflicting target (mirrors
    //    .ach imports). Re-importing the same path under the same
    //    alias is idempotent.
    if let Some(existing) = compiler.circom_namespaces.get(alias) {
        if existing.source_path != canonical {
            return Err(CompilerError::DuplicateModuleAlias(
                alias.to_string(),
                span_box(span),
            ));
        }
        return Ok(());
    }
    // An alias that's already used by a native module is also a
    // conflict.
    if compiler.imported_aliases.contains_key(alias) {
        return Err(CompilerError::DuplicateModuleAlias(
            alias.to_string(),
            span_box(span),
        ));
    }

    // 3. Load the library via the circom crate's public API.
    let library =
        circom::compile_template_library(&canonical, &compiler.circom_lib_dirs).map_err(|e| {
            let mut msg = format!("failed to load circom library `{}`: {e}", path);
            // Surface inner diagnostic messages when available (parse
            // / constraint errors from the circom frontend).
            for diag in e.to_diagnostics() {
                msg.push_str(&format!("\n  - {}", diag.message));
            }
            CompilerError::CompileError(msg, span_box(span))
        })?;

    // 4. Surface library-load warnings to the compiler's diagnostic
    //    channel so the user sees circom W101/W103/etc. rather than
    //    them being silently dropped at the import boundary.
    for warn in &library.warnings {
        compiler.emit_warning(warn.clone());
    }

    compiler
        .circom_namespaces
        .insert(alias.to_string(), Arc::new(library));

    Ok(())
}

/// Dispatch point for `import { T1, T2 } from "x.circom"` — selective
/// import of named templates from a Circom library. Like namespace
/// imports this is compile-time only: the template names are
/// registered in `circom_template_aliases` but no VM bytecode or
/// global_symbols entries are emitted. Phase 3 resolves
/// `Call { callee: Ident(T1), ... }` against the alias table.
pub(super) fn selective(
    compiler: &mut Compiler,
    names: &[String],
    path: &str,
    span: &Span,
) -> Result<(), CompilerError> {
    // 1. Resolve the path (same convention as namespace imports).
    let base = compiler
        .base_path
        .clone()
        .unwrap_or_else(|| Path::new(".").to_path_buf());
    let resolved = base.join(path);
    if !resolved.exists() {
        return Err(CompilerError::ModuleNotFound(
            format!(
                "circom file not found: {} (resolved from {})",
                path,
                base.display()
            ),
            span_box(span),
        ));
    }
    let canonical = resolved.canonicalize().map_err(|e| {
        CompilerError::CompileError(
            format!(
                "cannot canonicalize circom path {}: {e}",
                resolved.display()
            ),
            span_box(span),
        )
    })?;

    // 2. Reuse an already-loaded library if the same path has been
    //    imported (possibly via a different alias or a previous
    //    selective-import call). Otherwise load fresh and surface
    //    its warnings to the compiler's diagnostic channel.
    let library_arc = if let Some(existing) = compiler
        .circom_namespaces
        .values()
        .find(|lib| lib.source_path == canonical)
        .cloned()
    {
        existing
    } else {
        let fresh = circom::compile_template_library(&canonical, &compiler.circom_lib_dirs)
            .map_err(|e| {
                let mut msg = format!("failed to load circom library `{}`: {e}", path);
                for diag in e.to_diagnostics() {
                    msg.push_str(&format!("\n  - {}", diag.message));
                }
                CompilerError::CompileError(msg, span_box(span))
            })?;
        for warn in &fresh.warnings {
            compiler.emit_warning(warn.clone());
        }
        Arc::new(fresh)
    };

    // 3. Validate every requested name is declared by the library.
    //    Surface did-you-mean suggestions using the same Levenshtein
    //    helper as the .ach selective import path.
    for name in names {
        if library_arc.template(name).is_none() {
            let available: Vec<&str> = library_arc.template_names().collect();
            let suggestion = crate::suggest::find_similar(name, available.iter().copied(), 2);
            let mut msg = format!(
                "circom file \"{}\" does not declare template `{}`",
                path, name
            );
            if let Some(s) = suggestion {
                msg.push_str(&format!(". Did you mean `{s}`?"));
            }
            return Err(CompilerError::CompileError(msg, span_box(span)));
        }
    }

    // 4. Conflict detection: reject if the unqualified name is
    //    already bound — as a global, as a selective .ach import,
    //    or as a previously-imported circom template from a
    //    different library.
    for name in names {
        if compiler.global_symbols.contains_key(name) {
            return Err(CompilerError::CompileError(
                format!(
                    "cannot import `{}`: a global with this name already exists",
                    name
                ),
                span_box(span),
            ));
        }
        if let Some((existing_lib, existing_name)) = compiler.circom_template_aliases.get(name) {
            if existing_lib.source_path != canonical || existing_name != name {
                return Err(CompilerError::CompileError(
                    format!(
                        "`{}` already imported from \"{}\"",
                        name,
                        existing_lib.source_path.display()
                    ),
                    span_box(span),
                ));
            }
            // Same origin: idempotent re-import.
            continue;
        }
        if let Some((existing_path, _)) = compiler.imported_names.get(name) {
            return Err(CompilerError::CompileError(
                format!(
                    "`{}` already imported from \"{}\"",
                    name,
                    existing_path.display()
                ),
                span_box(span),
            ));
        }
    }

    // 5. Register the aliases.
    for name in names {
        compiler
            .circom_template_aliases
            .entry(name.clone())
            .or_insert_with(|| (library_arc.clone(), name.clone()));
    }

    Ok(())
}

/// Dispatch point for `import circuit "x.circom" as C` — full-circuit
/// embed of a `.circom` file that MUST declare `component main = ...`.
/// The file is lowered through the circom frontend to a complete
/// ProveIR, serialized as bytes, and bound to `alias` as a runtime
/// global (same shape the native .ach `import circuit` uses).
pub(super) fn full_circuit(
    compiler: &mut Compiler,
    path: &str,
    alias: &str,
    span: &Span,
) -> Result<(), CompilerError> {
    // 1. Resolve the path against base_path.
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

    // 2. Compile the circom file — must have `component main`.
    let result = circom::compile_file(&full_path, &compiler.circom_lib_dirs).map_err(|e| {
        let mut msg = format!("failed to compile circom circuit `{}`: {e}", path);
        for diag in e.to_diagnostics() {
            msg.push_str(&format!("\n  - {}", diag.message));
        }
        CompilerError::CompileError(msg, span_box(span))
    })?;
    let mut prove_ir = result.prove_ir;
    prove_ir.name = Some(alias.to_string());

    // 3. Serialize ProveIR → bytes (mirrors the .ach import circuit
    //    path).
    let ir_bytes = prove_ir.to_bytes(compiler.prime_id).map_err(|e| {
        CompilerError::CompileError(format!("ProveIR serialization: {e}"), span_box(span))
    })?;

    // 4. Store bytes + bind the alias as a global.
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
    compiler.emit_abx(OpCode::LoadConst, reg, idx as u16)?;
    compiler.emit_abx(OpCode::DefGlobalLet, reg, global_idx)?;
    compiler.free_reg(reg)?;

    Ok(())
}
