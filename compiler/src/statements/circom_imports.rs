//! Dispatch handlers for `.circom` imports in the Achronyme compiler.
//!
//! When an `.ach` file imports a `.circom` file, the three existing
//! import forms route here instead of the native module loader:
//!
//! - `import "x.circom" as P` → [`namespace`] (compile-time only,
//!   no VM bytecode)
//! - `import { T1, T2 } from "x.circom"` → [`selective`]
//!   (compile-time only)
//! - `import circuit "x.circom" as C` → [`full_circuit`] (lowers to
//!   a complete ProveIR, serializes as bytes, binds alias as a
//!   runtime global)
//!
//! All three share a common prefix (path resolution + alias conflict
//! checks) extracted into private helpers so a bug fix or behavior
//! tweak lives in exactly one place.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use achronyme_parser::ast::Span;
use ir::prove_ir::{CircomCallable, CircomLibraryHandle};
use memory::Value;
use vm::opcode::OpCode;

use crate::codegen::Compiler;
use crate::error::{span_box, CompilerError};

/// Flatten all circom imports registered on `compiler` into the
/// dispatcher key format expected by [`ir::prove_ir::OuterScope::circom_imports`].
///
/// Selective imports contribute one entry per template under their
/// bare name (`"Poseidon"`). Namespace imports (`import "x.circom" as P`)
/// contribute one entry per template in the library under the
/// `"P::TemplateName"` key — the flattening happens here rather than
/// in the ProveIR compiler so the lookup path at call time stays a
/// single `HashMap::get` instead of a two-step namespace + template
/// resolution.
///
/// Runs every time a prove/circuit block is about to be compiled,
/// which is O(total_templates_across_namespaces). This is cheap in
/// practice (real-world circomlib libraries expose tens of templates,
/// not thousands) and keeps the table immutable-once-built.
pub(crate) fn build_circom_imports_for_outer_scope(
    compiler: &Compiler,
) -> HashMap<String, CircomCallable> {
    let mut out: HashMap<String, CircomCallable> = HashMap::new();

    // Selective imports: `import { Poseidon } from "x.circom"`
    // → "Poseidon" → (library, "Poseidon").
    for (name, lib) in &compiler.circom_template_aliases {
        let handle: Arc<dyn CircomLibraryHandle> = lib.clone();
        out.insert(
            name.clone(),
            CircomCallable {
                library: handle,
                template_name: name.clone(),
            },
        );
    }

    // Namespace imports: `import "x.circom" as P`
    // → one "P::T" entry per template T in the library.
    for (alias, lib) in &compiler.circom_namespaces {
        let handle: Arc<dyn CircomLibraryHandle> = lib.clone();
        for template_name in CircomLibraryHandle::template_names(&**lib) {
            let key = format!("{alias}::{template_name}");
            out.insert(
                key,
                CircomCallable {
                    library: handle.clone(),
                    template_name,
                },
            );
        }
    }

    out
}

/// Resolve an import path relative to the compiler's current
/// `base_path`, verify it exists, and canonicalize it. Returns a
/// uniform [`CompilerError::ModuleNotFound`] on failure so every
/// `.circom` import surface reports the missing file the same way.
fn resolve_circom_path(
    compiler: &Compiler,
    path: &str,
    span: &Span,
) -> Result<PathBuf, CompilerError> {
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
    resolved.canonicalize().map_err(|e| {
        CompilerError::CompileError(
            format!(
                "cannot canonicalize circom path {}: {e}",
                resolved.display()
            ),
            span_box(span),
        )
    })
}

/// Reject an alias that is already bound in any of the compiler's
/// symbol tables:
///
/// - native + user globals (`global_symbols`)
/// - native `.ach` module aliases (`imported_aliases`)
/// - circom namespaces (`circom_namespaces`)
/// - circom template aliases from selective imports
///   (`circom_template_aliases`)
///
/// Callers that support idempotent re-import (e.g. the namespace path
/// re-importing the same `.circom` file under the same alias) should
/// handle that case BEFORE calling this helper.
fn check_alias_conflict(
    compiler: &Compiler,
    alias: &str,
    span: &Span,
) -> Result<(), CompilerError> {
    if compiler.circom_namespaces.contains_key(alias)
        || compiler.circom_template_aliases.contains_key(alias)
        || compiler.imported_aliases.contains_key(alias)
        || compiler.global_symbols.contains_key(alias)
    {
        return Err(CompilerError::DuplicateModuleAlias(
            alias.to_string(),
            span_box(span),
        ));
    }
    Ok(())
}

/// Load a circom library, surfacing any failure through
/// [`CompilerError::CircomImport`] with full structured diagnostics
/// rather than the flattened string form the original code used.
fn load_library_or_error(
    compiler: &Compiler,
    canonical: &Path,
    path: &str,
    span: &Span,
) -> Result<circom::CircomLibrary, CompilerError> {
    circom::compile_template_library(canonical, &compiler.circom_lib_dirs).map_err(|e| {
        CompilerError::CircomImport {
            path: PathBuf::from(path),
            diagnostics: e.to_diagnostics(),
            span: span_box(span),
        }
    })
}

/// Dispatch point for `import "x.circom" as P`.
///
/// Compile-time only: no VM bytecode is emitted and the alias is
/// **not** registered as a runtime global. References inside `prove {}`
/// / `circuit {}` blocks or VM expressions are resolved later by
/// pattern-matching against the namespace table (Phase 3).
pub(super) fn namespace(
    compiler: &mut Compiler,
    path: &str,
    alias: &str,
    span: &Span,
) -> Result<(), CompilerError> {
    let canonical = resolve_circom_path(compiler, path, span)?;

    // Idempotent re-import: same alias pointing at the same canonical
    // path is a no-op. A mismatched target falls through to
    // check_alias_conflict which raises DuplicateModuleAlias.
    if let Some(existing) = compiler.circom_namespaces.get(alias) {
        if existing.source_path == canonical {
            return Ok(());
        }
    }
    check_alias_conflict(compiler, alias, span)?;

    let library = load_library_or_error(compiler, &canonical, path, span)?;

    // Surface library-load warnings to the compiler's diagnostic
    // channel so the user sees circom W101/W103/etc. rather than
    // them being silently dropped at the import boundary.
    for warn in &library.warnings {
        compiler.emit_warning(warn.clone());
    }

    compiler
        .circom_namespaces
        .insert(alias.to_string(), Arc::new(library));

    Ok(())
}

/// Dispatch point for `import { T1, T2 } from "x.circom"`.
///
/// Like namespace imports this is compile-time only: the template
/// names are registered in `circom_template_aliases` but no VM
/// bytecode or `global_symbols` entries are emitted. Phase 3 resolves
/// `Call { callee: Ident(T1), ... }` against the alias table.
pub(super) fn selective(
    compiler: &mut Compiler,
    names: &[String],
    path: &str,
    span: &Span,
) -> Result<(), CompilerError> {
    let canonical = resolve_circom_path(compiler, path, span)?;

    // Reuse an already-loaded library if the same path has been
    // imported (possibly via a different alias or a previous
    // selective-import call). Otherwise load fresh and surface its
    // warnings to the compiler's diagnostic channel.
    let library_arc = if let Some(existing) = compiler
        .circom_namespaces
        .values()
        .find(|lib| lib.source_path == canonical)
        .cloned()
    {
        existing
    } else {
        let fresh = load_library_or_error(compiler, &canonical, path, span)?;
        for warn in &fresh.warnings {
            compiler.emit_warning(warn.clone());
        }
        Arc::new(fresh)
    };

    // Validate every requested name is declared by the library.
    // Surface did-you-mean suggestions using the same Levenshtein
    // helper as the .ach selective import path.
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

    // Conflict detection: reject if the unqualified name is already
    // bound. Same-origin re-imports are idempotent.
    for name in names {
        if let Some(existing_lib) = compiler.circom_template_aliases.get(name) {
            if existing_lib.source_path == canonical {
                continue;
            }
            return Err(CompilerError::CompileError(
                format!(
                    "`{}` already imported from \"{}\"",
                    name,
                    existing_lib.source_path.display()
                ),
                span_box(span),
            ));
        }
        check_alias_conflict(compiler, name, span)?;
    }

    // Register the aliases.
    for name in names {
        compiler
            .circom_template_aliases
            .entry(name.clone())
            .or_insert_with(|| library_arc.clone());
    }

    Ok(())
}

/// Dispatch point for `import circuit "x.circom" as C`.
///
/// Full-circuit embed of a `.circom` file that MUST declare
/// `component main = ...`. The file is lowered through the circom
/// frontend to a complete ProveIR, serialized as bytes, and bound
/// to `alias` as a runtime global — the same shape the native
/// `.ach` `import circuit` path already uses.
pub(super) fn full_circuit(
    compiler: &mut Compiler,
    path: &str,
    alias: &str,
    span: &Span,
) -> Result<(), CompilerError> {
    let canonical = resolve_circom_path(compiler, path, span)?;
    check_alias_conflict(compiler, alias, span)?;

    // Compile the circom file — must have `component main`.
    let result = circom::compile_file(&canonical, &compiler.circom_lib_dirs).map_err(|e| {
        CompilerError::CircomImport {
            path: PathBuf::from(path),
            diagnostics: e.to_diagnostics(),
            span: span_box(span),
        }
    })?;
    let mut prove_ir = result.prove_ir;
    prove_ir.name = Some(alias.to_string());

    // Serialize ProveIR → bytes (mirrors the .ach import circuit path).
    let ir_bytes = prove_ir.to_bytes(compiler.prime_id).map_err(|e| {
        CompilerError::CompileError(format!("ProveIR serialization: {e}"), span_box(span))
    })?;

    // Store bytes + bind the alias as a global.
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
