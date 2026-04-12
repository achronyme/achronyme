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

use achronyme_parser::ast::{Expr, Span};
use ir::prove_ir::{CircomCallable, CircomLibraryHandle};
use memory::{CircomHandle, Value};
use vm::opcode::OpCode;

use crate::codegen::Compiler;
use crate::error::{span_box, CompilerError};
use crate::expressions::ExpressionCompiler;

// ---------------------------------------------------------------------------
// Phase 4.3: VM-mode circom template call emission
// ---------------------------------------------------------------------------

/// Extension trait adding circom-call support to the bytecode
/// compiler. Kept in this module (rather than in `expressions/`)
/// so every circom-related state mutation on the compiler lives in
/// one place.
pub trait CircomVmCallEmitter {
    /// Resolve the inner callee of a `T(...)(...)` / `P.T(...)(...)`
    /// shape to a `(library, template_name)` pair if one of the
    /// compiler's circom import tables contains it. Returns `None`
    /// for any other shape so the normal call dispatch takes over.
    fn try_resolve_circom_vm_call(
        &self,
        inner_callee: &Expr,
    ) -> Option<(Arc<circom::CircomLibrary>, String)>;

    /// Emit a `CallCircomTemplate` opcode sequence for a VM-mode
    /// template call. Handles template-arg const evaluation, signal
    /// input compilation into contiguous registers, handle
    /// interning, and register cleanup.
    fn compile_circom_vm_call(
        &mut self,
        library: Arc<circom::CircomLibrary>,
        template_name: String,
        template_args: &[&Expr],
        signal_inputs: &[&Expr],
    ) -> Result<u8, CompilerError>;
}

impl CircomVmCallEmitter for Compiler {
    fn try_resolve_circom_vm_call(
        &self,
        inner_callee: &Expr,
    ) -> Option<(Arc<circom::CircomLibrary>, String)> {
        match inner_callee {
            Expr::Ident { name, .. } => self
                .circom_template_aliases
                .get(name)
                .map(|lib| (lib.clone(), name.clone())),
            Expr::DotAccess { object, field, .. } => {
                let Expr::Ident { name: alias, .. } = object.as_ref() else {
                    return None;
                };
                let lib = self.circom_namespaces.get(alias)?.clone();
                // Validate the template actually exists in the
                // library; otherwise let the normal call path
                // produce a proper error.
                if lib.template(field).is_some() {
                    Some((lib, field.clone()))
                } else {
                    None
                }
            }
            _ => None,
        }
    }

    fn compile_circom_vm_call(
        &mut self,
        library: Arc<circom::CircomLibrary>,
        template_name: String,
        template_args: &[&Expr],
        signal_inputs: &[&Expr],
    ) -> Result<u8, CompilerError> {
        // Look up the template signature to validate arity and
        // discover the declared input-signal count.
        let entry = library.template(&template_name).ok_or_else(|| {
            CompilerError::CompileError(
                format!(
                    "circom library `{}` has no template `{template_name}`",
                    library.source_path.display()
                ),
                self.cur_span(),
            )
        })?;
        let expected_params = entry.params.len();
        let expected_inputs = entry.inputs.len();

        // --- Template args: must be compile-time integer constants ---
        if template_args.len() != expected_params {
            return Err(CompilerError::CompileError(
                format!(
                    "circom template `{template_name}` expects {expected_params} \
                     template parameter(s), got {}",
                    template_args.len()
                ),
                self.cur_span(),
            ));
        }
        let mut template_u64_args: Vec<u64> = Vec::with_capacity(expected_params);
        for (i, arg) in template_args.iter().enumerate() {
            match arg {
                Expr::Number { value, .. } => {
                    let parsed: u64 = value.parse().map_err(|_| {
                        CompilerError::CompileError(
                            format!(
                                "circom template `{template_name}`: template argument \
                                 at position {i} (`{value}`) does not fit in u64"
                            ),
                            self.cur_span(),
                        )
                    })?;
                    template_u64_args.push(parsed);
                }
                _ => {
                    return Err(CompilerError::CompileError(
                        format!(
                            "circom template `{template_name}`: template argument at \
                             position {i} must be an integer literal at VM-mode call \
                             sites (compile-time constant folding for template params \
                             is not yet implemented in VM mode)"
                        ),
                        self.cur_span(),
                    ));
                }
            }
        }

        // --- Validate signal input count ---
        if signal_inputs.len() != expected_inputs {
            return Err(CompilerError::CompileError(
                format!(
                    "circom template `{template_name}` expects {expected_inputs} \
                     signal input(s), got {}",
                    signal_inputs.len()
                ),
                self.cur_span(),
            ));
        }

        // Expand array signal inputs: for every declared array input
        // the caller must pass an `Expr::Array` literal whose total
        // element count matches the resolved array size. Each element
        // lands in its own register — the runtime handler maps them
        // back to `signal_name_i` keys via the same layout.
        //
        // Resolve the layout here (rather than relying on the raw
        // library entry) so parametric sizes like `inputs[nInputs]`
        // collapse to the concrete value the user passed as template arg.
        let template_const_args: Vec<ir::prove_ir::types::FieldConst> = template_u64_args
            .iter()
            .map(|n| ir::prove_ir::types::FieldConst::from_u64(*n))
            .collect();
        let layouts = <circom::CircomLibrary as CircomLibraryHandle>::resolve_input_layout(
            library.as_ref(),
            &template_name,
            &template_const_args,
        )
        .ok_or_else(|| {
            CompilerError::CompileError(
                format!(
                    "circom template `{template_name}`: could not resolve input signal \
                     dimensions for the given template arguments"
                ),
                self.cur_span(),
            )
        })?;

        // Build a flat list of (expression, owned optional allocation)
        // that compile_expr should evaluate in order. Scalar inputs
        // map 1:1 to the user's expression; array inputs are
        // replaced by their ArrayLit elements in row-major order.
        let mut flat_exprs: Vec<&Expr> = Vec::with_capacity(expected_inputs);
        for (layout, input_expr) in layouts.iter().zip(signal_inputs.iter()) {
            if layout.dims.is_empty() {
                flat_exprs.push(*input_expr);
                continue;
            }
            let expected_len: usize = layout.dims.iter().product::<u64>() as usize;
            let Expr::Array { elements, .. } = *input_expr else {
                return Err(CompilerError::CompileError(
                    format!(
                        "circom template `{template_name}`: signal input `{}` is declared \
                         as an array of size {} but the caller passed a non-array \
                         expression; wrap the inputs in `[...]`",
                        layout.name, expected_len
                    ),
                    self.cur_span(),
                ));
            };
            if elements.len() != expected_len {
                return Err(CompilerError::CompileError(
                    format!(
                        "circom template `{template_name}`: signal input `{}` expects an \
                         array of {} element(s) but the caller passed {}",
                        layout.name,
                        expected_len,
                        elements.len()
                    ),
                    self.cur_span(),
                ));
            }
            for elem in elements {
                flat_exprs.push(elem);
            }
        }

        if flat_exprs.len() > 254 {
            return Err(CompilerError::CompileError(
                format!(
                    "circom template `{template_name}` expands to {} signal input \
                     element(s); VM-mode calls are limited to 254 (register budget)",
                    flat_exprs.len()
                ),
                self.cur_span(),
            ));
        }

        // --- Register the library and build the handle descriptor ---
        let library_id = self.register_circom_library(library);
        let handle = CircomHandle {
            library_id,
            template_name: template_name.clone(),
            template_args: template_u64_args,
        };
        let handle_idx = self.intern_circom_handle(handle);
        let handle_const_val = Value::circom_handle(handle_idx);
        let const_idx = self.add_constant(handle_const_val)?;
        if const_idx > 0xFFFF {
            return Err(CompilerError::TooManyConstants(self.cur_span()));
        }

        // --- Emit the register sequence ---
        //
        // Layout (same convention MethodCall uses for its name slot):
        //   handle_reg = R[top]       ← LoadConst handle_const
        //   R[handle_reg + 1 .. + N]  ← each signal input expression
        //   CallCircomTemplate A=handle_reg, B=handle_reg+1, C=N
        //
        // Reusing `handle_reg` as the destination A matches the rest
        // of the compiler's "first allocated register becomes the
        // result register" convention (see compile_method_call).
        let handle_reg = self.alloc_reg()?;
        self.emit_abx(OpCode::LoadConst, handle_reg, const_idx as u16)?;

        // Compile every signal input in sequence. compile_expr
        // allocates at `reg_top`, which has already advanced past
        // `handle_reg`, so the first input lands at handle_reg + 1,
        // second at handle_reg + 2, etc. `flat_exprs` already expanded
        // any array-valued inputs into their individual elements.
        let first_input_reg = handle_reg + 1;
        for (i, input) in flat_exprs.iter().enumerate() {
            let landed = self.compile_expr(input)?;
            debug_assert_eq!(
                landed as usize,
                first_input_reg as usize + i,
                "circom input {i} landed in r{landed}, expected r{}",
                first_input_reg as usize + i
            );
        }

        let input_count = flat_exprs.len() as u8;
        self.emit_abc(
            OpCode::CallCircomTemplate,
            handle_reg,
            first_input_reg,
            input_count,
        )?;

        // Free the input registers; the dest is handle_reg which
        // becomes the result register returned to the caller.
        for _ in 0..input_count {
            let top = self.current()?.reg_top - 1;
            self.free_reg(top)?;
        }

        Ok(handle_reg)
    }
}

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
