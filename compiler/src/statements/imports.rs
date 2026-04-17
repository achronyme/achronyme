//! Module import compilation for `.ach` and `.circom` files.
//!
//! Two entry points:
//!
//! - [`compile_import`]: `import "path" as Alias` — binds the module's
//!   exports into a runtime `Map { export_name: value }` under `Alias`.
//! - [`compile_selective_import`]: `import { A, B } from "path"` —
//!   copies individual names into fresh globals, validating each request
//!   exists in the target's export list with a "did you mean?" suggestion
//!   on typos.
//!
//! Both dispatch to the circom frontend (`circom_imports::namespace` /
//! `circom_imports::selective`) when the path ends in `.circom`.

use std::path::Path;

use super::circom_imports;
use super::import_kind::{detect_import_kind, ImportFileKind};
use crate::codegen::Compiler;
use crate::error::{span_box, CompilerError};
use crate::statements::StatementCompiler;
use achronyme_parser::ast::*;
use memory::Value;
use vm::opcode::OpCode;

pub(super) fn compile_import(
    compiler: &mut Compiler,
    path: &str,
    alias: &str,
    span: &Span,
) -> Result<(), CompilerError> {
    if detect_import_kind(path) == ImportFileKind::Circom {
        return circom_imports::namespace(compiler, path, alias, span);
    }

    // 1. Resolve path relative to base_path
    let base = compiler
        .base_path
        .clone()
        .unwrap_or_else(|| Path::new(".").to_path_buf());
    let resolved = base.join(path);
    let canonical = resolved.canonicalize().map_err(|_| {
        CompilerError::ModuleNotFound(
            format!(
                "module not found: {} (resolved from {})",
                path,
                base.display()
            ),
            span_box(span),
        )
    })?;

    // 2. Check for duplicate alias
    if let Some(existing) = compiler.imported_aliases.get(alias) {
        if *existing != canonical {
            return Err(CompilerError::DuplicateModuleAlias(
                alias.to_string(),
                span_box(span),
            ));
        }
        // Same path, same alias → already imported, skip
        return Ok(());
    }
    compiler
        .imported_aliases
        .insert(alias.to_string(), canonical.clone());

    // 3. Check for circular imports
    if compiler.compiling_modules.contains(&canonical) {
        return Err(CompilerError::CircularImport(
            canonical.display().to_string(),
            span_box(span),
        ));
    }

    // 4. Load and parse the module
    let module = compiler
        .module_loader
        .load(&canonical)
        .map_err(CompilerError::ModuleLoadError)?;
    let module_stmts = module.program.stmts.clone();
    let exported_names = module.exported_names.clone();

    // 5. Mark as compiling (for cycle detection during stmt compilation)
    compiler.compiling_modules.insert(canonical.clone());

    // 6. Save and set module_prefix + base_path for name mangling
    let old_prefix = compiler.module_prefix.take();
    let old_base = compiler.base_path.take();
    compiler.module_prefix = Some(alias.to_string());
    compiler.base_path = canonical.parent().map(|p| p.to_path_buf());

    // 7. Compile the module's statements (globals get mangled as alias::name)
    for stmt in &module_stmts {
        compiler.compile_stmt(stmt)?;
    }

    // 8. Restore prefix and base_path, remove from compiling set
    compiler.module_prefix = old_prefix;
    compiler.base_path = old_base;
    compiler.compiling_modules.remove(&canonical);

    // 9. Build a Map { export_name: value } and bind it to the alias
    let count = exported_names.len();

    // Allocate target register first (LIFO register hygiene)
    let map_reg = compiler.alloc_reg()?;

    let start_reg = if count > 0 {
        compiler.alloc_contiguous((count * 2) as u8)?
    } else {
        compiler.current()?.reg_top
    };

    for (i, name) in exported_names.iter().enumerate() {
        let key_reg = start_reg + (i as u8 * 2);
        let val_reg = key_reg + 1;

        // Key: the export name as a string constant
        let key_handle = compiler.intern_string(name);
        let key_val = Value::string(key_handle);
        let const_idx = compiler.add_constant(key_val)?;
        if const_idx > 0xFFFF {
            return Err(CompilerError::TooManyConstants(span_box(span)));
        }
        compiler.emit_abx(OpCode::LoadConst, key_reg, const_idx as u16)?;

        // Value: load from the mangled global
        let mangled = format!("{}::{}", alias, name);
        let global_idx = compiler
            .global_symbols
            .get(&mangled)
            .ok_or_else(|| {
                CompilerError::CompileError(
                    format!(
                        "internal error: mangled global `{}` not found after module compilation",
                        mangled
                    ),
                    span_box(span),
                )
            })?
            .index;
        compiler.emit_abx(OpCode::GetGlobal, val_reg, global_idx)?;
    }

    compiler.emit_abc(OpCode::BuildMap, map_reg, start_reg, count as u8)?;

    // Free pair registers (LIFO: last allocated = first freed)
    if count > 0 {
        for _ in 0..(count * 2) {
            let top = compiler.current()?.reg_top - 1;
            compiler.free_reg(top)?;
        }
    }

    // Bind the map to the alias as a global
    if compiler.next_global_idx == u16::MAX {
        return Err(CompilerError::TooManyConstants(span_box(span)));
    }
    let idx = compiler.next_global_idx;
    compiler.next_global_idx += 1;
    compiler.global_symbols.insert(
        alias.to_string(),
        crate::types::GlobalEntry {
            index: idx,
            type_ann: None,
            is_mutable: false,
            param_names: None,
        },
    );
    compiler.emit_abx(OpCode::DefGlobalLet, map_reg, idx)?;
    compiler.free_reg(map_reg)?;

    Ok(())
}

pub(super) fn compile_selective_import(
    compiler: &mut Compiler,
    names: &[String],
    path: &str,
    span: &Span,
) -> Result<(), CompilerError> {
    if detect_import_kind(path) == ImportFileKind::Circom {
        return circom_imports::selective(compiler, names, path, span);
    }

    // 1. Resolve path relative to base_path
    let base = compiler
        .base_path
        .clone()
        .unwrap_or_else(|| Path::new(".").to_path_buf());
    let resolved = base.join(path);
    let canonical = resolved.canonicalize().map_err(|_| {
        CompilerError::ModuleNotFound(
            format!(
                "module not found: {} (resolved from {})",
                path,
                base.display()
            ),
            span_box(span),
        )
    })?;

    // 2. Check for circular imports
    if compiler.compiling_modules.contains(&canonical) {
        return Err(CompilerError::CircularImport(
            canonical.display().to_string(),
            span_box(span),
        ));
    }

    // 3. Load and parse the module
    let module = compiler
        .module_loader
        .load(&canonical)
        .map_err(CompilerError::ModuleLoadError)?;
    let module_stmts = module.program.stmts.clone();
    let exported_names = module.exported_names.clone();

    // 4. Validate that all requested names are exported
    for name in names {
        if !exported_names.contains(name) {
            let suggestion = crate::suggest::find_similar(
                name,
                exported_names.iter().map(|s| s.as_str()),
                2,
            );
            let mut msg = format!("module \"{}\" does not export `{}`", path, name);
            if let Some(s) = suggestion {
                msg.push_str(&format!(". Did you mean `{s}`?"));
            }
            return Err(CompilerError::CompileError(msg, span_box(span)));
        }
    }

    // 5. Check for conflicts with existing names
    for name in names {
        if let Some((existing_path, _)) = compiler.imported_names.get(name) {
            if *existing_path != canonical {
                return Err(CompilerError::CompileError(
                    format!(
                        "`{}` already imported from \"{}\"",
                        name,
                        existing_path.display()
                    ),
                    span_box(span),
                ));
            }
            // Same name from same module — already imported, skip
            continue;
        }
        if compiler.global_symbols.contains_key(name) {
            return Err(CompilerError::CompileError(
                format!(
                    "cannot import `{}`: a global with this name already exists",
                    name
                ),
                span_box(span),
            ));
        }
    }

    // 6. Generate internal module prefix
    let internal_prefix = format!("__sel_{}", compiler.imported_aliases.len());

    // 7. Mark as compiling (for cycle detection)
    compiler.compiling_modules.insert(canonical.clone());

    // 8. Save and set module_prefix + base_path for name mangling
    let old_prefix = compiler.module_prefix.take();
    let old_base = compiler.base_path.take();
    compiler.module_prefix = Some(internal_prefix.clone());
    compiler.base_path = canonical.parent().map(|p| p.to_path_buf());

    // 9. Compile the module's statements
    for stmt in &module_stmts {
        compiler.compile_stmt(stmt)?;
    }

    // 10. Restore prefix and base_path, remove from compiling set
    compiler.module_prefix = old_prefix;
    compiler.base_path = old_base;
    compiler.compiling_modules.remove(&canonical);

    // 11. Copy only the requested names from mangled globals to user-visible globals
    for name in names {
        if compiler.imported_names.contains_key(name) {
            // Already imported from same module — skip
            continue;
        }

        let mangled = format!("{}::{}", internal_prefix, name);
        let mangled_entry = compiler.global_symbols.get(&mangled).ok_or_else(|| {
            CompilerError::CompileError(
                format!(
                    "internal error: mangled global `{}` not found after module compilation",
                    mangled
                ),
                span_box(span),
            )
        })?;
        let global_idx = mangled_entry.index;
        let source_type_ann = mangled_entry.type_ann.clone();
        let source_is_mutable = mangled_entry.is_mutable;

        // Emit GetGlobal + DefGlobalLet to copy value to a new global slot
        let tmp_reg = compiler.alloc_reg()?;
        compiler.emit_abx(OpCode::GetGlobal, tmp_reg, global_idx)?;

        if compiler.next_global_idx == u16::MAX {
            compiler.free_reg(tmp_reg)?;
            return Err(CompilerError::TooManyConstants(span_box(span)));
        }
        let new_idx = compiler.next_global_idx;
        compiler.next_global_idx += 1;
        compiler.global_symbols.insert(
            name.clone(),
            crate::types::GlobalEntry {
                index: new_idx,
                type_ann: source_type_ann,
                is_mutable: source_is_mutable,
                param_names: None,
            },
        );
        compiler.emit_abx(OpCode::DefGlobalLet, tmp_reg, new_idx)?;
        compiler.free_reg(tmp_reg)?;

        compiler
            .imported_names
            .insert(name.clone(), (canonical.clone(), span.clone()));
    }

    Ok(())
}
