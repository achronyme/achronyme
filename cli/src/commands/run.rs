use std::rc::Rc;

use anyhow::{Context, Result};
use memory::Function;
use std::fs;
use vm::{CallFrame, ValueOps, VM};

use super::ErrorFormat;
use crate::prove_handler::{DefaultProveHandler, ProveBackend, SharedProveHandler};

#[allow(clippy::too_many_arguments)]
pub fn run_file(
    path: &str,
    stress_gc: bool,
    ptau: Option<&str>,
    prove_backend: &str,
    max_heap: Option<&str>,
    gc_stats: bool,
    circuit_stats: bool,
    error_format: ErrorFormat,
) -> Result<()> {
    if ptau.is_some() {
        eprintln!(
            "Warning: --ptau is deprecated and ignored (native Groth16 backend does not use ptau files)"
        );
    }

    let backend = match prove_backend {
        "plonkish" => ProveBackend::Plonkish,
        _ => ProveBackend::R1cs,
    };

    if path.ends_with(".achb") {
        let mut file = fs::File::open(path).context("Failed to open binary file")?;

        let mut vm = VM::new();
        super::register_std_modules(&mut vm)?;
        vm.stress_mode = stress_gc;
        if let Some(limit_str) = max_heap {
            let limit = parse_size(limit_str).ok_or_else(|| {
                anyhow::anyhow!(
                    "invalid --max-heap value: `{limit_str}` (expected e.g. \"256M\", \"1G\", \"512K\")"
                )
            })?;
            vm.heap.max_heap_bytes = limit;
        }
        let handler = Rc::new(DefaultProveHandler::new(
            backend,
            error_format,
            circuit_stats,
        ));
        vm.verify_handler = Some(Box::new(SharedProveHandler(Rc::clone(&handler))));
        vm.prove_handler = Some(Box::new(SharedProveHandler(Rc::clone(&handler))));

        // Use the new secure loader
        vm.load_executable(&mut file)
            .map_err(|e| anyhow::anyhow!("Loader error: {e}"))?;

        let result = vm.interpret();
        print_gc_stats(gc_stats, &vm);
        handler.print_circuit_stats();
        if let Err(e) = result {
            let msg = format_runtime_error(&vm, &e);
            return Err(anyhow::anyhow!("{}", msg));
        }

        if let Some(val) = vm.stack.last() {
            println!("Exit Status: {}", vm.val_to_string(val));
        }
        Ok(())
    } else {
        let content = fs::read_to_string(path).context("Failed to source file")?;
        let mut compiler = super::new_compiler();
        let source_path = std::path::Path::new(path);
        compiler.base_path = Some(
            source_path
                .parent()
                .unwrap_or(std::path::Path::new("."))
                .to_path_buf(),
        );
        // Register the main file as "compiling" for circular import detection
        if let Ok(canonical) = source_path.canonicalize() {
            compiler.compiling_modules.insert(canonical);
        }
        let bytecode = compiler.compile(&content).map_err(|e| {
            let rendered = super::render_compile_error(&e, &content, error_format);
            anyhow::anyhow!("{rendered}")
        })?;

        super::print_warnings(&mut compiler, &content, error_format);

        let mut vm = VM::new();
        super::register_std_modules(&mut vm)?;
        vm.stress_mode = stress_gc;
        if let Some(limit_str) = max_heap {
            let limit = parse_size(limit_str).ok_or_else(|| {
                anyhow::anyhow!(
                    "invalid --max-heap value: `{limit_str}` (expected e.g. \"256M\", \"1G\", \"512K\")"
                )
            })?;
            vm.heap.max_heap_bytes = limit;
        }
        let handler = Rc::new(DefaultProveHandler::new(
            backend,
            error_format,
            circuit_stats,
        ));
        vm.verify_handler = Some(Box::new(SharedProveHandler(Rc::clone(&handler))));
        vm.prove_handler = Some(Box::new(SharedProveHandler(Rc::clone(&handler))));

        // Transfer strings from compiler to VM
        vm.import_strings(compiler.interner.strings);
        // Transfer byte blobs (serialized ProveIR) from compiler to VM
        vm.heap.import_bytes(compiler.bytes_interner.blobs);

        // Transfer field literals from compiler to VM
        let field_map = vm.heap.import_fields(compiler.field_interner.fields)?;
        // Transfer bigint literals from compiler to VM
        let bigint_map = vm.heap.import_bigints(compiler.bigint_interner.bigints)?;
        // Remap field and bigint handles in constants
        for proto in &mut compiler.prototypes {
            remap_field_handles(&mut proto.constants, &field_map);
            remap_bigint_handles(&mut proto.constants, &bigint_map);
        }

        // Transfer Debug Symbols (Source Mode)
        let mut debug_map = std::collections::HashMap::new();
        for (name, entry) in &compiler.global_symbols {
            debug_map.insert(entry.index, name.clone());
        }
        vm.debug_symbols = Some(debug_map);

        // Get constants and max_slots from the main function compiler
        let main_func = compiler
            .compilers
            .last()
            .ok_or_else(|| anyhow::anyhow!("compiler has no main function"))?;

        // Allocate ALL prototypes on heap (flat global architecture)
        for proto in &compiler.prototypes {
            let handle = vm.heap.alloc_function(proto.clone())?;
            vm.prototypes.push(handle);
        }

        let mut main_constants = main_func.constants.clone();
        remap_field_handles(&mut main_constants, &field_map);
        remap_bigint_handles(&mut main_constants, &bigint_map);

        let func = Function {
            name: "main".to_string(),
            arity: 0,
            chunk: bytecode,
            constants: main_constants,
            max_slots: main_func.max_slots,
            upvalue_info: vec![],
            line_info: main_func.line_info.clone(),
        };
        let func_idx = vm.heap.alloc_function(func)?;
        let closure_idx = vm.heap.alloc_closure(memory::Closure {
            function: func_idx,
            upvalues: vec![],
        })?;

        vm.frames.push(CallFrame {
            closure: closure_idx,
            ip: 0,
            base: 0,
            dest_reg: 0, // Top-level script, unused
        });

        let result = vm.interpret();
        print_gc_stats(gc_stats, &vm);
        handler.print_circuit_stats();
        if let Err(e) = result {
            let msg = format_runtime_error(&vm, &e);
            return Err(anyhow::anyhow!("{}", msg));
        }

        if let Some(val) = vm.stack.last() {
            println!("Exit Status: {}", vm.val_to_string(val));
        }

        Ok(())
    }
}

fn print_gc_stats(gc_stats: bool, vm: &VM) {
    if gc_stats {
        let s = &vm.heap.stats;
        eprintln!("-- GC Stats --");
        eprintln!("  Collections:    {}", s.collections);
        eprintln!("  Freed (total):  {} bytes", s.total_freed_bytes);
        eprintln!("  Peak heap:      {} bytes", s.peak_heap_bytes);
        eprintln!(
            "  GC time:        {:.3} ms",
            s.total_gc_time_ns as f64 / 1_000_000.0
        );
        eprintln!("  Heap now:       {} bytes", vm.heap.bytes_allocated);
    }
}

/// Remap field literal handles from compiler-space to VM heap-space.
pub fn remap_field_handles(constants: &mut [memory::Value], field_map: &[u32]) {
    for val in constants.iter_mut() {
        if val.is_field() {
            let old_handle = val.as_handle().expect("Field value must have handle");
            if let Some(&new_handle) = field_map.get(old_handle as usize) {
                *val = memory::Value::field(new_handle);
            }
        }
    }
}

/// Remap BigInt literal handles from compiler-space to VM heap-space.
pub fn remap_bigint_handles(constants: &mut [memory::Value], bigint_map: &[u32]) {
    for val in constants.iter_mut() {
        if val.is_bigint() {
            let old_handle = val.as_handle().expect("BigInt value must have handle");
            if let Some(&new_handle) = bigint_map.get(old_handle as usize) {
                *val = memory::Value::bigint(new_handle);
            }
        }
    }
}

/// Parse a human-readable size string (e.g., "256M", "1G", "512K") into bytes.
fn parse_size(s: &str) -> Option<usize> {
    let s = s.trim();
    if s.is_empty() {
        return None;
    }
    let (num_part, multiplier) = match s.as_bytes().last()? {
        b'K' | b'k' => (&s[..s.len() - 1], 1024usize),
        b'M' | b'm' => (&s[..s.len() - 1], 1024 * 1024),
        b'G' | b'g' => (&s[..s.len() - 1], 1024 * 1024 * 1024),
        _ => (s, 1),
    };
    let num: usize = num_part.parse().ok()?;
    num.checked_mul(multiplier)
}

/// Format a runtime error with source location if available.
fn format_runtime_error(vm: &VM, err: &vm::RuntimeError) -> String {
    match &vm.last_error_location {
        Some((func_name, line)) => format!("[line {line}] in {func_name}: {err}"),
        None => format!("Runtime error: {err}"),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_size;

    #[test]
    fn test_parse_size_bytes() {
        assert_eq!(parse_size("1048576"), Some(1048576));
    }
    #[test]
    fn test_parse_size_kb() {
        assert_eq!(parse_size("512K"), Some(524288));
    }
    #[test]
    fn test_parse_size_mb() {
        assert_eq!(parse_size("256M"), Some(268435456));
    }
    #[test]
    fn test_parse_size_gb() {
        assert_eq!(parse_size("1G"), Some(1073741824));
    }
    #[test]
    fn test_parse_size_lowercase() {
        assert_eq!(parse_size("256m"), Some(268435456));
    }
    #[test]
    fn test_parse_size_zero() {
        assert_eq!(parse_size("0"), Some(0));
    }
    #[test]
    fn test_parse_size_empty() {
        assert_eq!(parse_size(""), None);
    }
    #[test]
    fn test_parse_size_invalid() {
        assert_eq!(parse_size("abc"), None);
    }
}
