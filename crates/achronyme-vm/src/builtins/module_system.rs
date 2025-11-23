//! Module system builtin functions

use crate::error::VmError;
use crate::value::Value;
use crate::vm::VM;

/// Import a module by path
///
/// This builtin function:
/// 1. Reads the .soc file
/// 2. Parses and compiles it
/// 3. Executes it to get the exports Record
/// 4. Returns the exports Record
///
/// Note: Module caching is currently not implemented due to thread-safety
/// constraints with Value types. Each import re-loads and re-executes the module.
///
/// # Arguments
/// * `vm` - The VM instance
/// * `args` - Single argument: the module path as a string
///
/// # Returns
/// * `Ok(Value::Record)` - The module's exports Record
/// * `Err(VmError)` - If the module cannot be loaded
pub fn vm_import(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    // Validate argument count
    if args.len() != 1 {
        return Err(VmError::Runtime(format!(
            "import() expects 1 argument (module path), got {}",
            args.len()
        )));
    }

    // Extract module path
    let module_path = match &args[0] {
        Value::String(s) => s.as_str(),
        _ => {
            return Err(VmError::TypeError {
                operation: "import".to_string(),
                expected: "String".to_string(),
                got: format!("{:?}", args[0]),
            });
        }
    };

    // Convert path to file path (add .soc extension if missing)
    let mut file_path = if module_path.ends_with(".soc") {
        module_path.to_string()
    } else {
        format!("{}.soc", module_path)
    };

    // Resolve relative paths based on current module
    use std::path::Path;
    if let Some(current_module) = &vm.current_module {
        // If the path starts with ./ or ../, it's relative to the current module
        if file_path.starts_with("./") || file_path.starts_with("../") {
            if let Some(parent) = Path::new(current_module).parent() {
                let resolved = parent.join(&file_path);
                file_path = resolved.to_string_lossy().to_string();
            }
        }
        // Otherwise, if it's not an absolute path, leave it as-is (relative to CWD)
    }

    // Load and compile the module
    use std::fs;

    // Read the module file
    let source = fs::read_to_string(&file_path)
        .map_err(|e| VmError::Runtime(format!("Failed to read module '{}': {}", file_path, e)))?;

    // Parse the module
    let ast = achronyme_parser::parse(&source).map_err(|e| {
        VmError::Runtime(format!("Failed to parse module '{}': {:?}", file_path, e))
    })?;

    // Compile the module
    let mut module_compiler = crate::compiler::Compiler::new(file_path.clone());
    let module_bytecode = module_compiler.compile(&ast).map_err(|e| {
        VmError::Runtime(format!("Failed to compile module '{}': {:?}", file_path, e))
    })?;

    // Execute the module to get the exports Record
    let mut module_vm = VM::new();
    let module_result = module_vm.execute(module_bytecode).map_err(|e| {
        VmError::Runtime(format!("Failed to execute module '{}': {:?}", file_path, e))
    })?;

    // Verify the result is a Record (module should return exports Record)
    if !matches!(module_result, Value::Record(_)) {
        return Err(VmError::Runtime(format!(
            "Module '{}' did not return a Record (got {:?})",
            file_path, module_result
        )));
    }

    Ok(module_result)
}
