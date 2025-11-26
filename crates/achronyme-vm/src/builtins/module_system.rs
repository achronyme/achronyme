//! Module system builtin functions

use crate::error::VmError;
use crate::value::Value;
use crate::vm::VM;
use achronyme_types::value::VmFuture;

/// Import a module by path
///
/// This builtin function:
/// 1. Reads the .soc file (async)
/// 2. Parses and compiles it
/// 3. Executes it to get the exports Record (async)
/// 4. Returns the exports Record
///
/// Note: Module caching is currently not implemented.
///
/// # Arguments
/// * `vm` - The VM instance
/// * `args` - Single argument: the module path as a string
///
/// # Returns
/// * `Ok(Value::Future)` - A future that resolves to the module's exports Record
pub fn vm_import(vm: &VM, args: &[Value]) -> Result<Value, VmError> {
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
    
    let current_module = {
        let state = vm.state.read();
        state.current_module.clone()
    };

    if let Some(current_module) = &current_module {
        // If the path starts with ./ or ../, it's relative to the current module
        if file_path.starts_with("./") || file_path.starts_with("../") {
            if let Some(parent) = Path::new(current_module).parent() {
                let resolved = parent.join(&file_path);
                file_path = resolved.to_string_lossy().to_string();
            }
        }
    }

    let file_path_captured = file_path.clone();

    // Since Compiler now uses Arc, it is Send, so the async block is Send
    let future = async move {
        match load_module_async(file_path_captured).await {
            Ok(val) => val,
            Err(e) => Value::Error {
                message: e.to_string(),
                kind: Some("ImportError".into()),
                source: None,
            },
        }
    };

    Ok(Value::Future(VmFuture::new(future)))
}

async fn load_module_async(file_path: String) -> Result<Value, VmError> {
    // Read the module file async
    let source = tokio::fs::read_to_string(&file_path)
        .await
        .map_err(|e| VmError::Runtime(format!("Failed to read module '{}': {}", file_path, e)))?;

    // Parse the module (CPU bound, synchronous)
    let ast = achronyme_parser::parse(&source).map_err(|e| {
        VmError::Runtime(format!("Failed to parse module '{}': {:?}", file_path, e))
    })?;

    // Compile the module (CPU bound, synchronous)
    // Compiler holds Arc<BuiltinRegistry> which is Send + Sync
    let mut module_compiler = crate::compiler::Compiler::new(file_path.clone());
    let module_bytecode = module_compiler.compile(&ast).map_err(|e| {
        VmError::Runtime(format!("Failed to compile module '{}': {:?}", file_path, e))
    })?;

    // Execute the module to get the exports Record (Async)
    let mut module_vm = VM::new();
    let module_result = module_vm.execute(module_bytecode).await.map_err(|e| {
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
