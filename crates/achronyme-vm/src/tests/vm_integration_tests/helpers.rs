//! Helper functions and common imports for integration tests.

use crate::compiler::Compiler;
use crate::value::Value;
use crate::vm::VM;

/// Helper to compile and execute source code (Async)
pub async fn execute_async(source: &str) -> Result<Value, String> {
    // Parse
    let ast = achronyme_parser::parse(source).map_err(|e| format!("Parse error: {:?}", e))?;

    // Compile
    let mut compiler = Compiler::new("<test>".to_string());
    let module = compiler
        .compile(&ast)
        .map_err(|e| format!("Compile error: {}", e))?;

    // Execute
    let mut vm = VM::new();
    vm.execute(module)
        .await
        .map_err(|e| format!("Runtime error: {}", e))
}

/// Helper to compile and execute source code (Synchronous wrapper)
pub fn execute(source: &str) -> Result<Value, String> {
    // Execute in a new runtime + LocalSet
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let local = tokio::task::LocalSet::new();

    local.block_on(&rt, execute_async(source))
}
