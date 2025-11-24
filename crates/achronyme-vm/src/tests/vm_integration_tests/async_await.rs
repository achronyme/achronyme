use crate::compiler::Compiler;
use crate::value::Value;
use crate::vm::VM;
use achronyme_parser::parse;

/// Helper to compile and execute source code
async fn execute(source: &str) -> Result<Value, String> {
    // Parse
    let ast = parse(source).map_err(|e| format!("Parse error: {:?}", e))?;

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

#[test]
fn test_async_sleep() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async {
        let source = r#"
            // Mocking time not easy without 'now()', relying on sleep duration
            // Just check if it executes without error and returns null
            await sleep(10)
        "#;

        let result = execute(source).await;
        assert!(result.is_ok(), "Execution failed: {:?}", result.err());
        assert_eq!(result.unwrap(), Value::Null);
    });
}

#[test]
fn test_async_function_call() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async {
        let source = r#"
            let f = async () => do {
                await sleep(1)
                42
            }
            await f()
        "#;

        let result = execute(source).await;
        assert!(result.is_ok(), "Execution failed: {:?}", result.err());
        assert_eq!(result.unwrap(), Value::Number(42.0));
    });
}

#[test]
fn test_async_block() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async {
        let source = r#"
            let result = await async do {
                await sleep(1)
                100
            }
            result
        "#;

        let result = execute(source).await;
        assert!(result.is_ok(), "Execution failed: {:?}", result.err());
        assert_eq!(result.unwrap(), Value::Number(100.0));
    });
}

#[test]
fn test_async_nested() {
    let rt = tokio::runtime::Runtime::new().unwrap();
    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, async {
        let source = r#"
            let inner = async (x) => x * 2
            let outer = async (y) => do {
                let a = await inner(y)
                a + 1
            }
            await outer(10)
        "#;

        let result = execute(source).await;
        assert!(result.is_ok(), "Execution failed: {:?}", result.err());
        assert_eq!(result.unwrap(), Value::Number(21.0));
    });
}
