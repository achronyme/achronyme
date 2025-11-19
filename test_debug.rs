use achronyme_vm::compiler::Compiler;
use achronyme_vm::value::Value;
use achronyme_vm::vm::VM;

fn execute(source: &str) -> Result<Value, String> {
    // Parse
    let ast = achronyme_parser::parse(source).map_err(|e| format!("Parse error: {:?}", e))?;

    // Compile
    let mut compiler = Compiler::new("<test>".to_string());
    let module = compiler
        .compile(&ast[..])
        .map_err(|e| format!("Compile error: {}", e))?;

    // Print bytecode for debugging
    println!("\n=== Bytecode ===");
    println!("Main function:");
    for (i, instr) in module.main.code.iter().enumerate() {
        println!("  {}: {:08x}", i, instr);
    }

    if !module.main.functions.is_empty() {
        println!("\nNested functions:");
        for (fi, func) in module.main.functions.iter().enumerate() {
            println!("  Function {}: {}", fi, func.name);
            println!("    Params: {}, Registers: {}", func.param_count, func.register_count);
            for (i, instr) in func.code.iter().enumerate() {
                println!("    {}: {:08x}", i, instr);
            }
        }
    }

    // Execute
    let mut vm = VM::new();
    vm.execute(module)
        .map_err(|e| format!("Runtime error: {}", e))
}

fn main() {
    let source = "let add = (x, y) => x + y\nadd(2, 3)";
    println!("Source: {}", source);

    match execute(source) {
        Ok(result) => println!("\n=== Result ===\n{:?}", result),
        Err(e) => println!("\n=== Error ===\n{}", e),
    }
}
