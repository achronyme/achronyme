use achronyme_vm::compiler::Compiler;
use achronyme_vm::value::Value;
use achronyme_vm::vm::VM;

fn main() {
    // Simple recursive test
    let source = r#"
        let f = (n) => if (n <= 0) { 0 } else { n + rec(n - 1) }
        f(3)
    "#;

    println!("Source: {}", source);

    let ast = achronyme_parser::parse(source).unwrap();
    let mut compiler = Compiler::new("<test>".to_string());
    let module = compiler.compile(&ast[..]).unwrap();

    println!("\n=== Main function bytecode ===");
    for (i, instr) in module.main.code.iter().enumerate() {
        println!("{:3}: {:08x}", i, instr);
    }

    if !module.main.functions.is_empty() {
        println!("\n=== Nested functions ===");
        for (fi, func) in module.main.functions.iter().enumerate() {
            println!("\nFunction {}: {}", fi, func.name);
            println!("  Params: {}, Registers: {}", func.param_count, func.register_count);
            println!("  Code:");
            for (i, instr) in func.code.iter().enumerate() {
                println!("    {:3}: {:08x}", i, instr);
            }
        }
    }

    println!("\n=== Executing ===");
    let mut vm = VM::new();
    match vm.execute(module) {
        Ok(result) => println!("Result: {:?}", result),
        Err(e) => println!("Error: {}", e),
    }
}
