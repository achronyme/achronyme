use achronyme_parser::parser::Parser;
use achronyme_vm::compiler::Compiler;

fn main() {
    let source = r#"
        let factorial = (n) => if (n <= 1) { 1 } else { n * rec(n - 1) }
        factorial(5)
    "#;
    
    let mut parser = Parser::new(source);
    let ast = parser.parse().unwrap();
    
    let mut compiler = Compiler::new("test".to_string());
    let module = compiler.compile(&ast).unwrap();
    
    // Print main function bytecode
    println!("Main function bytecode:");
    for (i, instr) in module.main_function.code.iter().enumerate() {
        println!("{:4}: {:#010x}", i, instr);
    }
    
    // Print nested functions
    for (idx, func) in module.main_function.functions.iter().enumerate() {
        println!("\nFunction {}: {} params", idx, func.arity);
        for (i, instr) in func.code.iter().enumerate() {
            println!("{:4}: {:#010x}", i, instr);
        }
    }
}
