use compiler::Compiler;
use vm::opcode::{instruction::*, OpCode};

#[test]
fn test_compile_simple_arithmetic() {
    let mut compiler = Compiler::new();
    // 1 + 2 * 3
    // Precedence should do 2*3 first.
    let bytecode = compiler.compile("1 + 2 * 3").expect("Failed to compile");

    println!("Bytecode len: {}", bytecode.len());
    for (i, inst) in bytecode.iter().enumerate() {
        let op = OpCode::from_u8(decode_opcode(*inst));
        println!(
            "{}: {:?} A={} B={} C={}",
            i,
            op,
            decode_a(*inst),
            decode_b(*inst),
            decode_c(*inst)
        );
    }

    // Rough check of opcodes
    let ops: Vec<u8> = bytecode.iter().map(|inst| decode_opcode(*inst)).collect();

    // Check for presence of MUL and ADD
    assert!(ops.contains(&OpCode::Mul.as_u8()));
    assert!(ops.contains(&OpCode::Add.as_u8()));
    assert!(ops.contains(&OpCode::LoadConst.as_u8()));

    // The last instruction should be Return
    assert_eq!(*ops.last().unwrap(), OpCode::Return.as_u8());
}
