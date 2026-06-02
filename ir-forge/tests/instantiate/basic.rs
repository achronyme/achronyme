use super::helpers::*;

#[test]
fn instantiate_empty_circuit() {
    let ir = compile_and_instantiate("");
    assert!(ir.instructions.is_empty());
}

#[test]
fn instantiate_public_input() {
    let ir = compile_and_instantiate("public x");
    assert_eq!(ir.instructions.len(), 1);
    assert!(matches!(
        &ir.instructions[0],
        Instruction::Input {
            name,
            visibility: Visibility::Public,
            ..
        } if name == "x"
    ));
}

#[test]
fn instantiate_witness_input() {
    let ir = compile_and_instantiate("witness s");
    assert_eq!(ir.instructions.len(), 1);
    assert!(matches!(
        &ir.instructions[0],
        Instruction::Input {
            name,
            visibility: Visibility::Witness,
            ..
        } if name == "s"
    ));
}

#[test]
fn instantiate_array_input() {
    let ir = compile_and_instantiate("public arr[3]");
    // 3 Input instructions for arr_0, arr_1, arr_2
    assert_eq!(ir.instructions.len(), 3);
    for (i, inst) in ir.instructions.iter().enumerate() {
        assert!(matches!(
            inst,
            Instruction::Input { name, visibility: Visibility::Public, .. }
                if name == &format!("arr_{i}")
        ));
    }
}

#[test]
fn instantiate_basic_arithmetic() {
    let ir = compile_and_instantiate("public x\npublic y\npublic out\nassert_eq(x + y, out)");
    // Inputs: x, y, out (3)
    // Add: x + y (1)
    // AssertEq: (x+y) == out (1)
    let inputs = ir
        .instructions
        .iter()
        .filter(|i| matches!(i, Instruction::Input { .. }))
        .count();
    let adds = ir
        .instructions
        .iter()
        .filter(|i| matches!(i, Instruction::Add { .. }))
        .count();
    let asserts = ir
        .instructions
        .iter()
        .filter(|i| matches!(i, Instruction::AssertEq { .. }))
        .count();
    assert_eq!(inputs, 3);
    assert_eq!(adds, 1);
    assert_eq!(asserts, 1);
}

#[test]
fn instantiate_let_binding() {
    let ir = compile_and_instantiate("public x\npublic out\nlet y = x * 2\nassert_eq(y, out)");
    // Should have: Input(x), Input(out), Const(2), Mul(x,2), AssertEq
    let muls = ir
        .instructions
        .iter()
        .filter(|i| matches!(i, Instruction::Mul { .. }))
        .count();
    assert_eq!(muls, 1);
}

#[test]
fn instantiate_poseidon() {
    let ir = compile_and_instantiate(
        "public hash\nwitness a\nwitness b\nassert_eq(poseidon(a, b), hash)",
    );
    let hashes = ir
        .instructions
        .iter()
        .filter(|i| matches!(i, Instruction::PoseidonHash { .. }))
        .count();
    assert_eq!(hashes, 1);
}

#[test]
fn instantiate_poseidon_many() {
    let ir = compile_and_instantiate(
        "public hash\nwitness a\nwitness b\nwitness c\nassert_eq(poseidon_many(a, b, c), hash)",
    );
    // poseidon_many(a, b, c) → poseidon(poseidon(a, b), c) — 2 hashes
    let hashes = ir
        .instructions
        .iter()
        .filter(|i| matches!(i, Instruction::PoseidonHash { .. }))
        .count();
    assert_eq!(hashes, 2);
}

#[test]
fn instantiate_range_check() {
    let ir = compile_and_instantiate("witness x\nrange_check(x, 8)");
    let checks = ir
        .instructions
        .iter()
        .filter(|i| matches!(i, Instruction::RangeCheck { bits: 8, .. }))
        .count();
    assert_eq!(checks, 1);
}

#[test]
fn instantiate_mux() {
    let ir = compile_and_instantiate("public c\nwitness a\nwitness b\nlet r = mux(c, a, b)");
    let muxes = ir
        .instructions
        .iter()
        .filter(|i| matches!(i, Instruction::Mux { .. }))
        .count();
    assert_eq!(muxes, 1);
}

#[test]
fn instantiate_if_else() {
    let ir = compile_and_instantiate(
        "public c\npublic out\nlet r = if c { 1 } else { 0 }\nassert_eq(r, out)",
    );
    // Should produce a Mux
    let muxes = ir
        .instructions
        .iter()
        .filter(|i| matches!(i, Instruction::Mux { .. }))
        .count();
    assert!(muxes >= 1);
}

#[test]
fn instantiate_pow() {
    let ir = compile_and_instantiate("public x\npublic out\nassert_eq(x ^ 3, out)");
    // x^3 via square-and-multiply: x*x=x², x²*x=x³ → 2 Mul
    let muls = ir
        .instructions
        .iter()
        .filter(|i| matches!(i, Instruction::Mul { .. }))
        .count();
    assert_eq!(muls, 2, "x^3 should use 2 multiplications");
}

#[test]
fn instantiate_pow_zero() {
    let ir = compile_and_instantiate("public x\npublic out\nassert_eq(x ^ 0, out)");
    // x^0 = 1
    let has_const_one = ir
        .instructions
        .iter()
        .any(|i| matches!(i, Instruction::Const { value, .. } if *value == FieldElement::<Bn254Fr>::one()));
    assert!(has_const_one, "x^0 should produce Const(1)");
}

// --- For loop unrolling ---

#[test]
fn instantiate_for_loop() {
    // Runtime seed `y` prevents `Add(Const(0), x) -> x` from folding
    // the first iteration away.
    let ir = compile_and_instantiate(
        "public x\npublic y\npublic out\nmut acc = y\nfor i in 0..3 { acc = acc + x }\nassert_eq(acc, out)",
    );
    // Unrolled: 3 iterations, each adds x
    let adds = ir
        .instructions
        .iter()
        .filter(|i| matches!(i, Instruction::Add { .. }))
        .count();
    assert_eq!(adds, 3, "3 iterations of acc + x");
}

#[test]
fn instantiate_for_empty_range() {
    let ir = compile_and_instantiate("public out\nfor i in 5..3 { }\nassert_eq(0, out)");
    // 5..3 = empty range, no loop body emitted
    // Should just have: Input(out), Const(0), AssertEq
    let consts = ir
        .instructions
        .iter()
        .filter(|i| matches!(i, Instruction::Const { .. }))
        .count();
    assert!(consts >= 1);
}
