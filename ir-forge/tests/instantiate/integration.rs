use super::helpers::*;

#[test]
fn integration_poseidon_preimage() {
    let ir = compile_and_instantiate(
        "public hash\n\
         witness secret\n\
         assert_eq(poseidon(secret, Field::ZERO), hash)",
    );
    let inputs = ir
        .instructions
        .iter()
        .filter(|i| matches!(i, Instruction::Input { .. }))
        .count();
    let hashes = ir
        .instructions
        .iter()
        .filter(|i| matches!(i, Instruction::PoseidonHash { .. }))
        .count();
    let asserts = ir
        .instructions
        .iter()
        .filter(|i| matches!(i, Instruction::AssertEq { .. }))
        .count();
    assert_eq!(inputs, 2);
    assert_eq!(hashes, 1);
    assert_eq!(asserts, 1);
}

#[test]
fn integration_accumulator_with_for() {
    // Runtime seed `start` prevents `Add(Const(0), x) -> x` folding
    // the first iteration away.
    let ir = compile_and_instantiate(
        "public total\n\
         public start\n\
         witness vals[4]\n\
         mut sum = start\n\
         for i in 0..4 { sum = sum + vals_0 }\n\
         assert_eq(sum, total)",
    );
    // 4 iterations of sum + vals_0
    let adds = ir
        .instructions
        .iter()
        .filter(|i| matches!(i, Instruction::Add { .. }))
        .count();
    assert_eq!(adds, 4);
}

#[test]
fn integration_array_len() {
    let ir = compile_and_instantiate(
        "let arr = [1, 2, 3]\nlet n = len(arr)\npublic out\nassert_eq(n, out)",
    );
    // len(arr) → Const(3)
    let has_const_3 = ir.instructions.iter().any(|i| {
        matches!(i, Instruction::Const { value, .. } if *value == FieldElement::<Bn254Fr>::from_u64(3))
    });
    assert!(has_const_3);
}

// =====================================================================
// Phase B audit regression tests
// =====================================================================
