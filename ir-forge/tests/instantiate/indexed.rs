use super::helpers::*;

#[test]
fn instantiate_indexed_assignment_constant() {
    // Use distinct values + a runtime witness to block Const dedup
    // collapsing them all into a single entry.
    let ir = compile_and_instantiate(
        "public out\nwitness w\nmut arr = [w, 1, 2]\narr[1] = 42\nassert_eq(arr[1], out)",
    );
    // After instantiation, arr_1 should be set to 42 (constant).
    // Distinct Consts: 1, 2, 42 — each lives as one instruction
    // thanks to dedup.
    let consts: Vec<_> = ir
        .instructions
        .iter()
        .filter(|i| matches!(i, Instruction::Const { .. }))
        .collect();
    assert!(
        consts.len() >= 3,
        "expected at least 3 Const instructions (1, 2, 42), got {}",
        consts.len()
    );
}

#[test]
fn instantiate_indexed_assignment_in_loop() {
    // `(i + 2) * x`: runtime `x` blocks the Const*Const fold, and the
    // `+2` offset ensures no iteration lands on the `Mul by 0/1`
    // identity shortcuts (i=0 would fold `0*x -> 0`, i=1 would fold
    // `1*x -> x`).
    let ir = compile_and_instantiate(
        "public out\npublic x\nmut arr = [0, 0, 0]\nfor i in 0..3 { arr[i] = x * (i + 2) }\nassert_eq(arr[2], out)",
    );
    // Loop should unroll, producing 3 Mul instructions: x*2, x*3, x*4.
    let muls: Vec<_> = ir
        .instructions
        .iter()
        .filter(|i| matches!(i, Instruction::Mul { .. }))
        .collect();
    assert_eq!(
        muls.len(),
        3,
        "expected 3 Mul instructions from unrolled loop"
    );
}
