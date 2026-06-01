use super::*;

// -----------------------------------------------------------------
// LoopUnroll
// -----------------------------------------------------------------

/// Body of the loop below:
///   EmitMul r1, r0, r0; 1 + 1 + 1 + 1 = 4 bytes
/// (opcode size for EmitMul = 1 tag + 3 regs = 4 bytes)
pub(super) const MUL_BODY_BYTES: u16 = 4;

#[test]
fn loop_unroll_three_iterations_emits_three_muls() {
    let mut builder = b();
    // Loop: for i in 0..3 { r1 = r0 * r0 }  where r0 = iter_var
    builder
        .loop_unroll(0, 0, 3, MUL_BODY_BYTES)
        .emit_mul(1, 0, 0)
        .halt();
    let sink = run(&builder.finish(), &[]);
    // Expect: 3 Consts (iter values 0, 1, 2) + 3 Muls.
    // Dedup: Mul(r0, r0) references r0 (the iter const). Each
    // iteration's iter is distinct (0 vs 1 vs 2) so the Muls
    // don't dedup across iterations.
    let consts: Vec<_> = sink
        .instructions()
        .iter()
        .filter(|i| matches!(i, InstructionKind::Const { .. }))
        .collect();
    let muls: Vec<_> = sink
        .instructions()
        .iter()
        .filter(|i| matches!(i, InstructionKind::Mul { .. }))
        .collect();
    assert_eq!(consts.len(), 3, "one Const per iteration (iter_var)");
    assert_eq!(muls.len(), 3, "one Mul per iteration");
}

#[test]
fn loop_unroll_empty_range_emits_nothing() {
    let mut builder = b();
    builder
        .loop_unroll(0, 5, 5, MUL_BODY_BYTES) // start == end
        .emit_mul(1, 0, 0)
        .halt();
    let sink = run(&builder.finish(), &[]);
    // Body skipped entirely — no Consts, no Muls.
    assert_eq!(sink.count(), 0);
}

#[test]
fn loop_unroll_single_iteration_runs_once() {
    let mut builder = b();
    builder
        .loop_unroll(0, 0, 1, MUL_BODY_BYTES)
        .emit_mul(1, 0, 0)
        .halt();
    let sink = run(&builder.finish(), &[]);
    let consts: Vec<_> = sink
        .instructions()
        .iter()
        .filter(|i| matches!(i, InstructionKind::Const { .. }))
        .collect();
    let muls: Vec<_> = sink
        .instructions()
        .iter()
        .filter(|i| matches!(i, InstructionKind::Mul { .. }))
        .collect();
    assert_eq!(consts.len(), 1);
    assert_eq!(muls.len(), 1);
}
