use super::*;

/// Fase 2.1 lift extension: a nested function call inside another
/// lifted function body is inlined into the same Artik program.
/// `compute(x)` calls `helper` twice; both invocations lower into
/// `compute`'s single program (no separate WitnessCall per call),
/// and the resulting payload contains exactly one `Return` opcode.
#[test]
fn fn_witness_lift_inlines_nested_call() {
    use ir_forge::types::CircuitNode;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_nested_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("nested-call lift test failed to compile: {e}"));

    let mut witness_call_count = 0;
    let mut payload: Option<Vec<u8>> = None;
    for node in &result.prove_ir.body {
        if let CircuitNode::WitnessCall { program_bytes, .. } = node {
            witness_call_count += 1;
            payload = Some(program_bytes.clone());
        }
    }
    assert_eq!(
        witness_call_count, 1,
        "nested calls must be inlined into a single WitnessCall"
    );
    let prog = artik::bytecode::decode(&payload.unwrap(), Some(memory::FieldFamily::BnLike256))
        .expect("nested-lift payload must decode and validate");

    let return_count = prog.subprograms[0]
        .body
        .iter()
        .filter(|i| matches!(i, artik::Instr::Return { .. }))
        .count();
    assert_eq!(
        return_count, 1,
        "the final program must have exactly one Return — nested returns are captured, not emitted"
    );
}

/// Fase 2.2 lift extension: an `if / else` with a runtime-signal
/// condition lifts to a field-arithmetic mux instead of falling back
/// to E212. The lift normalizes `cond` via `FEq(cond, 0)` +
/// `FieldFromInt U64` + `FSub` so circom's "0 is false, non-zero is
/// true" semantics hold, then merges scalar locals with
/// `cond * then + (1 - cond) * else`. No `Jump` / `JumpIf` opcodes
/// are emitted.
#[test]
fn fn_witness_lift_muxes_runtime_if_else() {
    use ir_forge::types::CircuitNode;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_mux_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("mux lift test failed to compile: {e}"));

    let bytes = result
        .prove_ir
        .body
        .iter()
        .find_map(|n| match n {
            CircuitNode::WitnessCall { program_bytes, .. } => Some(program_bytes.clone()),
            _ => None,
        })
        .expect("expected a CircuitNode::WitnessCall in ProveIR");

    let prog = artik::bytecode::decode(&bytes, Some(memory::FieldFamily::BnLike256))
        .expect("mux payload must decode and validate");

    // No control flow emitted — the mux is pure arithmetic.
    for instr in &prog.subprograms[0].body {
        assert!(
            !matches!(
                instr,
                artik::Instr::Jump { .. } | artik::Instr::JumpIf { .. }
            ),
            "runtime if/else should lower to a mux, not Jump instructions"
        );
    }

    // Evidence the normalization prelude ran: exactly one FEq (for
    // `cond == 0`), at least one FieldFromInt (lifting the FEq result
    // back to Field), and at least three FMul (two arm-multiplies +
    // at least one from the body's own arithmetic).
    let feq_count = prog.subprograms[0]
        .body
        .iter()
        .filter(|i| matches!(i, artik::Instr::FEq { .. }))
        .count();
    assert_eq!(
        feq_count, 1,
        "expected exactly one FEq from the cond-normalization prelude"
    );
    let field_from_int_count = prog.subprograms[0]
        .body
        .iter()
        .filter(|i| matches!(i, artik::Instr::FieldFromInt { .. }))
        .count();
    assert!(
        field_from_int_count >= 1,
        "expected FieldFromInt to lift FEq result back to Field"
    );
    let fmul_count = prog.subprograms[0]
        .body
        .iter()
        .filter(|i| matches!(i, artik::Instr::FMul { .. }))
        .count();
    assert!(
        fmul_count >= 3,
        "expected at least 3 FMul ops (then/else mux + body multiplies), got {fmul_count}"
    );

    // End-to-end execution check: feed both cond=0 and cond=1 cases
    // through the Artik executor directly. This proves the mux
    // actually selects the right arm — the decoder/validator above
    // only verifies structural soundness, not semantics.
    use memory::field::{Bn254Fr, FieldElement};
    type FE = FieldElement<Bn254Fr>;

    // cond=1, a=10, b=99 → select returns a + 1 == 11.
    let signals_true = [FE::from_u64(1), FE::from_u64(10), FE::from_u64(99)];
    let mut slots = [FE::zero()];
    let mut ctx = artik::ArtikContext::<Bn254Fr>::new(&signals_true, &mut slots);
    artik::execute(&prog, &mut ctx).expect("execute cond=1");
    assert_eq!(slots[0], FE::from_u64(11), "mux cond=1 should pick a + 1");

    // cond=0, a=10, b=99 → select returns b * 2 == 198.
    let signals_false = [FE::from_u64(0), FE::from_u64(10), FE::from_u64(99)];
    let mut slots = [FE::zero()];
    let mut ctx = artik::ArtikContext::<Bn254Fr>::new(&signals_false, &mut slots);
    artik::execute(&prog, &mut ctx).expect("execute cond=0");
    assert_eq!(slots[0], FE::from_u64(198), "mux cond=0 should pick b * 2");

    // cond=7 (non-zero, non-bool) exercises the FEq-normalization
    // prelude — circom treats any non-zero as true.
    let signals_seven = [FE::from_u64(7), FE::from_u64(10), FE::from_u64(99)];
    let mut slots = [FE::zero()];
    let mut ctx = artik::ArtikContext::<Bn254Fr>::new(&signals_seven, &mut slots);
    artik::execute(&prog, &mut ctx).expect("execute cond=7");
    assert_eq!(
        slots[0],
        FE::from_u64(11),
        "non-bool cond should normalize to true and pick a + 1"
    );
}
