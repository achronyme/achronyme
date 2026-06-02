use super::*;

/// Real `while` loops lift to Artik via slot-promoted scalars + a
/// conditional back-edge. Validates the smallest interesting shape:
/// `var i = start; while (i > 0) { i = i - 1; } return i;` returns
/// 0 for any non-negative `start`. Decode + run the payload against
/// `start = 5`; the program must end with witness slot 0 holding 0.
#[test]
fn fn_witness_lift_while_terminates() {
    use ir_forge::types::CircuitNode;
    use memory::field::{Bn254Fr, FieldElement};

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_while_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("while lift test failed to compile: {e}"));

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
        .expect("while payload must decode and validate");

    // The lift must have emitted a back-edge jump pair — `Jump`
    // (back to the loop header) and `JumpIf` (exit when cond is
    // false). A regression that silently bails through the
    // unrolled-for path or fails to wire the back-edge would leave
    // the body straight-line.
    let saw_jump = prog.subprograms[0]
        .body
        .iter()
        .any(|i| matches!(i, artik::Instr::Jump { .. }));
    let saw_jump_if = prog.subprograms[0]
        .body
        .iter()
        .any(|i| matches!(i, artik::Instr::JumpIf { .. }));
    assert!(saw_jump && saw_jump_if, "expected back-edge + exit jumps");

    type FE = FieldElement<Bn254Fr>;
    let sigs = [FE::from_u64(5)];
    let mut slots = [FE::zero()];
    let mut ctx = artik::ArtikContext::<Bn254Fr>::new(&sigs, &mut slots);
    artik::execute(&prog, &mut ctx).expect("while program must execute");
    assert_eq!(slots[0], FE::zero(), "countdown_to_zero(5) should be 0");
}

/// A descending `for (i = start - 1; i >= 0; i--)` whose bound is a
/// runtime argument routes through the runtime loop path. `i >= 0` is
/// a tautology for a field counter, so a naive desugaring underflows
/// past zero and runs on with a wrapped counter (garbage indices /
/// non-termination). The lift must rewrite it to a terminating form
/// that counts down to and including zero exactly once. Executes the
/// lifted witness and pins the closed-form sum.
#[test]
fn fn_witness_lift_runtime_descending_to_zero() {
    use ir_forge::types::CircuitNode;
    use memory::field::{Bn254Fr, FieldElement};

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path =
        manifest_dir.join("test/circomlib/fn_witness_lift_runtime_descending_to_zero_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("runtime-descending lift test failed to compile: {e}"));

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
        .expect("runtime-descending payload must decode and validate");

    // It must be a real runtime loop (back-edge + exit jumps), not a
    // silent fall-through to the unrolled-for path.
    let saw_jump = prog.subprograms[0]
        .body
        .iter()
        .any(|i| matches!(i, artik::Instr::Jump { .. }));
    let saw_jump_if = prog.subprograms[0]
        .body
        .iter()
        .any(|i| matches!(i, artik::Instr::JumpIf { .. }));
    assert!(saw_jump && saw_jump_if, "expected back-edge + exit jumps");

    // sum_down(5) = 4+3+2+1+0 = 10. A counter underflow would instead
    // exhaust the budget or read a wrapped index.
    type FE = FieldElement<Bn254Fr>;
    let sigs = [FE::from_u64(5)];
    let mut slots = [FE::zero()];
    let mut ctx = artik::ArtikContext::<Bn254Fr>::new(&sigs, &mut slots);
    artik::execute(&prog, &mut ctx).expect("runtime-descending program must execute");
    assert_eq!(
        slots[0],
        FE::from_u64(10),
        "sum_down(5) must be 10 — the descending loop counts down to zero inclusive"
    );

    // Edge: sum_down(0) — circom runs zero iterations (`i = -1`,
    // `-1 >= 0` is false). The rewrite must also produce 0 here, not
    // run once or underflow.
    let sigs0 = [FE::zero()];
    let mut slots0 = [FE::zero()];
    let mut ctx0 = artik::ArtikContext::<Bn254Fr>::new(&sigs0, &mut slots0);
    artik::execute(&prog, &mut ctx0).expect("runtime-descending program must execute at start=0");
    assert_eq!(
        slots0[0],
        FE::zero(),
        "sum_down(0) must be 0 — no iterations when start-1 < 0"
    );
}

/// A `while`-promoted runtime counter used as the index of an array
/// *write* (`arr[i] = i * 2`). The 1D indexed-assignment lift must
/// accept a runtime index — the symmetric mirror of the runtime-index
/// array read — or the function declines and the call falls back to
/// the E212 diagnostic, failing compilation. Executes the lifted
/// witness and pins the closed form `n*(n-1)`, plus the full-range
/// edge where every cell is written through the runtime index.
#[test]
fn fn_witness_lift_runtime_index_store() {
    use ir_forge::types::CircuitNode;
    use memory::field::{Bn254Fr, FieldElement};

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_runtime_index_store_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("runtime-index store lift failed to compile: {e}"));

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
        .expect("runtime-index store payload must decode and validate");

    // It must be a real runtime loop (back-edge + exit jumps): a
    // const-folded index would have unrolled and emitted no JumpIf,
    // which would not exercise the runtime-index StoreArr path.
    let saw_jump = prog.subprograms[0]
        .body
        .iter()
        .any(|i| matches!(i, artik::Instr::Jump { .. }));
    let saw_jump_if = prog.subprograms[0]
        .body
        .iter()
        .any(|i| matches!(i, artik::Instr::JumpIf { .. }));
    assert!(
        saw_jump && saw_jump_if,
        "expected a real runtime loop (back-edge + exit jumps)"
    );

    // fill_and_sum(5): arr = [0,2,4,6,8,0,0,0], total = 20 = 5*4.
    type FE = FieldElement<Bn254Fr>;
    let sigs = [FE::from_u64(5)];
    let mut slots = [FE::zero()];
    let mut ctx = artik::ArtikContext::<Bn254Fr>::new(&sigs, &mut slots);
    artik::execute(&prog, &mut ctx).expect("runtime-index store program must execute");
    assert_eq!(
        slots[0],
        FE::from_u64(20),
        "fill_and_sum(5) must be 20 — runtime-index writes land in the right cells"
    );

    // Edge: every cell written through the runtime index (n == len).
    // fill_and_sum(8): arr = [0,2,4,6,8,10,12,14], total = 56 = 8*7.
    let sigs8 = [FE::from_u64(8)];
    let mut slots8 = [FE::zero()];
    let mut ctx8 = artik::ArtikContext::<Bn254Fr>::new(&sigs8, &mut slots8);
    artik::execute(&prog, &mut ctx8).expect("runtime-index store program must execute at n=8");
    assert_eq!(
        slots8[0],
        FE::from_u64(56),
        "fill_and_sum(8) must be 56 — full-range runtime-index writes"
    );
}

/// A `return cond ? a : b;` with a runtime condition. The expression
/// lift must lower it as a branchless select (`cond_bool * a + (1 -
/// cond_bool) * b`) — no conditional jump — or the callee return
/// declines and compilation fails with E212. circomlib's `isNegative`
/// is exactly this shape. Both arms are exercised.
#[test]
fn fn_witness_lift_ternary_select() {
    use ir_forge::types::CircuitNode;
    use memory::field::{Bn254Fr, FieldElement};

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_ternary_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("ternary lift failed to compile: {e}"));

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
        .expect("ternary payload must decode and validate");

    // Branchless: a runtime-condition ternary lowers to a select, not
    // a conditional jump.
    let saw_jump_if = prog
        .subprograms
        .iter()
        .flat_map(|s| s.body.iter())
        .any(|i| matches!(i, artik::Instr::JumpIf { .. }));
    assert!(
        !saw_jump_if,
        "a runtime-condition ternary must be a branchless select, not a JumpIf"
    );

    // compute(50) = is_big(50) = (50 > 100 ? 7 : 13) = 13;
    // compute(200) = 7. Both arms.
    type FE = FieldElement<Bn254Fr>;
    let sigs_lo = [FE::from_u64(50)];
    let mut slots_lo = [FE::zero()];
    let mut ctx_lo = artik::ArtikContext::<Bn254Fr>::new(&sigs_lo, &mut slots_lo);
    artik::execute(&prog, &mut ctx_lo).expect("ternary program must execute");
    assert_eq!(
        slots_lo[0],
        FE::from_u64(13),
        "compute(50) must be 13 — the false arm"
    );

    let sigs_hi = [FE::from_u64(200)];
    let mut slots_hi = [FE::zero()];
    let mut ctx_hi = artik::ArtikContext::<Bn254Fr>::new(&sigs_hi, &mut slots_hi);
    artik::execute(&prog, &mut ctx_hi).expect("ternary program must execute");
    assert_eq!(
        slots_hi[0],
        FE::from_u64(7),
        "compute(200) must be 7 — the true arm"
    );
}
