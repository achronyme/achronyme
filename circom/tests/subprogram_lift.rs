//! End-to-end gate for the subprogram witness lift.
//!
//! The fixture's `compute(x) = helper(x) + helper(x + 1) = 4*x + 4`
//! exercises the whole path: a nested call lifted as a real Artik
//! `Call`, two call sites with the same runtime parameter signature
//! deduplicated to one callee subprogram, and the callee returning by
//! value. The decoded program is validated (the bytecode validator
//! runs inside `decode`) and then executed to confirm the witness
//! value is correct.

use std::path::Path;

use ir_forge::types::CircuitNode;
use memory::{Bn254Fr, FieldElement};

#[test]
fn nested_call_lifts_to_subprograms_and_computes_the_witness() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_nested_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("subprogram-lift fixture failed to compile: {e}"));

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
        "the call lifts to a single WitnessCall payload"
    );

    // `decode` runs the bytecode validator: Call arity/types,
    // entry-only signal/witness access, Return arity vs the
    // subprogram signature. A malformed multi-subprogram program
    // would fail here.
    let prog = artik::bytecode::decode(&payload.unwrap(), Some(memory::FieldFamily::BnLike256))
        .expect("multi-subprogram payload must decode and validate");

    // Entry (compute) + one deduplicated callee (helper, called
    // twice with the same runtime signature).
    assert_eq!(
        prog.subprograms.len(),
        2,
        "expected entry + one deduplicated callee subprogram"
    );

    let entry_calls = prog.subprograms[0]
        .body
        .iter()
        .filter(|i| matches!(i, artik::Instr::Call { .. }))
        .count();
    assert_eq!(
        entry_calls, 2,
        "both helper(x) and helper(x + 1) must be real Calls to the shared callee"
    );

    // The callee returns by value: a Return carrying one source.
    let callee_returns_value = prog.subprograms[1]
        .body
        .iter()
        .any(|i| matches!(i, artik::Instr::Return { srcs } if srcs.len() == 1));
    assert!(
        callee_returns_value,
        "the callee subprogram must return its value via Return"
    );
    // The entry never returns a value (it writes witness slots).
    assert!(
        !prog.subprograms[0]
            .body
            .iter()
            .any(|i| matches!(i, artik::Instr::Return { srcs } if !srcs.is_empty())),
        "the entry subprogram returns no value — it writes witness slots"
    );

    // Execute: compute(7) = 4*7 + 4 = 32.
    type FE = FieldElement<Bn254Fr>;
    let sigs = [FE::from_u64(7)];
    let mut slots = [FE::zero()];
    let mut ctx = artik::ArtikContext::<Bn254Fr>::new(&sigs, &mut slots);
    artik::execute(&prog, &mut ctx).expect("multi-subprogram program must execute");
    assert_eq!(
        slots[0],
        FE::from_u64(32),
        "compute(7) must be 4*7 + 4 = 32"
    );
}
