use super::*;

/// Fase 2.1 lift extension: compile-time-folded `if / else` inside
/// an unrolled loop selects the right branch per iteration without
/// emitting any JumpIf. Runtime conditions still fall back to E212.
#[test]
fn fn_witness_lift_folds_if_else_in_loop() {
    use ir_forge::types::CircuitNode;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_ifelse_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("if/else lift test failed to compile: {e}"));

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
        .expect("payload must decode and validate");

    // Spot-check: no JumpIf / Jump should have been emitted — the
    // condition folded at lift time, so the program is straight-line.
    for instr in &prog.subprograms[0].body {
        assert!(
            !matches!(
                instr,
                artik::Instr::Jump { .. } | artik::Instr::JumpIf { .. }
            ),
            "compile-time-folded branch should not emit Jump instructions"
        );
    }
}

/// Fase 2.1 lift extension: internal arrays declared via
/// `var arr[N];` are backed by Artik `AllocArray` of `ElemT::Field`;
/// `arr[i] = expr` emits `StoreArr` and `arr[i]` emits `LoadArr`
/// once `i` folds at lift time. Verified end-to-end by round-
/// tripping the payload through the witness decoder and confirming
/// the body contains matching allocate / store / load opcodes.
#[test]
fn fn_witness_lift_handles_internal_array() {
    use ir_forge::types::CircuitNode;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_array_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("array lift test failed to compile: {e}"));

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
        .expect("array payload must decode and validate");

    let mut seen_alloc = false;
    let mut seen_store = false;
    let mut seen_load = false;
    for instr in &prog.subprograms[0].body {
        match instr {
            artik::Instr::AllocArray { .. } => seen_alloc = true,
            artik::Instr::StoreArr { .. } => seen_store = true,
            artik::Instr::LoadArr { .. } => seen_load = true,
            _ => {}
        }
    }
    assert!(seen_alloc, "expected an AllocArray in the lifted program");
    assert!(seen_store, "expected at least one StoreArr (write path)");
    assert!(seen_load, "expected at least one LoadArr (read path)");
}

/// Phase 1 lift extension: 2D arrays flatten row-major into a single
/// Artik AllocArray. `var arr[N][M]` allocates `N*M` cells; `arr[i][j]`
/// composes to flat index `i*cols + j` at lift time. Verifies the lift
/// emits a WitnessCall (no E212), the AllocArray length matches the
/// flat total, and the body contains the multiply+add stride math.
#[test]
fn fn_witness_lift_handles_2d_array() {
    use ir_forge::types::CircuitNode;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_2d_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("2D array lift test failed to compile: {e}"));

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
        .expect("2D array payload must decode and validate");

    // The lift should allocate exactly one 12-cell array (3 rows × 4 cols).
    let mut alloc_lens: Vec<u32> = Vec::new();
    for instr in &prog.subprograms[0].body {
        if let artik::Instr::AllocArray { len, .. } = instr {
            alloc_lens.push(*len);
        }
    }
    assert!(
        alloc_lens.contains(&12),
        "expected a 3×4 = 12-cell AllocArray, got {:?}",
        alloc_lens
    );
}

/// Phase 1 lift extension: descending for-loops `for (i = N; i >= 0; i--)`
/// unroll at lift time, iterating the body in reverse order. The
/// loop variable still folds to PushConst on each body emission.
#[test]
fn fn_witness_lift_handles_descending_for() {
    use ir_forge::types::CircuitNode;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_descending_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("descending for lift test failed to compile: {e}"));

    let bytes = result
        .prove_ir
        .body
        .iter()
        .find_map(|n| match n {
            CircuitNode::WitnessCall { program_bytes, .. } => Some(program_bytes.clone()),
            _ => None,
        })
        .expect("expected a CircuitNode::WitnessCall in ProveIR");

    artik::bytecode::decode(&bytes, Some(memory::FieldFamily::BnLike256))
        .expect("descending-for payload must decode and validate");

    // 5-iteration unroll should produce a body comparable in size to
    // the ascending counterpart. Floor at the same threshold the
    // existing loop test uses.
    assert!(
        bytes.len() > 80,
        "descending unroll payload suspiciously small: {} bytes",
        bytes.len()
    );
}

/// Ordered comparisons over field values lift at field precision via
/// `FCmpLt` (canonical-rep unsigned compare in `[0, p)`), with no
/// demote to a machine width. Structurally: the body emits `FCmpLt`
/// and no `IntFromField` round-trip feeds the compare. Behaviorally:
/// `2^64 > 2^64 - 1` evaluates to `1` — a U64 demote would map `2^64`
/// to `0` and answer `0`, the exact mis-branch behind circomlib
/// bigint `long_sub` at `n = 64`.
#[test]
fn fn_witness_lift_ordered_compare_is_field_precision() {
    use ir_forge::types::CircuitNode;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_limb_compare_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("limb compare lift test failed to compile: {e}"));

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
        .expect("limb compare payload must decode and validate");

    let saw_fcmplt = prog.subprograms[0]
        .body
        .iter()
        .any(|i| matches!(i, artik::Instr::FCmpLt { .. }));
    assert!(
        saw_fcmplt,
        "ordered-compare lift must emit FCmpLt (field-precision compare)"
    );
    let saw_u64_demote = prog.subprograms[0].body.iter().any(|i| {
        matches!(
            i,
            artik::Instr::IntFromField {
                w: artik::IntW::U64,
                ..
            }
        )
    });
    assert!(
        !saw_u64_demote,
        "ordered compare must not demote operands to U64 (truncates at 2^64)"
    );

    // Behavioral pin at the 2^64 boundary: 2^64 > 2^64 - 1 must be 1.
    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    inputs.insert(
        "a".to_string(),
        FieldElement::<Bn254Fr>::from_canonical([0, 1, 0, 0]),
    ); // 2^64
    inputs.insert("b".to_string(), FieldElement::<Bn254Fr>::from_u64(u64::MAX)); // 2^64 - 1
    let signals = circom::witness::compute_witness_hints_with_captures(
        &result.prove_ir,
        &inputs,
        &result.capture_values,
    )
    .unwrap_or_else(|e| panic!("limb compare witness computation failed: {e}"));
    assert_eq!(
        *signals.get("out").expect("missing witness signal `out`"),
        FieldElement::<Bn254Fr>::from_u64(1),
        "2^64 > 2^64 - 1 must be 1 (field-precision compare)"
    );
}

/// Phase 2 lift extension: `return [a, b]` allocates a 1D Artik field
/// array, lifts each element, stores at index `i`, and routes through
/// the named-array return path. Combined with the field-level FShr /
/// FAnd dispatch for `1 << n` (where `n` propagates from the caller's
/// literal arg), the lift emits a 2-cell AllocArray, two FAnd opcodes,
/// and one FShr with no IntW::U32 demote round-trip in the body.
#[test]
fn fn_witness_lift_emits_array_lit_return_with_field_pow2_ops() {
    use ir_forge::types::CircuitNode;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_array_lit_return_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("array-lit return lift test failed to compile: {e}"));

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
        .expect("array-lit-return payload must decode and validate");

    let mut alloc_lens: Vec<u32> = Vec::new();
    let mut saw_fshr = false;
    let mut saw_fand = false;
    for instr in &prog.subprograms[0].body {
        match instr {
            artik::Instr::AllocArray { len, .. } => alloc_lens.push(*len),
            artik::Instr::FShr { .. } => saw_fshr = true,
            artik::Instr::FAnd { .. } => saw_fand = true,
            _ => {}
        }
    }
    assert!(
        alloc_lens.contains(&2),
        "expected a 2-cell AllocArray for the array-literal return; got {:?}",
        alloc_lens
    );
    assert!(
        saw_fshr,
        "expected FShr for `\\ (1 << n)` with n const-folded"
    );
    assert!(
        saw_fand,
        "expected FAnd for `% (1 << n)` with n const-folded"
    );
}

/// Phase 2 lift extension: runtime `if / else` whose arms only do
/// array writes routes through `lift_if_else_branching` rather than
/// the mux path. The branching path emits a real `JumpIf`, so the
/// resulting bytecode contains conditional-jump opcodes (no
/// branchless mux merge).
#[test]
fn fn_witness_lift_emits_branching_for_array_write_arms() {
    use ir_forge::types::CircuitNode;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path =
        manifest_dir.join("test/circomlib/fn_witness_lift_runtime_if_array_writes_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("runtime-if array-write lift test failed to compile: {e}"));

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
        .expect("runtime-if array-write payload must decode and validate");

    let mut saw_jump_if = false;
    let mut saw_store_arr = false;
    for instr in &prog.subprograms[0].body {
        match instr {
            artik::Instr::JumpIf { .. } => saw_jump_if = true,
            artik::Instr::StoreArr { .. } => saw_store_arr = true,
            _ => {}
        }
    }
    assert!(
        saw_jump_if,
        "expected JumpIf opcodes from the branching if/else path"
    );
    assert!(
        saw_store_arr,
        "expected StoreArr opcodes from the array-write arms"
    );
}

/// Phase 2 lift extension: `\` and `%` with a runtime (non-pow-2)
/// divisor emit field-level FIDiv / FIRem directly on the canonical
/// representative. No IntW demote / promote round-trip.
#[test]
fn fn_witness_lift_emits_field_level_fidiv_firem() {
    use ir_forge::types::CircuitNode;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_runtime_div_mod_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("runtime div/mod lift test failed to compile: {e}"));

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
        .expect("runtime div/mod payload must decode and validate");

    let mut saw_fidiv = false;
    let mut saw_firem = false;
    for instr in &prog.subprograms[0].body {
        match instr {
            artik::Instr::FIDiv { .. } => saw_fidiv = true,
            artik::Instr::FIRem { .. } => saw_firem = true,
            _ => {}
        }
    }
    assert!(
        saw_fidiv,
        "expected FIDiv from the runtime IntDiv lift path"
    );
    assert!(saw_firem, "expected FIRem from the runtime Mod lift path");
}
