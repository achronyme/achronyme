use super::*;

/// `long_sub(64, 8, x, y)` at the `b[i] + borrow == 2^64` boundary.
/// When a divisor limb is `2^64 - 1` and a borrow propagates, the
/// circomlib borrow test compares against exactly `2^64`. An ordered
/// compare that truncates operands to a machine width maps `2^64` to
/// `0`, takes the wrong branch, and yields a difference that wraps in
/// the field. The field-precision compare keeps this exact. Inputs
/// are a real `long_div` partial-remainder / subtrahend pair over
/// 256-bit operands; expected output is the integer reference.
#[test]
fn fn_witness_lift_long_sub_borrow_boundary() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path =
        manifest_dir.join("test/circomlib/fn_witness_lift_long_sub_borrow_boundary_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];
    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("long_sub boundary fixture failed to compile: {e}"));

    let x: [u64; 8] = [
        3034450356386720504,
        145874006219229635,
        15567548394240428106,
        13395347571023486071,
        12490773560222501483,
        7380319988929937060,
        3725325838365157872,
        6785630426380839144,
    ];
    let y: [u64; 8] = [
        0,
        0,
        0,
        15481419810749866648,
        18446744072129648556,
        18446744073709551615,
        18446744073709551615,
        6785630426380839143,
    ];
    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    for (i, &v) in x.iter().enumerate() {
        inputs.insert(format!("x_{i}"), FieldElement::<Bn254Fr>::from_u64(v));
    }
    for (i, &v) in y.iter().enumerate() {
        inputs.insert(format!("y_{i}"), FieldElement::<Bn254Fr>::from_u64(v));
    }

    let signals = circom::witness::compute_witness_hints_with_captures(
        &result.prove_ir,
        &inputs,
        &result.capture_values,
    )
    .unwrap_or_else(|e| panic!("long_sub boundary witness computation failed: {e}"));

    // Borrow subtraction over the field: d = x - y with limb borrows,
    // y[5] = y[6] = 2^64 - 1 force the `y[i] + borrow == 2^64` path.
    let expected: [u64; 8] = [
        3034450356386720504,
        145874006219229635,
        15567548394240428106,
        16360671833983171039,
        12490773561802404542,
        7380319988929937060,
        3725325838365157872,
        0,
    ];
    for (i, &want) in expected.iter().enumerate() {
        let key = format!("d_{i}");
        let actual = signals
            .get(&key)
            .unwrap_or_else(|| panic!("missing witness signal `{key}`"));
        assert_eq!(
            *actual,
            FieldElement::<Bn254Fr>::from_u64(want),
            "long_sub d[{i}] mismatch (2^64-boundary borrow)"
        );
    }
}

/// Lift `mod_exp` from circomlib's bigint witness call graph at
/// `n=32, k=2`. The outer `for (var i = k*n - 1; i >= 0; i--)` runs
/// 64 iters, fitting under the lift's compile-time unroll cap; each
/// iter exercises the new 1D-from-2D-row copy (`out = temp2[1]`),
/// whole-array rebinds (`temp = prod(...)`, `temp2 = long_div(...)`),
/// and the if-without-else branching path on `eBits[i] == 1`.
#[test]
fn fn_witness_lift_circomlib_mod_exp_unrolled_integration() {
    use ir_forge::types::CircuitNode;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_bigint_mod_exp_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];
    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("mod_exp integration failed to compile: {e}"));
    let bytes = result
        .prove_ir
        .body
        .iter()
        .find_map(|n| match n {
            CircuitNode::WitnessCall { program_bytes, .. } => Some(program_bytes.clone()),
            _ => None,
        })
        .expect("expected a CircuitNode::WitnessCall for mod_exp");

    let prog = artik::bytecode::decode(&bytes, Some(memory::FieldFamily::BnLike256))
        .expect("mod_exp payload must decode and validate");

    // Each unrolled iter that triggers a squaring branch emits a
    // 200-cell `var temp[200]` AllocArray. With 64 outer iters and
    // two inner ifs, the lifted body must surface at least one such
    // allocation.
    let alloc_lens: Vec<u32> = prog.subprograms[0]
        .body
        .iter()
        .filter_map(|i| match i {
            artik::Instr::AllocArray { len, .. } => Some(*len),
            _ => None,
        })
        .collect();
    assert!(
        alloc_lens.contains(&200),
        "expected a 200-cell AllocArray (var temp[200] inside if-block); got {alloc_lens:?}"
    );
}

/// Lift `mod_inv` from circomlib's bigint witness call graph at
/// `n=32, k=2`. Composes the full Phase 1-5 surface: outer for with
/// runtime if + scalar mux, an early-return branching on `isZero`,
/// compile-time-folded inner if/else for the `pCopy` fill, and two
/// whole-array rebinds — `pMinusTwo = long_sub(...)` and the
/// runtime-while-lifted `out = mod_exp(...)`.
#[test]
fn fn_witness_lift_circomlib_mod_inv_integration() {
    use ir_forge::types::CircuitNode;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_bigint_mod_inv_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];
    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("mod_inv integration failed to compile: {e}"));
    let bytes = result
        .prove_ir
        .body
        .iter()
        .find_map(|n| match n {
            CircuitNode::WitnessCall { program_bytes, .. } => Some(program_bytes.clone()),
            _ => None,
        })
        .expect("expected a CircuitNode::WitnessCall for mod_inv");

    let prog = artik::bytecode::decode(&bytes, Some(memory::FieldFamily::BnLike256))
        .expect("mod_inv payload must decode and validate");

    // mod_inv has two return paths (`if (isZero) return ret;` and the
    // tail `return out;`); each path emits its own write-witness loop
    // at lift time, but both must target the *same* slot ids so the
    // function's effective witness signature stays at 100 outputs.
    let unique_slots: std::collections::HashSet<u32> = prog.subprograms[0]
        .body
        .iter()
        .filter_map(|i| match i {
            artik::Instr::WriteWitness { slot_id, .. } => Some(*slot_id),
            _ => None,
        })
        .collect();
    assert_eq!(
        unique_slots.len(),
        100,
        "mod_inv must reuse the same 100 witness slots across its two \
         return paths; saw {} unique ids",
        unique_slots.len()
    );
}
