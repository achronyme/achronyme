use super::*;

/// Guards a potentially-faulting `100 \ x` behind `if (x != 0)`. The
/// artik lift must route if/else arms whose substitutions invoke a
/// function call through the branching path, so the not-taken arm's
/// bytecode is jumped over instead of executed; with `x = 0` the
/// witness must take the else-arm and write `out = 0` without ever
/// running an integer division on zero.
#[test]
fn artik_mux_call_divbyzero_probe() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circom/artik_mux_call_divbyzero_probe.circom");
    let lib_dirs: Vec<PathBuf> = vec![];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("probe failed to compile: {e}"));

    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    inputs.insert("x".to_string(), FieldElement::<Bn254Fr>::zero());

    let all_signals = circom::witness::compute_witness_hints_with_captures(
        &result.prove_ir,
        &inputs,
        &result.capture_values,
    )
    .unwrap_or_else(|e| panic!("witness computation failed: {e}"));

    let actual = all_signals
        .get("out")
        .unwrap_or_else(|| panic!("missing witness signal `out`"));
    assert_eq!(
        *actual,
        FieldElement::<Bn254Fr>::zero(),
        "with x=0 the else-arm must dominate, expected out=0"
    );
}

/// A function body whose for-loop contains a guarded early `return`
/// must yield the value captured by the *first* iteration whose
/// guard fires at runtime, not the trailing fall-through return.
/// With `(a=5, b=3)` the first iteration's `a > b` is true so the
/// witness must observe `out = 1`.
#[test]
fn artik_inlined_return_in_loop_probe() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circom/artik_inlined_return_in_loop_probe.circom");
    let lib_dirs: Vec<PathBuf> = vec![];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("probe failed to compile: {e}"));

    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::<Bn254Fr>::from_u64(5));
    inputs.insert("b".to_string(), FieldElement::<Bn254Fr>::from_u64(3));

    let all_signals = circom::witness::compute_witness_hints_with_captures(
        &result.prove_ir,
        &inputs,
        &result.capture_values,
    )
    .unwrap_or_else(|e| panic!("witness computation failed: {e}"));

    let actual = all_signals
        .get("out")
        .unwrap_or_else(|| panic!("missing witness signal `out`"));
    assert_eq!(
        *actual,
        FieldElement::<Bn254Fr>::from_u64(1),
        "the earliest iteration whose guard fires at runtime must win"
    );
}

/// Array analogue of `artik_inlined_return_in_loop_probe`. A nested
/// function whose for-loop body has guarded array returns must yield
/// the array literal from the iteration that actually fires at
/// runtime. With `(a=5, b=3)` the first iteration's `a > b` is true
/// so the witness must observe `out = [1, 2, 3]`.
#[test]
fn artik_inlined_array_return_in_loop_probe() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circom/artik_inlined_array_return_in_loop_probe.circom");
    let lib_dirs: Vec<PathBuf> = vec![];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("probe failed to compile: {e}"));

    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::<Bn254Fr>::from_u64(5));
    inputs.insert("b".to_string(), FieldElement::<Bn254Fr>::from_u64(3));

    let all_signals = circom::witness::compute_witness_hints_with_captures(
        &result.prove_ir,
        &inputs,
        &result.capture_values,
    )
    .unwrap_or_else(|e| panic!("witness computation failed: {e}"));

    let expected: [u64; 3] = [1, 2, 3];
    for (i, want) in expected.iter().enumerate() {
        let key = format!("out_{i}");
        let actual = all_signals
            .get(&key)
            .unwrap_or_else(|| panic!("missing witness signal `{key}`"));
        assert_eq!(
            *actual,
            FieldElement::<Bn254Fr>::from_u64(*want),
            "out[{i}] must reflect the iteration whose guard fires at runtime"
        );
    }
}

/// Named-array analogue of `artik_inlined_array_return_in_loop_probe`.
/// A nested function whose for-loop body has guarded `return <ident>`
/// statements over locally-declared arrays must yield the array that
/// the iteration which actually fires at runtime built up.
#[test]
fn artik_inlined_named_array_return_in_loop_probe() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path =
        manifest_dir.join("test/circom/artik_inlined_named_array_return_in_loop_probe.circom");
    let lib_dirs: Vec<PathBuf> = vec![];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("probe failed to compile: {e}"));

    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    inputs.insert("a".to_string(), FieldElement::<Bn254Fr>::from_u64(5));
    inputs.insert("b".to_string(), FieldElement::<Bn254Fr>::from_u64(3));

    let all_signals = circom::witness::compute_witness_hints_with_captures(
        &result.prove_ir,
        &inputs,
        &result.capture_values,
    )
    .unwrap_or_else(|e| panic!("witness computation failed: {e}"));

    let expected: [u64; 3] = [1, 2, 3];
    for (i, want) in expected.iter().enumerate() {
        let key = format!("out_{i}");
        let actual = all_signals
            .get(&key)
            .unwrap_or_else(|| panic!("missing witness signal `{key}`"));
        assert_eq!(
            *actual,
            FieldElement::<Bn254Fr>::from_u64(*want),
            "out[{i}] must reflect the iteration whose guard fires at runtime"
        );
    }
}

/// Bit-extraction `(e >> j) & 1` over a 64-bit limb must preserve
/// every bit, including indices 32..63. A constant `>>` lowered at
/// u32 width would truncate `e` and read those high bits as zero;
/// peeling it to a field-precision shift keeps them exact. The input
/// sets bits 0, 31, 32, 62, 63 — the test asserts each extracted bit
/// matches, so a high-limb truncation regresses it.
#[test]
fn fn_witness_lift_bit_extract_preserves_high_limb_bits() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path =
        manifest_dir.join("test/circomlib/fn_witness_lift_bit_extract_high_limb_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];
    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("bit-extract fixture failed to compile: {e}"));

    // Bits set at 0, 31, 32, 62, 63 — spans the 32-bit boundary a
    // fixed-width demote would truncate.
    let e: u64 = 0xC000_0001_8000_0001;
    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    inputs.insert("e".to_string(), FieldElement::<Bn254Fr>::from_u64(e));

    let signals = circom::witness::compute_witness_hints_with_captures(
        &result.prove_ir,
        &inputs,
        &result.capture_values,
    )
    .unwrap_or_else(|err| panic!("bit-extract witness computation failed: {err}"));

    for i in 0..64u32 {
        let key = format!("b_{i}");
        let actual = signals
            .get(&key)
            .unwrap_or_else(|| panic!("missing witness signal `{key}`"));
        let want = (e >> i) & 1;
        assert_eq!(
            *actual,
            FieldElement::<Bn254Fr>::from_u64(want),
            "bit {i} mismatch: a high-limb truncation zeroes bits >= 32"
        );
    }
}
