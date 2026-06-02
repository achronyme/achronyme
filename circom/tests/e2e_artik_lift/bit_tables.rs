use super::*;

/// Bitwise lowering split: a constant-amount `>>` and a constant
/// bit-mask `&` lower at field precision (`FShr` / `FAnd`, no width
/// truncation, exact for operands above `2^32`); every other bit op
/// (`<<`, `|`, `^`, `~`, a two-variable `&`) lifts through the
/// int-promotion scaffold (`IntFromField U32` → `IBin` →
/// `FieldFromInt U32`), which is exact for the <=32-bit gadgets that
/// rely on its modular wrap. Exercised by a SHA-256 σ0-style function
/// `rotr(x,7) ^ rotr(x,18) ^ (x >> 3)`: the three `>>` peel to
/// `FShr`, while the rotate tails (`<<`) and the `|` / `^` combines
/// stay on the int scaffold. The Artik payload is decoded, executed
/// on known 32-bit inputs (including the high-bit edge cases), and
/// the output cross-validated against the hand-computed reference.
#[test]
fn fn_witness_lift_handles_bit_ops() {
    use ir_forge::types::CircuitNode;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_bitops_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("bit-op lift test failed to compile: {e}"));

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
        .expect("bit-op payload must decode and validate");

    // Structural evidence of the lowering split: the three constant
    // `>>` amounts peel to field-precision `FShr` (no int-promotion
    // scaffold around them), while the non-peeled bit ops (`<<` of
    // the rotate tails, the `|` and `^` combines) still lift through
    // `IntFromField U32` → `IBin` → `FieldFromInt U32`.
    let mut fshr = 0usize;
    let mut ibin = 0usize;
    let mut ito_int = 0usize;
    let mut ito_field = 0usize;
    for instr in &prog.subprograms[0].body {
        match instr {
            artik::Instr::FShr { .. } => fshr += 1,
            artik::Instr::IBin { .. } => ibin += 1,
            artik::Instr::IntFromField { .. } => ito_int += 1,
            artik::Instr::FieldFromInt { .. } => ito_field += 1,
            _ => {}
        }
    }
    assert!(
        fshr >= 3,
        "expected ≥3 field-precision FShr (the peeled `>>` amounts), got {fshr}"
    );
    assert!(
        ibin >= 6,
        "expected ≥6 IBin ops for the non-peeled `<<` / `|` / `^`, got {ibin}"
    );
    assert!(
        ito_int >= 1 && ito_field >= 1,
        "non-peeled bit ops must still bracket IBin with the int scaffold, \
         got IntFromField={ito_int} FieldFromInt={ito_field}"
    );

    // End-to-end correctness check: compute σ0(x) = rotr(x,7) ^
    // rotr(x,18) ^ (x >> 3) at u32 width, then pick an input and
    // compare the Artik output to the hand-computed reference.
    fn rotr32(x: u32, k: u32) -> u32 {
        // Explicit matching of circomlib expansion so we detect any
        // discrepancy caused by the lift treating `<< k` or `>> k`
        // differently (e.g., wider masking slipping through).
        (x >> k) | (x.wrapping_shl(32 - k))
    }
    fn sigma0_ref(x: u32) -> u32 {
        rotr32(x, 7) ^ rotr32(x, 18) ^ (x >> 3)
    }

    use memory::field::{Bn254Fr, FieldElement};
    type FE = FieldElement<Bn254Fr>;

    for &x in &[0u32, 1, 7, 0xDEAD_BEEF, 0x8000_0001, u32::MAX] {
        let signals = [FE::from_u64(x as u64)];
        let mut slots = [FE::zero()];
        let mut ctx = artik::ArtikContext::<Bn254Fr>::new(&signals, &mut slots);
        artik::execute(&prog, &mut ctx).expect("execute σ0");
        let expected = sigma0_ref(x);
        assert_eq!(
            slots[0],
            FE::from_u64(expected as u64),
            "σ0({:#010x}) mismatch: got {:?}, expected {:#010x}",
            x,
            slots[0],
            expected,
        );
    }
}

/// SHA-256 constant-table probe: a function-local `var k[4] = […]`
/// returning `k[i]` with a runtime `i`. Pins the lift path that
/// circomlib's `sha256K(t)` depends on — `var arr[N] = [literals]`
/// inside a function body must reach the Artik VM as `AllocArray` +
/// store-once + `LoadArr` keyed by a runtime register.
#[test]
fn fn_witness_lift_sha256k_constant_table() {
    use ir_forge::types::CircuitNode;
    use memory::field::FieldFamily;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_sha256k_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("sha256k lift test failed to compile: {e}"));

    let bytes = result
        .prove_ir
        .body
        .iter()
        .find_map(|n| match n {
            CircuitNode::WitnessCall { program_bytes, .. } => Some(program_bytes.clone()),
            _ => None,
        })
        .expect("expected a CircuitNode::WitnessCall in ProveIR");

    let prog = artik::bytecode::decode(&bytes, Some(FieldFamily::BnLike256))
        .expect("sha256k payload must decode and validate");

    let mut seen_alloc = false;
    let mut seen_load = false;
    for instr in &prog.subprograms[0].body {
        match instr {
            artik::Instr::AllocArray { .. } => seen_alloc = true,
            artik::Instr::LoadArr { .. } => seen_load = true,
            _ => {}
        }
    }
    assert!(
        seen_alloc,
        "expected AllocArray for the 4-entry K table backing"
    );
    assert!(seen_load, "expected LoadArr for the runtime-indexed read");

    // Execute with idx=0..3 and confirm the table lookup reproduces
    // the SHA-256 first-four round constants.
    const K: [u64; 4] = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5];
    type FE = FieldElement<Bn254Fr>;
    for (i, expected) in K.iter().enumerate() {
        let signals = [FE::from_u64(i as u64)];
        let mut slots = [FE::zero()];
        let mut ctx = artik::ArtikContext::<Bn254Fr>::new(&signals, &mut slots);
        artik::execute(&prog, &mut ctx).expect("execute sha256K_tiny");
        assert_eq!(
            slots[0],
            FE::from_u64(*expected),
            "K[{i}] mismatch: got {:?}, expected {:#010x}",
            slots[0],
            expected,
        );
    }
}

/// Asserts inside a witness function are advisory (no R1CS
/// constraints). The lift skips a const-foldable-true predicate and
/// bails on a const-foldable-false or runtime predicate. circomlib's
/// `get_secp256k1_prime` opens with
/// `assert((n == 86 && k == 3) || (n == 64 && k == 4))` — without
/// this handling the whole secp256k1 helper chain falls back to E212.
#[test]
fn fn_witness_lift_assert_const_drop() {
    use ir_forge::types::CircuitNode;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_assert_const_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("const-assert lift failed to compile: {e}"));

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
        .expect("const-assert payload must decode and validate");
}
