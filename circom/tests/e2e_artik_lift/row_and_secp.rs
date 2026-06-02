use super::*;

/// Row slice as return: `return arr2d[row]` where the local is a
/// Flat2D. The lift materializes the row as a fresh 1D field array
/// and emits per-cell witness slots. Without this, the lift bails to
/// E212 — the symptom that surfaced in circomlib's `prod_mod_p`,
/// which builds `result[2][100]` and returns `result[1]`.
#[test]
fn fn_witness_lift_row_slice_return() {
    use ir_forge::types::CircuitNode;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_row_slice_return_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("row-slice return lift failed to compile: {e}"));

    let call = result.prove_ir.body.iter().find_map(|n| match n {
        CircuitNode::WitnessCall {
            program_bytes,
            output_bindings,
            ..
        } => Some((program_bytes.clone(), output_bindings.clone())),
        _ => None,
    });
    let (bytes, outputs) = call.expect("expected a CircuitNode::WitnessCall in ProveIR");
    assert_eq!(
        outputs.len(),
        3,
        "row-slice return should expose 3 witness slots (one per row cell), got {outputs:?}"
    );
    artik::bytecode::decode(&bytes, Some(memory::FieldFamily::BnLike256))
        .expect("row-slice return payload must decode and validate");
}

/// Row slice as nested-call argument: `f(..., arr2d[row], ...)`
/// where the source is a Flat2D local. The lift materializes the row
/// as a fresh Flat1D so the callee binds it as an array parameter.
/// Without this, the lift bails to E212 — the symptom that surfaced
/// in circomlib's `secp256k1_addunequal_func`, which passes `b[1]`
/// and `a[1]` (rows of `var a[2][100]` / `var b[2][100]`) to
/// `long_sub_mod_p`.
#[test]
fn fn_witness_lift_row_slice_arg() {
    use ir_forge::types::CircuitNode;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_row_slice_arg_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("row-slice arg lift failed to compile: {e}"));

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
        .expect("row-slice arg payload must decode and validate");
}

/// `secp256k1_addunequal_func(64, 4, ...)` is the heaviest witness
/// body in the corpus: a chain of nested helper calls (long_sub_mod_p,
/// long_div, short_div, short_div_norm, prod, mod_inv,
/// get_secp256k1_prime, long_scalar_mult, long_sub, SplitFn,
/// SplitThreeFn, ...) returning a 2D point. It lifts to a single
/// WitnessCall whose payload is one multi-subprogram program — the
/// entry plus a deduplicated subprogram per helper specialization,
/// invoked by real `Call`s. This pins the structural contract (one
/// payload, decodes + validates, genuinely multi-subprogram); the
/// witness values are cross-validated against the snarkjs reference
/// by `fn_witness_decompose_secp256k1_addunequal_values`.
#[test]
fn fn_witness_decompose_secp256k1_addunequal() {
    use ir_forge::types::CircuitNode;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path =
        manifest_dir.join("test/circomlib/fn_witness_decompose_secp256k1_addunequal_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("secp256k1_addunequal failed to compile: {e}"));

    let witness_calls: Vec<&Vec<u8>> = result
        .prove_ir
        .body
        .iter()
        .filter_map(|n| match n {
            CircuitNode::WitnessCall { program_bytes, .. } => Some(program_bytes),
            _ => None,
        })
        .collect();

    assert_eq!(
        witness_calls.len(),
        1,
        "the helper chain lifts to one multi-subprogram WitnessCall, got {}",
        witness_calls.len()
    );

    let prog = artik::bytecode::decode(witness_calls[0], Some(memory::FieldFamily::BnLike256))
        .expect("secp256k1_addunequal payload must decode and validate");

    assert!(
        prog.subprograms.len() >= 11,
        "expected the helper chain as ≥11 callee subprograms (entry + \
         deduplicated helpers), got {}",
        prog.subprograms.len()
    );
}
