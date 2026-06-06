use super::*;

/// `var X; ... X = <const-expr>;` compile-time tracking.
///
/// Regression for the pattern circomlib SHA256 uses:
///
/// ```circom
/// var nBlocks;
/// nBlocks = ((nBits + 64)\512) + 1;
/// signal paddedIn[nBlocks*512];
/// for (var k = nBits+1; k < nBlocks*512 - 64; k++) { ... }
/// paddedIn[nBlocks*512 - k - 1] <== ...;
/// ```
///
/// Before the fix, `precompute_all` only tracked `var X = expr;` on a
/// single statement and `template::lower` never injected precomputed
/// scalars into `env.known_constants`, so `nBlocks` reached the ProveIR
/// instantiator as `CircuitExpr::Var("nBlocks")` and indexing failed
/// with "indexed assignment requires a compile-time constant index".
///
/// All four padding loops have const-tractable bodies (every read
/// resolves to a `Const`/`Capture` when the iter var is bound to
/// `Const(i)`), so `emit_range_loop` takes the eager-unroll path:
/// each iteration emits one `AssertEq(pub_var, const_v)` and the
/// `(nBits >> k) & 1` value folds via `eval_const_expr` without
/// materialising any Decompose. This fixture historically also
/// exercised the Lysis walker's wide-body spill discipline; that
/// path is now bypassed entirely for this pattern, so the test
/// stands as a regression for the var-postdecl tracking only.
#[test]
fn var_postdecl_padding_e2e() {
    let n = circomlib_e2e_verify(
        "VarPostDeclPadding(64)",
        "test/circomlib/var_postdecl_padding_test.circom",
        &[],
    );
    assert_eq!(
        n, 513,
        "expected 513 constraints (512 output AssertEqs + 1 boundary; \
         eager-unroll folds the `(nBits >> k) & 1` Decompose chain to \
         constants per iter)"
    );
}

/// Gap E closed: a function that declares internal state (`var`
/// arrays, loops, multi-statement computation) and returns the
/// internal array now lowers to an Artik witness call instead of
/// E212. The lift emits one witness slot per array element, and
/// `inline_function_call` re-bundles the slots into a `LetArray` so
/// the caller's `var tmp[4] = derive(in); out[i] <-- tmp[i];`
/// pattern round-trips without hitting the old name-shadowing bug
/// (`var out[256]` vs `signal output out[256]`).
///
/// This test was originally the E212 regression asserted by Fase 1.
/// With Fase 2.1's array-return support, the same fixture now
/// compiles cleanly, so the assertion flips: we verify that the
/// lift produced four output slots and a matching LetArray.
#[test]
fn fn_local_shadowing_lifts_through_artik() {
    use ir_forge::types::CircuitNode;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_local_shadowing_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("Gap E fixture failed to compile after lift: {e}"));

    let mut witness_call_outputs: Option<Vec<String>> = None;
    let mut let_array_len: Option<usize> = None;
    for node in &result.prove_ir.body {
        match node {
            CircuitNode::WitnessCall {
                output_bindings, ..
            } => {
                witness_call_outputs = Some(output_bindings.clone());
            }
            CircuitNode::LetArray { elements, .. } if let_array_len.is_none() => {
                let_array_len = Some(elements.len());
            }
            _ => {}
        }
    }

    let outs = witness_call_outputs.expect("expected a WitnessCall in ProveIR");
    assert_eq!(outs.len(), 4, "array-return should expose 4 witness slots");
    assert_eq!(
        let_array_len,
        Some(4),
        "expected a LetArray of length 4 re-bundling the 4 witness slots"
    );
}

/// Fase 2 lift success: a function with a non-trivial body (one
/// `var` + a `return` over arithmetic on the parameter) now lowers
/// through the Artik witness-call pass instead of E212. We verify
/// that (a) compilation succeeds, (b) the ProveIR contains a
/// `WitnessCall` node carrying an Artik bytecode payload, and (c)
/// the payload round-trips through the witness decoder cleanly (so
/// the structural validator accepts it).
#[test]
fn fn_witness_lift_produces_artik_call() {
    use ir_forge::types::CircuitNode;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("witness lift test failed to compile: {e}"));

    // Walk the ProveIR body looking for the new WitnessCall variant.
    let mut call: Option<(Vec<String>, usize)> = None;
    for node in &result.prove_ir.body {
        if let CircuitNode::WitnessCall {
            output_bindings,
            program_bytes,
            ..
        } = node
        {
            call = Some((output_bindings.clone(), program_bytes.len()));
            break;
        }
    }
    let (outs, byte_len) = call.expect("expected a CircuitNode::WitnessCall in ProveIR");
    assert_eq!(outs.len(), 1, "expected exactly one output binding");
    assert!(
        outs[0].starts_with("__artik_derive_scalar_"),
        "unexpected output name: {}",
        outs[0]
    );
    assert!(
        byte_len > 16,
        "Artik payload must be larger than the header"
    );

    // Round-trip the payload: if decode + validate accept it, the
    // lift produced a structurally sound program.
    //
    // We grab the bytes again now that we know one exists.
    let bytes = result
        .prove_ir
        .body
        .iter()
        .find_map(|n| match n {
            CircuitNode::WitnessCall { program_bytes, .. } => Some(program_bytes.clone()),
            _ => None,
        })
        .unwrap();
    artik::bytecode::decode(&bytes, Some(memory::FieldFamily::BnLike256))
        .expect("Artik payload must decode and validate");
}

/// Fase 2.1 lift extension: a function body with a compile-time
/// bounded `for` loop now unrolls at lift time. The loop variable
/// becomes a ConstInt in the lift state; each iteration's body is
/// lowered with the variable substituted as `PushConst`. Verifies
/// that (a) the loop-bearing function lowers without E212, (b) the
/// resulting Artik payload is larger than the single-iteration
/// baseline (evidence the body was actually emitted 4×), and (c)
/// the payload validates.
#[test]
fn fn_witness_lift_unrolls_for_loop() {
    use ir_forge::types::CircuitNode;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_loop_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("loop lift test failed to compile: {e}"));

    let bytes = result
        .prove_ir
        .body
        .iter()
        .find_map(|n| match n {
            CircuitNode::WitnessCall { program_bytes, .. } => Some(program_bytes.clone()),
            _ => None,
        })
        .expect("expected a CircuitNode::WitnessCall in ProveIR");

    // Bytes from the simpler baseline (`var y = x*2; return y+1;`)
    // land around 50–60. An unrolled 4-iteration loop with an
    // accumulator is measurably larger — assert we passed that floor
    // so a regression that silently falls back to the single-return
    // path (or worse, truncates the body) gets caught.
    assert!(
        bytes.len() > 80,
        "unrolled loop payload suspiciously small: {} bytes",
        bytes.len()
    );

    artik::bytecode::decode(&bytes, Some(memory::FieldFamily::BnLike256))
        .expect("unrolled Artik payload must decode and validate");
}
