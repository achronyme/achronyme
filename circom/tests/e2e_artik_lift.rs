mod common;
use common::*;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use memory::{Bn254Fr, FieldElement};
use zkc::r1cs_backend::R1CSCompiler;

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
            CircuitNode::LetArray { elements, .. } => {
                if let_array_len.is_none() {
                    let_array_len = Some(elements.len());
                }
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

/// Phase 3 integration: lift `prod(n, k, a, b)` from circomlib's
/// bigint_func.circom — the convolution-style polynomial product that
/// stitches `SplitThreeFn` + `SplitFn` calls into a 2D `split[i][j]`
/// matrix. Two new lift surfaces unblock this:
///
/// - Whole-row 2D assignment `split[i] = SplitThreeFn(...)` where the
///   target row index folds compile-time and the call returns a 1D
///   array of length matching `cols`.
/// - VarDecl with array dim + Call init `var sumAndCarry[2] =
///   SplitFn(...)` — the callee's returned handle is aliased into the
///   caller's `arrays` map without re-allocation.
///
/// Verifies the WitnessCall exists, bytecode decodes, and the program
/// allocates the expected `split[2*k-1][3]` 2D array (3 rows × 3 cols
/// at k=2 ⇒ 9 cells; also a `100`-cell `prod_val[100]` from the
/// outer's `var prod_val[100]`).
#[test]
fn fn_witness_lift_circomlib_prod_integration() {
    use ir_forge::types::CircuitNode;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_bigint_prod_probe.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];
    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("prod integration failed to compile: {e}"));
    let bytes = result
        .prove_ir
        .body
        .iter()
        .find_map(|n| match n {
            CircuitNode::WitnessCall { program_bytes, .. } => Some(program_bytes.clone()),
            _ => None,
        })
        .expect(
            "expected a CircuitNode::WitnessCall — prod must lift via the witness-calc \
             pipeline, not fall back to E212",
        );

    let prog = artik::bytecode::decode(&bytes, Some(memory::FieldFamily::BnLike256))
        .expect("prod payload must decode and validate");

    // `prod` declares `var split[100][3]` — flattened to a 300-cell
    // AllocArray. The 100-cell allocations come from `var
    // prod_val[100]`, `var out[100]`, `var carry[100]`. The smaller
    // allocations are from each `SplitThreeFn` (3-cell return),
    // `SplitFn` (2-cell return), and the `a[2]` / `b[2]` input
    // signal-array params bound by `LiftState::new`.
    let alloc_lens: Vec<u32> = prog.subprograms[0]
        .body
        .iter()
        .filter_map(|i| match i {
            artik::Instr::AllocArray { len, .. } => Some(*len),
            _ => None,
        })
        .collect();
    assert!(
        alloc_lens.contains(&300),
        "expected a 300-cell AllocArray (split[100][3] flattened); got {:?}",
        alloc_lens
    );
    assert!(
        alloc_lens.iter().filter(|&&l| l == 100).count() >= 3,
        "expected at least 3× 100-cell AllocArray (prod_val + out + carry); got {:?}",
        alloc_lens
    );
    assert!(
        alloc_lens.contains(&3),
        "expected at least one 3-cell AllocArray from SplitThreeFn ArrayLit return; got {:?}",
        alloc_lens
    );
    assert!(
        alloc_lens.iter().filter(|&&l| l == 2).count() >= 2,
        "expected at least 2× 2-cell AllocArray from SplitFn ArrayLit returns; got {:?}",
        alloc_lens
    );

    // The inner SplitFn / SplitThreeFn calls must each fold their
    // `1 << n` divisors at lift time and emit field-level FShr / FAnd.
    // A regression in nested-call const-arg propagation would silently
    // route those through FIDiv / FIRem — passing the AllocArray
    // assertions but failing this one.
    let saw_fshr = prog.subprograms[0]
        .body
        .iter()
        .any(|i| matches!(i, artik::Instr::FShr { .. }));
    let saw_fand = prog.subprograms[0]
        .body
        .iter()
        .any(|i| matches!(i, artik::Instr::FAnd { .. }));
    assert!(
        saw_fshr,
        "prod payload must contain FShr from inner SplitFn / SplitThreeFn calls"
    );
    assert!(
        saw_fand,
        "prod payload must contain FAnd from inner SplitFn / SplitThreeFn calls"
    );
}

/// Phase 3 width-stress integration: lift `prod(64, 4, a, b)` from
/// circomlib's bigint_func.circom at the call-graph's nominal config.
/// At k=4, n=64 the `prod_val[i]` accumulator sums up to 4 products
/// of 64-bit operands ⇒ peak value ~2^130, exceeding U128. The lift's
/// field-level FShr / FAnd dispatch (vs IntW demote) is what makes
/// this representable — bits 128-191 must survive the SplitThreeFn
/// extraction, and they would truncate under U128.
#[test]
fn fn_witness_lift_circomlib_prod_k4_n64_width_stress() {
    use ir_forge::types::CircuitNode;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_bigint_prod_k4_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];
    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("prod k=4 n=64 lift failed to compile: {e}"));
    let bytes = result
        .prove_ir
        .body
        .iter()
        .find_map(|n| match n {
            CircuitNode::WitnessCall { program_bytes, .. } => Some(program_bytes.clone()),
            _ => None,
        })
        .expect("expected a CircuitNode::WitnessCall at k=4 n=64");

    let prog = artik::bytecode::decode(&bytes, Some(memory::FieldFamily::BnLike256))
        .expect("prod k=4 n=64 payload must decode and validate");

    // SplitThreeFn extracts bits via three `% / \` shapes:
    //   `in % (1 << n)`        → FShr 0 / FAnd low-n   (bit range 0..n)
    //   `(in \ (1 << n)) % (1 << m)`        → FShr n  / FAnd low-m
    //   `(in \ (1 << n + m)) % (1 << k)`    → FShr n+m / FAnd low-k
    // At n=m=k=64, the third shape needs FShr by amount 128 — that's
    // the load-bearing FShr boundary for a >U128 input. Confirm we
    // emit it (not by checking the *value* of amount, which would
    // require pinning every FShr in the program, but by checking at
    // least one FShr exists with amount ≥ 64; combined with FAnd this
    // proves the bit-extraction dispatch fired for all three shapes).
    let max_fshr_amount = prog.subprograms[0]
        .body
        .iter()
        .filter_map(|i| match i {
            artik::Instr::FShr { amount, .. } => Some(*amount),
            _ => None,
        })
        .max()
        .unwrap_or(0);
    assert!(
        max_fshr_amount >= 64,
        "expected at least one FShr with amount ≥ 64 (SplitThreeFn's bit-128 \
         extraction at n=64); max amount seen = {max_fshr_amount}"
    );
    let saw_fand = prog.subprograms[0]
        .body
        .iter()
        .any(|i| matches!(i, artik::Instr::FAnd { .. }));
    assert!(
        saw_fand,
        "expected FAnd at k=4 n=64 from SplitThreeFn / SplitFn bit-mask dispatch"
    );
}

/// Phase 2 integration: pull `SplitFn` directly from circomlib's
/// bigint witness call graph and verify the lift produces an E2E
/// WitnessCall. This is the load-bearing test that the Phase 2 surface
/// works on a real call-graph function (not a hand-rolled lookalike).
/// Asserts the WitnessCall exists, its body decodes, and FShr / FAnd
/// fire — proving the const-pow-2 dispatch flows through the actual
/// circomlib source.
#[test]
fn fn_witness_lift_circomlib_split_fn_integration() {
    use ir_forge::types::CircuitNode;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_bigint_split_fn_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("circomlib SplitFn integration failed to compile: {e}"));

    let bytes = result
        .prove_ir
        .body
        .iter()
        .find_map(|n| match n {
            CircuitNode::WitnessCall { program_bytes, .. } => Some(program_bytes.clone()),
            _ => None,
        })
        .expect(
            "expected a CircuitNode::WitnessCall — SplitFn must lift via the witness-calc \
             pipeline, not fall back to E212",
        );

    let prog = artik::bytecode::decode(&bytes, Some(memory::FieldFamily::BnLike256))
        .expect("circomlib SplitFn payload must decode and validate");

    let mut saw_fshr = false;
    let mut saw_fand = false;
    for instr in &prog.subprograms[0].body {
        match instr {
            artik::Instr::FShr { .. } => saw_fshr = true,
            artik::Instr::FAnd { .. } => saw_fand = true,
            _ => {}
        }
    }
    assert!(
        saw_fshr,
        "circomlib SplitFn lift must emit FShr for `\\ (1 << n)` with const n"
    );
    assert!(
        saw_fand,
        "circomlib SplitFn lift must emit FAnd for `% (1 << n)` with const n"
    );
}

/// Lift `short_div_norm` from circomlib's bigint witness call graph.
/// Exercises the runtime FIDiv dispatch on the qhat shape
/// `(a[k] * (1 << n) + a[k-1]) \ b[k-1]` (non-power-of-2 divisor, both
/// operands runtime), the runtime if/else qhat clamp (mux-compatible
/// scalar reassignment), and the whole-array reassignment from a call
/// (`mult = long_sub(...)`) which re-binds an existing array slot to
/// the callee's returned heap handle.
#[test]
fn fn_witness_lift_circomlib_short_div_norm_integration() {
    use ir_forge::types::CircuitNode;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path =
        manifest_dir.join("test/circomlib/fn_witness_lift_bigint_short_div_norm_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];
    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("short_div_norm integration failed to compile: {e}"));
    let bytes = result
        .prove_ir
        .body
        .iter()
        .find_map(|n| match n {
            CircuitNode::WitnessCall { program_bytes, .. } => Some(program_bytes.clone()),
            _ => None,
        })
        .expect(
            "expected a CircuitNode::WitnessCall — short_div_norm must lift via the \
             witness-calc pipeline, not fall back to E212",
        );

    let prog = artik::bytecode::decode(&bytes, Some(memory::FieldFamily::BnLike256))
        .expect("short_div_norm payload must decode and validate");

    // The qhat shape `(a[k] * (1 << n) + a[k-1]) \ b[k-1]` divides by a
    // runtime-valued register (`b[k-1]`), so the divisor never folds to
    // a const power of two — the lift must dispatch through FIDiv. A
    // regression to FShr / FAnd would silently drop the high bits of
    // the dividend.
    let saw_fidiv = prog.subprograms[0]
        .body
        .iter()
        .any(|i| matches!(i, artik::Instr::FIDiv { .. }));
    assert!(
        saw_fidiv,
        "short_div_norm lift must emit at least one FIDiv (qhat shape with runtime divisor)"
    );
}

/// Lift `short_div` from circomlib's bigint witness call graph.
/// Composes `short_div_norm` + `long_scalar_mult` and adds another
/// runtime FIDiv (`scale = (1 << n) \ (1 + b[k-1])`).
#[test]
fn fn_witness_lift_circomlib_short_div_integration() {
    use ir_forge::types::CircuitNode;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_bigint_short_div_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];
    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("short_div integration failed to compile: {e}"));
    let bytes = result
        .prove_ir
        .body
        .iter()
        .find_map(|n| match n {
            CircuitNode::WitnessCall { program_bytes, .. } => Some(program_bytes.clone()),
            _ => None,
        })
        .expect("expected a CircuitNode::WitnessCall for short_div");

    let prog = artik::bytecode::decode(&bytes, Some(memory::FieldFamily::BnLike256))
        .expect("short_div payload must decode and validate");

    // short_div emits at least two FIDiv calls: one for the `scale =
    // (1 << n) \ (1 + b[k-1])` shape and one inside the nested
    // short_div_norm for qhat. Both have non-power-of-2 divisors so
    // they fall into the runtime FIDiv path, not FShr / FAnd.
    let fidiv_count = prog.subprograms[0]
        .body
        .iter()
        .filter(|i| matches!(i, artik::Instr::FIDiv { .. }))
        .count();
    assert!(
        fidiv_count >= 2,
        "short_div lift must emit at least 2× FIDiv (scale + qhat); got {fidiv_count}"
    );
}

/// Lift `long_div` from circomlib's bigint witness call graph.
/// Returns a 2D `out[2][100]` array — exercises the new
/// `NestedResult::Array2D` path and exposes the flattened layout as
/// 200 witness slots at the top level. Composes `short_div`,
/// `long_scalar_mult`, and `long_sub` (whole-array reassignment from
/// a call).
#[test]
fn fn_witness_lift_circomlib_long_div_integration() {
    use ir_forge::types::CircuitNode;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_bigint_long_div_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];
    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("long_div integration failed to compile: {e}"));
    let bytes = result
        .prove_ir
        .body
        .iter()
        .find_map(|n| match n {
            CircuitNode::WitnessCall { program_bytes, .. } => Some(program_bytes.clone()),
            _ => None,
        })
        .expect("expected a CircuitNode::WitnessCall for long_div");

    let prog = artik::bytecode::decode(&bytes, Some(memory::FieldFamily::BnLike256))
        .expect("long_div payload must decode and validate");

    // 200-slot witness output (2 * 100 flattened) is the load-bearing
    // signature of the 2D return path.
    let witness_writes = prog.subprograms[0]
        .body
        .iter()
        .filter(|i| matches!(i, artik::Instr::WriteWitness { .. }))
        .count();
    assert_eq!(
        witness_writes, 200,
        "long_div's 2D return must expose rows*cols = 2*100 witness slots; got {witness_writes}"
    );

    // The 2D `out[2][100]` declaration becomes a single 200-cell
    // AllocArray after the row-major flattening.
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
        "expected a 200-cell AllocArray (out[2][100] flattened); got {alloc_lens:?}"
    );
}

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

/// Fase 5.1 — array parameters in the Artik lift. A function with
/// `arr[N]` as a formal parameter binds to N input signals (one
/// per element). Verified by lifting `array_sum(arr[4])`, pushing
/// it through instantiate + R1CS + Groth16, and confirming the
/// proof verifies when the template constraints match the Artik
/// witness.
#[test]
fn fn_witness_lift_array_param_e2e_groth16() {
    use std::collections::{HashMap, HashSet};

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_array_param_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("array-param lift failed to compile: {e}"));

    let captures: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    let output_names: HashSet<String> = compile_result.output_names.iter().cloned().collect();

    let mut program = compile_result
        .prove_ir
        .instantiate_lysis_with_outputs(&captures, &output_names)
        .expect("instantiate");
    ir::passes::optimize(&mut program);

    // array_sum(inp) = inp[0] + 2*inp[1] + 3*inp[2] + 4*inp[3].
    let inp = [3u64, 5, 7, 11];
    let expected_out = inp[0] + 2 * inp[1] + 3 * inp[2] + 4 * inp[3];

    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    for (i, v) in inp.iter().enumerate() {
        inputs.insert(format!("inp_{i}"), FieldElement::<Bn254Fr>::from_u64(*v));
    }
    inputs.insert(
        "out".to_string(),
        FieldElement::<Bn254Fr>::from_u64(expected_out),
    );

    let mut r1cs = R1CSCompiler::<Bn254Fr>::new();
    let witness = r1cs
        .compile_ir_with_witness(&program, &inputs)
        .expect("R1CS compile + witness");
    r1cs.cs.verify(&witness).expect("R1CS verify");

    let cache_dir = std::env::temp_dir().join("achronyme_test_keys");
    let result = proving::groth16_bn254::generate_proof(&r1cs.cs, &witness, &cache_dir)
        .unwrap_or_else(|e| panic!("Groth16 proof failed: {e}"));

    match &result {
        akron::ProveResult::Proof {
            proof_json,
            public_json,
            vkey_json,
        } => {
            let valid =
                proving::groth16_bn254::verify_proof_from_json(proof_json, public_json, vkey_json)
                    .unwrap_or_else(|e| panic!("Groth16 verify failed: {e}"));
            assert!(valid, "Groth16 proof did not verify");
            eprintln!("  ✓ array_sum(inp[4]={inp:?}) = {expected_out} — Artik→Groth16 VERIFIED");
        }
        _ => panic!("expected Proof variant from Groth16"),
    }
}

/// Fase 5.1 (array-literal init): a function body declares
/// `var k[N] = [literal, ...];` and indexes `k[i]` in a loop.
/// The lift allocates the backing store at declaration time and
/// StoreArrs each literal into its slot, so later reads resolve
/// via `LoadArr`. This is the `sha256K` shape: a constant table
/// packed into a `var` at the top of a helper function.
///
/// Verifies `n * (1+2+3+4) = 10*n` through Groth16 with n=7.
#[test]
fn fn_witness_lift_array_literal_e2e_groth16() {
    use std::collections::{HashMap, HashSet};

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_array_literal_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("array-literal lift failed to compile: {e}"));

    let captures: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    let output_names: HashSet<String> = compile_result.output_names.iter().cloned().collect();

    let mut program = compile_result
        .prove_ir
        .instantiate_lysis_with_outputs(&captures, &output_names)
        .expect("instantiate");
    ir::passes::optimize(&mut program);

    let n = 7u64;
    let expected_out = 10 * n;

    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    inputs.insert("n".to_string(), FieldElement::<Bn254Fr>::from_u64(n));
    inputs.insert(
        "out".to_string(),
        FieldElement::<Bn254Fr>::from_u64(expected_out),
    );

    let mut r1cs = R1CSCompiler::<Bn254Fr>::new();
    let witness = r1cs
        .compile_ir_with_witness(&program, &inputs)
        .expect("R1CS compile + witness");
    r1cs.cs.verify(&witness).expect("R1CS verify");

    let cache_dir = std::env::temp_dir().join("achronyme_test_keys");
    let result = proving::groth16_bn254::generate_proof(&r1cs.cs, &witness, &cache_dir)
        .unwrap_or_else(|e| panic!("Groth16 proof failed: {e}"));

    match &result {
        akron::ProveResult::Proof {
            proof_json,
            public_json,
            vkey_json,
        } => {
            let valid =
                proving::groth16_bn254::verify_proof_from_json(proof_json, public_json, vkey_json)
                    .unwrap_or_else(|e| panic!("Groth16 verify failed: {e}"));
            assert!(valid, "Groth16 proof did not verify");
            eprintln!("  ✓ table_sum() * {n} = {expected_out} — Artik→Groth16 VERIFIED");
        }
        _ => panic!("expected Proof variant from Groth16"),
    }
}

/// Fase 4 deliverable check: a circom template whose `out <--`
/// value comes from an Artik witness program goes all the way
/// through Groth16 proof generation and verification on BN-254.
/// This is the end-to-end "can I ship this" test — the same path
/// `ach prove file.circom --input inputs.toml` will walk once the
/// CLI gets wired up.
///
/// Uses `triangle_sum` (for-loop lift producing `6*in`) so the
/// constraint `out === 6 * in` is non-trivial and the proof
/// actually has something to prove.
#[test]
fn fn_witness_lift_e2e_groth16_triangle_sum() {
    use std::collections::HashSet;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_loop_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("Artik→Groth16 compile failed: {e}"));

    let captures: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    let output_names: HashSet<String> = compile_result.output_names.iter().cloned().collect();

    let mut program = compile_result
        .prove_ir
        .instantiate_lysis_with_outputs(&captures, &output_names)
        .expect("instantiate");
    ir::passes::optimize(&mut program);

    // triangle_sum(n) = 6*n; template enforces `out === 6 * in`.
    let n = 11u64;
    let expected_out = 6 * n;
    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    inputs.insert("in".to_string(), FieldElement::<Bn254Fr>::from_u64(n));
    inputs.insert(
        "out".to_string(),
        FieldElement::<Bn254Fr>::from_u64(expected_out),
    );

    let mut r1cs = R1CSCompiler::<Bn254Fr>::new();
    let witness = r1cs
        .compile_ir_with_witness(&program, &inputs)
        .expect("R1CS compile + witness");
    r1cs.cs.verify(&witness).expect("R1CS verify");

    let cache_dir = std::env::temp_dir().join("achronyme_test_keys");
    let result = proving::groth16_bn254::generate_proof(&r1cs.cs, &witness, &cache_dir)
        .unwrap_or_else(|e| panic!("Groth16 proof generation failed: {e}"));

    match &result {
        akron::ProveResult::Proof {
            proof_json,
            public_json,
            vkey_json,
        } => {
            let valid =
                proving::groth16_bn254::verify_proof_from_json(proof_json, public_json, vkey_json)
                    .unwrap_or_else(|e| panic!("Groth16 verification failed: {e}"));
            assert!(valid, "Groth16 proof did not verify");
            eprintln!("  ✓ Artik→Groth16: triangle_sum({n}) = {expected_out} — PROOF VERIFIED");
        }
        _ => panic!("expected Proof variant from Groth16"),
    }
}

/// Fase 3+4 end-to-end on a SHA-style bit-op body: the same σ0
/// function that exercises `& | ^ >> <<` in the lift gets pushed
/// through instantiate + R1CS + witness verify. The template pins
/// `out === out` so there's no independent constraint on the σ0
/// value — this test is specifically for "the Artik dispatch
/// produces *some* value that satisfies the circuit", confirming
/// the bit-op witness path runs end-to-end (decode → IntFromField →
/// IBin at u32 → FieldFromInt → write slot → R1CS witness wire).
#[test]
fn fn_witness_lift_e2e_r1cs_bitops_dispatch() {
    use memory::{Bn254Fr, FieldElement};
    use std::collections::{HashMap, HashSet};
    use zkc::r1cs_backend::R1CSCompiler;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_bitops_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("bit-op E2E compile failed: {e}"));

    let captures: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    let output_names: HashSet<String> = compile_result.output_names.iter().cloned().collect();

    let mut program = compile_result
        .prove_ir
        .instantiate_lysis_with_outputs(&captures, &output_names)
        .expect("instantiate");

    ir::passes::optimize(&mut program);

    // Compute σ0 reference on the chosen input so we can supply the
    // matching public-output value: `out === out` only tautologizes
    // once `out` has a concrete binding on both sides of the R1CS
    // wire, which requires a user-supplied public-input value.
    fn sigma0_ref(x: u32) -> u32 {
        let r7 = (x >> 7) | (x.wrapping_shl(25));
        let r18 = (x >> 18) | (x.wrapping_shl(14));
        let r3 = x >> 3;
        (r7 ^ r18) ^ r3
    }
    let input_val: u32 = 0xDEAD_BEEF;
    let expected_out = sigma0_ref(input_val);

    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    inputs.insert(
        "in".to_string(),
        FieldElement::<Bn254Fr>::from_u64(input_val as u64),
    );
    inputs.insert(
        "out".to_string(),
        FieldElement::<Bn254Fr>::from_u64(expected_out as u64),
    );

    let mut rc = R1CSCompiler::<Bn254Fr>::new();
    let witness = rc
        .compile_ir_with_witness(&program, &inputs)
        .expect("compile_ir_with_witness");
    rc.cs
        .verify(&witness)
        .expect("R1CS should verify with Artik-dispatched σ0 witness");
}

/// Fase 3+4 end-to-end: an Artik-lifted circom function survives
/// through instantiate → optimize → R1CS compile, with the lifted
/// Artik program executed at witness-gen time to fill the output
/// wires. Verified by running `compile_ir_with_witness` and checking
/// that the R1CS verifier accepts the generated witness — this is
/// only possible if the Artik executor produced the same value the
/// downstream `===` constraint expects.
#[test]
fn fn_witness_lift_e2e_r1cs_artik_dispatch() {
    use memory::{Bn254Fr, FieldElement};
    use std::collections::{HashMap, HashSet};
    use zkc::r1cs_backend::R1CSCompiler;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_loop_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let compile_result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("Artik R1CS E2E test failed to compile: {e}"));

    let captures: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    let output_names: HashSet<String> = compile_result.output_names.iter().cloned().collect();

    let mut program = compile_result
        .prove_ir
        .instantiate_lysis_with_outputs(&captures, &output_names)
        .expect("instantiate");

    ir::passes::optimize(&mut program);

    // The loop-test function `triangle_sum(n)` returns
    // `sum_{i=0..3} (n * i)` = 6*n; its template fixes that as the
    // `===` constraint. We pick n = 7 → expected out = 42.
    let n = 7u64;
    let expected_out = 6 * n;
    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    inputs.insert("in".to_string(), FieldElement::<Bn254Fr>::from_u64(n));
    inputs.insert(
        "out".to_string(),
        FieldElement::<Bn254Fr>::from_u64(expected_out),
    );

    let mut rc = R1CSCompiler::<Bn254Fr>::new();
    let witness = rc
        .compile_ir_with_witness(&program, &inputs)
        .expect("compile_ir_with_witness");
    rc.cs
        .verify(&witness)
        .expect("R1CS should verify after Artik dispatch");
}

/// Fase 2.4 mux extension: nested function calls on the RHS of
/// assignments inside either arm of a runtime if/else are admissible.
/// Each call inlines at nested_depth > 0 (return captured via
/// nested_result, no WriteWitness), so both arms execute their call
/// under the mux without corrupting the top-level witness write.
/// Validated by decoding the payload and running the Artik executor
/// with cond ∈ {0, 1} against a hand-computed reference.
#[test]
fn fn_witness_lift_mux_admits_nested_calls() {
    use ir_forge::types::CircuitNode;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path = manifest_dir.join("test/circomlib/fn_witness_lift_mux_calls_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("mux+calls lift test failed to compile: {e}"));

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
        .expect("mux+calls payload must decode and validate");

    use memory::field::{Bn254Fr, FieldElement};
    type FE = FieldElement<Bn254Fr>;

    // cond=1 → triple(x) == 3x.
    let sigs = [FE::from_u64(1), FE::from_u64(17)];
    let mut slots = [FE::zero()];
    let mut ctx = artik::ArtikContext::<Bn254Fr>::new(&sigs, &mut slots);
    artik::execute(&prog, &mut ctx).expect("execute cond=1");
    assert_eq!(slots[0], FE::from_u64(51), "cond=1 should pick triple(x)");

    // cond=0 → quadruple(x) == 4x.
    let sigs = [FE::from_u64(0), FE::from_u64(17)];
    let mut slots = [FE::zero()];
    let mut ctx = artik::ArtikContext::<Bn254Fr>::new(&sigs, &mut slots);
    artik::execute(&prog, &mut ctx).expect("execute cond=0");
    assert_eq!(
        slots[0],
        FE::from_u64(68),
        "cond=0 should pick quadruple(x)"
    );
}

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

/// Per-statement decomposition: `secp256k1_addunequal_func(64, 4, ...)`
/// has a body too heavy for a single Artik frame (11 nested helper
/// calls + 2D return) and the standard `lift_function_to_artik`
/// returns None. The decomposition path lifts each helper call as
/// its own `CircuitNode::WitnessCall` fragment and emits a flat
/// `LetArray` carrying the 2D result. Pins the multi-fragment emission
/// and verifies each fragment's Artik payload decodes.
#[test]
fn fn_witness_decompose_secp256k1_addunequal() {
    use ir_forge::types::CircuitNode;

    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path =
        manifest_dir.join("test/circomlib/fn_witness_decompose_secp256k1_addunequal_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("secp256k1_addunequal decomposition failed to compile: {e}"));

    let witness_calls: Vec<&Vec<u8>> = result
        .prove_ir
        .body
        .iter()
        .filter_map(|n| match n {
            CircuitNode::WitnessCall { program_bytes, .. } => Some(program_bytes),
            _ => None,
        })
        .collect();

    assert!(
        witness_calls.len() >= 11,
        "expected ≥11 WitnessCall fragments from the helper-call chain, got {}",
        witness_calls.len()
    );

    for (i, bytes) in witness_calls.iter().enumerate() {
        artik::bytecode::decode(bytes, Some(memory::FieldFamily::BnLike256))
            .unwrap_or_else(|e| panic!("fragment {i} payload failed to decode: {e}"));
    }
}

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

/// Cross-validates the multi-fragment witness output of
/// `secp256k1_addunequal_func(64, 4, ...)` against a reference vector
/// computed by circom 2.2.3 + snarkjs. Inputs are the secp256k1
/// generator `G` and `2G` (decomposed into 64-bit little-endian
/// limbs); the expected sum `3G` matches both the mathematical
/// definition (G + 2G on secp256k1) and the canonical limb output of
/// the official circomlib function. Pinning these values catches any
/// silent mis-wiring in the decomposition — swapped argument order
/// in `prod_mod_p` / `long_sub_mod_p`, off-by-one in the row-major
/// flattening of the 2D return, or a `CircuitExpr::Var(name)` whose
/// name no longer matches a fragment's `output_bindings`.
#[test]
fn fn_witness_decompose_secp256k1_addunequal_values() {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR")).parent().unwrap();
    let path =
        manifest_dir.join("test/circomlib/fn_witness_decompose_secp256k1_addunequal_test.circom");
    let lib_dirs = vec![manifest_dir.join("test/circomlib")];

    let result = circom::compile_file(&path, &lib_dirs)
        .unwrap_or_else(|e| panic!("secp256k1_addunequal decomposition failed to compile: {e}"));

    // secp256k1 generator G and 2G, 64-bit little-endian limbs.
    let inputs_u64: [(&str, u64); 16] = [
        ("x1_0", 0x59F2_815B_16F8_1798),
        ("x1_1", 0x029B_FCDB_2DCE_28D9),
        ("x1_2", 0x55A0_6295_CE87_0B07),
        ("x1_3", 0x79BE_667E_F9DC_BBAC),
        ("y1_0", 0x9C47_D08F_FB10_D4B8),
        ("y1_1", 0xFD17_B448_A685_5419),
        ("y1_2", 0x5DA4_FBFC_0E11_08A8),
        ("y1_3", 0x483A_DA77_26A3_C465),
        ("x2_0", 0xABAC_09B9_5C70_9EE5),
        ("x2_1", 0x5C77_8E4B_8CEF_3CA7),
        ("x2_2", 0x3045_406E_95C0_7CD8),
        ("x2_3", 0xC604_7F94_41ED_7D6D),
        ("y2_0", 0x2364_31A9_50CF_E52A),
        ("y2_1", 0xF7F6_3265_3266_D0E1),
        ("y2_2", 0xA3C5_8419_466C_EAEE),
        ("y2_3", 0x1AE1_68FE_A63D_C339),
    ];
    let inputs: HashMap<String, FieldElement<Bn254Fr>> = inputs_u64
        .iter()
        .map(|(n, v)| (n.to_string(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();

    let all_signals = circom::witness::compute_witness_hints_with_captures(
        &result.prove_ir,
        &inputs,
        &result.capture_values,
    )
    .unwrap_or_else(|e| panic!("witness computation failed: {e}"));

    // Reference 3G = G + 2G, captured from circom 2.2.3 + snarkjs run
    // on the same fixture; matches the modular arithmetic on
    // secp256k1's prime field. Order is little-endian limbs.
    let expected_outx: [u64; 4] = [
        0x8601_F113_BCE0_36F9,
        0xB531_C845_836F_99B0,
        0x4934_4F85_F89D_5229,
        0xF930_8A01_9258_C310,
    ];
    let expected_outy: [u64; 4] = [
        0x6CB9_FD75_84B8_E672,
        0x6500_A999_34C2_231B,
        0x0FE3_37E6_2A37_F356,
        0x388F_7B0F_632D_E814,
    ];

    for (i, expected) in expected_outx.iter().enumerate() {
        let key = format!("outx_{i}");
        let actual = all_signals
            .get(&key)
            .unwrap_or_else(|| panic!("missing witness signal `{key}`"));
        let want = FieldElement::<Bn254Fr>::from_u64(*expected);
        assert_eq!(
            *actual, want,
            "outx[{i}] mismatch: got {actual:?}, want {want:?}"
        );
    }
    for (i, expected) in expected_outy.iter().enumerate() {
        let key = format!("outy_{i}");
        let actual = all_signals
            .get(&key)
            .unwrap_or_else(|| panic!("missing witness signal `{key}`"));
        let want = FieldElement::<Bn254Fr>::from_u64(*expected);
        assert_eq!(
            *actual, want,
            "outy[{i}] mismatch: got {actual:?}, want {want:?}"
        );
    }
}
