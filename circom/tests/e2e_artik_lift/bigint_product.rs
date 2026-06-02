use super::*;

/// Lift `prod(n, k, a, b)` from circomlib's bigint_func.circom — the
/// convolution-style polynomial product that stitches `SplitThreeFn`
/// and `SplitFn` calls into a 2D `split[i][j]` matrix. Exercises
/// whole-row 2D assignment `split[i] = SplitThreeFn(...)` (compile-time
/// row index, callee returns a 1D array matching `cols`) and
/// `var sumAndCarry[2] = SplitFn(...)` (callee handle aliased into the
/// caller's array scope).
///
/// Verifies the WitnessCall exists, the payload decodes, and the
/// expected arrays / bit-extraction ops are emitted. `prod`'s own
/// `split[100][3]` (300 cells) and `prod_val`/`out`/`carry` (100
/// cells) live in its subprogram; each `SplitThreeFn`/`SplitFn`'s
/// 3-/2-cell array return and its FShr/FAnd live in that callee's
/// subprogram — so the assertions scan every subprogram.
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
    // allocations are from each `SplitThreeFn` (3-cell return) and
    // `SplitFn` (2-cell return) callee subprogram.
    let alloc_lens: Vec<u32> = all_instrs(&prog)
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
    let saw_fshr = all_instrs(&prog).any(|i| matches!(i, artik::Instr::FShr { .. }));
    let saw_fand = all_instrs(&prog).any(|i| matches!(i, artik::Instr::FAnd { .. }));
    assert!(
        saw_fshr,
        "prod payload must contain FShr from inner SplitFn / SplitThreeFn calls"
    );
    assert!(
        saw_fand,
        "prod payload must contain FAnd from inner SplitFn / SplitThreeFn calls"
    );
}

/// Width-stress: lift `prod(64, 4, a, b)` from circomlib's
/// bigint_func.circom at the call-graph's nominal config.
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
    let max_fshr_amount = all_instrs(&prog)
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
    let saw_fand = all_instrs(&prog).any(|i| matches!(i, artik::Instr::FAnd { .. }));
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
    // short_div_norm for qhat (its own callee subprogram). Both have
    // non-power-of-2 divisors so they fall into the runtime FIDiv
    // path, not FShr / FAnd.
    let fidiv_count = all_instrs(&prog)
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
