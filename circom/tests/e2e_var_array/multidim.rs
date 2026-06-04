use std::collections::HashMap;

use memory::{Bn254Fr, FieldElement};
use zkc::r1cs_backend::R1CSCompiler;

// circomlib bigint emulation declares working buffers via the shape
// `var X[R][C] = call(signal_array, …);` where `call` lifts to Artik
// (`long_div`, `secp256k1_addunequal_func`, `secp256k1_double_func`,
// …) and returns a 2D var array. The lift flattens the return into a
// 1D `LetArray` of `R*C` slots, so without the dimension-aware
// stride seeding the downstream `X[i][j]` reads either fold to the
// wrong slot (stride=1 default) or surface E213 against the R1″
// memoization placeholder when the outer index is the loop variable.

/// Positive: 2D var assigned from an Artik-lifted call has its
/// declared `[R][C]` strides registered. `X[i][j]` reads inside a
/// memoizable loop linearise to `i * C + j` instead of fingering a
/// non-existent flat slot.
#[test]
fn multidim_var_from_call_seeds_strides() {
    let src = r#"
        pragma circom 2.0.0;
        function pair(N, a, b) {
            var out[2][N];
            for (var i = 0; i < N; i++) {
                out[0][i] = a[i] + b[i];
                out[1][i] = a[i] - b[i];
            }
            return out;
        }
        template T(N) {
            signal input a[N];
            signal input b[N];
            signal output sums[N];
            signal output diffs[N];

            var pr[2][N] = pair(N, a, b);
            for (var i = 0; i < N; i++) {
                sums[i]  <-- pr[0][i];
                sums[i]  === pr[0][i];
                diffs[i] <-- pr[1][i];
                diffs[i] === pr[1][i];
            }
        }
        component main {public [a, b]} = T(8);
    "#;
    let tmp = std::env::temp_dir().join("ach_multidim_call_strides.circom");
    std::fs::write(&tmp, src).unwrap();
    circom::compile_file(&tmp, &[]).unwrap_or_else(|e| panic!("compile failed: {e}"));
}

/// Positive: a memoizable read loop over a 2D var bound from a call
/// compiles cleanly (the read body crosses the memoize threshold,
/// `end - start >= 4`, so the inner `i` is held as the R1″
/// placeholder). Without the dimension-aware stride seeding, the
/// `pr[0][i]` lowering would surface E213 against the placeholder.
#[test]
fn multidim_var_from_call_memoizable_loop_compiles() {
    let src = r#"
        pragma circom 2.0.0;
        function pair(N, a, b) {
            var out[2][N];
            for (var i = 0; i < N; i++) {
                out[0][i] = a[i] + b[i];
                out[1][i] = a[i] - b[i];
            }
            return out;
        }
        template T(N) {
            signal input a[N];
            signal input b[N];
            signal output sums[N];
            signal output diffs[N];

            var pr[2][N] = pair(N, a, b);
            for (var i = 0; i < N; i++) {
                sums[i]  <-- pr[0][i];
                sums[i]  === pr[0][i];
                diffs[i] <-- pr[1][i];
                diffs[i] === pr[1][i];
            }
        }
        component main {public [a, b]} = T(8);
    "#;
    let tmp = std::env::temp_dir().join("ach_multidim_call_memoizable.circom");
    std::fs::write(&tmp, src).unwrap();
    circom::compile_file(&tmp, &[]).unwrap_or_else(|e| panic!("compile failed: {e}"));
}

// A *partial-index* write into a multi-dim var array — one row at a
// time from an array-returning call inside a loop — is the shape
// circomlib `LongToShortNoEndCarry` uses: `var split[k][3];` then
// `split[i] = SplitThreeFn(in[i], n, n, n);`. The row's cells must
// land in the flat slots `split_{i*C + j}` the read side resolves
// for `split[i][j]`. Binding the row under a single name instead
// trips a scalar/array mismatch at instantiate; mis-striding the
// base index points writes and reads at different slots.

const ROW_FROM_CALL_LEAF: &str = r#"
        function tri(x) {
            var r[3];
            r[0] = x;
            r[1] = x + 1;
            r[2] = x + 2;
            return r;
        }
        template Leaf(k) {
            signal input  in[k];
            signal output out[k];
            var split[k][3];
            for (var i = 0; i < k; i++) {
                split[i] = tri(in[i]);
            }
            for (var i = 0; i < k; i++) {
                out[i] <-- split[i][0] + split[i][1] + split[i][2];
                out[i] === 3 * in[i] + 3;
            }
        }
"#;

/// Positive: per-row assignment from an array-returning call, read
/// back via full 2D index, instantiated and R1CS-verified. The
/// witness asserts `out[i] = 3*in[i]+3`, so a wrong base index or a
/// row bound under a single name (rather than fanned into flat
/// slots) fails here rather than slipping through a compile-only
/// check.
#[test]
fn var_array_2d_row_from_call_standalone() {
    let src = format!(
        "pragma circom 2.0.0;\n{ROW_FROM_CALL_LEAF}\ncomponent main {{public [in]}} = Leaf(3);\n"
    );
    let tmp = std::env::temp_dir().join("ach_var_array_2d_row_call.circom");
    std::fs::write(&tmp, src).unwrap();

    let result = circom::compile_file(&tmp, &[]).unwrap_or_else(|e| panic!("compile failed: {e}"));
    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = result
        .capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();
    let mut program = result
        .prove_ir
        .instantiate_lysis_with_outputs(&fe_captures, &result.output_names)
        .unwrap_or_else(|e| panic!("instantiate failed: {e}"));
    ir::passes::optimize(&mut program);

    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    inputs.insert("in_0".into(), FieldElement::<Bn254Fr>::from_u64(4));
    inputs.insert("in_1".into(), FieldElement::<Bn254Fr>::from_u64(5));
    inputs.insert("in_2".into(), FieldElement::<Bn254Fr>::from_u64(6));

    let all_signals = circom::witness::compute_witness_hints_with_captures(
        &result.prove_ir,
        &inputs,
        &result.capture_values,
    )
    .unwrap_or_else(|e| panic!("witness computation failed: {e}"));

    for (name, want) in [("out_0", 15u64), ("out_1", 18), ("out_2", 21)] {
        let got = all_signals
            .get(name)
            .unwrap_or_else(|| panic!("witness missing signal `{name}`"));
        assert_eq!(
            *got,
            FieldElement::<Bn254Fr>::from_u64(want),
            "row-from-call slot `{name}`: expected {want}, got {got:?}"
        );
    }

    let proven = ir::passes::bool_prop::compute_proven_boolean(&program);
    let mut rc = R1CSCompiler::<Bn254Fr>::new();
    rc.set_proven_boolean(proven);
    let witness = rc
        .compile_ir_with_witness(&program, &all_signals)
        .unwrap_or_else(|e| panic!("R1CS compile-with-witness failed: {e}"));
    rc.cs
        .verify(&witness)
        .unwrap_or_else(|e| panic!("R1CS verify failed: {e}"));
}

/// Positive: the same body one component level deep. The defect is
/// independent of component inlining (the row write is mishandled
/// with or without a `comp.` prefix); this locks that in so the bug
/// class cannot silently re-emerge only under a prefix.
#[test]
fn var_array_2d_row_from_call_wrapped() {
    let src = format!(
        r#"pragma circom 2.0.0;
{ROW_FROM_CALL_LEAF}
        template Wrap(k) {{
            signal input  in[k];
            signal output out[k];
            component leaf = Leaf(k);
            for (var i = 0; i < k; i++) {{ leaf.in[i] <== in[i]; }}
            for (var i = 0; i < k; i++) {{ out[i] <== leaf.out[i]; }}
        }}
        component main {{public [in]}} = Wrap(3);
"#
    );
    let tmp = std::env::temp_dir().join("ach_var_array_2d_row_call_wrapped.circom");
    std::fs::write(&tmp, src).unwrap();

    let result = circom::compile_file(&tmp, &[]).unwrap_or_else(|e| panic!("compile failed: {e}"));
    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = result
        .capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();
    result
        .prove_ir
        .instantiate_lysis_with_outputs(&fe_captures, &result.output_names)
        .unwrap_or_else(|e| panic!("instantiate failed (inlined): {e}"));
}

/// Positive: an expression-length template-local `var` array read
/// back inside a loop whose bound is a parameter *expression*
/// (`2*k-1`). An expression bound routes the loop through the
/// memoized unroll path, which holds the loop variable as a
/// placeholder during body capture, so the array-element read is
/// emitted symbolically rather than as the flat-scalar `acc_<i>` the
/// direct-unroll path produces. A template-local `var` array carries
/// no array binding past lowering (only per-element zero-init
/// `Let`s), so a residual `acc[<const>]` that the post-substitution
/// fold fails to collapse dangles at instantiate (`… is not an
/// array`). The witness asserts `out[i] = (Σ a) * (i+1)`, so a wrong
/// flat-slot name fails here at R1CS verification rather than
/// slipping through a compile-only check. This is the minimal repro
/// of the circomlib BigMultNoCarry `out_poly` blocker on the
/// secp256k1 boss-fight path.
#[test]
fn var_array_expr_bound_loop_read_standalone() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("test/circomlib/var_array_expr_bound_loop_test.circom");

    let result = circom::compile_file(&path, &[]).unwrap_or_else(|e| panic!("compile failed: {e}"));
    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = result
        .capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();
    let mut program = result
        .prove_ir
        .instantiate_lysis_with_outputs(&fe_captures, &result.output_names)
        .unwrap_or_else(|e| panic!("instantiate failed: {e}"));
    ir::passes::optimize(&mut program);

    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    for (i, v) in [(0u32, 2u64), (1, 3), (2, 4)] {
        inputs.insert(format!("a_{i}"), FieldElement::<Bn254Fr>::from_u64(v));
    }

    let all_signals = circom::witness::compute_witness_hints_with_captures(
        &result.prove_ir,
        &inputs,
        &result.capture_values,
    )
    .unwrap_or_else(|e| panic!("witness computation failed: {e}"));

    // a = [2,3,4] ⇒ Σa = 9 ⇒ acc[i] = 9*(i+1); 2*k-1 = 5 slots.
    for (name, want) in [
        ("out_0", 9u64),
        ("out_1", 18),
        ("out_2", 27),
        ("out_3", 36),
        ("out_4", 45),
    ] {
        let got = all_signals
            .get(name)
            .unwrap_or_else(|| panic!("witness missing signal `{name}`"));
        assert_eq!(
            *got,
            FieldElement::<Bn254Fr>::from_u64(want),
            "expr-bound-loop var-array slot `{name}`: expected {want}, got {got:?}"
        );
    }

    let proven = ir::passes::bool_prop::compute_proven_boolean(&program);
    let mut rc = R1CSCompiler::<Bn254Fr>::new();
    rc.set_proven_boolean(proven);
    let witness = rc
        .compile_ir_with_witness(&program, &all_signals)
        .unwrap_or_else(|e| panic!("R1CS compile-with-witness failed: {e}"));
    rc.cs
        .verify(&witness)
        .unwrap_or_else(|e| panic!("R1CS verify failed: {e}"));
}

/// Regression: a multi-dimensional **signal** array declared in the
/// *main* template (`signal input m[2][C]`) must have its `[R][C]`
/// strides registered, so `m[1][i]` linearises to the flat slot
/// `1*C + i` and not the stride-1 default `1 + i`. The main-template
/// lowering entry seeds these the same way component inlining does;
/// before that seeding existed, every non-leading-row read on a
/// main-template signal array fingered the wrong flat slot. This is
/// the exact shape of the secp256k1 `ECDSAVerifyNoPubkeyCheck`
/// `signal input pubkey[2][k]` read at the heart of the boss-fight:
/// the witness asserts `o[i] = m[1][i]`, so a stride-1 read pulls
/// row-0 cells and fails here at R1CS verification rather than
/// slipping through a compile-only check.
#[test]
fn signal_array_2d_main_template_seeds_strides() {
    // Literal element indices (manual unroll) keep the read off the
    // memoized-loop path, isolating the stride linearisation; the
    // `[2][C]` shape still resolves its column count through the
    // parameter `C` exactly as the real `pubkey[2][k]` does.
    let src = r#"
        pragma circom 2.0.0;
        template T(C) {
            signal input m[2][C];
            signal output o0;
            signal output o1;
            signal output o2;
            signal output o3;
            o0 <== m[1][0];
            o1 <== m[1][1];
            o2 <== m[1][2];
            o3 <== m[1][3];
        }
        component main {public [m]} = T(4);
    "#;
    let tmp = std::env::temp_dir().join("ach_signal_2d_main_strides.circom");
    std::fs::write(&tmp, src).unwrap();

    let result = circom::compile_file(&tmp, &[]).unwrap_or_else(|e| panic!("compile failed: {e}"));
    let fe_captures: HashMap<String, FieldElement<Bn254Fr>> = result
        .capture_values
        .iter()
        .map(|(k, v)| (k.clone(), FieldElement::<Bn254Fr>::from_u64(*v)))
        .collect();
    let mut program = result
        .prove_ir
        .instantiate_lysis_with_outputs(&fe_captures, &result.output_names)
        .unwrap_or_else(|e| panic!("instantiate failed: {e}"));
    ir::passes::optimize(&mut program);

    // Flat layout of `m[2][4]`: row 0 = m_0..m_3, row 1 = m_4..m_7.
    // Make the rows clearly distinct so a stride-1 read of `m[1][i]`
    // (= m_{1+i}, i.e. row-0 cells) yields detectably wrong values.
    let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
    for (i, v) in [(0u32, 10u64), (1, 20), (2, 30), (3, 40)] {
        inputs.insert(format!("m_{i}"), FieldElement::<Bn254Fr>::from_u64(v));
    }
    for (i, v) in [(4u32, 1u64), (5, 2), (6, 3), (7, 4)] {
        inputs.insert(format!("m_{i}"), FieldElement::<Bn254Fr>::from_u64(v));
    }

    let all_signals = circom::witness::compute_witness_hints_with_captures(
        &result.prove_ir,
        &inputs,
        &result.capture_values,
    )
    .unwrap_or_else(|e| panic!("witness computation failed: {e}"));

    // Correct strides read row 1: o{i} = m[1][i] = m_{4+i} = [1,2,3,4].
    // Stride-1 would read m_{1+i} = [20,30,40,1] and fail here.
    for (name, want) in [("o0", 1u64), ("o1", 2), ("o2", 3), ("o3", 4)] {
        let got = all_signals
            .get(name)
            .unwrap_or_else(|| panic!("witness missing signal `{name}`"));
        assert_eq!(
            *got,
            FieldElement::<Bn254Fr>::from_u64(want),
            "main-template 2D signal slot `{name}`: expected {want}, got {got:?}"
        );
    }

    let proven = ir::passes::bool_prop::compute_proven_boolean(&program);
    let mut rc = R1CSCompiler::<Bn254Fr>::new();
    rc.set_proven_boolean(proven);
    let witness = rc
        .compile_ir_with_witness(&program, &all_signals)
        .unwrap_or_else(|e| panic!("R1CS compile-with-witness failed: {e}"));
    rc.cs
        .verify(&witness)
        .unwrap_or_else(|e| panic!("R1CS verify failed: {e}"));
}

/// Adversarial: declared multi-dim shape whose cell count disagrees
/// with the initializer's flat length surfaces a clean error, not a
/// silently mis-strided array.
#[test]
fn multidim_var_from_call_dim_mismatch_rejected() {
    let src = r#"
        pragma circom 2.0.0;
        function pair_len(N, a) {
            var out[N];
            for (var i = 0; i < N; i++) {
                out[i] = a[i];
            }
            return out;
        }
        template T(N) {
            signal input a[N];
            signal output sums[N];
            // Declared shape [2][N] = 2*N cells, but pair_len returns N.
            var bad[2][N] = pair_len(N, a);
            sums[0] <-- bad[0][0];
            sums[0] === bad[0][0];
        }
        component main {public [a]} = T(4);
    "#;
    let tmp = std::env::temp_dir().join("ach_multidim_call_mismatch.circom");
    std::fs::write(&tmp, src).unwrap();
    let err = match circom::compile_file(&tmp, &[]) {
        Ok(_) => panic!("expected compile failure on shape mismatch, got success"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("declared shape") && msg.contains("but the initializer produced"),
        "unexpected error: {msg}"
    );
}
