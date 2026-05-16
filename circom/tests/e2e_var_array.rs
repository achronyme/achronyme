mod common;

use std::collections::HashMap;

use memory::{Bn254Fr, FieldElement};
use zkc::r1cs_backend::R1CSCompiler;

// circomlib's bigint-emulation templates (BigMultNoCarry,
// BigMultShortLong, BigSub, etc.) use template-local `var` arrays as
// symbolic accumulators for the polynomial-fingerprint witness-hint
// pattern. Each accumulator slot holds a CircuitExpr built up via
// indexed `=` reset and compound `+=` writes in nested loops; the
// per-slot SSA-shadow lowering rebinds the flat element under
// `<base>_<flat>` so the later `out[i] <-- prod_val[i]` and
// `out_poly[i] === a_poly[i] * b_poly[i]` constraint emissions read
// the correct accumulated value.

/// Positive: zero-init then read back a 1D var-array slot.
///
/// Smallest unit that exercises:
/// 1. `var X[N];` with no init materialising N zero Lets.
/// 2. `X[i] = 0;` re-binding the slot under the const-folded iter
///    index via SSA shadow.
/// 3. `out[i] <-- X[i];` reading the slot back through
///    `env.resolve_array_element` and emitting a witness hint.
#[test]
fn var_array_indexed_assign_smoke() {
    let src = r#"
        pragma circom 2.0.0;
        template T(n) {
            signal input a[n];
            signal output out[n];
            var acc[n];
            for (var i = 0; i < n; i++) {
                acc[i] = 0;
            }
            for (var i = 0; i < n; i++) {
                out[i] <-- acc[i];
                out[i] === a[i];
            }
        }
        component main = T(3);
    "#;
    let tmp = std::env::temp_dir().join("ach_var_array_smoke.circom");
    std::fs::write(&tmp, src).unwrap();
    let result = circom::compile_file(&tmp, &[]).unwrap_or_else(|e| panic!("compile failed: {e}"));
    assert!(
        result.prove_ir.body.len() >= 3,
        "expected at least 3 nodes (zero-init Lets), got {}",
        result.prove_ir.body.len()
    );
}

/// Positive: compound `+=` writes to a 1D var-array slot accumulate
/// signal-arithmetic, exercising the polynomial-fingerprint shape
/// (`prod_val[i+j] += a[i] * b[j]`) on the smallest possible body.
#[test]
fn var_array_compound_add_accumulator_smoke() {
    let src = r#"
        pragma circom 2.0.0;
        template T(n) {
            signal input a[n];
            signal input b[n];
            signal output out[2 * n - 1];
            var prod_val[2 * n - 1];
            for (var i = 0; i < 2 * n - 1; i++) {
                prod_val[i] = 0;
            }
            for (var i = 0; i < n; i++) {
                for (var j = 0; j < n; j++) {
                    prod_val[i + j] += a[i] * b[j];
                }
            }
            for (var i = 0; i < 2 * n - 1; i++) {
                out[i] <-- prod_val[i];
                out[i] === prod_val[i];
            }
        }
        component main = T(2);
    "#;
    let tmp = std::env::temp_dir().join("ach_var_array_accumulator.circom");
    std::fs::write(&tmp, src).unwrap();
    circom::compile_file(&tmp, &[]).unwrap_or_else(|e| panic!("compile failed: {e}"));
}

/// Positive: 2D var-array allocation + per-slot writes through
/// `env.strides`. Mirrors the `var split[k][3];` shape in
/// `BigMultShortLong`.
#[test]
fn var_array_2d_indexed_assign_smoke() {
    let src = r#"
        pragma circom 2.0.0;
        template T(n) {
            signal input a[n];
            signal output out[n];
            var grid[2][3];
            for (var i = 0; i < 2; i++) {
                for (var j = 0; j < 3; j++) {
                    grid[i][j] = 0;
                }
            }
            for (var i = 0; i < n; i++) {
                grid[0][i] += a[i];
                out[i] <-- grid[0][i];
                out[i] === grid[0][i];
            }
        }
        component main = T(3);
    "#;
    let tmp = std::env::temp_dir().join("ach_var_array_2d.circom");
    std::fs::write(&tmp, src).unwrap();
    circom::compile_file(&tmp, &[]).unwrap_or_else(|e| panic!("compile failed: {e}"));
}

/// Adversarial: a non-const dimension on a var-array declaration must
/// fail loudly rather than silently producing a zero-length array.
#[test]
fn var_array_non_const_dim_rejected() {
    let src = r#"
        pragma circom 2.0.0;
        template T() {
            signal input n;
            var arr[n];
            arr[0] = 0;
        }
        component main = T();
    "#;
    let tmp = std::env::temp_dir().join("ach_var_array_nonconst_dim.circom");
    std::fs::write(&tmp, src).unwrap();
    let err = match circom::compile_file(&tmp, &[]) {
        Ok(_) => panic!("expected compile failure on non-const dim, got success"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("var array dimension must be a compile-time constant"),
        "unexpected error: {msg}"
    );
}

/// Adversarial: an out-of-bounds indexed write must fail loudly rather
/// than materialising an unbacked slot.
#[test]
fn var_array_out_of_bounds_write_rejected() {
    let src = r#"
        pragma circom 2.0.0;
        template T() {
            signal output out;
            var arr[4];
            arr[5] = 0;
            out <-- arr[0];
            out === 0;
        }
        component main = T();
    "#;
    let tmp = std::env::temp_dir().join("ach_var_array_oob.circom");
    std::fs::write(&tmp, src).unwrap();
    let err = match circom::compile_file(&tmp, &[]) {
        Ok(_) => panic!("expected compile failure on OOB write, got success"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(msg.contains("out of bounds"), "unexpected error: {msg}");
}

/// Positive math: polynomial accumulator round-trip. Verifies that the
/// SSA-shadow chain materialises the correct CircuitExpr per slot —
/// not just that the compile succeeds. Computes a polynomial product
/// `out[k] = Σ_{i+j=k} a[i] * b[j]` for `n = 2` over the inputs
/// a = [2, 3], b = [5, 7]; expected outputs `[10, 29, 21]`. The R1CS
/// verifier asserts every emitted constraint holds against the provided
/// witness, so a wrong accumulation (stale binding, off-by-one flat
/// index) would fail here rather than slip through the compile-only
/// smoke tests.
#[test]
fn var_array_accumulator_witness_verify() {
    let src = r#"
        pragma circom 2.0.0;
        template Poly2(n) {
            signal input a[n];
            signal input b[n];
            signal output out[2 * n - 1];
            var prod_val[2 * n - 1];
            for (var i = 0; i < 2 * n - 1; i++) {
                prod_val[i] = 0;
            }
            for (var i = 0; i < n; i++) {
                for (var j = 0; j < n; j++) {
                    prod_val[i + j] += a[i] * b[j];
                }
            }
            for (var i = 0; i < 2 * n - 1; i++) {
                out[i] <== prod_val[i];
            }
        }
        component main {public [a, b]} = Poly2(2);
    "#;
    let tmp = std::env::temp_dir().join("ach_var_array_witness.circom");
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
    inputs.insert("a_0".into(), FieldElement::<Bn254Fr>::from_u64(2));
    inputs.insert("a_1".into(), FieldElement::<Bn254Fr>::from_u64(3));
    inputs.insert("b_0".into(), FieldElement::<Bn254Fr>::from_u64(5));
    inputs.insert("b_1".into(), FieldElement::<Bn254Fr>::from_u64(7));

    let mut all_signals = circom::witness::compute_witness_hints_with_captures(
        &result.prove_ir,
        &inputs,
        &result.capture_values,
    )
    .unwrap_or_else(|e| panic!("witness computation failed: {e}"));
    for (cname, fe) in &fe_captures {
        all_signals.entry(cname.clone()).or_insert(*fe);
    }

    // Math sanity: assert the witness-hint pass actually computed the
    // expected polynomial values before handing them to R1CS.
    let expected = [
        ("out_0", 10u64), // a[0]*b[0]
        ("out_1", 29),    // a[0]*b[1] + a[1]*b[0]
        ("out_2", 21),    // a[1]*b[1]
    ];
    for (name, want) in expected {
        let got = all_signals
            .get(name)
            .unwrap_or_else(|| panic!("witness missing signal `{name}`"));
        assert_eq!(
            *got,
            FieldElement::<Bn254Fr>::from_u64(want),
            "polynomial slot `{name}`: expected {want}, got {got:?} — \
             SSA-shadow chain produced wrong accumulator value"
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

/// Adversarial: shadowing a signal output (or any signal-array local)
/// with a `var X[N];` must be rejected. Without the shadow check the
/// zero-init Lets would mask the signal's slot bindings and produce
/// wrong constraints.
#[test]
fn var_array_shadows_signal_output_rejected() {
    let src = r#"
        pragma circom 2.0.0;
        template T(n) {
            signal output out[n];
            var out[n];
            out[0] = 0;
        }
        component main = T(2);
    "#;
    let tmp = std::env::temp_dir().join("ach_var_array_shadow_signal.circom");
    std::fs::write(&tmp, src).unwrap();
    let err = match circom::compile_file(&tmp, &[]) {
        Ok(_) => panic!("expected compile failure on shadowing signal output, got success"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("shadows an existing signal"),
        "unexpected error: {msg}"
    );
}

/// Adversarial: shadowing a template input with a `var` array of the
/// same name must be rejected so reads after the decl stay unambiguous.
#[test]
fn var_array_shadows_input_rejected() {
    let src = r#"
        pragma circom 2.0.0;
        template T(n) {
            signal input arr[n];
            var arr[n];
            arr[0] = 0;
        }
        component main = T(2);
    "#;
    let tmp = std::env::temp_dir().join("ach_var_array_shadow_input.circom");
    std::fs::write(&tmp, src).unwrap();
    let err = match circom::compile_file(&tmp, &[]) {
        Ok(_) => panic!("expected compile failure on shadowing input, got success"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("shadows an existing signal"),
        "unexpected error: {msg}"
    );
}

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

// `for (var i = 0; i <= k; i++)` with `k` a template parameter
// appears across circomlib's bigint emulation as the canonical
// k+1-iteration range-check loop (`Num2Bits(n)` per quotient
// register, etc.). The classifier rewrites the inclusive form to
// `i < k + 1` via `LoopBound::Expr`; the downstream witness +
// instantiation path evaluates the expression against the bound
// capture values.

/// Positive: `i <= k` over a template parameter compiles and
/// emits the correct iteration count. The k+1-sized output array
/// is fully written.
#[test]
fn loop_inclusive_bound_capture_compiles() {
    let src = r#"
        pragma circom 2.0.0;
        template T(k) {
            signal input  a[k + 1];
            signal output out[k + 1];
            for (var i = 0; i <= k; i++) {
                out[i] <== a[i];
            }
        }
        component main {public [a]} = T(3);
    "#;
    let tmp = std::env::temp_dir().join("ach_loop_le_capture_smoke.circom");
    std::fs::write(&tmp, src).unwrap();
    circom::compile_file(&tmp, &[]).unwrap_or_else(|e| panic!("compile failed: {e}"));
}

/// Positive math: the k+1-th iteration actually runs. Wires
/// distinguishable values per slot and R1CS-verifies the resulting
/// constraints — a wrong iteration count (e.g. off-by-one from a
/// stale `i < k` rewrite) would leave `out_k` unconstrained.
#[test]
fn loop_inclusive_bound_capture_witness_verify() {
    let src = r#"
        pragma circom 2.0.0;
        template T(k) {
            signal input  a[k + 1];
            signal output out[k + 1];
            for (var i = 0; i <= k; i++) {
                out[i] <== a[i];
            }
        }
        component main {public [a]} = T(3);
    "#;
    let tmp = std::env::temp_dir().join("ach_loop_le_capture_witness.circom");
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
    for i in 0..4u64 {
        inputs.insert(format!("a_{i}"), FieldElement::<Bn254Fr>::from_u64(100 + i));
    }

    let mut all_signals = circom::witness::compute_witness_hints_with_captures(
        &result.prove_ir,
        &inputs,
        &result.capture_values,
    )
    .unwrap_or_else(|e| panic!("witness computation failed: {e}"));
    for (cname, fe) in &fe_captures {
        all_signals.entry(cname.clone()).or_insert(*fe);
    }

    // The k+1-th slot (`out_3`, since k=3) must be written; a stale
    // `i < k` rewrite would leave it absent from the witness.
    for i in 0..4u64 {
        let got = all_signals
            .get(&format!("out_{i}"))
            .unwrap_or_else(|| panic!("witness missing signal `out_{i}`"));
        assert_eq!(
            *got,
            FieldElement::<Bn254Fr>::from_u64(100 + i),
            "out_{i}: expected {}, got {got:?}",
            100 + i,
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

/// Adversarial: `i >= k` (ascending step) is still not a recognised
/// loop shape — only the descending family `i >= 0` / `i != -1` is
/// supported, and only the inclusive-upper-bound family widens to
/// include captures via this change. A stray `i >= k` with `i++`
/// would produce an infinite range if accepted naively.
#[test]
fn loop_ascending_ge_capture_still_rejected() {
    let src = r#"
        pragma circom 2.0.0;
        template T(k) {
            signal input  a;
            signal output out;
            var acc = 0;
            for (var i = 0; i >= k; i++) {
                acc = acc + 1;
            }
            out <== a + acc;
        }
        component main {public [a]} = T(3);
    "#;
    let tmp = std::env::temp_dir().join("ach_loop_ge_capture_rejected.circom");
    std::fs::write(&tmp, src).unwrap();
    let err = match circom::compile_file(&tmp, &[]) {
        Ok(_) => panic!("expected compile failure on ascending i >= k, got success"),
        Err(e) => e,
    };
    let msg = format!("{err}");
    assert!(
        msg.contains("for loop condition must be"),
        "unexpected error: {msg}"
    );
}
