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
