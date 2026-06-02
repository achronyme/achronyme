use std::collections::HashMap;

use memory::{Bn254Fr, FieldElement};
use zkc::r1cs_backend::R1CSCompiler;

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
