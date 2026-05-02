//! End-to-end compiler tests for the Circom import dispatcher.
//!
//! The dispatcher chains a trait surface in the `ir` crate, a
//! `CircomLibrary` impl, and `OuterScope.circom_imports` seeded
//! from the .ach compiler. `ProveIrCompiler::compile_call`
//! instantiates templates inside prove/circuit blocks.
//!
//! These tests drive a full `.ach` → bytecode compile through the
//! real circom frontend (no stubs) to pin the happy path:
//!
//! 1. `import { T } from "x.circom"` populates `circom_template_aliases`.
//! 2. A `prove {}` block calling `T()(signal)` succeeds at compile
//!    time and the resulting bytecode references the template's
//!    instantiated body.
//!
//! The goal is a smoke-test — detailed unit coverage lives in
//! `ir_forge::akronc::tests::circom_dispatch` against the
//! StubLibrary.

use akronc::codegen::Compiler;
use tempfile::TempDir;

/// Owns a `tempfile::TempDir` + a `.circom` file inside it. On drop
/// the directory and its contents are removed.
struct TempCircom {
    _dir: TempDir,
    path: std::path::PathBuf,
}

impl TempCircom {
    fn dir(&self) -> std::path::PathBuf {
        self.path.parent().unwrap().to_path_buf()
    }
    fn filename(&self) -> String {
        self.path.file_name().unwrap().to_str().unwrap().to_string()
    }
}

fn temp_circom(src: &str) -> TempCircom {
    let dir = tempfile::tempdir().expect("create temp dir");
    let path = dir.path().join("module.circom");
    std::fs::write(&path, src).expect("write temp circom");
    TempCircom { _dir: dir, path }
}

#[test]
fn prove_block_can_call_selective_imported_scalar_template() {
    // Square is a single-scalar-input, single-scalar-output template.
    // Seed `x_val` in the outer scope so the prove block captures it
    // and hands it to Square()(x_val). The prove public parameter
    // `out` is what the caller supplies when proving.
    let tc = temp_circom(
        r#"
        pragma circom 2.0.0;
        template Square() {
            signal input x;
            signal output y;
            y <== x * x;
        }
        "#,
    );
    let rel = tc.filename();
    let ach_src = format!(
        r#"
import {{ Square }} from "./{rel}"
let x_val = 0p5
let expected = 0p25
prove(expected: Public) {{
    let y = Square()(x_val)
    assert_eq(y, expected)
}}
"#
    );

    let mut compiler = Compiler::new();
    compiler.base_path = Some(tc.dir());
    compiler
        .compile(&ach_src)
        .expect("prove block calling imported circom Square should compile");
}

#[test]
fn prove_block_can_call_namespaced_imported_scalar_template() {
    // import "x.circom" as P; P.Square()(x_val)
    let tc = temp_circom(
        r#"
        pragma circom 2.0.0;
        template Square() {
            signal input x;
            signal output y;
            y <== x * x;
        }
        "#,
    );
    let rel = tc.filename();
    let ach_src = format!(
        r#"
import "./{rel}" as P
let x_val = 0p5
let expected = 0p25
prove(expected: Public) {{
    let y = P.Square()(x_val)
    assert_eq(y, expected)
}}
"#
    );

    let mut compiler = Compiler::new();
    compiler.base_path = Some(tc.dir());
    compiler
        .compile(&ach_src)
        .expect("namespaced circom call should compile");
}

#[test]
fn prove_block_can_access_array_output_bits_via_dot() {
    // Num2Bits(4) exposes a 4-bit array output. The prove block
    // binds the call with `let r = Num2Bits(4)(x_val)` and asserts
    // on individual bits via `r.out_0`, `r.out_1`, ... — exercises
    // the dotted-env-entry resolution path.
    let tc = temp_circom(
        r#"
        pragma circom 2.0.0;
        template Num2Bits(n) {
            signal input in;
            signal output out[n];
            var lc = 0;
            var e = 1;
            for (var i = 0; i < n; i++) {
                out[i] <-- (in >> i) & 1;
                out[i] * (out[i] - 1) === 0;
                lc += out[i] * e;
                e = e + e;
            }
            lc === in;
        }
        "#,
    );
    let rel = tc.filename();
    // 5 = 0b0101 → bit0=1, bit1=0, bit2=1, bit3=0
    let ach_src = format!(
        r#"
import {{ Num2Bits }} from "./{rel}"
let x_val = 0p5
let bit0 = 0p1
prove(bit0: Public) {{
    let r = Num2Bits(4)(x_val)
    assert_eq(r.out_0, bit0)
}}
"#
    );

    let mut compiler = Compiler::new();
    compiler.base_path = Some(tc.dir());
    compiler
        .compile(&ach_src)
        .expect("array-output DotAccess should compile");
}

#[test]
fn prove_block_rejects_non_const_template_arg() {
    // Num2Bits expects a compile-time constant param. Passing a
    // captured variable (which is a runtime value inside the circuit)
    // must be rejected with a clear compile-time-constant diagnostic.
    let tc = temp_circom(
        r#"
        pragma circom 2.0.0;
        template Num2Bits(n) {
            signal input in;
            signal output out[n];
            var lc = 0;
            var e = 1;
            for (var i = 0; i < n; i++) {
                out[i] <-- (in >> i) & 1;
                out[i] * (out[i] - 1) === 0;
                lc += out[i] * e;
                e = e + e;
            }
            lc === in;
        }
        "#,
    );
    let rel = tc.filename();
    let ach_src = format!(
        r#"
import {{ Num2Bits }} from "./{rel}"
let n_val = 0p8
let x_val = 0p5
prove(out: Public) {{
    let _ = Num2Bits(n_val)(x_val)
    assert_eq(x_val, out)
}}
"#
    );

    let mut compiler = Compiler::new();
    compiler.base_path = Some(tc.dir());
    let err = compiler
        .compile(&ach_src)
        .expect_err("runtime template arg must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("compile-time constant"),
        "expected compile-time constant error, got: {msg}"
    );
}

#[test]
fn prove_block_can_call_template_with_array_signal_input() {
    // SumArr(n) takes an array input and returns a scalar sum.
    // The user passes the elements as an ArrayLit; the dispatcher
    // must expand it into per-element entries before instantiation.
    let tc = temp_circom(
        r#"
        pragma circom 2.0.0;
        template SumArr(n) {
            signal input in[n];
            signal output out;
            var acc = 0;
            for (var i = 0; i < n; i++) {
                acc += in[i];
            }
            out <== acc;
        }
        "#,
    );
    let rel = tc.filename();
    let ach_src = format!(
        r#"
import {{ SumArr }} from "./{rel}"
let a = 0p3
let b = 0p4
let c = 0p5
let expected = 0p12
prove(expected: Public) {{
    let sum = SumArr(3)([a, b, c])
    assert_eq(sum, expected)
}}
"#
    );

    let mut compiler = Compiler::new();
    compiler.base_path = Some(tc.dir());
    compiler
        .compile(&ach_src)
        .expect("SumArr(3)([a, b, c]) should compile");
}

#[test]
fn prove_block_array_input_wrong_length_errors() {
    let tc = temp_circom(
        r#"
        pragma circom 2.0.0;
        template SumArr(n) {
            signal input in[n];
            signal output out;
            var acc = 0;
            for (var i = 0; i < n; i++) {
                acc += in[i];
            }
            out <== acc;
        }
        "#,
    );
    let rel = tc.filename();
    let ach_src = format!(
        r#"
import {{ SumArr }} from "./{rel}"
prove(expected: Public) {{
    // Template expects 3 elements but caller passes 2.
    let sum = SumArr(3)([0p1, 0p2])
    assert_eq(sum, expected)
}}
"#
    );

    let mut compiler = Compiler::new();
    compiler.base_path = Some(tc.dir());
    let err = compiler
        .compile(&ach_src)
        .expect_err("array length mismatch must fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("expects an array of 3") || msg.contains("passed 2"),
        "expected array-length mismatch error, got: {msg}"
    );
}

#[test]
fn prove_block_array_input_non_array_expr_errors() {
    let tc = temp_circom(
        r#"
        pragma circom 2.0.0;
        template SumArr(n) {
            signal input in[n];
            signal output out;
            var acc = 0;
            for (var i = 0; i < n; i++) {
                acc += in[i];
            }
            out <== acc;
        }
        "#,
    );
    let rel = tc.filename();
    // Caller passes a scalar instead of an ArrayLit for an array signal.
    let ach_src = format!(
        r#"
import {{ SumArr }} from "./{rel}"
prove(expected: Public) {{
    let sum = SumArr(2)(0p1)
    assert_eq(sum, expected)
}}
"#
    );

    let mut compiler = Compiler::new();
    compiler.base_path = Some(tc.dir());
    let err = compiler
        .compile(&ach_src)
        .expect_err("non-array expression for array signal must fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("array of size") || msg.contains("wrap the inputs"),
        "expected array-input error, got: {msg}"
    );
}
