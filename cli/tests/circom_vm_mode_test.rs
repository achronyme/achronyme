//! End-to-end test for Phase 4: circom templates invoked from VM mode.
//!
//! These tests drive the whole pipeline:
//! 1. Write a real `.circom` file to a temp dir.
//! 2. Write an `.ach` file that `import { T } from "./module.circom"`
//!    and calls `T()(...)` at the top level (VM mode — NOT inside a
//!    prove/circuit block).
//! 3. Call `cli::commands::run::run_file` which compiles + wires the
//!    `DefaultCircomWitnessHandler` + runs `vm.interpret()`.
//! 4. Assert the call succeeds (the program exits with no runtime
//!    error, meaning the handler resolved the library id, marshalled
//!    inputs, ran `evaluate_template_witness`, and marshalled the
//!    result back into a VM value).
//!
//! Phase 4.5 scope: scalar single-output (Square), array single-output
//! (Num2Bits), and namespaced call form (`P.Square()(x)`). Witness
//! correctness of the templates themselves is already covered by the
//! circom crate's own library tests; these tests verify the
//! compile_call → opcode → handler → `evaluate_template_witness`
//! dispatch pipeline is wired correctly.

use cli::commands::ErrorFormat;
use memory::field::PrimeId;
use std::io::Write;
use tempfile::TempDir;

const EF: ErrorFormat = ErrorFormat::Human;

struct CircomFixture {
    _dir: TempDir,
    dir_path: std::path::PathBuf,
    circom_filename: String,
    ach_path: std::path::PathBuf,
}

fn write_fixture(circom_src: &str, ach_src: &str) -> CircomFixture {
    let dir = tempfile::tempdir().expect("create temp dir");
    let dir_path = dir.path().to_path_buf();

    let circom_path = dir_path.join("module.circom");
    std::fs::write(&circom_path, circom_src).expect("write circom");

    let ach_path = dir_path.join("main.ach");
    let mut f = std::fs::File::create(&ach_path).expect("create ach");
    f.write_all(ach_src.as_bytes()).expect("write ach");
    f.flush().expect("flush");

    CircomFixture {
        _dir: dir,
        dir_path,
        circom_filename: "module.circom".to_string(),
        ach_path,
    }
}

fn run(fixture: &CircomFixture) -> anyhow::Result<()> {
    cli::commands::run::run_file(
        fixture.ach_path.to_str().unwrap(),
        false,
        None,
        "r1cs",
        PrimeId::Bn254,
        None,
        false,
        false,
        EF,
        &[],
    )
}

#[test]
fn vm_mode_selective_scalar_template_executes_successfully() {
    let fixture = write_fixture(
        r#"
        pragma circom 2.0.0;
        template Square() {
            signal input x;
            signal output y;
            y <== x * x;
        }
        "#,
        // Square(5) = 25 — assert via a native comparison.
        // `==` returns a boolean; assert(...) panics on false, so
        // if the handler misroutes we get a runtime error instead
        // of a silent pass.
        &format!(
            r#"
import {{ Square }} from "./{filename}"
let h = Square()(0p5)
assert(h == 0p25)
"#,
            filename = "module.circom"
        ),
    );
    let _ = fixture.circom_filename; // silence unused warning
    let _ = fixture.dir_path.clone();
    run(&fixture).expect("VM-mode Square call should succeed");
}

#[test]
fn vm_mode_namespaced_scalar_template_executes_successfully() {
    let fixture = write_fixture(
        r#"
        pragma circom 2.0.0;
        template Square() {
            signal input x;
            signal output y;
            y <== x * x;
        }
        "#,
        r#"
import "./module.circom" as P
let h = P.Square()(0p7)
assert(h == 0p49)
"#,
    );
    run(&fixture).expect("namespaced VM-mode Square call should succeed");
}

#[test]
fn vm_mode_template_call_wrong_arity_compile_error() {
    // Square takes 1 signal input — passing 2 must fail at compile
    // time with a clear signal-input-count error.
    let fixture = write_fixture(
        r#"
        pragma circom 2.0.0;
        template Square() {
            signal input x;
            signal output y;
            y <== x * x;
        }
        "#,
        r#"
import { Square } from "./module.circom"
let h = Square()(0p3, 0p4)
"#,
    );
    let err = run(&fixture).expect_err("wrong signal-input count must fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("signal input"),
        "expected signal-input count error, got: {msg}"
    );
}

#[test]
fn vm_mode_const_let_template_arg_accepted() {
    // Phase 5: `let n = 4; Num2Bits(n)(x)` should work because the
    // resolver's const evaluator proves `n` is a compile-time constant.
    let fixture = write_fixture(
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
        r#"
import { Num2Bits } from "./module.circom"
let n = 4
let h = Num2Bits(n)(0p5)
assert(h[0] == 0p1)
assert(h[2] == 0p1)
"#,
    );
    run(&fixture).expect("const let template arg should be accepted");
}

#[test]
fn vm_mode_array_output_returns_list_of_fields() {
    // Num2Bits(4) returns a 4-element array. The handler should
    // marshal it into a Value::list; accessing elements via
    // list indexing must work.
    //
    // 5 = 0b0101 → bit0=1, bit1=0, bit2=1, bit3=0.
    let fixture = write_fixture(
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
        r#"
import { Num2Bits } from "./module.circom"
let bits = Num2Bits(4)(0p5)
assert(bits[0] == 0p1)
assert(bits[1] == 0p0)
assert(bits[2] == 0p1)
assert(bits[3] == 0p0)
"#,
    );
    run(&fixture).expect("array-output Num2Bits should succeed");
}

#[test]
fn vm_mode_array_input_expansion_executes_successfully() {
    // SumArr(3) takes an array signal input. The compiler must
    // expand the ArrayLit `[3, 4, 5]` into 3 individual registers,
    // and the handler must reassemble them as `in_0`, `in_1`, `in_2`
    // before calling `evaluate_template_witness`.
    let fixture = write_fixture(
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
        r#"
import { SumArr } from "./module.circom"
let s = SumArr(3)([0p3, 0p4, 0p5])
assert(s == 0p12)
"#,
    );
    run(&fixture).expect("array-input SumArr should succeed");
}

#[test]
fn vm_mode_array_input_wrong_length_is_rejected() {
    let fixture = write_fixture(
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
        r#"
import { SumArr } from "./module.circom"
let s = SumArr(3)([0p3, 0p4])
"#,
    );
    let err = run(&fixture).expect_err("wrong array length should fail");
    let msg = format!("{err}");
    assert!(
        msg.contains("expects an array of 3") || msg.contains("passed 2"),
        "expected array-length mismatch error, got: {msg}"
    );
}

#[test]
fn vm_mode_poseidon_array_input_from_circomlib() {
    // Real circomlib Poseidon(2) has a 2-element array signal input.
    // This test locates the upstream `test/circomlib/circuits/poseidon.circom`
    // fixture from CARGO_MANIFEST_DIR and exercises the full
    // ArrayLit → expanded registers → witness pipeline.
    //
    // The Poseidon(1,2) constant is widely published; we assert on
    // exact equality with the native `poseidon(1, 2)` value that
    // already shipped in `test/prove/prove_with_poseidon.ach`.
    let manifest_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let poseidon_path = manifest_dir
        .parent()
        .unwrap()
        .join("test/circomlib/circuits/poseidon.circom");
    if !poseidon_path.exists() {
        eprintln!("skipping: {poseidon_path:?} not present");
        return;
    }

    let dir = tempfile::tempdir().expect("create temp dir");
    let ach_path = dir.path().join("main.ach");
    let mut f = std::fs::File::create(&ach_path).expect("create ach");
    let poseidon_path_str = poseidon_path.to_str().unwrap();
    use std::io::Write;
    // poseidon(1, 2) known vector — same as prove_with_poseidon.ach.
    let expected_hex =
        "7853200120776062878684798364095072458815029376092732009249414926327459813530";
    let ach_src = format!(
        r#"
import {{ Poseidon }} from "{poseidon_path_str}"
let h = Poseidon(2)([0p1, 0p2])
assert(h == 0p{expected_hex})
"#
    );
    f.write_all(ach_src.as_bytes()).expect("write ach");
    f.flush().expect("flush");

    cli::commands::run::run_file(
        ach_path.to_str().unwrap(),
        false,
        None,
        "r1cs",
        PrimeId::Bn254,
        None,
        false,
        false,
        EF,
        &[],
    )
    .expect("Poseidon(2)([1, 2]) should match native poseidon(1, 2)");
}
