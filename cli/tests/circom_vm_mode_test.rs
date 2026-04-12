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
fn vm_mode_runtime_template_arg_rejected_at_compile_time() {
    // Num2Bits expects a compile-time integer template parameter.
    // Passing a runtime identifier must be rejected at .ach compile
    // time with a clear message — Phase 4.3 limitation.
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
"#,
    );
    let err = run(&fixture).expect_err("runtime template arg must be rejected");
    let msg = format!("{err}");
    assert!(
        msg.contains("integer literal") || msg.contains("compile-time"),
        "expected compile-time constant error, got: {msg}"
    );
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
