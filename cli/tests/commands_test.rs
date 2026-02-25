use std::io::Write;
use tempfile::NamedTempFile;

fn write_temp_source(content: &str) -> NamedTempFile {
    let mut f = NamedTempFile::with_suffix(".ach").unwrap();
    f.write_all(content.as_bytes()).unwrap();
    f.flush().unwrap();
    f
}

// ======================================================================
// compile_file
// ======================================================================

#[test]
fn compile_valid_source_with_output() {
    let src = write_temp_source("let x = 1 + 2\nprint(x)");
    let out = tempfile::NamedTempFile::with_suffix(".achb").unwrap();
    let out_path = out.path().to_str().unwrap().to_string();

    let result =
        cli::commands::compile::compile_file(src.path().to_str().unwrap(), Some(&out_path));
    assert!(result.is_ok(), "compile_file failed: {:?}", result.err());

    // Verify .achb was created with the ACH magic header
    let bytes = std::fs::read(&out_path).unwrap();
    assert!(bytes.len() >= 4, "output file too small");
    assert_eq!(&bytes[..4], b"ACH\x09", "wrong magic header");
}

#[test]
fn compile_valid_source_no_output() {
    let src = write_temp_source("let x = 42");
    let result = cli::commands::compile::compile_file(src.path().to_str().unwrap(), None);
    assert!(
        result.is_ok(),
        "compile_file (no output) failed: {:?}",
        result.err()
    );
}

#[test]
fn compile_invalid_source_returns_error() {
    let src = write_temp_source("let = ???");
    let result = cli::commands::compile::compile_file(src.path().to_str().unwrap(), None);
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("Compile error"),
        "expected compile error, got: {err}"
    );
}

#[test]
fn compile_nonexistent_file_returns_error() {
    let result = cli::commands::compile::compile_file("/tmp/nonexistent_achronyme_test.ach", None);
    assert!(result.is_err());
}

// ======================================================================
// run_file
// ======================================================================

#[test]
fn run_valid_arithmetic_source() {
    let src = write_temp_source("let x = 2 + 3\nprint(x)");
    let result = cli::commands::run::run_file(src.path().to_str().unwrap(), false, None, "r1cs");
    assert!(result.is_ok(), "run_file failed: {:?}", result.err());
}

#[test]
fn run_source_with_runtime_error() {
    let src = write_temp_source("let x = 1 / 0");
    let result = cli::commands::run::run_file(src.path().to_str().unwrap(), false, None, "r1cs");
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("DivisionByZero"),
        "expected runtime error, got: {err}"
    );
}

#[test]
fn run_nonexistent_file_returns_error() {
    let result =
        cli::commands::run::run_file("/tmp/nonexistent_achronyme_test.ach", false, None, "r1cs");
    assert!(result.is_err());
}

#[test]
fn run_compiled_binary() {
    // First compile to .achb, then run the binary
    let src = write_temp_source("let x = 10\nprint(x)");
    let out = tempfile::NamedTempFile::with_suffix(".achb").unwrap();
    let out_path = out.path().to_str().unwrap().to_string();

    cli::commands::compile::compile_file(src.path().to_str().unwrap(), Some(&out_path))
        .expect("compile should succeed");

    let result = cli::commands::run::run_file(&out_path, false, None, "r1cs");
    assert!(
        result.is_ok(),
        "run compiled binary failed: {:?}",
        result.err()
    );
}

// ======================================================================
// disassemble_file
// ======================================================================

#[test]
fn disassemble_valid_source() {
    let src = write_temp_source("let x = 1 + 2\nprint(x)");
    let result = cli::commands::disassemble::disassemble_file(src.path().to_str().unwrap());
    assert!(result.is_ok(), "disassemble failed: {:?}", result.err());
}

#[test]
fn disassemble_invalid_source_returns_error() {
    let src = write_temp_source("let = ???");
    let result = cli::commands::disassemble::disassemble_file(src.path().to_str().unwrap());
    assert!(result.is_err());
}

// ======================================================================
// run_repl (stub)
// ======================================================================

#[test]
fn repl_stub_returns_ok() {
    let result = cli::repl::run_repl();
    assert!(result.is_ok());
}
