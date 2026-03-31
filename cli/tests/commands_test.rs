use cli::commands::ErrorFormat;
use std::io::Write;
use tempfile::NamedTempFile;

const EF: ErrorFormat = ErrorFormat::Human;

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
        cli::commands::compile::compile_file(src.path().to_str().unwrap(), Some(&out_path), EF);
    assert!(result.is_ok(), "compile_file failed: {:?}", result.err());

    // Verify .achb was created with the ACH magic header
    let bytes = std::fs::read(&out_path).unwrap();
    assert!(bytes.len() >= 4, "output file too small");
    assert_eq!(&bytes[..4], b"ACH\x0B", "wrong magic header");
}

#[test]
fn compile_valid_source_no_output() {
    let src = write_temp_source("let x = 42");
    let result = cli::commands::compile::compile_file(src.path().to_str().unwrap(), None, EF);
    assert!(
        result.is_ok(),
        "compile_file (no output) failed: {:?}",
        result.err()
    );
}

#[test]
fn compile_invalid_source_returns_error() {
    let src = write_temp_source("let = ???");
    let result = cli::commands::compile::compile_file(src.path().to_str().unwrap(), None, EF);
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(err.contains("error"), "expected compile error, got: {err}");
}

#[test]
fn compile_nonexistent_file_returns_error() {
    let result =
        cli::commands::compile::compile_file("/tmp/nonexistent_achronyme_test.ach", None, EF);
    assert!(result.is_err());
}

// ======================================================================
// run_file
// ======================================================================

#[test]
fn run_valid_arithmetic_source() {
    let src = write_temp_source("let x = 2 + 3\nprint(x)");
    let result = cli::commands::run::run_file(
        src.path().to_str().unwrap(),
        false,
        None,
        "r1cs",
        None,
        false,
        false,
        EF,
    );
    assert!(result.is_ok(), "run_file failed: {:?}", result.err());
}

#[test]
fn run_source_with_runtime_error() {
    let src = write_temp_source("let x = 1 / 0");
    let result = cli::commands::run::run_file(
        src.path().to_str().unwrap(),
        false,
        None,
        "r1cs",
        None,
        false,
        false,
        EF,
    );
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    assert!(
        err.contains("division by zero"),
        "expected runtime error, got: {err}"
    );
}

#[test]
fn run_nonexistent_file_returns_error() {
    let result = cli::commands::run::run_file(
        "/tmp/nonexistent_achronyme_test.ach",
        false,
        None,
        "r1cs",
        None,
        false,
        false,
        EF,
    );
    assert!(result.is_err());
}

#[test]
fn run_compiled_binary() {
    // First compile to .achb, then run the binary
    let src = write_temp_source("let x = 10\nprint(x)");
    let out = tempfile::NamedTempFile::with_suffix(".achb").unwrap();
    let out_path = out.path().to_str().unwrap().to_string();

    cli::commands::compile::compile_file(src.path().to_str().unwrap(), Some(&out_path), EF)
        .expect("compile should succeed");

    let result =
        cli::commands::run::run_file(&out_path, false, None, "r1cs", None, false, false, EF);
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
    let result = cli::commands::disassemble::disassemble_file(src.path().to_str().unwrap(), EF);
    assert!(result.is_ok(), "disassemble failed: {:?}", result.err());
}

#[test]
fn disassemble_invalid_source_returns_error() {
    let src = write_temp_source("let = ???");
    let result = cli::commands::disassemble::disassemble_file(src.path().to_str().unwrap(), EF);
    assert!(result.is_err());
}

// ======================================================================
// error_format tests
// ======================================================================

#[test]
fn json_error_format_produces_valid_json() {
    let src = write_temp_source("let = ???");
    let result =
        cli::commands::compile::compile_file(src.path().to_str().unwrap(), None, ErrorFormat::Json);
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    // Should be valid JSON
    let parsed: serde_json::Value = serde_json::from_str(&err).expect("should be valid JSON");
    assert!(parsed.get("message").is_some(), "JSON should have message");
    assert!(parsed.get("level").is_some(), "JSON should have level");
    assert!(parsed.get("spans").is_some(), "JSON should have spans");
}

#[test]
fn short_error_format_is_grep_friendly() {
    let src = write_temp_source("let = ???");
    let result = cli::commands::compile::compile_file(
        src.path().to_str().unwrap(),
        None,
        ErrorFormat::Short,
    );
    assert!(result.is_err());
    let err = format!("{}", result.unwrap_err());
    // Should contain severity and colon-separated location
    assert!(
        err.contains("error:"),
        "short format should contain 'error:', got: {err}"
    );
}

#[test]
fn json_warning_format_produces_valid_json() {
    // This source triggers an unused variable warning
    let src = write_temp_source("fn test() { let x = 5; 1 }");
    let content = std::fs::read_to_string(src.path()).unwrap();
    let mut compiler = compiler::Compiler::new();
    let _ = compiler.compile(&content);
    let warnings = compiler.take_warnings();
    assert!(!warnings.is_empty(), "should have warnings");

    // Render each warning as JSON
    for w in &warnings {
        let rendered = cli::commands::render_compile_error(
            &compiler::CompilerError::DiagnosticError(Box::new(w.clone())),
            &content,
            ErrorFormat::Json,
        );
        let parsed: serde_json::Value =
            serde_json::from_str(&rendered).expect("warning JSON should be valid");
        assert_eq!(parsed["level"], "warning");
    }
}
