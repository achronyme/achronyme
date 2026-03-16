//! Fuzz target: Parser
//!
//! Feeds arbitrary bytes to the Achronyme parser. The parser must NEVER panic
//! regardless of input — it should return parse errors gracefully via Diagnostic.
//!
//! This catches:
//! - Buffer overflows in the lexer
//! - Stack overflows from deeply nested expressions
//! - Panics from unexpected token sequences
//! - Unicode edge cases (multi-byte chars, BOM, etc.)

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Only process valid UTF-8 (parser expects strings)
    if let Ok(source) = std::str::from_utf8(data) {
        // Must not panic — errors returned via Diagnostic vector
        let (_program, _diagnostics) = achronyme_parser::parse_program(source);
    }
});
