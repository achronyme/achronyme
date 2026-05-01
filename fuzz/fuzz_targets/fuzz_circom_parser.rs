//! Fuzz target: Circom Parser
//!
//! Feeds arbitrary bytes (interpreted as UTF-8) to `circom::parser::parse_circom`.
//! The parser must NEVER panic regardless of input — lexer-level errors must be
//! returned as `Err(ParseError)`, recoverable parse errors must surface as
//! `Diagnostic`s in the returned vector. A panic is a hard fuzz failure.
//!
//! This catches:
//! - Buffer overflows in the Circom lexer (different lexer than `.ach` —
//!   pragma/include/template/component-main lexing has its own state machine).
//! - Stack overflows from deeply nested expressions / template instantiations
//!   (Circom allows `template T()` with arbitrary signal/component nesting).
//! - Panics from unexpected token sequences (unicode, BOM, malformed pragma,
//!   mismatched brace/bracket).
//! - Recovery-state bugs — the Circom parser carries a `take_errors()` vector
//!   the same way `.ach` does, but its recovery points (template body, signal
//!   decl, expression) are different from `.ach` blocks.
//!
//! ## Discriminator (verified during development, then reverted)
//!
//! Inserted a synthetic panic guard at the top of `parse_circom`:
//! ```ignore
//! if source.starts_with("PANIC_FUZZ_DISCRIMINATOR") { panic!("..."); }
//! ```
//! Verified `cargo +nightly fuzz run fuzz_circom_parser -- -runs=10000`
//! triggers it within a few seconds (libfuzzer biases toward ASCII string
//! prefixes in the corpus, so the prefix guard fires fast). The patch was
//! reverted before the commit landing this target.
//!
//! Without a verified discriminator, this target is theater — we have no
//! evidence it would catch a real panic that didn't reach the corpus.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Only process valid UTF-8 (parser expects strings — same precondition
    // as the lexer, which is tokenized via `Lexer::tokenize(source: &str)`).
    if let Ok(source) = std::str::from_utf8(data) {
        // Both branches are valid graceful failures — only panics fail the fuzz.
        // - `Err(ParseError)`: lexer-level unrecoverable error.
        // - `Ok((_program, _diagnostics))`: parser succeeded; diagnostics may
        //   carry recoverable errors via `Diagnostic` placeholders in the AST.
        let _ = circom::parser::parse_circom(source);
    }
});
