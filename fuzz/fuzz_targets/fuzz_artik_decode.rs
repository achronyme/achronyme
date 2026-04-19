//! Fuzz target: Artik bytecode decoder.
//!
//! Feeds arbitrary bytes to [`witness::bytecode::decode`]. The decoder
//! must NEVER panic — it may return `Err(ArtikError)` for malformed
//! input or `Ok(Program)` for well-formed input, but nothing else.
//!
//! This catches:
//! - Buffer over-reads in the header / const pool / body cursors.
//! - Arithmetic overflow in declared lengths (header lies about lens).
//! - Unhandled opcode / sub-op tag byte combinations.
//! - Validator oversights that would otherwise reach the executor.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = witness::bytecode::decode(data, None);
});
