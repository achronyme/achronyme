//! Fuzz target: random bytes → decode → validate must never panic.
//!
//! Harder than `fuzz_lysis_decode`: we fuzz the whole pre-execution
//! pipeline. A successful decode is fed to the validator; both must
//! return a `LysisError` rather than unwind.

#![no_main]

use libfuzzer_sys::fuzz_target;
use lysis::LysisConfig;
use memory::field::Bn254Fr;

fuzz_target!(|data: &[u8]| {
    if let Ok(program) = lysis::decode::<Bn254Fr>(data) {
        let _ = lysis::bytecode::validate(&program, &LysisConfig::default());
    }
});
