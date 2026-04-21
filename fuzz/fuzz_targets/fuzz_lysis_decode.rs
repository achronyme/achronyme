//! Fuzz target: random bytes → `lysis::decode` must never panic.
//!
//! RFC §10 Phase 1 exit criterion: "Fuzz target `fuzz_decode` runs
//! 10M iterations without panic." The target body is deliberately
//! minimal — any input, including completely random garbage, must
//! either decode successfully or return a `LysisError`. Panics,
//! unwinds, or UB are test failures.
//!
//! Run locally with:
//!
//! ```text
//! cd fuzz
//! cargo fuzz run fuzz_lysis_decode -- -runs=100000
//! ```
//!
//! CI should run the 10M-iteration workload per release.

#![no_main]

use libfuzzer_sys::fuzz_target;
use memory::field::Bn254Fr;

fuzz_target!(|data: &[u8]| {
    let _ = lysis::decode::<Bn254Fr>(data);
});
