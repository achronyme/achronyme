#![allow(dead_code)]
//! Shared helpers for the circom E2E test binaries.

mod e2e;
mod inputs;
mod runner;
mod sha256;

#[allow(unused_imports)]
pub use e2e::{circomlib_e2e_optimized, circomlib_e2e_verify, circomlib_e2e_verify_fe};
#[allow(unused_imports)]
pub use inputs::load_inputs;
#[allow(unused_imports)]
pub use runner::{find_circom_tests, run_circom_test, TestResult};
#[allow(unused_imports)]
pub use sha256::{hex_encode, print_constraint_histogram, run_sha256_lysis_hard_gate};
