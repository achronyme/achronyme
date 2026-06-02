//! Frozen-baseline regression test for `prove {}` blocks across the
//! `examples/` and `test/prove/` corpora. Sister sweep to
//! `circom/tests/cross_path_baseline.rs`.
//!
//! For every `.ach` example listed in [`EXAMPLES`], this test:
//!
//! 1. Compiles the source via `cli::new_compiler()`.
//! 2. Runs the resulting bytecode in an Akron VM with a custom
//!    [`CapturingProveHandler`] that records `(seq, name, prove_ir_bytes,
//!    scope_values)` on every `Prove` opcode and returns
//!    `ProveResult::VerifiedOnly` so the script proceeds.
//! 3. Replays each captured prove block via `instantiate_lysis`,
//!    compiles the resulting `IrProgram` to R1CS, runs `optimize_r1cs`,
//!    and computes a `FrozenBaseline` snapshot.
//! 4. Compares the snapshot to a pinned `FrozenBaseline` keyed by
//!    `format!("{file}/{block}")`. Drift surfaces as actionable
//!    panic with the diff site (counts, public partition, hash).
//!
//! ## Why a frozen baseline
//!
//! With a single instantiation path, dual-path byte-identity is vacuous.
//! Frozen-baseline pins the structural identity of each prove block,
//! surfacing both intentional changes (re-pin via
//! `REGEN_FROZEN_BASELINES=1`) and silent regressions (assertion fails
//! with a diff that names the drift surface).
//!
//! ## Determinism precondition
//!
//! All 34 captured prove blocks use hardcoded literal inputs (no
//! `OsRng`, no time-based seeds, no HashMap-iteration leaks reaching
//! scope_values). Sort-based canonicalization in
//! `zkc::test_support::canonical_multiset_hash` handles the term-order
//! axis. Full hash pinning is therefore safe; no shape-only allowlist
//! needed (unlike circom's EdDSAPoseidon). To verify determinism on
//! this test, run it 5+ times and confirm the assertion body's
//! printed counts and hashes match across runs.
//!
//! ## Re-generating pinned values
//!
//! ```ignore
//! REGEN_FROZEN_BASELINES=1 cargo test --release -p cli \
//!     --test cross_path_prove_baseline -- --nocapture
//! ```
//! Then copy each printed `FrozenBaseline { ... }` literal into the
//! corresponding `pin_*` function below. Every re-pin is a documented
//! intentional change — a passing pin that later starts failing means
//! a regression that needs root-cause, not a re-pin.

pub(crate) use std::cell::RefCell;
pub(crate) use std::collections::HashMap;
pub(crate) use std::path::{Path, PathBuf};
pub(crate) use std::rc::Rc;
pub(crate) use std::time::{Duration, Instant};

pub(crate) use akron::{CallFrame, ProveError, ProveHandler, ProveResult, VM};
pub(crate) use cli::commands::{new_compiler, register_std_modules};
pub(crate) use ir_forge::{ArraySize, ProveIR};
pub(crate) use memory::{Bn254Fr, FieldElement, Function};
pub(crate) use zkc::test_support::{
    assert_frozen_baseline_matches, compute_frozen_baseline, FrozenBaseline,
};

pub(crate) type F = Bn254Fr;

#[path = "cross_path_prove_baseline/examples.rs"]
mod examples;
#[path = "cross_path_prove_baseline/harness.rs"]
mod harness;
#[path = "cross_path_prove_baseline/pins.rs"]
mod pins;
#[path = "cross_path_prove_baseline/runner.rs"]
mod runner;
