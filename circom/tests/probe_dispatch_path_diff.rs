//! Probe — dispatch-path A/B comparison for SHA-256(64).
//!
//! Empirical disambiguation between three failure-mode hypotheses for
//! the `frame overflow: register slot 255 exceeds max frame size 255`
//! error that hits when a `.ach prove` block invokes a heavy circomlib
//! template:
//!
//! - **H1** — outer-wrapping miss: pure-circom's top-level body has
//!   structure that the walker sees as its own frame; the `.ach`
//!   dispatch flattens into a parent body without that boundary.
//! - **H2** — nested-lift gap: both bodies have `LoopUnroll` nodes,
//!   but the per-iter split heuristic doesn't fire when the parent is
//!   a flat body rather than a top-level template.
//! - **H3** — wide single instruction: a giant `Decompose` or
//!   similarly-sized leaf overflows within one iter that the walker
//!   can't pre-emit-split.
//!
//! Run with:
//!
//! ```bash
//! cargo test --release -p circom --test probe_dispatch_path_diff -- --ignored --nocapture
//! ```
//!
//! Add `LYSIS_WALKER_TRACE=1` to capture the slot/cost numbers on the
//! failing path:
//!
//! ```bash
//! LYSIS_WALKER_TRACE=1 cargo test --release -p circom --test probe_dispatch_path_diff -- --ignored --nocapture
//! ```
//!
//! Both probes are `#[ignore]`-gated to keep CI green; this file is
//! observation-only and produces no assertions beyond bare smoke
//! checks. The output is the deliverable.

#[path = "probe_dispatch_path_diff/common.rs"]
mod common;
#[path = "probe_dispatch_path_diff/embedded.rs"]
mod embedded;
#[path = "probe_dispatch_path_diff/lower.rs"]
mod lower;
#[path = "probe_dispatch_path_diff/sides.rs"]
mod sides;
#[path = "probe_dispatch_path_diff/stats.rs"]
mod stats;
