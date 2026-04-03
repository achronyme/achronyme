//! Lowering from Circom AST to ProveIR.
//!
//! This module translates a parsed Circom template into ProveIR, Achronyme's
//! pre-compiled circuit representation. The translation happens in layers:
//!
//! - **Signals** (`signals.rs`): Categorize signal declarations into public
//!   inputs, witness inputs, outputs, and intermediates.
//! - **Expressions** (`expressions.rs`): Map Circom expression trees to
//!   ProveIR `CircuitExpr` nodes.
//! - **Statements** (future): Map Circom statements (`<==`, `===`, `<--`,
//!   control flow) to `CircuitNode` sequences.
//! - **Templates** (future): Handle component instantiation via template
//!   inlining with signal renaming.

#[allow(dead_code)]
pub mod error;
#[allow(dead_code)]
pub mod expressions;
#[allow(dead_code)]
pub mod signals;
