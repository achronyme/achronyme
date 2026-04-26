//! Lowering from Circom AST to ProveIR.
//!
//! This module translates a parsed Circom template into ProveIR, Achronyme's
//! pre-compiled circuit representation. The translation happens in layers:
//!
//! - **Context** (`context.rs`): Program-level template/function resolution.
//! - **Environment** (`env.rs`): Shared identifier resolution state.
//! - **Utilities** (`utils.rs`): Shared helpers (const eval, ident extraction).
//! - **Signals** (`signals.rs`): Categorize signal declarations into public
//!   inputs, witness inputs, outputs, and intermediates.
//! - **Expressions** (`expressions.rs`): Map Circom expression trees to
//!   ProveIR `CircuitExpr` nodes.
//! - **Statements** (`statements.rs`): Map Circom statements (`<==`, `===`,
//!   `<--`, control flow) to `CircuitNode` sequences.
//! - **Components** (`components.rs`): Component instantiation via template
//!   body inlining with signal name mangling.
//! - **Templates** (`template.rs`): Orchestrate the full pipeline from
//!   `TemplateDef` to `ProveIR`.

#[allow(dead_code)]
pub mod artik_lift;
#[allow(dead_code)]
pub mod bit_width;
#[allow(dead_code)]
pub mod branch_flip;
#[allow(dead_code)]
pub mod compile_time;
#[allow(dead_code)]
pub mod components;
#[allow(dead_code)]
pub mod const_fold;
#[allow(dead_code)]
pub mod context;
#[allow(dead_code)]
pub mod env;
#[allow(dead_code)]
pub mod error;
#[allow(dead_code)]
pub mod expressions;
#[allow(dead_code)]
pub mod loop_var_subst;
#[allow(dead_code)]
pub mod signals;
#[allow(dead_code)]
pub mod statements;
#[allow(dead_code)]
pub mod suggest;
#[allow(dead_code)]
pub mod template;
#[cfg(test)]
pub(crate) mod test_helpers;
#[allow(dead_code)]
pub mod utils;
