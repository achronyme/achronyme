//! R1″ for-loop body memoization: substitute the `LoopVar` placeholder.
//!
//! When `lower_for_loop` captures iter 0 of a memoizable for-loop body,
//! every reference to the loop variable's *value* becomes
//! `CircuitExpr::LoopVar(token)`, and every name that mangled in the
//! loop variable embeds `loop_var_placeholder(token)` as a substring.
//! The captured slice is then cloned for each iter `N` and rewritten
//! by `substitute_loop_var(&mut slice, token, N)`:
//!
//! - `CircuitExpr::LoopVar(token)` leaves → `CircuitExpr::Const(N)`
//! - Name strings containing `$LV{token}$` → string with that
//!   substring replaced by `N`'s decimal form
//!
//! Leaves with a *different* token are left untouched so an outer-loop
//! placeholder can survive a nested-loop substitution pass.
//!
//! Visitor only. The lowering integration that actually emits
//! `LoopVar` and the placeholder lives in `lower_for_loop`.

mod flush;
mod subst;

#[allow(unused_imports)]
pub use flush::{body_only_indices, flushed_node_count};
pub use subst::{loop_var_placeholder, substitute_loop_var};

#[cfg(test)]
mod tests;
