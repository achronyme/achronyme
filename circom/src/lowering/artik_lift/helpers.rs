//! Pure free-function helpers used across submodules.
//!
//! - [`eval_const_expr`] — fold an expression to a compile-time integer
//!   using the lift state's `const_locals` map. Returns `None` for
//!   anything signal- or runtime-dependent.
//! - [`extract_call_name`] — pull a bare identifier out of a call's
//!   `callee` expression.
//! - [`is_increment_on`] — shape check for `name++` / `++name`.
//! - [`stmts_are_mux_compatible`] / [`stmt_is_mux_compatible`] /
//!   [`expr_is_mux_compatible`] — pre-flight for the runtime mux pass:
//!   reject arms with `return`, array writes, witness writes, or
//!   non-scalar assignment targets.
//! - [`compound_to_binop`] — map a compound-assignment operator to the
//!   plain binary op the lift knows how to emit.

mod compound;
mod consts;
mod dims;
mod mutation;
mod mux;
mod returns;
mod scan;

#[cfg(test)]
mod tests;

#[allow(unused_imports)]
pub(super) use compound::compound_to_binop;
#[allow(unused_imports)]
pub(super) use consts::{
    eval_const_expr, expr_is_one, extract_call_name, is_decrement_on, is_increment_on,
    match_one_shl_const,
};
#[allow(unused_imports)]
pub(super) use dims::compute_dim_signature;
#[allow(unused_imports)]
pub(super) use mutation::{collect_mutated_scalars, MutationSummary};
#[allow(unused_imports)]
pub(super) use mux::{expr_is_mux_compatible, stmt_is_mux_compatible, stmts_are_mux_compatible};
#[allow(unused_imports)]
pub(super) use returns::{infer_callee_return_shape, CalleeReturnShape};
#[allow(unused_imports)]
pub(super) use scan::{collect_array_decls, stmt_has_return, stmts_have_return};
