//! Loop lowering: for loops, while loops, and compile-time loop evaluation.
//!
//! Circom for loops must have deterministic bounds for circuit compilation.
//! While loops are only allowed when they touch variables (not signals/components)
//! and are evaluated entirely at compile time.

use std::collections::{HashMap, HashSet};

use diagnostics::SpanRange;
use ir_forge::types::{CircuitNode, FieldConst, ForRange};

use crate::ast::{self, AssignOp, BinOp, CompoundOp, ElseBranch, Expr, PostfixOp, Stmt};

use super::super::compile_time::CompileTimeEnv;
use super::super::context::LoweringContext;
use super::super::env::LoweringEnv;
use super::super::env_footprint::EnvFootprint;
use super::super::error::LoweringError;
use super::super::expressions::lower_expr;
use super::super::loop_var_subst::substitute_loop_var;
use super::arrays::{body_has_component_array_ops, body_references_known_arrays};
use super::targets::extract_target_name;
use super::wiring::{collect_pending_refs_in_stmts, flush_specific_component, PendingComponent};
use crate::lowering::utils::{const_eval_u64, BigVal, EvalValue};

mod array_predicates;
mod bounds;
mod classify;
mod classify_predicates;
mod compile_time;
mod emit;
mod for_loop;
mod memo;
mod memo_predicates;
mod replay;

pub(super) use classify::{classify_loop_body, LoopLowering};
pub(super) use compile_time::{eval_while_compile_time, stmts_are_var_only};
pub(super) use for_loop::lower_for_loop;

use array_predicates::{
    body_has_indexed_assign_shape, body_has_local_var_array_indexed_reads,
    body_has_local_var_array_indexed_writes, body_mixes_signals_and_vars,
};
use bounds::{extract_loop_bound, validate_loop_step, LoopBound};
use classify_predicates::{
    body_has_any_signal_ops, body_has_loop_var_indexed_assignments, body_writes_to_outer_scope_var,
    body_writes_to_subcomponent_array, expr_references_ident,
};
use compile_time::stmt_is_var_only;
use emit::{emit_for_node, resolve_bound_to_u64};
use memo::{is_memoizable, r1pp_enabled, MemoPlan};
use memo_predicates::{
    body_has_component_or_call, body_has_dot_access, body_has_loop_var_dependent_var_decl,
    body_has_nested_loop_with_loop_var_bound, body_has_state_carrying_var_mutation,
    body_has_witness_call,
};
use replay::{memoize_loop, sync_post_emission, try_eval_at_compile_time};

#[cfg(test)]
mod tests;
