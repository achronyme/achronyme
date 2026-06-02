//! Component wiring state machine.
//!
//! Tracks pending components whose input signals haven't been fully wired yet.
//! When all inputs are wired, the component body is inlined into the circuit.
//!
//! ## Protocol
//!
//! 1. **Declaration**: `component c = Template(args)` creates a `PendingComponent`
//!    with the set of expected input signals (extracted from the template definition).
//!    If the template has no inputs, it's inlined immediately — no pending entry.
//!
//! 2. **Wiring**: Each `c.signal <== expr` calls `mark_wired` on the
//!    pending entry. The component holds a [`WiringState`] enum:
//!    - Scalar wiring (`c.in <== x`): adds to the wired set, stays
//!      in `AllScalar`.
//!    - Indexed wiring (`c.in[i] <== x`): adds to the wired set and
//!      transitions to `PartialIndexed`. The transition is monotonic
//!      — `PartialIndexed` never reverts.
//!
//! 3. **Trigger**: After every `mark_wired`, callers check
//!    `is_ready_to_inline()`. It returns `true` iff the state is
//!    still `AllScalar` and the wired set covers `input_signals`.
//!    `PartialIndexed` always returns `false` — those components are
//!    inlined via flush, not trigger.
//!
//! 4. **Demand-driven flush**: Before a substitution that references a
//!    component output, [`collect_value_component_refs`] walks the read
//!    side of the statement and emits a list of pending components the
//!    value depends on; [`flush_specific_component`] inlines exactly
//!    those. This replaces an older bulk-flush approach that could
//!    inline components before their inputs were fully wired.
//!
//! 5. **Cleanup**: At the end of a statement block, `lower_stmts_with_pending`
//!    inlines any remaining pending components (partial wiring or no-input).

use std::collections::{HashMap, HashSet};

use ir_forge::types::mangle::mangle_name;
use ir_forge::types::{CircuitExpr, CircuitNode, FieldConst};

use super::super::const_fold::try_fold_const;

use crate::ast::{self, Expr};

use super::super::components::inline_component_body_with_const_inputs;
use super::super::context::LoweringContext;
use super::super::env::LoweringEnv;
use super::super::error::LoweringError;
use super::super::utils::{extract_ident_name, EvalValue};
// memoized unroll: wiring.rs uses the ctx-aware resolver so the
// `pending` HashMap stays consistent with the IR emission side. During
// a memoized iter-0 capture, `try_resolve_component_array_target`
// (assignment side) and `resolve_component_array_name_ctx` (read +
// wiring side) both return the placeholder substring (`Sigma0_$LV7$`),
// so the component is REGISTERED in pending under the placeholder key
// AND looked up under the same key — no collision. After the loop,
// all components are inlined; pending is empty; outside callers (where
// `placeholder_loop_var = None`) get back to legacy numeric names.
use super::targets::resolve_component_array_name_ctx;

mod component;
mod consts;
mod refs;
#[cfg(test)]
mod tests;
mod trigger;

pub(super) use component::PendingComponent;
#[cfg(test)]
pub(super) use component::WiringState;
pub(crate) use consts::{collect_const_lifts, propagate_const_nodes};
pub(super) use refs::{
    collect_pending_refs_in_stmts, collect_value_component_refs, flush_specific_component,
};
pub(super) use trigger::{extract_component_wiring_with_env, maybe_trigger_inline};
