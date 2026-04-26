//! R1″ Phase 5: capture and replay [`LoweringEnv`] mutations across
//! memoized iterations.
//!
//! When the for-loop unroller captures iter 0 with the
//! [`crate::lowering::loop_var_subst::loop_var_placeholder`] in
//! place of the loop variable's value, every name added to `env`
//! during that iter (locals, arrays, component arrays, etc.)
//! contains the placeholder substring `$LV{token}$`. Replaying
//! those mutations for iter `N` means substituting that substring
//! for `N`'s decimal form and re-applying the resulting names.
//!
//! [`EnvFootprint::from_diff`] computes the additive diff between a
//! pre-iter snapshot and the post-iter env state.
//! [`EnvFootprint::apply_substituted`] re-applies that diff with the
//! placeholder substituted, so the post-state of a memoized iter `N`
//! matches what the legacy unrolled lowering would have produced.
//!
//! Phase 5 does NOT integrate with `lower_for_loop` — that's Phase 6.
//! This module is the replay primitive plus tests.

use std::collections::{HashMap, HashSet};

use ir_forge::types::FieldConst;

use super::env::LoweringEnv;
use super::loop_var_subst::loop_var_placeholder;
use super::utils::EvalValue;

/// The additive mutations a single iteration imprinted on
/// [`LoweringEnv`]. Captured against a pre-iter snapshot via
/// [`EnvFootprint::from_diff`] and replayed (with the loop-var
/// placeholder substituted) via [`EnvFootprint::apply_substituted`].
///
/// **Additive only.** Removals are not captured. The for-loop
/// unroller manages the loop variable's `known_constants` lifecycle
/// directly (insert at iter start, remove at loop end), so any
/// removals seen during a memoized iter would be redundant or wrong.
///
/// **Value-dependent vars are out of scope.** If iter 0 set
/// `known_constants["k"] = Const(5)` and iter 1 would have set
/// `Const(6)`, replaying iter-0's footprint at iter 1 produces
/// `Const(5)` — wrong. Phase 6's integration is responsible for
/// refusing to memoize loops where any compile-time var depends on
/// the loop variable. This module assumes the caller has already
/// gated on that property.
#[derive(Debug, Clone, Default)]
pub struct EnvFootprint {
    /// Names newly inserted into `env.locals`.
    pub added_locals: Vec<String>,
    /// Names newly inserted into `env.inputs`. (Rare in loop body —
    /// signal inputs are declared at template scope — but defensible.)
    pub added_inputs: Vec<String>,
    /// (name, length) pairs newly inserted into `env.arrays`.
    pub added_arrays: Vec<(String, usize)>,
    /// (name, strides) pairs newly inserted into `env.strides`.
    pub added_strides: Vec<(String, Vec<usize>)>,
    /// Names newly inserted into `env.component_arrays`.
    pub added_component_arrays: Vec<String>,
    /// (name, value) pairs newly inserted into `env.known_constants`.
    /// The loop variable's own entry is filtered out — the unroller
    /// owns its lifecycle.
    pub added_known_constants: Vec<(String, FieldConst)>,
    /// (name, value) pairs newly inserted into `env.known_array_values`.
    pub added_known_array_values: Vec<(String, EvalValue)>,
}

impl EnvFootprint {
    /// Compute the additive diff `post - pre`. Entries present in
    /// `pre` are filtered out; only newly-added entries appear in
    /// the resulting footprint.
    ///
    /// `loop_var` names the loop variable; its entry in
    /// `known_constants` is filtered out of `added_known_constants`
    /// because the unroller manages it directly per iter.
    pub fn from_diff(pre: &LoweringEnv, post: &LoweringEnv, loop_var: &str) -> Self {
        Self {
            added_locals: diff_set(&pre.locals, &post.locals),
            added_inputs: diff_set(&pre.inputs, &post.inputs),
            added_arrays: diff_map_owned(&pre.arrays, &post.arrays, |v| *v),
            added_strides: diff_map_owned(&pre.strides, &post.strides, |v| v.clone()),
            added_component_arrays: diff_set(&pre.component_arrays, &post.component_arrays),
            added_known_constants: diff_map_owned(
                &pre.known_constants,
                &post.known_constants,
                |v| *v,
            )
            .into_iter()
            .filter(|(name, _)| name != loop_var)
            .collect(),
            added_known_array_values: diff_map_owned(
                &pre.known_array_values,
                &post.known_array_values,
                |v| v.clone(),
            ),
        }
    }

    /// Re-apply the footprint to `env`, substituting the loop-var
    /// placeholder `$LV{token}$` for `value`'s decimal form in every
    /// name. Values are copied verbatim — see the value-dependent
    /// caveat in the type doc.
    ///
    /// Insertions that collide with an existing entry are no-ops on
    /// sets and overwrite on maps (the latter shouldn't happen since
    /// we only capture additions, but the [`HashMap::insert`]
    /// semantics are predictable).
    pub fn apply_substituted(&self, env: &mut LoweringEnv, token: u32, value: u64) {
        let placeholder = loop_var_placeholder(token);
        let value_str = value.to_string();
        let subst = |name: &str| -> String {
            if name.contains(&placeholder) {
                name.replace(&placeholder, &value_str)
            } else {
                name.to_string()
            }
        };

        for name in &self.added_locals {
            env.locals.insert(subst(name));
        }
        for name in &self.added_inputs {
            env.inputs.insert(subst(name));
        }
        for (name, len) in &self.added_arrays {
            env.arrays.insert(subst(name), *len);
        }
        for (name, strides) in &self.added_strides {
            env.strides.insert(subst(name), strides.clone());
        }
        for name in &self.added_component_arrays {
            env.component_arrays.insert(subst(name));
        }
        for (name, fc) in &self.added_known_constants {
            env.known_constants.insert(subst(name), *fc);
        }
        for (name, val) in &self.added_known_array_values {
            env.known_array_values.insert(subst(name), val.clone());
        }
    }

    /// Total number of entries this footprint will insert. Useful
    /// for shape statistics and asserts.
    pub fn total_entries(&self) -> usize {
        self.added_locals.len()
            + self.added_inputs.len()
            + self.added_arrays.len()
            + self.added_strides.len()
            + self.added_component_arrays.len()
            + self.added_known_constants.len()
            + self.added_known_array_values.len()
    }

    /// `true` iff no entries were added.
    pub fn is_empty(&self) -> bool {
        self.total_entries() == 0
    }
}

fn diff_set(pre: &HashSet<String>, post: &HashSet<String>) -> Vec<String> {
    post.iter().filter(|n| !pre.contains(*n)).cloned().collect()
}

fn diff_map_owned<V, W, F>(
    pre: &HashMap<String, V>,
    post: &HashMap<String, V>,
    copy: F,
) -> Vec<(String, W)>
where
    F: Fn(&V) -> W,
{
    post.iter()
        .filter(|(k, _)| !pre.contains_key(k.as_str()))
        .map(|(k, v)| (k.clone(), copy(v)))
        .collect()
}
