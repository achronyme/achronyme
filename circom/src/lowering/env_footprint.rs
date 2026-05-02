//! Capture and replay [`LoweringEnv`] mutations across memoized
//! iterations.
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
//! matches what a hand-unrolled lowering would have produced.
//!
//! This module is the replay primitive plus tests; the integration
//! into `lower_for_loop` happens upstream in `loops.rs`.

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
/// `Const(5)` — wrong. The lowering integration is responsible for
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

#[cfg(test)]
mod tests {
    use super::*;

    fn fc(v: u64) -> FieldConst {
        FieldConst::from_u64(v)
    }

    #[test]
    fn empty_diff_is_empty_footprint() {
        let pre = LoweringEnv::new();
        let post = LoweringEnv::new();
        let fp = EnvFootprint::from_diff(&pre, &post, "i");
        assert!(fp.is_empty());
        assert_eq!(fp.total_entries(), 0);
    }

    #[test]
    fn locals_added_show_up_in_footprint() {
        let pre = LoweringEnv::new();
        let mut post = LoweringEnv::new();
        post.locals.insert("t1_$LV0$".into());
        post.locals.insert("t2_$LV0$".into());
        let fp = EnvFootprint::from_diff(&pre, &post, "i");
        assert_eq!(fp.added_locals.len(), 2);
        assert!(fp.added_locals.contains(&"t1_$LV0$".to_string()));
        assert!(fp.added_locals.contains(&"t2_$LV0$".to_string()));
    }

    #[test]
    fn loop_var_known_constant_is_filtered() {
        // The unroller writes `i = Const(0)` into known_constants at
        // iter start. The footprint must NOT include this entry —
        // otherwise replay would clobber the unroller's iter-N value.
        let pre = LoweringEnv::new();
        let mut post = LoweringEnv::new();
        post.known_constants.insert("i".into(), fc(0));
        post.known_constants.insert("k_$LV0$".into(), fc(99));
        let fp = EnvFootprint::from_diff(&pre, &post, "i");
        assert_eq!(fp.added_known_constants.len(), 1);
        assert_eq!(fp.added_known_constants[0].0, "k_$LV0$");
    }

    #[test]
    fn pre_existing_entries_are_not_in_diff() {
        let mut pre = LoweringEnv::new();
        pre.locals.insert("outer_local".into());
        pre.captures.insert("n".into());
        let mut post = pre.clone();
        post.locals.insert("loop_local_$LV0$".into());
        let fp = EnvFootprint::from_diff(&pre, &post, "i");
        assert_eq!(fp.added_locals, vec!["loop_local_$LV0$".to_string()]);
    }

    #[test]
    fn apply_substitutes_placeholder_in_names() {
        let pre = LoweringEnv::new();
        let mut post_iter0 = LoweringEnv::new();
        post_iter0.locals.insert("t1_$LV0$".into());
        post_iter0.arrays.insert("buf_$LV0$".into(), 4);
        let fp = EnvFootprint::from_diff(&pre, &post_iter0, "i");

        let mut env_iter5 = LoweringEnv::new();
        fp.apply_substituted(&mut env_iter5, 0, 5);

        assert!(env_iter5.locals.contains("t1_5"));
        assert_eq!(env_iter5.arrays.get("buf_5"), Some(&4));
    }

    #[test]
    fn apply_preserves_names_without_placeholder() {
        let pre = LoweringEnv::new();
        let mut post = LoweringEnv::new();
        post.locals.insert("static_local".into());
        let fp = EnvFootprint::from_diff(&pre, &post, "i");

        let mut env = LoweringEnv::new();
        fp.apply_substituted(&mut env, 0, 42);
        assert!(env.locals.contains("static_local"));
    }

    #[test]
    fn apply_replays_all_field_kinds() {
        let pre = LoweringEnv::new();
        let mut post = LoweringEnv::new();
        post.locals.insert("L_$LV0$".into());
        post.inputs.insert("I_$LV0$".into());
        post.arrays.insert("A_$LV0$".into(), 8);
        post.strides.insert("S_$LV0$".into(), vec![2, 4]);
        post.component_arrays.insert("C_$LV0$".into());
        post.known_constants.insert("K_$LV0$".into(), fc(7));
        post.known_array_values.insert(
            "V_$LV0$".into(),
            EvalValue::Scalar(super::super::utils::BigVal::from_u64(13)),
        );
        let fp = EnvFootprint::from_diff(&pre, &post, "i");

        // Sanity: every kind contributed one entry.
        assert_eq!(fp.added_locals.len(), 1);
        assert_eq!(fp.added_inputs.len(), 1);
        assert_eq!(fp.added_arrays.len(), 1);
        assert_eq!(fp.added_strides.len(), 1);
        assert_eq!(fp.added_component_arrays.len(), 1);
        assert_eq!(fp.added_known_constants.len(), 1);
        assert_eq!(fp.added_known_array_values.len(), 1);
        assert_eq!(fp.total_entries(), 7);

        let mut env = LoweringEnv::new();
        fp.apply_substituted(&mut env, 0, 9);

        assert!(env.locals.contains("L_9"));
        assert!(env.inputs.contains("I_9"));
        assert_eq!(env.arrays.get("A_9"), Some(&8));
        assert_eq!(env.strides.get("S_9"), Some(&vec![2, 4]));
        assert!(env.component_arrays.contains("C_9"));
        assert_eq!(env.known_constants.get("K_9"), Some(&fc(7)));
        // EvalValue equality isn't derived; check the scalar form.
        let kav = env.known_array_values.get("V_9").expect("V_9 missing");
        assert_eq!(kav.as_scalar().and_then(|b| b.to_u64()), Some(13));
    }

    #[test]
    fn replay_round_trip_matches_baseline_for_synthetic_iter() {
        // Setup: a pre-iter env with some shared scope.
        // Iter 0 (with placeholder) adds names embedding `$LV0$`.
        // Iter N would have added the same names with `$LVN$` substituted to N's value.
        // After applying the iter-0 footprint with token=0, value=5,
        // the resulting env should match what an iter-5 lowering
        // would have produced from the same pre-state.
        let mut shared = LoweringEnv::new();
        shared.locals.insert("preexisting".into());

        // Iter 0 emission (placeholder).
        let mut iter0_post = shared.clone();
        iter0_post.locals.insert("t1_$LV0$".into());
        iter0_post.locals.insert("t2_$LV0$".into());
        iter0_post.known_constants.insert("loop_var".into(), fc(0));

        // Iter 5 emission baseline (no placeholder, real iter value).
        let mut iter5_baseline = shared.clone();
        iter5_baseline.locals.insert("t1_5".into());
        iter5_baseline.locals.insert("t2_5".into());
        iter5_baseline
            .known_constants
            .insert("loop_var".into(), fc(5));

        // Build footprint from iter 0 and replay onto a fresh shared env.
        let fp = EnvFootprint::from_diff(&shared, &iter0_post, "loop_var");
        let mut replayed = shared.clone();
        // Unroller writes the loop var separately:
        replayed.known_constants.insert("loop_var".into(), fc(5));
        fp.apply_substituted(&mut replayed, 0, 5);

        // Compare locals (the part the footprint owns).
        assert_eq!(replayed.locals, iter5_baseline.locals);
        assert_eq!(replayed.known_constants, iter5_baseline.known_constants);
    }
}
