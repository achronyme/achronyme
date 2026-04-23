//! Single source of truth for compile-time variables visible during
//! lowering.
//!
//! Pre-refactor, three maps were kept in manual sync inside
//! `statements/loops.rs`:
//!
//!   - `env.known_constants: HashMap<String, FieldConst>`
//!   - `ctx.param_values:    HashMap<String, FieldConst>`
//!   - `eval_vars:           HashMap<String, BigVal>` (function-local)
//!
//! That triple bookkeeping has produced real bugs — the MiMCSponge
//! loop-var pollution (2026-04-11) was a case where the write-back
//! path failed to skip the loop variable, and the deep-inlining
//! negative-index regression (2026-04-04) was caused by a `BigVal`
//! being mirrored into `known_constants` as a `FieldConst` and
//! losing its sign.
//!
//! `CompileTimeEnv` replaces the triple: values are canonically stored
//! as `BigVal` (256-bit two's complement) and projected down to
//! `FieldConst` on demand. This preserves the sign bit across read/
//! write cycles and collapses the three maps into one.

use std::collections::HashMap;

use ir_forge::types::FieldConst;

use super::utils::BigVal;

/// A merged view over the compile-time variables available during a
/// loop unroll. `BigVal` is the canonical form; `FieldConst` is a
/// derived projection.
pub(super) struct CompileTimeEnv {
    vars: HashMap<String, BigVal>,
}

impl CompileTimeEnv {
    pub(super) fn new() -> Self {
        Self {
            vars: HashMap::new(),
        }
    }

    /// Seed from two external maps merged into a single view. The
    /// second map (`known`) wins on key collision — matches the
    /// existing `eval_vars` seeding order in `loops.rs` where
    /// `env.known_constants` is inserted after `ctx.param_values`.
    pub(super) fn from_constants(
        params: &HashMap<String, FieldConst>,
        known: &HashMap<String, FieldConst>,
    ) -> Self {
        let mut env = Self::new();
        for (k, v) in params {
            env.vars.insert(k.clone(), BigVal::from_field_const(*v));
        }
        for (k, v) in known {
            env.vars.insert(k.clone(), BigVal::from_field_const(*v));
        }
        env
    }

    pub(super) fn insert(&mut self, name: impl Into<String>, value: BigVal) {
        self.vars.insert(name.into(), value);
    }

    pub(super) fn remove(&mut self, name: &str) -> Option<BigVal> {
        self.vars.remove(name)
    }

    pub(super) fn get(&self, name: &str) -> Option<&BigVal> {
        self.vars.get(name)
    }

    pub(super) fn contains(&self, name: &str) -> bool {
        self.vars.contains_key(name)
    }

    /// Iterate all `(name, FieldConst)` pairs for vars that round-trip
    /// through `FieldConst` losslessly. Negative `BigVal`s are skipped
    /// because `FieldConst` has no sign bit — writing a negative
    /// compile-time var into `env.known_constants` and reading it back
    /// would flip it to a huge positive field element. See the
    /// `negative_bigval_roundtrip_preserves_sign` test.
    pub(super) fn field_const_iter(&self) -> impl Iterator<Item = (&String, FieldConst)> + '_ {
        self.vars.iter().filter_map(|(k, v)| {
            if v.is_negative() {
                None
            } else {
                Some((k, v.to_field_const()))
            }
        })
    }

    /// Names of all tracked variables. Used by the loop unroll cleanup
    /// path to purge compile-time keys from `env.known_constants` so
    /// they don't leak past the loop scope.
    pub(super) fn var_names(&self) -> impl Iterator<Item = &String> + '_ {
        self.vars.keys()
    }

    /// Mutable access to the underlying `BigVal` map. Needed because
    /// `try_eval_stmt_in_place` expects `&mut HashMap<String, BigVal>`
    /// directly.
    pub(super) fn as_bigval_map_mut(&mut self) -> &mut HashMap<String, BigVal> {
        &mut self.vars
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_env_is_empty() {
        let env = CompileTimeEnv::new();
        assert_eq!(env.field_const_iter().count(), 0);
    }

    #[test]
    fn insert_and_get() {
        let mut env = CompileTimeEnv::new();
        env.insert("x", BigVal::from_u64(42));
        assert_eq!(env.get("x"), Some(&BigVal::from_u64(42)));
        assert_eq!(env.get("y"), None);
        assert!(env.contains("x"));
        assert!(!env.contains("y"));
    }

    #[test]
    fn remove_returns_old_value() {
        let mut env = CompileTimeEnv::new();
        env.insert("x", BigVal::from_u64(7));
        assert_eq!(env.remove("x"), Some(BigVal::from_u64(7)));
        assert_eq!(env.remove("x"), None);
    }

    #[test]
    fn field_const_iter_skips_negatives() {
        let mut env = CompileTimeEnv::new();
        env.insert("pos", BigVal::from_i64(3));
        env.insert("neg", BigVal::from_i64(-3));
        let names: Vec<&String> = env.field_const_iter().map(|(k, _)| k).collect();
        assert_eq!(names.len(), 1);
        assert_eq!(names[0], "pos");
    }

    #[test]
    fn from_constants_last_write_wins() {
        // params has x=5; known has x=7. The loops.rs seeding inserts
        // params first, then known (with `insert`, not `or_insert`),
        // so known wins. `from_constants` preserves that order.
        let mut params = HashMap::new();
        params.insert("x".to_string(), FieldConst::from_u64(5));
        let mut known = HashMap::new();
        known.insert("x".to_string(), FieldConst::from_u64(7));
        let env = CompileTimeEnv::from_constants(&params, &known);
        assert_eq!(env.get("x"), Some(&BigVal::from_u64(7)));
    }

    #[test]
    fn from_constants_disjoint_merge() {
        let mut params = HashMap::new();
        params.insert("a".to_string(), FieldConst::from_u64(1));
        let mut known = HashMap::new();
        known.insert("b".to_string(), FieldConst::from_u64(2));
        let env = CompileTimeEnv::from_constants(&params, &known);
        assert_eq!(env.get("a"), Some(&BigVal::from_u64(1)));
        assert_eq!(env.get("b"), Some(&BigVal::from_u64(2)));
    }

    #[test]
    fn negative_bigval_roundtrip_preserves_sign() {
        let mut env = CompileTimeEnv::new();
        env.insert("neg", BigVal::from_i64(-3));
        // Via get(): the signed BigVal is preserved.
        let v = env.get("neg").copied().expect("var present");
        assert!(v.is_negative());
        assert_eq!(v.to_i64(), Some(-3));
        // Via field_const_iter(): the negative is filtered out because
        // FieldConst has no sign bit.
        assert!(env.field_const_iter().next().is_none());
    }

    #[test]
    fn as_bigval_map_mut_exposes_underlying_map() {
        let mut env = CompileTimeEnv::new();
        env.insert("x", BigVal::from_u64(1));
        env.as_bigval_map_mut()
            .insert("y".to_string(), BigVal::from_u64(2));
        assert_eq!(env.get("y"), Some(&BigVal::from_u64(2)));
        // Length grew from 1 to 2.
        assert_eq!(env.as_bigval_map_mut().len(), 2);
    }

    #[test]
    fn var_names_lists_all() {
        let mut env = CompileTimeEnv::new();
        env.insert("a", BigVal::from_u64(1));
        env.insert("b", BigVal::from_u64(2));
        let mut names: Vec<String> = env.var_names().cloned().collect();
        names.sort();
        assert_eq!(names, vec!["a".to_string(), "b".to_string()]);
    }
}
