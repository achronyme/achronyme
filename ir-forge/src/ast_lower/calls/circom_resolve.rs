//! Circom template lookup helpers.
//!
//! [`try_resolve_circom_key`](super::super::ProveIrCompiler::try_resolve_circom_key)
//! tries to resolve the inner callee of a `T(args)(inputs)` curry to
//! a key in `circom_table`, accepting the bare-name, `T::U`
//! `StaticAccess`, and `alias.template` `DotAccess` shapes used by
//! selective and namespaced circom imports.
//!
//! [`diagnose_unresolved_circom_curry`](super::super::ProveIrCompiler::diagnose_unresolved_circom_curry)
//! produces a clean "did you mean?" diagnostic when the inner callee
//! looks like it was meant to name a registered template but doesn't
//! resolve, so the user gets a typed error instead of a generic
//! function-dispatch failure.

use achronyme_parser::ast::*;
use memory::FieldBackend;

use super::super::helpers::to_span;
use super::super::ProveIrCompiler;
use crate::error::{CircomDispatchErrorKind, ProveIrError};

impl<F: FieldBackend> ProveIrCompiler<F> {
    /// When a `T(args)(inputs)` shape fails to resolve against the
    /// circom_table, try to produce a clean "did you mean?" diagnostic
    /// that points at the inner callee. Returns `Some(err)` only if
    /// the user appears to have *meant* a circom template — otherwise
    /// returns `None` so the caller falls through to the normal
    /// function dispatch.
    pub(super) fn diagnose_unresolved_circom_curry(
        &self,
        inner_callee: &Expr,
        span: &Span,
    ) -> Option<ProveIrError> {
        if self.circom_table.is_empty() {
            return None;
        }
        match inner_callee {
            // Bare `Template(args)(inputs)` with a misspelled name.
            Expr::Ident { name, .. } => {
                // Only produce a suggestion if we have at least one
                // selective (non-namespaced) entry — otherwise this
                // is almost certainly a regular function call typo.
                let flat_keys: Vec<&str> = self
                    .circom_table
                    .keys()
                    .filter(|k| !k.contains("::"))
                    .map(String::as_str)
                    .collect();
                if flat_keys.is_empty() {
                    return None;
                }
                let did_you_mean = crate::suggest::find_similar_ir(name, flat_keys.into_iter());
                // Only emit the diagnostic if we actually found a
                // similar registered name — otherwise the user's
                // call is probably a regular function call and we
                // shouldn't assume circom intent.
                did_you_mean.map(|suggestion| ProveIrError::CircomDispatch {
                    kind: CircomDispatchErrorKind::TemplateNotFoundSelective {
                        template: name.clone(),
                        did_you_mean: Some(suggestion),
                    },
                    span: to_span(span),
                })
            }
            // `P.Template(args)(inputs)` — namespace or template typo.
            Expr::DotAccess { object, field, .. } => {
                let Expr::Ident { name: alias, .. } = object.as_ref() else {
                    return None;
                };
                // Collect registered namespace prefixes (everything
                // before "::" in circom_table keys).
                let mut namespaces: std::collections::HashSet<String> =
                    std::collections::HashSet::new();
                for k in self.circom_table.keys() {
                    if let Some((ns, _)) = k.split_once("::") {
                        namespaces.insert(ns.to_string());
                    }
                }
                if !namespaces.contains(alias) {
                    // Alias itself is unknown — suggest a namespace.
                    let suggestion = crate::suggest::find_similar_ir(
                        alias,
                        namespaces.iter().map(String::as_str),
                    );
                    return Some(ProveIrError::CircomDispatch {
                        kind: CircomDispatchErrorKind::NamespaceNotFound {
                            alias: alias.clone(),
                            did_you_mean: suggestion,
                        },
                        span: to_span(span),
                    });
                }
                // Alias is valid; the template name is wrong.
                let expected_prefix = format!("{alias}::");
                let templates_in_ns: Vec<String> = self
                    .circom_table
                    .keys()
                    .filter_map(|k| k.strip_prefix(&expected_prefix).map(String::from))
                    .collect();
                let suggestion = crate::suggest::find_similar_ir(
                    field,
                    templates_in_ns.iter().map(String::as_str),
                );
                Some(ProveIrError::CircomDispatch {
                    kind: CircomDispatchErrorKind::TemplateNotFoundInNamespace {
                        alias: alias.clone(),
                        template: field.clone(),
                        did_you_mean: suggestion,
                    },
                    span: to_span(span),
                })
            }
            _ => None,
        }
    }

    /// Try to resolve an expression used as the inner callee of a
    /// `T(...)(...)` atomic curry to a key in `circom_table`.
    ///
    /// Returns `Some(key)` when the expression is either:
    /// - `Expr::Ident { name }` and `name` is a registered selective
    ///   import (bare template name key), or
    /// - `Expr::DotAccess { object: Ident(P), field: T }` and
    ///   `"P::T"` is registered as a namespace entry (Phase 3.4).
    ///
    /// Returns `None` for every other shape so the caller falls
    /// through to the normal call dispatch without regression.
    pub(super) fn try_resolve_circom_key(&self, callee: &Expr) -> Option<String> {
        match callee {
            Expr::Ident { name, .. } => {
                if self.circom_table.contains_key(name) {
                    Some(name.clone())
                } else {
                    None
                }
            }
            // Namespaced circom template via the compile-time `::` path:
            // `P::Poseidon(2)([a, b])` parses as
            //   Call { Call { StaticAccess { P, Poseidon }, [2] }, [arr] }
            // so the inner callee is a `StaticAccess` whose `type_name`
            // is the import alias. Match the same `{alias}::{template}`
            // key format the circom dispatch table uses for namespace
            // imports.
            Expr::StaticAccess {
                type_name, member, ..
            } => {
                let key = format!("{type_name}::{member}");
                if self.circom_table.contains_key(&key) {
                    Some(key)
                } else {
                    None
                }
            }
            Expr::DotAccess { object, field, .. } => {
                if let Expr::Ident { name: alias, .. } = object.as_ref() {
                    let key = format!("{alias}::{field}");
                    if self.circom_table.contains_key(&key) {
                        return Some(key);
                    }
                }
                None
            }
            _ => None,
        }
    }
}
