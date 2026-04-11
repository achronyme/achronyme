//! Extract library-level metadata from a parsed Circom `TemplateDef`.
//!
//! This walks the top-level signal declarations of a template body and
//! builds a [`CircomTemplateEntry`] whose array dimensions are either
//! resolved constants, known parameter references, or preserved raw
//! expressions (to be evaluated later at instantiation time).

use std::collections::HashMap;

use ir::prove_ir::types::FieldConst;

use crate::ast;
use crate::lowering::utils::{const_eval_u64, const_eval_with_params};

use super::types::{CircomTemplateEntry, DimensionExpr, SignalSig};

/// Return a copy of `entry` where every dimension that can be resolved
/// against `known_params` is folded to [`DimensionExpr::Const`].
///
/// This is the cheap, O(signals × dims) path used at each call site
/// (instantiation or witness evaluation) — it reuses the pre-built
/// library entry and avoids re-walking the template body's AST.
pub fn resolve_entry(
    entry: &CircomTemplateEntry,
    known_params: &HashMap<String, FieldConst>,
) -> CircomTemplateEntry {
    CircomTemplateEntry {
        name: entry.name.clone(),
        params: entry.params.clone(),
        inputs: entry
            .inputs
            .iter()
            .map(|s| resolve_signal(s, known_params))
            .collect(),
        outputs: entry
            .outputs
            .iter()
            .map(|s| resolve_signal(s, known_params))
            .collect(),
    }
}

fn resolve_signal(sig: &SignalSig, known_params: &HashMap<String, FieldConst>) -> SignalSig {
    SignalSig {
        name: sig.name.clone(),
        dimensions: sig
            .dimensions
            .iter()
            .map(|d| resolve_existing_dimension(d, known_params))
            .collect(),
    }
}

fn resolve_existing_dimension(
    dim: &DimensionExpr,
    known_params: &HashMap<String, FieldConst>,
) -> DimensionExpr {
    match dim {
        DimensionExpr::Const(n) => DimensionExpr::Const(*n),
        DimensionExpr::Param(name) => match known_params.get(name).and_then(|fc| fc.to_u64()) {
            Some(n) => DimensionExpr::Const(n),
            None => DimensionExpr::Param(name.clone()),
        },
        DimensionExpr::Expr(expr) => {
            if let Some(n) = const_eval_with_params(expr, known_params).and_then(|fc| fc.to_u64()) {
                DimensionExpr::Const(n)
            } else {
                DimensionExpr::Expr(expr.clone())
            }
        }
    }
}

/// Extract library-level metadata (params, input/output signatures)
/// from a parsed [`ast::TemplateDef`].
///
/// `known_params` may contain values for some template parameters
/// already resolved by the caller (e.g. when the parent component
/// passes concrete captures down). Any parameter referenced in a signal
/// dimension that is present in `known_params` is folded into a
/// [`DimensionExpr::Const`]; simple parameter references not yet
/// resolved become [`DimensionExpr::Param`], and anything more complex
/// is kept as [`DimensionExpr::Expr`] for later resolution at
/// instantiation time.
///
/// This only walks top-level statements of the template body — nested
/// `if` / `for` blocks are not descended into, because Circom requires
/// `signal input` and `signal output` declarations at the top level of
/// a template.
pub fn extract_template_metadata(
    template: &ast::TemplateDef,
    known_params: &HashMap<String, FieldConst>,
) -> CircomTemplateEntry {
    let mut inputs = Vec::new();
    let mut outputs = Vec::new();

    for stmt in &template.body.stmts {
        if let ast::Stmt::SignalDecl {
            signal_type,
            declarations,
            ..
        } = stmt
        {
            let bucket = match signal_type {
                ast::SignalType::Input => Some(&mut inputs),
                ast::SignalType::Output => Some(&mut outputs),
                ast::SignalType::Intermediate => None,
            };
            let Some(bucket) = bucket else { continue };
            for decl in declarations {
                bucket.push(SignalSig {
                    name: decl.name.clone(),
                    dimensions: decl
                        .dimensions
                        .iter()
                        .map(|d| resolve_dimension(d, &template.params, known_params))
                        .collect(),
                });
            }
        }
    }

    CircomTemplateEntry {
        name: template.name.clone(),
        params: template.params.clone(),
        inputs,
        outputs,
    }
}

fn resolve_dimension(
    expr: &ast::Expr,
    template_params: &[String],
    known_params: &HashMap<String, FieldConst>,
) -> DimensionExpr {
    // 1. Literal compile-time constant.
    if let Some(n) = const_eval_u64(expr) {
        return DimensionExpr::Const(n);
    }
    // 2. Resolvable against already-known params.
    if !known_params.is_empty() {
        if let Some(n) = const_eval_with_params(expr, known_params).and_then(|fc| fc.to_u64()) {
            return DimensionExpr::Const(n);
        }
    }
    // 3. Simple reference to an as-yet unresolved template parameter.
    if let ast::Expr::Ident { name, .. } = expr {
        if template_params.iter().any(|p| p == name) {
            return DimensionExpr::Param(name.clone());
        }
    }
    // 4. Fallback: preserve the raw expression.
    DimensionExpr::Expr(Box::new(expr.clone()))
}

#[cfg(test)]
mod tests {
    use super::super::test_support::parse_template;
    use super::*;

    #[test]
    fn extract_metadata_scalar_signals() {
        let t = parse_template(
            r#"
            template Pair() {
                signal input a;
                signal input b;
                signal output c;
                c <== a + b;
            }
            "#,
            "Pair",
        );
        let meta = extract_template_metadata(&t, &HashMap::new());
        assert_eq!(meta.name, "Pair");
        assert!(meta.params.is_empty());
        assert_eq!(meta.inputs.len(), 2);
        assert!(meta.inputs[0].is_scalar());
        assert_eq!(meta.inputs[0].name, "a");
        assert_eq!(meta.inputs[1].name, "b");
        assert_eq!(meta.outputs.len(), 1);
        assert_eq!(meta.outputs[0].name, "c");
        assert!(meta.outputs[0].is_scalar());
    }

    #[test]
    fn extract_metadata_parametric_output() {
        let t = parse_template(
            r#"
            template Num2Bits(n) {
                signal input in;
                signal output out[n];
            }
            "#,
            "Num2Bits",
        );
        let meta = extract_template_metadata(&t, &HashMap::new());
        assert_eq!(meta.params, vec!["n".to_string()]);
        assert_eq!(meta.outputs.len(), 1);
        let out = &meta.outputs[0];
        assert_eq!(out.dimensions.len(), 1);
        match &out.dimensions[0] {
            DimensionExpr::Param(p) => assert_eq!(p, "n"),
            other => panic!("expected Param, got {other:?}"),
        }
    }

    #[test]
    fn extract_metadata_known_params_folded_to_const() {
        let t = parse_template(
            r#"
            template T(n) {
                signal input in[n];
                signal output out[n];
            }
            "#,
            "T",
        );
        let mut known = HashMap::new();
        known.insert("n".to_string(), FieldConst::from_u64(8));
        let meta = extract_template_metadata(&t, &known);
        assert!(matches!(
            meta.inputs[0].dimensions[0],
            DimensionExpr::Const(8)
        ));
        assert!(matches!(
            meta.outputs[0].dimensions[0],
            DimensionExpr::Const(8)
        ));
    }

    #[test]
    fn extract_metadata_literal_array_dim_is_const() {
        let t = parse_template(
            r#"
            template Hasher() {
                signal input msg[16];
                signal output hash;
            }
            "#,
            "Hasher",
        );
        let meta = extract_template_metadata(&t, &HashMap::new());
        assert!(matches!(
            meta.inputs[0].dimensions[0],
            DimensionExpr::Const(16)
        ));
    }

    #[test]
    fn extract_metadata_computed_expr_dim_preserved() {
        let t = parse_template(
            r#"
            template T(n) {
                signal input in[n + 1];
                signal output out;
            }
            "#,
            "T",
        );
        // With no known params, `n + 1` can't fold and isn't a plain Ident,
        // so we expect the raw Expr variant.
        let meta = extract_template_metadata(&t, &HashMap::new());
        assert!(matches!(
            meta.inputs[0].dimensions[0],
            DimensionExpr::Expr(_)
        ));
        // With a known param, it should fold to a const.
        let mut known = HashMap::new();
        known.insert("n".to_string(), FieldConst::from_u64(4));
        let meta = extract_template_metadata(&t, &known);
        assert!(matches!(
            meta.inputs[0].dimensions[0],
            DimensionExpr::Const(5)
        ));
    }

    #[test]
    fn resolve_entry_folds_param_dims_to_const() {
        let t = parse_template(
            r#"
            template T(n) {
                signal input in[n];
                signal output out[n + 1];
            }
            "#,
            "T",
        );
        // Library-time extraction leaves dims symbolic.
        let raw = extract_template_metadata(&t, &HashMap::new());
        assert!(matches!(
            raw.inputs[0].dimensions[0],
            DimensionExpr::Param(_)
        ));
        assert!(matches!(
            raw.outputs[0].dimensions[0],
            DimensionExpr::Expr(_)
        ));

        // Call-site resolution folds both.
        let mut known = HashMap::new();
        known.insert("n".to_string(), FieldConst::from_u64(4));
        let resolved = resolve_entry(&raw, &known);
        assert!(matches!(
            resolved.inputs[0].dimensions[0],
            DimensionExpr::Const(4)
        ));
        assert!(matches!(
            resolved.outputs[0].dimensions[0],
            DimensionExpr::Const(5)
        ));

        // The original entry is unchanged (resolve returns a copy).
        assert!(matches!(
            raw.inputs[0].dimensions[0],
            DimensionExpr::Param(_)
        ));
    }

    #[test]
    fn resolve_entry_without_params_is_identity_for_const_dims() {
        let t = parse_template(
            r#"
            template T() {
                signal input msg[16];
                signal output hash;
            }
            "#,
            "T",
        );
        let raw = extract_template_metadata(&t, &HashMap::new());
        let resolved = resolve_entry(&raw, &HashMap::new());
        assert!(matches!(
            resolved.inputs[0].dimensions[0],
            DimensionExpr::Const(16)
        ));
        assert!(resolved.outputs[0].is_scalar());
    }

    #[test]
    fn extract_metadata_intermediate_signal_skipped() {
        let t = parse_template(
            r#"
            template T() {
                signal input a;
                signal tmp;
                signal output c;
                tmp <== a * a;
                c <== tmp + 1;
            }
            "#,
            "T",
        );
        let meta = extract_template_metadata(&t, &HashMap::new());
        assert_eq!(meta.inputs.len(), 1);
        assert_eq!(meta.outputs.len(), 1);
    }
}
