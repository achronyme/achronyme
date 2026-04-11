//! Instantiate a Circom template into a parent circuit body.
//!
//! This is the Achronyme-side entry point that wraps the existing
//! component-inlining pipeline with a clear, library-flavoured API.

use std::collections::HashMap;

use diagnostics::Span;
use ir::prove_ir::types::{CircuitExpr, CircuitNode, FieldConst};

use crate::lowering::components::inline_component_body_with_const_inputs;
use crate::lowering::context::LoweringContext;

use super::error::{check_param_count, find_template, LibraryError};
use super::metadata::resolve_entry;
use super::types::{CircomLibrary, DimensionExpr};

/// A single declared output of an instantiated template.
#[derive(Clone, Debug)]
pub enum TemplateOutput {
    /// Scalar signal output — single `CircuitExpr::Var` pointing at
    /// the mangled name in the parent's scope.
    Scalar(CircuitExpr),
    /// Array signal output — row-major flattening of all elements.
    ///
    /// `dims` holds the resolved shape (e.g. `[n]` for `out[n]`),
    /// `values` contains `dims.iter().product()` expressions in the
    /// same order the witness evaluator uses (`name_i`, `name_i_j`,
    /// etc.).
    Array {
        dims: Vec<u64>,
        values: Vec<CircuitExpr>,
    },
}

/// Result of inlining a Circom template into a parent circuit body.
#[derive(Clone, Debug)]
pub struct TemplateInstantiation {
    /// The circuit nodes to append to the parent body, in order.
    ///
    /// Contains the Let bindings that wire signal inputs to the
    /// sub-template's mangled signal names, followed by the mangled
    /// template body itself.
    pub body: Vec<CircuitNode>,
    /// One entry per declared signal output of the template, keyed
    /// by the original output name. Scalars and arrays are
    /// distinguished by the [`TemplateOutput`] variant, so callers
    /// never have to special-case `out` vs `out_0` lookup.
    pub outputs: HashMap<String, TemplateOutput>,
}

/// Reason an instantiation was rejected.
///
/// Shared low-level failures (unknown template, wrong param count,
/// unresolved output dimension) live in [`LibraryError`] and are
/// composed in via the [`InstantiationError::Library`] variant.
/// Instantiation-specific failures get their own variants below.
#[derive(Clone, Debug)]
pub enum InstantiationError {
    /// Shared library-level failure (unknown template, param count
    /// mismatch, unresolved output dimension).
    Library(LibraryError),
    /// An input signal was not wired by the caller.
    MissingSignalInput { template: String, signal: String },
    /// The template declares an array-valued input signal, which is
    /// not yet supported by `instantiate_template_into`. Dedicated
    /// variant so callers can special-case this rather than parsing
    /// the `Lowering(String)` message.
    UnsupportedArrayInput { template: String, signal: String },
    /// The underlying lowering step failed.
    Lowering(String),
}

impl std::fmt::Display for InstantiationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Library(e) => write!(f, "{e}"),
            Self::MissingSignalInput { template, signal } => write!(
                f,
                "template `{template}` requires signal input `{signal}` which was not provided"
            ),
            Self::UnsupportedArrayInput { template, signal } => write!(
                f,
                "template `{template}` declares array-valued signal input `{signal}` \
                 which is not yet supported by library-mode instantiation"
            ),
            Self::Lowering(msg) => write!(f, "lowering failed: {msg}"),
        }
    }
}

impl std::error::Error for InstantiationError {}

impl From<LibraryError> for InstantiationError {
    fn from(e: LibraryError) -> Self {
        Self::Library(e)
    }
}

/// Instantiate a Circom template into a parent circuit body.
///
/// Lowering happens on demand against the library's own AST.
/// `template_args` bind template parameters in declaration order;
/// `signal_inputs` wires each declared input signal to an expression
/// from the caller's scope (typically a `CircuitExpr::Var` referencing
/// an `.ach`-side binding, or a `CircuitExpr::Const` for
/// compile-time-known values, which are propagated through the
/// sub-template for O1/O2-friendly constraint generation).
///
/// Name mangling: all signals and locals inside the inlined body are
/// prefixed with `parent_prefix` + `_`. The returned
/// [`TemplateInstantiation::outputs`] map uses those mangled names so
/// callers can emit `result.out` access.
pub fn instantiate_template_into(
    library: &CircomLibrary,
    template_name: &str,
    template_args: &[FieldConst],
    signal_inputs: &HashMap<String, CircuitExpr>,
    parent_prefix: &str,
    span: &Span,
) -> Result<TemplateInstantiation, InstantiationError> {
    // 1. Locate the template and validate argument count — both shared
    //    with the witness-eval path via `error::LibraryError`.
    let template = find_template(library, template_name)?;
    check_param_count(template, template_args.len())?;

    // 2. Resolve the library's cached entry against the concrete
    //    captures so output dimensions become Const. This is O(signals
    //    × dims) and avoids re-walking the template body's AST.
    let mut known_params = HashMap::new();
    for (name, fc) in template.params.iter().zip(template_args.iter()) {
        known_params.insert(name.clone(), *fc);
    }
    let cached = library
        .template(template_name)
        .expect("find_template succeeded, cached entry must exist");
    let entry = resolve_entry(cached, &known_params);

    // 3. Wire signal inputs: emit a Let binding per input, splitting
    //    compile-time constants into `const_inputs` for propagation.
    let mut body = Vec::new();
    let mut const_inputs: HashMap<String, FieldConst> = HashMap::new();

    for input in &entry.inputs {
        if !input.is_scalar() {
            // TODO: support array-valued inputs by expanding to one Let
            // per element. For now array inputs get their own dedicated
            // error variant so callers can pattern-match cleanly rather
            // than grepping a string out of `Lowering`.
            return Err(InstantiationError::UnsupportedArrayInput {
                template: template_name.to_string(),
                signal: input.name.clone(),
            });
        }
        let expr = signal_inputs.get(&input.name).ok_or_else(|| {
            InstantiationError::MissingSignalInput {
                template: template_name.to_string(),
                signal: input.name.clone(),
            }
        })?;

        // Propagate compile-time-known inputs into the sub-template so
        // the lowerer emits `Const` instead of `Input` for them. We do
        // NOT emit a Let binding for Const inputs at all — it would be
        // dead code (the body never reads the mangled name because
        // const_inputs short-circuits in inline_component_body_with_const_inputs).
        if let CircuitExpr::Const(fc) = expr {
            const_inputs.insert(input.name.clone(), *fc);
            continue;
        }

        let mangled = format!("{parent_prefix}_{}", input.name);
        body.push(CircuitNode::Let {
            name: mangled,
            value: expr.clone(),
            span: None,
        });
    }

    // 4. Build a fresh LoweringContext bound to the library's program and
    //    inline the template body.
    let mut ctx = LoweringContext::from_program(&library.program);
    let template_arg_exprs: Vec<CircuitExpr> = template_args
        .iter()
        .map(|fc| CircuitExpr::Const(*fc))
        .collect();

    let inlined = inline_component_body_with_const_inputs(
        parent_prefix,
        template,
        &template_arg_exprs,
        &HashMap::new(), // array_args: none for now
        &const_inputs,
        &mut ctx,
        span,
    )
    .map_err(|e| InstantiationError::Lowering(e.to_string()))?;

    body.extend(inlined);

    // 5. Build the outputs map keyed by original output name.
    //    Scalar outputs wrap a single Var; array outputs hold the
    //    resolved shape + one Var per element in row-major order.
    let mut outputs = HashMap::new();
    for out in &entry.outputs {
        if out.is_scalar() {
            outputs.insert(
                out.name.clone(),
                TemplateOutput::Scalar(CircuitExpr::Var(format!("{parent_prefix}_{}", out.name))),
            );
            continue;
        }
        let dims = resolve_output_dims(&out.dimensions).ok_or_else(|| {
            InstantiationError::Library(LibraryError::UnresolvedOutputDimension {
                template: template_name.to_string(),
                signal: out.name.clone(),
            })
        })?;
        let values = iter_multi_index(&dims)
            .into_iter()
            .map(|index| {
                let suffix = index
                    .iter()
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
                    .join("_");
                CircuitExpr::Var(format!("{parent_prefix}_{}_{}", out.name, suffix))
            })
            .collect();
        outputs.insert(out.name.clone(), TemplateOutput::Array { dims, values });
    }

    Ok(TemplateInstantiation { body, outputs })
}

pub(super) fn resolve_output_dims(dims: &[DimensionExpr]) -> Option<Vec<u64>> {
    let mut out = Vec::with_capacity(dims.len());
    for d in dims {
        match d {
            DimensionExpr::Const(n) => out.push(*n),
            _ => return None,
        }
    }
    Some(out)
}

pub(super) fn iter_multi_index(dims: &[u64]) -> Vec<Vec<u64>> {
    let mut result = vec![Vec::new()];
    for &d in dims {
        let mut next = Vec::with_capacity(result.len() * d as usize);
        for prefix in &result {
            for i in 0..d {
                let mut p = prefix.clone();
                p.push(i);
                next.push(p);
            }
        }
        result = next;
    }
    result
}

#[cfg(test)]
mod tests {
    use super::super::test_support::{dummy_span, make_library};
    use super::*;

    #[test]
    fn instantiate_unknown_template_errors() {
        let lib = make_library(
            r#"
            template Square() {
                signal input x;
                signal output y;
                y <== x * x;
            }
            "#,
        );
        let result =
            instantiate_template_into(&lib, "Cube", &[], &HashMap::new(), "c0", &dummy_span());
        assert!(matches!(
            result,
            Err(InstantiationError::Library(
                LibraryError::UnknownTemplate { .. }
            ))
        ));
    }

    #[test]
    fn instantiate_param_count_mismatch() {
        let lib = make_library(
            r#"
            template Num2Bits(n) {
                signal input in;
                signal output out[n];
            }
            "#,
        );
        let result =
            instantiate_template_into(&lib, "Num2Bits", &[], &HashMap::new(), "c0", &dummy_span());
        assert!(matches!(
            result,
            Err(InstantiationError::Library(
                LibraryError::ParamCountMismatch {
                    expected: 1,
                    got: 0,
                    ..
                }
            ))
        ));
    }

    #[test]
    fn instantiate_missing_signal_input() {
        let lib = make_library(
            r#"
            template Square() {
                signal input x;
                signal output y;
                y <== x * x;
            }
            "#,
        );
        let result =
            instantiate_template_into(&lib, "Square", &[], &HashMap::new(), "c0", &dummy_span());
        assert!(matches!(
            result,
            Err(InstantiationError::MissingSignalInput { .. })
        ));
    }

    #[test]
    fn instantiate_scalar_template_produces_body_and_output() {
        let lib = make_library(
            r#"
            template Square() {
                signal input x;
                signal output y;
                y <== x * x;
            }
            "#,
        );
        let mut inputs = HashMap::new();
        inputs.insert("x".to_string(), CircuitExpr::Var("ach_x".to_string()));

        let inst = instantiate_template_into(&lib, "Square", &[], &inputs, "c0", &dummy_span())
            .expect("instantiation should succeed");

        match &inst.body[0] {
            CircuitNode::Let { name, value, .. } => {
                assert_eq!(name, "c0_x");
                assert!(matches!(value, CircuitExpr::Var(v) if v == "ach_x"));
            }
            other => panic!("expected Let, got {other:?}"),
        }
        assert_eq!(inst.outputs.len(), 1);
        match inst.outputs.get("y").expect("y output") {
            TemplateOutput::Scalar(CircuitExpr::Var(v)) => assert_eq!(v, "c0_y"),
            other => panic!("expected Scalar Var(c0_y), got {other:?}"),
        }
        assert!(inst.body.len() >= 2);
    }

    #[test]
    fn instantiate_const_input_skips_trivial_let() {
        // When a signal input is a compile-time Const, the wiring Let
        // would be dead code: inline_component_body_with_const_inputs
        // injects the value into the sub-template's known_constants
        // and the mangled name is never referenced. Verify no Let
        // binding for the mangled input name is emitted.
        let lib = make_library(
            r#"
            template Square() {
                signal input x;
                signal output y;
                y <== x * x;
            }
            "#,
        );
        let mut inputs = HashMap::new();
        inputs.insert("x".to_string(), CircuitExpr::Const(FieldConst::from_u64(5)));
        let inst = instantiate_template_into(&lib, "Square", &[], &inputs, "k0", &dummy_span())
            .expect("instantiation should succeed");

        let has_mangled_input_let = inst.body.iter().any(|n| match n {
            CircuitNode::Let { name, .. } => name == "k0_x",
            _ => false,
        });
        assert!(
            !has_mangled_input_let,
            "Const inputs should not emit a wiring Let, body was: {:?}",
            inst.body
        );
        // The Scalar output must still be present.
        assert!(matches!(
            inst.outputs.get("y"),
            Some(TemplateOutput::Scalar(CircuitExpr::Var(_)))
        ));
    }

    #[test]
    fn instantiate_parametric_array_output() {
        let lib = make_library(
            r#"
            template Num2Bits(n) {
                signal input in;
                signal output out[n];
                var lc = 0;
                var e = 1;
                for (var i = 0; i < n; i++) {
                    out[i] <-- (in >> i) & 1;
                    out[i] * (out[i] - 1) === 0;
                    lc += out[i] * e;
                    e = e + e;
                }
                lc === in;
            }
            "#,
        );
        let mut inputs = HashMap::new();
        inputs.insert("in".to_string(), CircuitExpr::Var("x".to_string()));

        let inst = instantiate_template_into(
            &lib,
            "Num2Bits",
            &[FieldConst::from_u64(4)],
            &inputs,
            "c1",
            &dummy_span(),
        )
        .expect("Num2Bits(4) should instantiate");

        // The entire array is under a single key keyed by the
        // declared output name, never `out_0`/`out_1`.
        assert_eq!(inst.outputs.len(), 1);
        match inst.outputs.get("out").expect("out entry") {
            TemplateOutput::Array { dims, values } => {
                assert_eq!(dims, &vec![4u64]);
                assert_eq!(values.len(), 4);
                for (i, v) in values.iter().enumerate() {
                    match v {
                        CircuitExpr::Var(name) => assert_eq!(name, &format!("c1_out_{i}")),
                        other => panic!("expected Var, got {other:?}"),
                    }
                }
            }
            other => panic!("expected Array, got {other:?}"),
        }
    }
}
