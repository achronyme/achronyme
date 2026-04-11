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
use super::metadata::extract_template_metadata;
use super::types::{CircomLibrary, DimensionExpr};

/// Result of inlining a Circom template into a parent circuit body.
#[derive(Clone, Debug)]
pub struct TemplateInstantiation {
    /// The circuit nodes to append to the parent body, in order.
    ///
    /// Contains the Let bindings that wire signal inputs to the
    /// sub-template's mangled signal names, followed by the mangled
    /// template body itself.
    pub body: Vec<CircuitNode>,
    /// One entry per declared signal output of the template.
    ///
    /// For scalar outputs the value is a `CircuitExpr::Var` pointing
    /// at the mangled output name in the parent's scope. For array
    /// outputs, the map contains one entry per element with the
    /// suffixed name (e.g. `out_0`, `out_1`, ...).
    pub outputs: HashMap<String, CircuitExpr>,
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

    // 2. Re-extract metadata with the concrete template args folded in so
    //    that output dimensions can be enumerated as scalar names.
    let mut known_params = HashMap::new();
    for (name, fc) in template.params.iter().zip(template_args.iter()) {
        known_params.insert(name.clone(), *fc);
    }
    let entry = extract_template_metadata(template, &known_params);

    // 3. Wire signal inputs: emit a Let binding per input, splitting
    //    compile-time constants into `const_inputs` for propagation.
    let mut body = Vec::new();
    let mut const_inputs: HashMap<String, FieldConst> = HashMap::new();

    for input in &entry.inputs {
        if !input.is_scalar() {
            // TODO (Phase 1.4+): support array-valued inputs by expanding
            // to one Let per element. For now only scalars are supported.
            return Err(InstantiationError::Lowering(format!(
                "array signal inputs are not yet supported; `{}.{}` is an array",
                template_name, input.name
            )));
        }
        let expr = signal_inputs.get(&input.name).ok_or_else(|| {
            InstantiationError::MissingSignalInput {
                template: template_name.to_string(),
                signal: input.name.clone(),
            }
        })?;

        // Propagate compile-time-known inputs into the sub-template
        // so the lowerer emits `Const` instead of `Input` for them.
        if let CircuitExpr::Const(fc) = expr {
            const_inputs.insert(input.name.clone(), *fc);
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

    // 5. Build the outputs map. Scalar outputs map to a single Var;
    //    array outputs produce one entry per element using the stride
    //    encoding the rest of the lowering pipeline already uses
    //    (`name_i`, or for multi-dim `name_i_j...`). Dimensions must be
    //    resolvable against the concrete template args.
    let mut outputs = HashMap::new();
    for out in &entry.outputs {
        if out.is_scalar() {
            outputs.insert(
                out.name.clone(),
                CircuitExpr::Var(format!("{parent_prefix}_{}", out.name)),
            );
            continue;
        }
        let dims = resolve_output_dims(&out.dimensions).ok_or_else(|| {
            InstantiationError::Library(LibraryError::UnresolvedOutputDimension {
                template: template_name.to_string(),
                signal: out.name.clone(),
            })
        })?;
        for index in iter_multi_index(&dims) {
            let suffix = index
                .iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join("_");
            let key = format!("{}_{}", out.name, suffix);
            outputs.insert(
                key.clone(),
                CircuitExpr::Var(format!("{parent_prefix}_{key}")),
            );
        }
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
        let y = inst.outputs.get("y").expect("y output");
        assert!(matches!(y, CircuitExpr::Var(v) if v == "c0_y"));
        assert!(inst.body.len() >= 2);
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

        for i in 0..4 {
            let key = format!("out_{i}");
            let expected = format!("c1_out_{i}");
            match inst.outputs.get(&key).expect("output present") {
                CircuitExpr::Var(v) => assert_eq!(v, &expected),
                other => panic!("expected Var, got {other:?}"),
            }
        }
        assert_eq!(inst.outputs.len(), 4);
    }
}
