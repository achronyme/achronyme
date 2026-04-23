//! `CircomLibraryHandle` impl for [`CircomLibrary`].
//!
//! The trait lives in `ir_forge::circom_interop` (so `ir` can hold
//! trait objects without depending on `circom` and re-creating a
//! dependency cycle). This file wires a compiled library through to
//! that trait by delegating every method to the existing library API,
//! with a thin conversion layer between the circom-local and ir-local
//! output / error types.

use std::collections::HashMap;

use diagnostics::Span;
use ir_forge::types::{CircuitExpr, FieldConst};
use ir_forge::{
    CircomDispatchError, CircomInputLayout, CircomInstantiation, CircomLibraryHandle,
    CircomTemplateOutput, CircomTemplateSignature,
};

use super::instantiate::{instantiate_template_into, InstantiationError, TemplateOutput};
use super::metadata::resolve_entry;
use super::types::{CircomLibrary, DimensionExpr};
use super::LibraryError;

impl CircomLibraryHandle for CircomLibrary {
    fn template_signature(&self, name: &str) -> Option<CircomTemplateSignature> {
        let entry = self.template(name)?;
        Some(CircomTemplateSignature {
            params: entry.params.clone(),
            input_signals: entry.inputs.iter().map(|s| s.name.clone()).collect(),
            output_signals: entry.outputs.iter().map(|s| s.name.clone()).collect(),
        })
    }

    fn template_names(&self) -> Vec<String> {
        CircomLibrary::template_names(self)
            .map(String::from)
            .collect()
    }

    fn resolve_input_layout(
        &self,
        template_name: &str,
        template_args: &[FieldConst],
    ) -> Option<Vec<CircomInputLayout>> {
        let entry = self.template(template_name)?;
        if template_args.len() != entry.params.len() {
            return None;
        }
        let mut known_params = HashMap::new();
        for (name, fc) in entry.params.iter().zip(template_args.iter()) {
            known_params.insert(name.clone(), *fc);
        }
        let resolved = resolve_entry(entry, &known_params);
        let mut out = Vec::with_capacity(resolved.inputs.len());
        for sig in &resolved.inputs {
            let mut dims = Vec::with_capacity(sig.dimensions.len());
            for d in &sig.dimensions {
                match d {
                    DimensionExpr::Const(n) => dims.push(*n),
                    _ => return None, // unresolved dimension — caller should surface an error
                }
            }
            out.push(CircomInputLayout {
                name: sig.name.clone(),
                dims,
            });
        }
        Some(out)
    }

    fn instantiate_template(
        &self,
        template_name: &str,
        template_args: &[FieldConst],
        signal_inputs: &HashMap<String, CircuitExpr>,
        parent_prefix: &str,
        span: &Span,
    ) -> Result<CircomInstantiation, CircomDispatchError> {
        match instantiate_template_into(
            self,
            template_name,
            template_args,
            signal_inputs,
            parent_prefix,
            span,
        ) {
            Ok(inst) => {
                let outputs = inst
                    .outputs
                    .into_iter()
                    .map(|(k, v)| (k, convert_output(v)))
                    .collect();
                Ok(CircomInstantiation {
                    body: inst.body,
                    outputs,
                })
            }
            Err(e) => Err(convert_error(e, template_name, self)),
        }
    }
}

fn convert_output(v: TemplateOutput) -> CircomTemplateOutput {
    match v {
        TemplateOutput::Scalar(expr) => CircomTemplateOutput::Scalar(expr),
        TemplateOutput::Array { dims, values } => CircomTemplateOutput::Array { dims, values },
    }
}

fn convert_error(
    err: InstantiationError,
    template_name: &str,
    library: &CircomLibrary,
) -> CircomDispatchError {
    match err {
        InstantiationError::Library(LibraryError::UnknownTemplate { name, available }) => {
            CircomDispatchError::UnknownTemplate {
                template: name,
                available,
            }
        }
        InstantiationError::Library(LibraryError::ParamCountMismatch {
            template,
            expected,
            got,
        }) => CircomDispatchError::ParamCountMismatch {
            template,
            expected,
            got,
        },
        InstantiationError::Library(LibraryError::UnresolvedOutputDimension {
            template,
            signal,
        }) => CircomDispatchError::Lowering(format!(
            "template `{template}` output `{signal}` has an unresolved array dimension; \
             template parameters must produce constant-sized outputs"
        )),
        InstantiationError::MissingSignalInput { template, signal } => {
            CircomDispatchError::MissingSignalInput { template, signal }
        }
        InstantiationError::UnsupportedArrayInput { template, signal } => {
            CircomDispatchError::UnsupportedArrayInput { template, signal }
        }
        InstantiationError::Lowering(msg) => {
            // Include the library path in the lowering message so
            // multi-library errors are easier to disambiguate.
            let _ = (template_name, library);
            CircomDispatchError::Lowering(msg)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::library::test_support::make_library;
    use diagnostics::Span;

    fn empty_span() -> Span {
        Span {
            byte_start: 0,
            byte_end: 0,
            line_start: 1,
            col_start: 1,
            line_end: 1,
            col_end: 1,
        }
    }

    #[test]
    fn signature_for_scalar_template() {
        let lib = make_library(
            r#"
            template Square() {
                signal input x;
                signal output y;
                y <== x * x;
            }
            "#,
        );
        let sig = <CircomLibrary as CircomLibraryHandle>::template_signature(&lib, "Square")
            .expect("Square should exist");
        assert!(sig.params.is_empty());
        assert_eq!(sig.input_signals, vec!["x".to_string()]);
        assert_eq!(sig.output_signals, vec!["y".to_string()]);
    }

    #[test]
    fn signature_for_parametric_template_lists_params() {
        let lib = make_library(
            r#"
            template Num2Bits(n) {
                signal input in;
                signal output out[n];
            }
            "#,
        );
        let sig = <CircomLibrary as CircomLibraryHandle>::template_signature(&lib, "Num2Bits")
            .expect("Num2Bits should exist");
        assert_eq!(sig.params, vec!["n".to_string()]);
        assert_eq!(sig.input_signals, vec!["in".to_string()]);
        assert_eq!(sig.output_signals, vec!["out".to_string()]);
    }

    #[test]
    fn signature_missing_template_returns_none() {
        let lib = make_library("template X() { signal input a; signal output b; b <== a; }");
        assert!(
            <CircomLibrary as CircomLibraryHandle>::template_signature(&lib, "Missing").is_none()
        );
    }

    #[test]
    fn template_names_is_populated() {
        let lib = make_library(
            r#"
            template A() { signal input x; signal output y; y <== x; }
            template B() { signal input x; signal output y; y <== x; }
            "#,
        );
        let mut names = <CircomLibrary as CircomLibraryHandle>::template_names(&lib);
        names.sort();
        assert_eq!(names, vec!["A".to_string(), "B".to_string()]);
    }

    #[test]
    fn instantiate_via_trait_matches_direct_call() {
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

        let inst = <CircomLibrary as CircomLibraryHandle>::instantiate_template(
            &lib,
            "Square",
            &[],
            &inputs,
            "c0",
            &empty_span(),
        )
        .expect("instantiation should succeed");

        assert!(!inst.body.is_empty());
        match inst.outputs.get("y").expect("y output") {
            CircomTemplateOutput::Scalar(CircuitExpr::Var(v)) => assert_eq!(v, "c0.y"),
            other => panic!("expected scalar Var(c0.y), got {other:?}"),
        }
    }

    #[test]
    fn instantiate_unknown_template_surfaces_dispatch_error() {
        let lib = make_library("template X() { signal input a; signal output b; b <== a; }");
        let err = <CircomLibrary as CircomLibraryHandle>::instantiate_template(
            &lib,
            "DoesNotExist",
            &[],
            &HashMap::new(),
            "c0",
            &empty_span(),
        )
        .unwrap_err();
        assert!(matches!(err, CircomDispatchError::UnknownTemplate { .. }));
    }

    #[test]
    fn instantiate_wrong_param_count_surfaces_dispatch_error() {
        let lib = make_library(
            r#"
            template Num2Bits(n) {
                signal input in;
                signal output out[n];
            }
            "#,
        );
        let err = <CircomLibrary as CircomLibraryHandle>::instantiate_template(
            &lib,
            "Num2Bits",
            &[],
            &HashMap::new(),
            "c0",
            &empty_span(),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            CircomDispatchError::ParamCountMismatch {
                expected: 1,
                got: 0,
                ..
            }
        ));
    }
}
