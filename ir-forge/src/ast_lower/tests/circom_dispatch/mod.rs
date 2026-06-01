use super::*;
use crate::{CircomDispatchErrorKind, ProveIrError};
use crate::{
    CircomInstantiation, CircomLibraryHandle, CircomTemplateOutput, CircomTemplateSignature,
};
use ::diagnostics::Span;
use std::collections::HashMap;
use std::sync::Arc;

fn sig(params: &[&str], inputs: &[&str], outputs: &[&str]) -> CircomTemplateSignature {
    CircomTemplateSignature {
        params: params.iter().map(|s| s.to_string()).collect(),
        input_signals: inputs.iter().map(|s| s.to_string()).collect(),
        output_signals: outputs.iter().map(|s| s.to_string()).collect(),
    }
}

/// Stub that records instantiation calls so tests can assert
/// what the dispatcher handed to the library handle. Mirrors
/// `StubLibrary` but captures every `instantiate_template` call
/// into an interior-mutable log.
#[derive(Debug)]
struct RecordingLibrary {
    sig: CircomTemplateSignature,
    template_name: String,
    calls: std::sync::Mutex<Vec<RecordedCall>>,
}

#[derive(Debug, Clone)]
struct RecordedCall {
    template_name: String,
    template_args: Vec<FieldConst>,
    signal_inputs: Vec<(String, CircuitExpr)>,
    parent_prefix: String,
}

impl RecordingLibrary {
    fn new(template_name: &str, sig: CircomTemplateSignature) -> Self {
        Self {
            sig,
            template_name: template_name.to_string(),
            calls: std::sync::Mutex::new(Vec::new()),
        }
    }
    fn recorded(&self) -> Vec<RecordedCall> {
        self.calls.lock().unwrap().clone()
    }
}

impl CircomLibraryHandle for RecordingLibrary {
    fn template_signature(&self, name: &str) -> Option<CircomTemplateSignature> {
        if name == self.template_name {
            Some(self.sig.clone())
        } else {
            None
        }
    }
    fn template_names(&self) -> Vec<String> {
        vec![self.template_name.clone()]
    }
    fn resolve_input_layout(
        &self,
        template_name: &str,
        _template_args: &[FieldConst],
    ) -> Option<Vec<crate::CircomInputLayout>> {
        if template_name != self.template_name {
            return None;
        }
        Some(
            self.sig
                .input_signals
                .iter()
                .map(|n| crate::CircomInputLayout {
                    name: n.clone(),
                    dims: Vec::new(),
                })
                .collect(),
        )
    }
    fn instantiate_template(
        &self,
        template_name: &str,
        template_args: &[FieldConst],
        signal_inputs: &HashMap<String, CircuitExpr>,
        parent_prefix: &str,
        _span: &Span,
    ) -> Result<CircomInstantiation, crate::CircomDispatchError> {
        let mut inputs: Vec<(String, CircuitExpr)> = signal_inputs
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        inputs.sort_by(|a, b| a.0.cmp(&b.0));
        self.calls.lock().unwrap().push(RecordedCall {
            template_name: template_name.to_string(),
            template_args: template_args.to_vec(),
            signal_inputs: inputs,
            parent_prefix: parent_prefix.to_string(),
        });
        // Emit a marker Let so tests can observe the body was
        // extended with the library's contribution.
        let body = vec![CircuitNode::Let {
            name: format!("{parent_prefix}_marker"),
            value: CircuitExpr::Const(FieldConst::from_u64(42)),
            span: None,
        }];
        // Populate every declared output so multi-output
        // tests can verify per-output binding in the env.
        let mut outputs = HashMap::new();
        for out in &self.sig.output_signals {
            outputs.insert(
                out.clone(),
                CircomTemplateOutput::Scalar(CircuitExpr::Var(format!("{parent_prefix}_{out}"))),
            );
        }
        Ok(CircomInstantiation {
            body,
            outputs,
            component_bodies: std::collections::HashMap::new(),
        })
    }
}

fn compiler_with_stub(
    template: &str,
    sig_val: CircomTemplateSignature,
) -> (ProveIrCompiler<Bn254Fr>, Arc<RecordingLibrary>) {
    let lib = Arc::new(RecordingLibrary::new(template, sig_val));
    let handle: Arc<dyn CircomLibraryHandle> = lib.clone();
    let mut compiler = ProveIrCompiler::<Bn254Fr>::new();
    compiler.register_circom_template(template.to_string(), handle, template.to_string());
    // The prove block has an "x" public input that the
    // template consumes.
    compiler
        .env
        .insert("x".to_string(), CompEnvValue::Scalar("x".to_string()));
    (compiler, lib)
}

fn parse_expr(source: &str) -> Expr {
    let (program, errors) = achronyme_parser::parse_program(source);
    assert!(errors.is_empty(), "parse errors: {errors:?}");
    match &program.stmts[0] {
        Stmt::Expr(e) => e.clone(),
        other => panic!("expected expression statement, got {other:?}"),
    }
}

mod array_output;
mod bindings;
mod diagnostics;
mod dispatch;
