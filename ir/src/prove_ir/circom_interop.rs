//! Dispatch surface for circom template instantiation from inside
//! ProveIR compilation, without forcing `ir` to depend on `circom`.
//!
//! The `circom` crate already depends on `ir` (for `CircuitExpr`,
//! `CircuitNode`, `FieldConst`). Having `ir` reach back into `circom`
//! for `CircomLibrary` would create a cycle, so Phase 3 abstracts the
//! capability as a trait living here in `ir`. The `circom` crate
//! implements the trait for `CircomLibrary`, and the `compiler` crate
//! — which depends on both — plumbs trait objects through
//! [`super::OuterScope`] into the ProveIR compiler.
//!
//! The types below intentionally mirror
//! `circom::library::{TemplateOutput, TemplateInstantiation,
//! InstantiationError}` but reference only `ir`-level types so the
//! trait stays dependency-free.

use std::collections::HashMap;
use std::sync::Arc;

use diagnostics::Span;

use super::types::{CircuitExpr, CircuitNode, FieldConst};

/// A single declared output of an instantiated circom template, keyed
/// by the original (unmangled) signal name in [`CircomInstantiation::outputs`].
#[derive(Clone, Debug)]
pub enum CircomTemplateOutput {
    /// Scalar signal output — a single `CircuitExpr::Var` pointing at
    /// the mangled signal name inside the parent body.
    Scalar(CircuitExpr),
    /// Array signal output — row-major flattening.
    ///
    /// `dims` holds the resolved shape (e.g. `[n]` for `out[n]`);
    /// `values` contains `dims.iter().product()` expressions in the
    /// same row-major order the witness evaluator uses
    /// (`name_i`, `name_i_j`, ...).
    Array {
        dims: Vec<u64>,
        values: Vec<CircuitExpr>,
    },
}

/// Result of inlining a circom template into a parent circuit body.
#[derive(Clone, Debug)]
pub struct CircomInstantiation {
    /// Circuit nodes to append to the parent body, in order: Let
    /// bindings wiring signal inputs to the sub-template's mangled
    /// signal names, then the mangled sub-template body itself.
    pub body: Vec<CircuitNode>,
    /// One entry per declared signal output, keyed by the original
    /// output name.
    pub outputs: HashMap<String, CircomTemplateOutput>,
}

/// Lightweight declared signature of a circom template — just enough
/// for the ProveIR dispatcher to validate argument counts and to map
/// signal inputs by name without exposing the circom AST.
#[derive(Clone, Debug)]
pub struct CircomTemplateSignature {
    /// Template parameter names (captures) in declaration order.
    pub params: Vec<String>,
    /// Declared input signal names in declaration order.
    pub input_signals: Vec<String>,
    /// Declared output signal names in declaration order.
    pub output_signals: Vec<String>,
}

/// Reasons a circom template instantiation can be rejected, reported
/// back to the ProveIR dispatcher so it can surface a proper
/// [`super::error::ProveIrError`] variant with span information.
#[derive(Clone, Debug)]
pub enum CircomDispatchError {
    /// The library does not contain a template by this name.
    UnknownTemplate {
        template: String,
        available: Vec<String>,
    },
    /// Template parameter count mismatch.
    ParamCountMismatch {
        template: String,
        expected: usize,
        got: usize,
    },
    /// Caller did not wire a declared signal input.
    MissingSignalInput { template: String, signal: String },
    /// Template declares an array-valued signal input, which the
    /// library-mode inliner does not yet support.
    UnsupportedArrayInput { template: String, signal: String },
    /// Lower-level lowering failure inside the circom frontend.
    Lowering(String),
}

impl std::fmt::Display for CircomDispatchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownTemplate { template, .. } => {
                write!(f, "unknown circom template `{template}`")
            }
            Self::ParamCountMismatch {
                template,
                expected,
                got,
            } => write!(
                f,
                "circom template `{template}` expects {expected} parameter(s), got {got}"
            ),
            Self::MissingSignalInput { template, signal } => write!(
                f,
                "circom template `{template}` requires signal input `{signal}` which was not provided"
            ),
            Self::UnsupportedArrayInput { template, signal } => write!(
                f,
                "circom template `{template}` declares array-valued signal input `{signal}` \
                 which is not yet supported by library-mode instantiation"
            ),
            Self::Lowering(msg) => write!(f, "circom lowering failed: {msg}"),
        }
    }
}

impl std::error::Error for CircomDispatchError {}

/// Dispatch-side view of a compiled circom library. Implemented in
/// the `circom` crate for `CircomLibrary`; constructed by the
/// `compiler` crate and handed to [`super::OuterScope`] so the
/// ProveIR compiler can look up templates without depending on
/// `circom` directly.
pub trait CircomLibraryHandle: std::fmt::Debug + Send + Sync {
    /// Return the declared signature of a template.
    fn template_signature(&self, name: &str) -> Option<CircomTemplateSignature>;

    /// All template names in this library — used for did-you-mean
    /// suggestions when the dispatcher can't find a name.
    fn template_names(&self) -> Vec<String>;

    /// Instantiate a template into a fresh sub-circuit body.
    ///
    /// `parent_prefix` is a caller-chosen unique identifier (e.g.
    /// `"circom_call_7"`) used to mangle all signal and local names
    /// so multiple instantiations never collide.
    fn instantiate_template(
        &self,
        template_name: &str,
        template_args: &[FieldConst],
        signal_inputs: &HashMap<String, CircuitExpr>,
        parent_prefix: &str,
        span: &Span,
    ) -> Result<CircomInstantiation, CircomDispatchError>;
}

/// A single entry in [`super::ProveIrCompiler::circom_table`] — binds
/// a lookup key (either the bare template name from a selective
/// import, or `"P::T"` from a namespace import) to the owning library
/// handle plus the resolved template name on that library.
#[derive(Clone, Debug)]
pub struct CircomCallable {
    /// Library that owns the template. Shared so the same library can
    /// back multiple namespace / selective entries without re-loading.
    pub library: Arc<dyn CircomLibraryHandle>,
    /// The resolved template name on `library` (never the `P::T`
    /// key — always the actual template name).
    pub template_name: String,
}

#[cfg(test)]
pub(crate) mod test_support {
    //! Minimal in-memory stub used by unit tests in this crate.
    use super::*;
    use std::collections::HashMap;

    /// Trivial fake library backed by a HashMap of signatures. The
    /// [`instantiate_template`] path just validates inputs and echoes
    /// back an empty body + scalar outputs — real instantiation lives
    /// in `circom` and is tested there.
    #[derive(Debug)]
    pub struct StubLibrary {
        pub templates: HashMap<String, CircomTemplateSignature>,
    }

    impl StubLibrary {
        pub fn with_template(name: &str, sig: CircomTemplateSignature) -> Self {
            let mut templates = HashMap::new();
            templates.insert(name.to_string(), sig);
            Self { templates }
        }
    }

    impl CircomLibraryHandle for StubLibrary {
        fn template_signature(&self, name: &str) -> Option<CircomTemplateSignature> {
            self.templates.get(name).cloned()
        }

        fn template_names(&self) -> Vec<String> {
            self.templates.keys().cloned().collect()
        }

        fn instantiate_template(
            &self,
            template_name: &str,
            template_args: &[FieldConst],
            signal_inputs: &HashMap<String, CircuitExpr>,
            parent_prefix: &str,
            _span: &Span,
        ) -> Result<CircomInstantiation, CircomDispatchError> {
            let sig = self.templates.get(template_name).ok_or_else(|| {
                CircomDispatchError::UnknownTemplate {
                    template: template_name.to_string(),
                    available: self.template_names(),
                }
            })?;
            if template_args.len() != sig.params.len() {
                return Err(CircomDispatchError::ParamCountMismatch {
                    template: template_name.to_string(),
                    expected: sig.params.len(),
                    got: template_args.len(),
                });
            }
            for sig_in in &sig.input_signals {
                if !signal_inputs.contains_key(sig_in) {
                    return Err(CircomDispatchError::MissingSignalInput {
                        template: template_name.to_string(),
                        signal: sig_in.clone(),
                    });
                }
            }
            let mut outputs = HashMap::new();
            for out in &sig.output_signals {
                outputs.insert(
                    out.clone(),
                    CircomTemplateOutput::Scalar(CircuitExpr::Var(format!(
                        "{parent_prefix}_{out}"
                    ))),
                );
            }
            Ok(CircomInstantiation {
                body: Vec::new(),
                outputs,
            })
        }
    }

    #[allow(dead_code)]
    pub fn dummy_span() -> Span {
        Span {
            byte_start: 0,
            byte_end: 0,
            line_start: 0,
            col_start: 0,
            line_end: 0,
            col_end: 0,
        }
    }
}
