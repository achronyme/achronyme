//! Error types for ProveIR compilation.

use std::fmt;

use diagnostics::{Diagnostic, SpanRange};
use ir_core::error::OptSpan;

/// Specific failure modes for circom template dispatch inside a
/// prove/circuit block. Wrapped under
/// [`ProveIrError::CircomDispatch`] together with a source span so
/// each variant can be rendered as a rustc-style diagnostic with a
/// pointer at the offending source location.
///
/// Each variant captures only what the error message needs;
/// unresolved names carry an optional `did_you_mean` suggestion
/// computed by Levenshtein against the compiler's registered names.
#[derive(Debug, Clone)]
pub enum CircomDispatchErrorKind {
    /// `P.Template(...)` where `P` is not a registered namespace
    /// alias. `alias` is what the user wrote; `did_you_mean` is a
    /// Levenshtein suggestion against the registered namespace keys.
    NamespaceNotFound {
        alias: String,
        did_you_mean: Option<String>,
    },
    /// `P.Template(...)` where `P` is a valid namespace but
    /// `Template` is not a template on the library backing it.
    /// `did_you_mean` is scoped to templates in that library only.
    TemplateNotFoundInNamespace {
        alias: String,
        template: String,
        did_you_mean: Option<String>,
    },
    /// Bare `Template(...)` where the name is not in the circom
    /// template aliases (selective import) table. This variant is
    /// only emitted when the user's name is a near-miss against an
    /// actually-registered template — otherwise the compiler falls
    /// through to the normal "undefined function" path.
    TemplateNotFoundSelective {
        template: String,
        did_you_mean: Option<String>,
    },
    /// Circom template called without its template parameter layer:
    /// `T(inputs)` instead of `T()(inputs)`. Carries the declared
    /// template-param count so the hint can cite it.
    MissingTemplateParams {
        template: String,
        expected_params: usize,
    },
    /// Circom template referenced as a bare identifier or dot access
    /// (`P.Template` / `Template`) without any call layer — circom
    /// templates are not first-class values in prove blocks.
    NotAtomic { template: String },
    /// Template parameter count mismatch (`T(wrong_count)(inputs)`).
    ParamCountMismatch {
        template: String,
        expected: usize,
        got: usize,
    },
    /// Signal input count mismatch (`T(args)(wrong_count)`).
    SignalInputCountMismatch {
        template: String,
        expected: usize,
        got: usize,
    },
    /// A template parameter was not a compile-time constant.
    /// Template params are captures, not runtime values.
    TemplateArgNotConst { template: String, arg_index: usize },
    /// Template declares an array-valued signal input which the
    /// library-mode instantiation pipeline does not yet support.
    ArrayInputUnsupported { template: String, signal: String },
    /// DotAccess on a circom result returned an array output, which
    /// requires element indexing that the dispatch surface does not
    /// yet support. (User-facing fallback for shapes not covered by
    /// the "<name>.<out>_<i>" pattern.)
    ArrayOutputRequiresIndex { template: String, signal: String },
    /// The underlying circom lowering stage produced its own error.
    /// Wrapped here so ProveIrError stays the single surface the CLI
    /// has to render.
    LoweringFailed { template: String, message: String },
}

impl fmt::Display for CircomDispatchErrorKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NamespaceNotFound {
                alias,
                did_you_mean,
            } => {
                write!(f, "circom namespace `{alias}` is not imported")?;
                if let Some(s) = did_you_mean {
                    write!(f, " (did you mean `{s}`?)")?;
                }
                Ok(())
            }
            Self::TemplateNotFoundInNamespace {
                alias,
                template,
                did_you_mean,
            } => {
                write!(
                    f,
                    "circom namespace `{alias}` does not declare template `{template}`"
                )?;
                if let Some(s) = did_you_mean {
                    write!(f, " (did you mean `{s}`?)")?;
                }
                Ok(())
            }
            Self::TemplateNotFoundSelective {
                template,
                did_you_mean,
            } => {
                write!(f, "circom template `{template}` is not imported")?;
                if let Some(s) = did_you_mean {
                    write!(f, " (did you mean `{s}`?)")?;
                }
                Ok(())
            }
            Self::MissingTemplateParams {
                template,
                expected_params,
            } => write!(
                f,
                "circom template `{template}` must be called atomically as \
                 `{template}(<{expected_params} template params>)(<signal inputs>)`"
            ),
            Self::NotAtomic { template } => write!(
                f,
                "circom template `{template}` is not a first-class value; \
                 it must be called atomically as `{template}(<params>)(<inputs>)`"
            ),
            Self::ParamCountMismatch {
                template,
                expected,
                got,
            } => write!(
                f,
                "circom template `{template}` expects {expected} template parameter(s), got {got}"
            ),
            Self::SignalInputCountMismatch {
                template,
                expected,
                got,
            } => write!(
                f,
                "circom template `{template}` expects {expected} signal input(s), got {got}"
            ),
            Self::TemplateArgNotConst {
                template,
                arg_index,
            } => write!(
                f,
                "circom template `{template}`: template argument at position {arg_index} must be \
                 a compile-time constant (captures and witness values are not allowed)"
            ),
            Self::ArrayInputUnsupported { template, signal } => write!(
                f,
                "circom template `{template}` declares array-valued signal input `{signal}`; \
                 library-mode instantiation does not yet support array inputs"
            ),
            Self::ArrayOutputRequiresIndex { template, signal } => write!(
                f,
                "circom template `{template}` output `{signal}` is an array; access elements \
                 via `result.{signal}_i` instead of `result.{signal}`"
            ),
            Self::LoweringFailed { template, message } => write!(
                f,
                "circom template `{template}` instantiation failed: {message}"
            ),
        }
    }
}

/// Errors emitted during ProveIR compilation (AST → ProveIR).
#[derive(Debug)]
pub enum ProveIrError {
    /// Reference to a variable not found in scope.
    UndeclaredVariable {
        name: String,
        span: OptSpan,
        suggestion: Option<String>,
    },
    /// An operation that has no circuit translation.
    UnsupportedOperation { description: String, span: OptSpan },
    /// A value type that cannot be represented in circuits.
    TypeNotConstrainable { type_name: String, span: OptSpan },
    /// A loop without statically-known bounds.
    UnboundedLoop { span: OptSpan },
    /// A builtin or method called with wrong arity.
    WrongArgumentCount {
        name: String,
        expected: usize,
        got: usize,
        span: OptSpan,
    },
    /// Recursive function detected.
    RecursiveFunction { name: String },
    /// Array index out of bounds.
    IndexOutOfBounds {
        name: String,
        index: usize,
        length: usize,
        span: OptSpan,
    },
    /// Array length mismatch.
    ArrayLengthMismatch {
        expected: usize,
        got: usize,
        span: OptSpan,
    },
    /// Type mismatch (e.g., scalar where array expected).
    TypeMismatch {
        expected: String,
        got: String,
        span: OptSpan,
    },
    /// Type annotation does not match inferred type.
    AnnotationMismatch {
        name: String,
        declared: String,
        inferred: String,
        span: OptSpan,
    },
    /// A static namespace member that cannot be used in circuits.
    StaticAccessNotConstrainable {
        type_name: String,
        member: String,
        reason: String,
        span: OptSpan,
    },
    /// A method that cannot be used in circuits.
    MethodNotConstrainable {
        method: String,
        reason: String,
        span: OptSpan,
    },
    /// For loop range exceeds maximum allowed iterations.
    RangeTooLarge {
        iterations: u64,
        max: u64,
        span: OptSpan,
    },
    /// Duplicate input declaration.
    DuplicateInput { name: String, span: OptSpan },
    /// Module not found.
    ModuleNotFound(String),
    /// Circular import detected.
    CircularImport(String),
    /// Module loading error.
    ModuleLoadError(String),
    /// Parse error (propagated from parser).
    ParseError(Box<Diagnostic>),
    /// A function that is VM-only (e.g. calls `print`) was referenced
    /// inside a prove/circuit block. Availability inference detected
    /// this at resolve time.
    VmOnlyFunction { name: String, span: OptSpan },
    /// Circom template dispatch failure inside a prove/circuit
    /// block. See [`CircomDispatchErrorKind`] for the variant list.
    CircomDispatch {
        kind: CircomDispatchErrorKind,
        span: OptSpan,
    },
}

impl fmt::Display for ProveIrError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UndeclaredVariable {
                name, suggestion, ..
            } => {
                write!(f, "undeclared variable in circuit: `{name}`")?;
                if let Some(s) = suggestion {
                    write!(f, " (did you mean `{s}`?)")?;
                }
                Ok(())
            }
            Self::UnsupportedOperation { description, .. } => write!(f, "{description}"),
            Self::TypeNotConstrainable { type_name, .. } => {
                write!(
                    f,
                    "type '{type_name}' cannot be used in circuits \
                     (circuits operate on field elements only)"
                )
            }
            Self::UnboundedLoop { .. } => write!(
                f,
                "unbounded loops (while/forever) are not allowed in circuits \
                 (all iterations must be known at compile time)"
            ),
            Self::WrongArgumentCount {
                name,
                expected,
                got,
                ..
            } => write!(f, "`{name}` expects {expected} arguments, got {got}"),
            Self::RecursiveFunction { name } => {
                write!(f, "recursive function `{name}` is not allowed in circuits")
            }
            Self::IndexOutOfBounds {
                name,
                index,
                length,
                ..
            } => write!(
                f,
                "index {index} out of bounds for `{name}` (length {length})"
            ),
            Self::ArrayLengthMismatch { expected, got, .. } => {
                write!(f, "array length mismatch: expected {expected}, got {got}")
            }
            Self::TypeMismatch { expected, got, .. } => {
                write!(f, "type mismatch: expected {expected}, got {got}")
            }
            Self::AnnotationMismatch {
                name,
                declared,
                inferred,
                ..
            } => write!(
                f,
                "type annotation mismatch for `{name}`: declared {declared}, inferred {inferred}"
            ),
            Self::StaticAccessNotConstrainable {
                type_name,
                member,
                reason,
                ..
            } => write!(
                f,
                "`{type_name}::{member}` cannot be used in circuits: {reason}"
            ),
            Self::MethodNotConstrainable { method, reason, .. } => {
                write!(f, "`.{method}()` cannot be used in circuits: {reason}")
            }
            Self::RangeTooLarge {
                iterations, max, ..
            } => write!(
                f,
                "for loop has {iterations} iterations, exceeding maximum of {max}"
            ),
            Self::DuplicateInput { name, .. } => {
                write!(f, "duplicate input declaration: `{name}`")
            }
            Self::ModuleNotFound(path) => write!(f, "module not found: `{path}`"),
            Self::CircularImport(path) => write!(f, "circular import detected: `{path}`"),
            Self::ModuleLoadError(msg) => write!(f, "module load error: {msg}"),
            Self::ParseError(diag) => write!(f, "parse error: {}", diag.message),
            Self::VmOnlyFunction { name, .. } => write!(
                f,
                "function `{name}` cannot be used inside a prove/circuit block \
                 because it uses VM-only operations"
            ),
            Self::CircomDispatch { kind, .. } => write!(f, "{kind}"),
        }
    }
}

impl std::error::Error for ProveIrError {}

impl ProveIrError {
    /// Convert to a `Diagnostic` for unified error rendering.
    pub fn to_diagnostic(&self) -> Diagnostic {
        let span = match self {
            Self::UndeclaredVariable { span, .. }
            | Self::UnsupportedOperation { span, .. }
            | Self::TypeNotConstrainable { span, .. }
            | Self::UnboundedLoop { span }
            | Self::WrongArgumentCount { span, .. }
            | Self::IndexOutOfBounds { span, .. }
            | Self::ArrayLengthMismatch { span, .. }
            | Self::TypeMismatch { span, .. }
            | Self::AnnotationMismatch { span, .. }
            | Self::StaticAccessNotConstrainable { span, .. }
            | Self::MethodNotConstrainable { span, .. }
            | Self::RangeTooLarge { span, .. } => span.as_ref().map(|s| (**s).clone()),
            Self::DuplicateInput { span, .. } | Self::VmOnlyFunction { span, .. } => {
                span.as_ref().map(|s| (**s).clone())
            }
            Self::CircomDispatch { span, .. } => span.as_ref().map(|s| (**s).clone()),
            Self::ParseError(diag) => return (**diag).clone(),
            // Variants without span information — listed explicitly so new
            // variants with spans produce a compile error instead of silently
            // falling through.
            Self::RecursiveFunction { .. }
            | Self::ModuleNotFound(_)
            | Self::CircularImport(_)
            | Self::ModuleLoadError(_) => None,
        };

        let span = span.unwrap_or(SpanRange::new(0, 0, 0, 0, 0, 0));
        Diagnostic::error(self.to_string(), span)
    }
}
