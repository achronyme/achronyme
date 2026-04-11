//! Shared error variants used across library-mode operations.
//!
//! Several error surfaces (instantiation, witness evaluation) need to
//! report the same low-level failures: unknown template name, wrong
//! template-arg count, unresolved output dimension. Rather than
//! duplicating each variant in every error enum, we factor them into
//! [`LibraryError`] and compose:
//!
//! ```ignore
//! pub enum InstantiationError {
//!     Library(LibraryError),
//!     // ... mode-specific variants ...
//! }
//! ```
//!
//! Each mode-specific enum implements `From<LibraryError>` so code
//! paths can use `?` transparently.

/// Errors shared between instantiation and witness-evaluation modes.
#[derive(Clone, Debug)]
pub enum LibraryError {
    /// The requested template does not exist in the library.
    UnknownTemplate {
        name: String,
        available: Vec<String>,
    },
    /// The number of supplied template arguments does not match the
    /// template's parameter list.
    ParamCountMismatch {
        template: String,
        expected: usize,
        got: usize,
    },
    /// An output's array dimension could not be resolved from the
    /// concrete template parameters.
    UnresolvedOutputDimension { template: String, signal: String },
}

impl std::fmt::Display for LibraryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownTemplate { name, available } => write!(
                f,
                "circom library has no template `{name}`; available: {}",
                available.join(", ")
            ),
            Self::ParamCountMismatch {
                template,
                expected,
                got,
            } => write!(
                f,
                "template `{template}` expects {expected} template parameter(s), got {got}"
            ),
            Self::UnresolvedOutputDimension { template, signal } => write!(
                f,
                "output `{signal}` of template `{template}` has an unresolved array dimension"
            ),
        }
    }
}

impl std::error::Error for LibraryError {}

/// Resolve a template by name. Returns a `LibraryError::UnknownTemplate`
/// whose `available` list is pulled from the library's metadata cache
/// when the template isn't present.
pub(super) fn find_template<'a>(
    library: &'a super::types::CircomLibrary,
    template_name: &str,
) -> Result<&'a crate::ast::TemplateDef, LibraryError> {
    library
        .program
        .definitions
        .iter()
        .find_map(|d| match d {
            crate::ast::Definition::Template(t) if t.name == template_name => Some(t),
            _ => None,
        })
        .ok_or_else(|| LibraryError::UnknownTemplate {
            name: template_name.to_string(),
            available: library.templates.keys().cloned().collect::<Vec<_>>(),
        })
}

/// Validate that the caller supplied the expected number of template
/// arguments for `template`, returning the mismatch variant otherwise.
pub(super) fn check_param_count(
    template: &crate::ast::TemplateDef,
    got: usize,
) -> Result<(), LibraryError> {
    if template.params.len() != got {
        return Err(LibraryError::ParamCountMismatch {
            template: template.name.clone(),
            expected: template.params.len(),
            got,
        });
    }
    Ok(())
}
