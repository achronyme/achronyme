//! Public library-mode API for the Circom frontend.
//!
//! A "library" here is a `.circom` source whose templates are imported
//! into an `.ach` file and called either in VM mode (witness evaluation)
//! or inside a `prove {}` / `circuit {}` block (constraint generation).
//!
//! Unlike [`crate::compile_file`], loading a library does **not** require
//! a `component main`. Templates are kept as metadata; their bodies are
//! lowered on demand at the call site, once template parameters and
//! signal inputs are known.
//!
//! The module is organized into four focused sub-modules:
//!
//! - [`types`]: the public data types ([`SignalSig`], [`DimensionExpr`],
//!   [`CircomTemplateEntry`], [`CircomLibrary`]).
//! - [`metadata`]: [`extract_template_metadata`] — walks a parsed
//!   `TemplateDef` and builds a [`CircomTemplateEntry`].
//! - [`instantiate`]: [`instantiate_template_into`] — lowers a template
//!   into a parent circuit body for constraint generation.
//! - [`witness_eval`]: [`evaluate_template_witness`] — runs a template
//!   off-circuit against concrete inputs (VM mode).
//!
//! All public items are re-exported from this module so downstream
//! crates use a single path: `circom::library::*`.

mod error;
mod handle;
mod instantiate;
mod metadata;
mod types;
mod witness_eval;

pub use error::LibraryError;
pub use instantiate::{
    instantiate_template_into, InstantiationError, TemplateInstantiation, TemplateOutput,
};
pub use metadata::{extract_template_metadata, resolve_entry};
pub use types::{CircomLibrary, CircomTemplateEntry, DimensionExpr, SignalSig};
pub use witness_eval::{evaluate_template_witness, TemplateOutputValue, WitnessEvalError};

#[cfg(test)]
pub(crate) mod test_support {
    //! Shared test helpers for library sub-modules.
    //!
    //! Provides a `dummy_span()` factory and a `make_library()`
    //! helper that parses a Circom source string into a `CircomLibrary`
    //! without touching the filesystem.

    use super::*;
    use crate::ast;
    use diagnostics::Span;
    use std::collections::HashMap;
    use std::path::PathBuf;

    pub(crate) fn dummy_span() -> Span {
        Span {
            byte_start: 0,
            byte_end: 0,
            line_start: 1,
            col_start: 1,
            line_end: 1,
            col_end: 1,
        }
    }

    pub(crate) fn parse_template(src: &str, name: &str) -> ast::TemplateDef {
        let (prog, errs) = crate::parser::parse_circom(src).expect("parse failed");
        assert!(errs.is_empty(), "parse errors: {errs:?}");
        prog.definitions
            .into_iter()
            .find_map(|d| match d {
                ast::Definition::Template(t) if t.name == name => Some(t),
                _ => None,
            })
            .expect("template not found")
    }

    pub(crate) fn make_library(src: &str) -> CircomLibrary {
        let (prog, errs) = crate::parser::parse_circom(src).expect("parse failed");
        assert!(errs.is_empty(), "parse errors: {errs:?}");
        let mut templates = HashMap::new();
        let mut functions = HashMap::new();
        for def in &prog.definitions {
            match def {
                ast::Definition::Template(t) => {
                    templates.insert(
                        t.name.clone(),
                        extract_template_metadata(t, &HashMap::new()),
                    );
                }
                ast::Definition::Function(f) => {
                    functions.insert(f.name.clone(), f.clone());
                }
                ast::Definition::Bus(_) => {}
            }
        }
        CircomLibrary {
            source_path: PathBuf::from("/tmp/inline.circom"),
            templates,
            functions,
            program: prog,
            warnings: Vec::new(),
        }
    }
}
