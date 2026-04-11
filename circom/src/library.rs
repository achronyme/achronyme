//! Public types describing a Circom file consumed as a *library*.
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
//! These types form the public surface used by the Achronyme compiler
//! crate to drive cross-language imports — they intentionally avoid any
//! field-backend generics so the compiler can hold them in shared state
//! without monomorphization.

use std::collections::HashMap;
use std::path::PathBuf;

use crate::ast;

/// A signal declaration's array-dimension expression.
///
/// Some Circom templates declare signals whose array sizes depend on
/// template parameters (e.g. `signal input in[n];`). Those dimensions
/// stay symbolic in the library metadata and are resolved when the
/// template is instantiated with concrete arguments.
#[derive(Clone, Debug)]
pub enum DimensionExpr {
    /// Dimension already resolved to a compile-time constant.
    Const(u64),
    /// Dimension is a single template parameter (capture) reference.
    Param(String),
    /// Dimension is a more complex expression (e.g. `n+1`).
    /// Must be evaluated against captures at instantiation time.
    Expr(Box<ast::Expr>),
}

/// Signature of a single signal: declared name and (possibly symbolic)
/// array dimensions.
///
/// A scalar signal has `dimensions = vec![]`. A 1D array of length `n`
/// has `dimensions = vec![DimensionExpr::Param("n".into())]`.
#[derive(Clone, Debug)]
pub struct SignalSig {
    pub name: String,
    pub dimensions: Vec<DimensionExpr>,
}

impl SignalSig {
    /// Convenience constructor for a scalar signal.
    pub fn scalar(name: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            dimensions: Vec::new(),
        }
    }

    /// Returns `true` if this signal has no array dimensions.
    pub fn is_scalar(&self) -> bool {
        self.dimensions.is_empty()
    }
}

/// Metadata about a single Circom template exposed by a library.
///
/// The template body itself is **not** stored here — it lives in the
/// parent [`CircomLibrary::program`] and is lowered lazily at each call
/// site so that captures, constant signal inputs, and parent context
/// can drive constant folding through component inlining.
#[derive(Clone, Debug)]
pub struct CircomTemplateEntry {
    /// Template name as declared in the source.
    pub name: String,
    /// Template parameter names, in declaration order.
    pub params: Vec<String>,
    /// `signal input` declarations, in declaration order.
    pub inputs: Vec<SignalSig>,
    /// `signal output` declarations, in declaration order.
    pub outputs: Vec<SignalSig>,
}

impl CircomTemplateEntry {
    /// Look up an input signal by name.
    pub fn input(&self, name: &str) -> Option<&SignalSig> {
        self.inputs.iter().find(|s| s.name == name)
    }

    /// Look up an output signal by name.
    pub fn output(&self, name: &str) -> Option<&SignalSig> {
        self.outputs.iter().find(|s| s.name == name)
    }
}

/// A loaded `.circom` file as a reusable library of templates.
///
/// Constructed by `compile_template_library` (added in a later commit).
/// `includes` are pre-resolved into a single flattened `program`.
#[derive(Clone, Debug)]
pub struct CircomLibrary {
    /// Absolute path of the source file (canonicalized when possible).
    pub source_path: PathBuf,
    /// Templates available in the library, keyed by name.
    pub templates: HashMap<String, CircomTemplateEntry>,
    /// Functions available for inlining inside templates, keyed by name.
    pub functions: HashMap<String, ast::FunctionDef>,
    /// Full program AST with `include` chain already resolved.
    pub program: ast::CircomProgram,
}

impl CircomLibrary {
    /// Look up a template by name.
    pub fn template(&self, name: &str) -> Option<&CircomTemplateEntry> {
        self.templates.get(name)
    }

    /// Iterate template names in unspecified order.
    pub fn template_names(&self) -> impl Iterator<Item = &str> {
        self.templates.keys().map(String::as_str)
    }

    /// Look up a function by name.
    pub fn function(&self, name: &str) -> Option<&ast::FunctionDef> {
        self.functions.get(name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use diagnostics::Span;

    fn dummy_span() -> Span {
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
    fn signal_sig_scalar_is_scalar() {
        let s = SignalSig::scalar("in");
        assert!(s.is_scalar());
        assert_eq!(s.name, "in");
        assert!(s.dimensions.is_empty());
    }

    #[test]
    fn signal_sig_with_param_dim_is_not_scalar() {
        let s = SignalSig {
            name: "in".into(),
            dimensions: vec![DimensionExpr::Param("n".into())],
        };
        assert!(!s.is_scalar());
        assert_eq!(s.dimensions.len(), 1);
    }

    #[test]
    fn dimension_expr_variants() {
        let c = DimensionExpr::Const(8);
        let p = DimensionExpr::Param("n".into());
        let e = DimensionExpr::Expr(Box::new(ast::Expr::Number {
            value: "1".into(),
            span: dummy_span(),
        }));
        assert!(matches!(c, DimensionExpr::Const(8)));
        assert!(matches!(p, DimensionExpr::Param(ref s) if s == "n"));
        assert!(matches!(e, DimensionExpr::Expr(_)));
    }

    #[test]
    fn template_entry_input_output_lookup() {
        let entry = CircomTemplateEntry {
            name: "Num2Bits".into(),
            params: vec!["n".into()],
            inputs: vec![SignalSig::scalar("in")],
            outputs: vec![SignalSig {
                name: "out".into(),
                dimensions: vec![DimensionExpr::Param("n".into())],
            }],
        };
        assert!(entry.input("in").is_some());
        assert!(entry.input("missing").is_none());
        assert!(entry.output("out").is_some());
        let out = entry.output("out").unwrap();
        assert_eq!(out.dimensions.len(), 1);
    }

    #[test]
    fn library_template_lookup_and_iter() {
        let mut templates = HashMap::new();
        templates.insert(
            "Num2Bits".into(),
            CircomTemplateEntry {
                name: "Num2Bits".into(),
                params: vec!["n".into()],
                inputs: vec![SignalSig::scalar("in")],
                outputs: vec![SignalSig {
                    name: "out".into(),
                    dimensions: vec![DimensionExpr::Param("n".into())],
                }],
            },
        );
        let lib = CircomLibrary {
            source_path: PathBuf::from("/tmp/example.circom"),
            templates,
            functions: HashMap::new(),
            program: ast::CircomProgram {
                version: None,
                custom_templates: false,
                includes: Vec::new(),
                definitions: Vec::new(),
                main_component: None,
            },
        };
        assert!(lib.template("Num2Bits").is_some());
        assert!(lib.template("Missing").is_none());
        let names: Vec<&str> = lib.template_names().collect();
        assert_eq!(names, vec!["Num2Bits"]);
    }
}
