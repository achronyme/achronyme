//! Circom frontend for Achronyme.
//!
//! Parses `.circom` files (Circom 2.x syntax) and lowers them through
//! Achronyme's ProveIR pipeline, producing R1CS or Plonkish constraints
//! with structural safety guarantees:
//!
//! - Every `<--` assignment must have a corresponding `===` constraint.
//! - Under-constrained signals are caught at compile time (hard error).
//!
//! # Pipeline
//!
//! `.circom` → Lexer → Parser → Circom AST → Analysis → Lowering → ProveIR
//!
//! # Usage
//!
//! ```ignore
//! let prove_ir = circom::compile_to_prove_ir(source)?;
//! let program = prove_ir.instantiate(&inputs)?;
//! ```

pub mod analysis;
pub mod ast;
pub mod lexer;
mod lowering;
pub mod parser;
pub mod token;
pub mod witness;

use diagnostics::Diagnostic;
use ir::prove_ir::types::ProveIR;

/// Error returned by the Circom compilation pipeline.
#[derive(Debug)]
pub enum CircomError {
    /// Parser failed to produce a valid AST.
    ParseError(Vec<Diagnostic>),
    /// Constraint analysis found under-constrained signals.
    ConstraintError(Vec<Diagnostic>),
    /// No `component main` declaration found in the source.
    NoMainComponent,
    /// The main component references a template that doesn't exist.
    MainTemplateNotFound(String),
    /// Lowering from Circom AST to ProveIR failed.
    LoweringError(lowering::error::LoweringError),
}

impl std::fmt::Display for CircomError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CircomError::ParseError(diags) => {
                write!(f, "parse error: ")?;
                for d in diags {
                    write!(f, "{}", d.message)?;
                }
                Ok(())
            }
            CircomError::ConstraintError(diags) => {
                write!(f, "constraint error: ")?;
                for d in diags {
                    write!(f, "{}", d.message)?;
                }
                Ok(())
            }
            CircomError::NoMainComponent => {
                write!(f, "no `component main` declaration found")
            }
            CircomError::MainTemplateNotFound(name) => {
                write!(f, "main component references undefined template `{name}`")
            }
            CircomError::LoweringError(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for CircomError {}

/// Compile a `.circom` source file to ProveIR.
///
/// Runs the full Circom frontend pipeline:
/// 1. Parse source → Circom AST
/// 2. Constraint analysis (E100: under-constrained signals)
/// 3. Lower main component's template → ProveIR
///
/// The returned `ProveIR` can be instantiated with input values and
/// fed into the standard Achronyme proof pipeline (optimize → R1CS → prove).
pub fn compile_to_prove_ir(source: &str) -> Result<ProveIR, CircomError> {
    // 1. Parse
    let (program, parse_errors) = parser::parse_circom(source).map_err(|e| {
        CircomError::ParseError(vec![Diagnostic::error(
            e.to_string(),
            diagnostics::SpanRange::point(0, 0, 0),
        )])
    })?;

    let errors: Vec<&Diagnostic> = parse_errors
        .iter()
        .filter(|d| d.severity == diagnostics::Severity::Error)
        .collect();
    if !errors.is_empty() {
        return Err(CircomError::ParseError(
            errors.into_iter().cloned().collect(),
        ));
    }

    // 2. Constraint analysis
    let reports = analysis::constraint_check::check_constraints(&program.definitions);
    let all_diags: Vec<Diagnostic> = reports.into_iter().flat_map(|r| r.diagnostics).collect();

    // Print warnings to stderr but don't block compilation
    for diag in &all_diags {
        if diag.severity == diagnostics::Severity::Warning {
            eprintln!("warning: {}", diag.message);
            for note in &diag.notes {
                eprintln!("  note: {note}");
            }
        }
    }

    // Only errors block compilation
    let constraint_errors: Vec<Diagnostic> = all_diags
        .into_iter()
        .filter(|d| d.severity == diagnostics::Severity::Error)
        .collect();
    if !constraint_errors.is_empty() {
        return Err(CircomError::ConstraintError(constraint_errors));
    }

    // 3. Find main component and its template
    let main = program
        .main_component
        .as_ref()
        .ok_or(CircomError::NoMainComponent)?;

    let template = program
        .definitions
        .iter()
        .find_map(|d| match d {
            ast::Definition::Template(t) if t.name == main.template_name => Some(t),
            _ => None,
        })
        .ok_or_else(|| CircomError::MainTemplateNotFound(main.template_name.clone()))?;

    // 4. Lower to ProveIR
    let prove_ir = lowering::template::lower_template(template, Some(main), &program)
        .map_err(CircomError::LoweringError)?;

    Ok(prove_ir)
}
