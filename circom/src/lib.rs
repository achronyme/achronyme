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
// pub(crate) so lib.rs can access lowering::utils::const_eval_u64
pub(crate) mod lowering;
pub mod parser;
pub mod token;
pub mod witness;

use std::collections::HashMap;
use std::path::{Path, PathBuf};

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
    /// Include resolution failed.
    IncludeError(analysis::include_resolver::IncludeError),
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
            CircomError::IncludeError(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for CircomError {}

/// Result of Circom compilation: a ProveIR plus the capture values
/// extracted from the main component's template arguments.
pub struct CircomCompileResult {
    pub prove_ir: ProveIR,
    /// Template parameter values from `component main = Template(arg1, arg2, ...)`.
    /// Maps parameter names to their constant values.
    pub capture_values: HashMap<String, u64>,
}

/// Check if the declared pragma version is consistent with features used.
fn validate_version_pragma(program: &ast::CircomProgram) {
    let version = match &program.version {
        Some(v) => v,
        None => return, // No pragma — skip validation
    };

    let (major, minor) = (version.major, version.minor);

    // Check for features that require specific versions
    let has_buses = program
        .definitions
        .iter()
        .any(|d| matches!(d, ast::Definition::Bus(_)));
    if has_buses && (major < 2 || (major == 2 && minor < 2)) {
        eprintln!(
            "warning: `bus` declarations require Circom ≥ 2.2.0, \
             but pragma declares {major}.{minor}.{}",
            version.patch
        );
    }

    if program.custom_templates {
        // custom_templates requires Circom 2.0.6+, but we only track major.minor
        // so just check >= 2.0
        if major < 2 {
            eprintln!(
                "warning: `pragma custom_templates` requires Circom ≥ 2.0.6, \
                 but pragma declares {major}.{minor}.{}",
                version.patch
            );
        }
    }

    // Warn if declared version is newer than what we support
    if major > 2 || (major == 2 && minor > 2) {
        eprintln!(
            "warning: Achronyme's Circom frontend targets Circom 2.0–2.2.x; \
             pragma declares {major}.{minor}.{} which may use unsupported features",
            version.patch
        );
    }
}

/// Compile a `.circom` source string to ProveIR (single-file, no includes).
///
/// For multi-file compilation with `include` support, use [`compile_file`].
pub fn compile_to_prove_ir(source: &str) -> Result<CircomCompileResult, CircomError> {
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

    compile_program(&program)
}

/// Compile a `.circom` file to ProveIR with `include` resolution.
///
/// `library_dirs` are additional directories to search for `include` paths
/// (equivalent to Circom's `-l` flag).
pub fn compile_file(
    path: &Path,
    library_dirs: &[PathBuf],
) -> Result<CircomCompileResult, CircomError> {
    let resolved = analysis::include_resolver::resolve_includes(path, library_dirs)
        .map_err(CircomError::IncludeError)?;

    // Check for parse errors in any included file
    let errors: Vec<&Diagnostic> = resolved
        .diagnostics
        .iter()
        .filter(|d| d.severity == diagnostics::Severity::Error)
        .collect();
    if !errors.is_empty() {
        return Err(CircomError::ParseError(
            errors.into_iter().cloned().collect(),
        ));
    }

    // Convert ResolvedProgram → CircomProgram for shared pipeline
    let program = ast::CircomProgram {
        version: resolved.version,
        custom_templates: resolved.custom_templates,
        includes: Vec::new(), // Already resolved
        definitions: resolved.definitions,
        main_component: resolved.main_component,
    };

    compile_program(&program)
}

/// Shared compilation pipeline: analysis + lowering.
fn compile_program(program: &ast::CircomProgram) -> Result<CircomCompileResult, CircomError> {
    // 1. Version pragma validation
    validate_version_pragma(program);

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
        .ok_or_else(|| {
            let is_bus = program
                .definitions
                .iter()
                .any(|d| matches!(d, ast::Definition::Bus(b) if b.name == main.template_name));
            if is_bus {
                CircomError::MainTemplateNotFound(format!(
                    "{} (this is a bus type, not a template; bus compilation is not yet supported)",
                    main.template_name
                ))
            } else {
                CircomError::MainTemplateNotFound(main.template_name.clone())
            }
        })?;

    // 4. Lower to ProveIR
    let prove_ir = lowering::template::lower_template(template, Some(main), program)
        .map_err(CircomError::LoweringError)?;

    // 5. Extract capture values from main component template args
    let mut capture_values = HashMap::new();
    for (i, param) in template.params.iter().enumerate() {
        if let Some(arg_expr) = main.template_args.get(i) {
            if let Some(val) = lowering::utils::const_eval_u64(arg_expr) {
                capture_values.insert(param.clone(), val);
            }
        }
    }

    Ok(CircomCompileResult {
        prove_ir,
        capture_values,
    })
}
