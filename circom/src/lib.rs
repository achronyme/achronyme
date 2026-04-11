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
pub mod library;
// pub(crate) so lib.rs can access lowering::utils::const_eval_u64
pub(crate) mod lowering;
pub mod parser;
pub mod token;
pub mod witness;

pub use library::{
    evaluate_template_witness, instantiate_template_into, CircomLibrary, CircomTemplateEntry,
    DimensionExpr, InstantiationError, LibraryError, SignalSig, TemplateInstantiation,
    TemplateOutput, TemplateOutputValue, WitnessEvalError,
};

use std::collections::{HashMap, HashSet};
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

impl CircomError {
    /// Convert this error into structured diagnostics for rendering.
    ///
    /// All error variants produce at least one `Diagnostic` with proper
    /// severity, message, and (where available) span information.
    pub fn to_diagnostics(&self) -> Vec<Diagnostic> {
        match self {
            CircomError::ParseError(diags) | CircomError::ConstraintError(diags) => diags.clone(),
            CircomError::NoMainComponent => {
                vec![Diagnostic::error(
                    "no `component main` declaration found in source",
                    diagnostics::SpanRange::point(0, 0, 0),
                )
                .with_code("E210")]
            }
            CircomError::MainTemplateNotFound(name) => {
                vec![Diagnostic::error(
                    format!("main component references undefined template `{name}`"),
                    diagnostics::SpanRange::point(0, 0, 0),
                )
                .with_code("E211")]
            }
            CircomError::LoweringError(e) => vec![(*e.diagnostic).clone()],
            CircomError::IncludeError(e) => vec![e.to_diagnostic()],
        }
    }
}

/// Result of Circom compilation: a ProveIR plus the capture values
/// extracted from the main component's template arguments.
pub struct CircomCompileResult {
    pub prove_ir: ProveIR,
    /// Names of output signals (always public in R1CS).
    /// Used by the instantiator to emit post-body AssertEq constraints
    /// tying public output wires to their body-computed values.
    pub output_names: HashSet<String>,
    /// Template parameter values from `component main = Template(arg1, arg2, ...)`.
    /// Maps parameter names to their constant values.
    pub capture_values: HashMap<String, u64>,
    /// Warnings emitted during compilation (constraint analysis, version checks).
    /// The caller is responsible for rendering these via `DiagnosticRenderer`.
    pub warnings: Vec<Diagnostic>,
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
    let (program, warnings) = load_and_validate_program(path, library_dirs)?;
    compile_program_with_warnings(&program, warnings)
}

/// Shared pipeline between [`compile_file`] and
/// [`compile_template_library`]: resolve includes, surface parse
/// errors, validate the version pragma, and run constraint analysis.
///
/// Returns the flattened [`ast::CircomProgram`] plus any non-fatal
/// warnings emitted by the constraint analyzer. Hard errors short-circuit
/// the pipeline via the appropriate [`CircomError`] variant.
fn load_and_validate_program(
    path: &Path,
    library_dirs: &[PathBuf],
) -> Result<(ast::CircomProgram, Vec<Diagnostic>), CircomError> {
    let resolved = analysis::include_resolver::resolve_includes(path, library_dirs)
        .map_err(CircomError::IncludeError)?;

    // Surface parse-time errors in the root or any include.
    let parse_errs: Vec<&Diagnostic> = resolved
        .diagnostics
        .iter()
        .filter(|d| d.severity == diagnostics::Severity::Error)
        .collect();
    if !parse_errs.is_empty() {
        return Err(CircomError::ParseError(
            parse_errs.into_iter().cloned().collect(),
        ));
    }

    let program = ast::CircomProgram {
        version: resolved.version,
        custom_templates: resolved.custom_templates,
        includes: Vec::new(), // Already resolved
        definitions: resolved.definitions,
        main_component: resolved.main_component,
    };

    let warnings = validate_program(&program)?;
    Ok((program, warnings))
}

/// Run the non-parse validation passes on an already-parsed
/// [`ast::CircomProgram`]: version pragma sanity and constraint
/// analysis. Returns non-fatal warnings; errors become the
/// appropriate [`CircomError`] variant.
fn validate_program(program: &ast::CircomProgram) -> Result<Vec<Diagnostic>, CircomError> {
    validate_version_pragma(program);

    let reports = analysis::constraint_check::check_constraints(&program.definitions);
    let mut constraint_errors = Vec::new();
    let mut warnings = Vec::new();
    for report in reports {
        for diag in report.diagnostics {
            if diag.severity == diagnostics::Severity::Error {
                constraint_errors.push(diag);
            } else {
                warnings.push(diag);
            }
        }
    }
    if !constraint_errors.is_empty() {
        return Err(CircomError::ConstraintError(constraint_errors));
    }
    Ok(warnings)
}

/// Compile a `.circom` file as a reusable library of templates.
///
/// Unlike [`compile_file`], this entry point does **not** require a
/// `component main` declaration. It parses the file, resolves includes,
/// runs constraint analysis (to surface errors early), and extracts
/// library-level metadata for every declared template.
///
/// Template bodies are **not** lowered here — lowering is deferred to
/// each call site via [`instantiate_template_into`] so that parent
/// context (captures, constant inputs) can drive constant folding
/// through component inlining.
///
/// Library-mode compilation is the frontend for `import "x.circom" as P`
/// and `import { T1, T2 } from "x.circom"` in `.ach` files.
pub fn compile_template_library(
    path: &Path,
    library_dirs: &[PathBuf],
) -> Result<CircomLibrary, CircomError> {
    let (program, warnings) = load_and_validate_program(path, library_dirs)?;

    // Collect templates + functions.
    let mut templates = HashMap::new();
    let mut functions = HashMap::new();
    for def in &program.definitions {
        match def {
            ast::Definition::Template(t) => {
                let entry = library::extract_template_metadata(t, &HashMap::new());
                templates.insert(t.name.clone(), entry);
            }
            ast::Definition::Function(f) => {
                functions.insert(f.name.clone(), f.clone());
            }
            ast::Definition::Bus(_) => {
                // Buses are not yet supported as library entries.
            }
        }
    }

    let source_path = path.canonicalize().unwrap_or_else(|_| path.to_path_buf());

    Ok(CircomLibrary {
        source_path,
        templates,
        functions,
        program,
        warnings,
    })
}

/// Shared compilation pipeline: analysis + lowering. Runs validation.
fn compile_program(program: &ast::CircomProgram) -> Result<CircomCompileResult, CircomError> {
    let warnings = validate_program(program)?;
    compile_program_with_warnings(program, warnings)
}

/// Same as [`compile_program`] but skips validation — callers who
/// already ran [`load_and_validate_program`] (e.g. [`compile_file`])
/// pass its warnings through here to avoid doing the work twice.
fn compile_program_with_warnings(
    program: &ast::CircomProgram,
    warnings: Vec<Diagnostic>,
) -> Result<CircomCompileResult, CircomError> {
    // 1. Find main component and its template
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
    let lower_result = lowering::template::lower_template(template, Some(main), program)
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
        prove_ir: lower_result.prove_ir,
        output_names: lower_result.output_names,
        capture_values,
        warnings,
    })
}

#[cfg(test)]
mod lib_tests {
    use super::*;
    use std::io::Write;

    /// Write a `.circom` source string to a temp file and return its path.
    /// Each call gets a unique filename so parallel tests don't collide.
    fn write_temp_circom(name: &str, src: &str) -> PathBuf {
        let dir = std::env::temp_dir();
        let path = dir.join(format!(
            "ach_lib_test_{}_{}.circom",
            std::process::id(),
            name
        ));
        let mut f = std::fs::File::create(&path).expect("create temp circom");
        f.write_all(src.as_bytes()).expect("write temp circom");
        path
    }

    #[test]
    fn compile_template_library_single_file_no_main() {
        let src = r#"
            pragma circom 2.0.0;

            template Pair() {
                signal input a;
                signal input b;
                signal output c;
                c <== a + b;
            }

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
        "#;
        let path = write_temp_circom("no_main", src);
        let lib = compile_template_library(&path, &[]).expect("library should compile");

        assert!(lib.template("Pair").is_some());
        assert!(lib.template("Num2Bits").is_some());

        let pair = lib.template("Pair").unwrap();
        assert!(pair.params.is_empty());
        assert_eq!(pair.inputs.len(), 2);
        assert_eq!(pair.outputs.len(), 1);

        let n2b = lib.template("Num2Bits").unwrap();
        assert_eq!(n2b.params, vec!["n".to_string()]);
        assert!(matches!(
            n2b.outputs[0].dimensions[0],
            library::DimensionExpr::Param(ref p) if p == "n"
        ));

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn compile_template_library_with_function() {
        let src = r#"
            pragma circom 2.0.0;

            function nbits(a) {
                var n = 1; var r = 0;
                while (n - 1 < a) { r++; n *= 2; }
                return r;
            }

            template T(maxval) {
                var nb = nbits(maxval);
                signal input in;
                signal output out[nb];
            }
        "#;
        let path = write_temp_circom("with_fn", src);
        let lib = compile_template_library(&path, &[]).expect("library should compile");

        assert!(lib.function("nbits").is_some());
        assert!(lib.template("T").is_some());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn compile_template_library_ignores_main_component() {
        // Even if the file declares component main, library mode should
        // still extract templates as reusable metadata without failing.
        let src = r#"
            pragma circom 2.0.0;

            template Square() {
                signal input x;
                signal output y;
                y <== x * x;
            }

            component main = Square();
        "#;
        let path = write_temp_circom("with_main", src);
        let lib = compile_template_library(&path, &[]).expect("library should compile");

        assert!(lib.template("Square").is_some());
        // Main component is preserved in the AST but not required.
        assert!(lib.program.main_component.is_some());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn compile_template_library_parse_error() {
        let src = "this is not circom at all @#$%";
        let path = write_temp_circom("broken", src);
        let result = compile_template_library(&path, &[]);
        // Lexer-level errors are surfaced through the include resolver as
        // IncludeError::Parse, while recovered-parser errors go through
        // ParseError. Either shape is acceptable here — the important
        // part is that compilation is rejected.
        assert!(
            matches!(
                result,
                Err(CircomError::ParseError(_)) | Err(CircomError::IncludeError(_))
            ),
            "expected ParseError or IncludeError, got {result:?}"
        );
        let _ = std::fs::remove_file(&path);
    }
}
