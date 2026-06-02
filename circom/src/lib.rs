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
//! let program = prove_ir.instantiate_lysis(&inputs)?;
//! ```

pub mod analysis;
pub mod ast;
pub mod lexer;
pub mod library;
// pub(crate) so lib.rs can access lowering::utils::const_eval_u64
pub(crate) mod lowering;
pub mod parser;
pub mod token;
mod version;
pub mod witness;

pub use library::{
    evaluate_template_witness, instantiate_template_into, CircomLibrary, CircomTemplateEntry,
    DimensionExpr, InstantiationError, LibraryError, SignalSig, TemplateInstantiation,
    TemplateOutput, TemplateOutputValue, WitnessEvalError,
};

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};

use diagnostics::Diagnostic;
use ir_forge::types::ProveIR;

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
                // Render the full diagnostic — including primary span — so
                // panics from `compile_file().unwrap()` give the reader a
                // file:line:col they can grep, not just a bare message that
                // hides which of dozens of like-named signals tripped.
                for (i, d) in diags.iter().enumerate() {
                    if i > 0 {
                        f.write_str("\n")?;
                    }
                    write!(f, "{d}")?;
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
///
/// Pairs with [`ProveIR::instantiate_lysis_with_outputs`] (or the
/// no-outputs `instantiate_lysis`) to walk the rolled loops through
/// the Walker. Loops with loop-var-indexed signal writes stay rolled
/// at lowering time so the Lysis lifter can per-iteration unfold them
/// via `SymbolicIndexedEffect` rather than amplifying the body N
/// times.
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
    version::validate_version_pragma(program);

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

/// Lower a library-resident template through the For-preserving
/// pipeline so a dispatch caller can inline the body without the
/// eager loop unrolling that walks per-iter signal arrays into
/// flat scalars. Captures are pre-bound from the call's template
/// args. Signal inputs are wired by the caller via name mangling
/// against `parent_prefix`.
///
/// Bit-width inference runs after the body lowering so `Decompose`
/// widths narrow against the captures — the walker would otherwise
/// reject wide leaves even with `For` loops preserved.
pub fn lower_library_template(
    library: &CircomLibrary,
    template_name: &str,
    captures: std::collections::HashMap<String, ir_forge::types::FieldConst>,
) -> Result<lowering::template::LowerTemplateResult, CircomError> {
    let template = library
        .program
        .definitions
        .iter()
        .find_map(|d| match d {
            ast::Definition::Template(t) if t.name == template_name => Some(t),
            _ => None,
        })
        .ok_or_else(|| CircomError::MainTemplateNotFound(template_name.to_string()))?;

    let mut lower_result = lowering::template::lower_template_with_captures(
        template,
        &captures,
        &[],
        &library.program,
    )
    .map_err(CircomError::LoweringError)?;

    let bool_widths = lowering::bit_width::scan_bool_constraints(&lower_result.prove_ir);
    let signal_widths =
        lowering::bit_width::propagate_let_widths(&lower_result.prove_ir, bool_widths);
    let inference_ctx = lowering::bit_width::InferenceCtx {
        param_values: Some(&captures),
        known_constants: None,
        signal_widths: Some(&signal_widths),
    };
    lowering::bit_width::rewrite_num_bits_in_prove_ir(&mut lower_result.prove_ir, &inference_ctx);
    // Deferred component bodies are not in `prove_ir.body`; give them
    // the same width treatment so their instantiate-time expansion is
    // constraint-identical to an inlined copy.
    lowering::bit_width::rewrite_num_bits_in_component_bodies(
        &mut lower_result.prove_ir,
        Some(&captures),
    );

    Ok(lower_result)
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
    let mut lower_result = lowering::template::lower_template(template, Some(main), program)
        .map_err(CircomError::LoweringError)?;

    // 5. Extract capture values from main component template args.
    //    Done BEFORE the bit-width pass so they can feed the
    //    inference context — a `Capture(name)` operand to a Shift
    //    whose value is, e.g., 64 should infer as `Exact(7)` instead
    //    of falling back to `Field` (254). Without this, even one
    //    such shift produces a `SymbolicShift(num_bits=254)` (cost
    //    255) that on its own exceeds the Lysis frame cap.
    let mut capture_values = HashMap::new();
    let mut capture_field_consts: HashMap<String, ir_forge::types::FieldConst> = HashMap::new();
    for (i, param) in template.params.iter().enumerate() {
        if let Some(arg_expr) = main.template_args.get(i) {
            if let Some(val) = lowering::utils::const_eval_u64(arg_expr) {
                capture_values.insert(param.clone(), val);
                capture_field_consts
                    .insert(param.clone(), ir_forge::types::FieldConst::from_u64(val));
            }
        }
    }

    // 6. Bit-width inference rewriter — tightens `num_bits` /
    //    `max_bits` fields where the operand's actual range is
    //    provably narrower than the conservative
    //    `DEFAULT_MAX_BITS = 254` default. Sound: only ever
    //    decreases.
    //
    //    Stage 2C: scan the IR for Num2Bits-style bool constraints
    //    (`x * (x - 1) === 0`) and register the constrained signals
    //    as `Exact(1)` in a `SignalWidths` side-table. The rewriter
    //    consults this table when resolving `Input`/`Var` operands,
    //    enabling tight bit-width derivation for SHA-256-shaped
    //    circuits whose accumulator widths chain through the bit
    //    signals.
    let bool_widths = lowering::bit_width::scan_bool_constraints(&lower_result.prove_ir);
    let signal_widths =
        lowering::bit_width::propagate_let_widths(&lower_result.prove_ir, bool_widths);
    if std::env::var("BITWIDTH_TRACE").is_ok() {
        eprintln!(
            "[bitwidth] scan + let-propagation populated {} signal widths",
            signal_widths.len()
        );
    }
    let inference_ctx = lowering::bit_width::InferenceCtx {
        param_values: Some(&capture_field_consts),
        known_constants: None,
        signal_widths: Some(&signal_widths),
    };
    lowering::bit_width::rewrite_num_bits_in_prove_ir(&mut lower_result.prove_ir, &inference_ctx);
    // Deferred component bodies are not in `prove_ir.body`; give them
    // the same width treatment so their instantiate-time expansion is
    // constraint-identical to an inlined copy.
    lowering::bit_width::rewrite_num_bits_in_component_bodies(
        &mut lower_result.prove_ir,
        Some(&capture_field_consts),
    );

    Ok(CircomCompileResult {
        prove_ir: lower_result.prove_ir,
        output_names: lower_result.output_names,
        capture_values,
        warnings,
    })
}

#[cfg(test)]
mod lib_tests;
