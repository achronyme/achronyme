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

use diagnostics::Span;
use ir::prove_ir::types::{CircuitExpr, CircuitNode, FieldConst};
use memory::{FieldBackend, FieldElement};

use crate::ast;
use crate::lowering::components::inline_component_body_with_const_inputs;
use crate::lowering::context::LoweringContext;
use crate::lowering::template::lower_template;
use crate::lowering::utils::{const_eval_u64, const_eval_with_params};
use crate::witness::{compute_witness_hints_with_captures, WitnessError};

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

/// Extract library-level metadata (params, input/output signatures) from a
/// parsed [`ast::TemplateDef`].
///
/// `known_params` may contain values for some template parameters already
/// resolved by the caller (e.g. when the parent component passes concrete
/// captures down). Any parameter referenced in a signal dimension that is
/// present in `known_params` is folded into a [`DimensionExpr::Const`];
/// simple parameter references not yet resolved become
/// [`DimensionExpr::Param`], and anything more complex is kept as
/// [`DimensionExpr::Expr`] for later resolution at instantiation time.
///
/// This only walks top-level statements of the template body — nested
/// `if` / `for` blocks are not descended into, because Circom requires
/// `signal input` and `signal output` declarations at the top level of
/// a template.
pub fn extract_template_metadata(
    template: &ast::TemplateDef,
    known_params: &HashMap<String, FieldConst>,
) -> CircomTemplateEntry {
    let mut inputs = Vec::new();
    let mut outputs = Vec::new();

    for stmt in &template.body.stmts {
        if let ast::Stmt::SignalDecl {
            signal_type,
            declarations,
            ..
        } = stmt
        {
            let bucket = match signal_type {
                ast::SignalType::Input => Some(&mut inputs),
                ast::SignalType::Output => Some(&mut outputs),
                ast::SignalType::Intermediate => None,
            };
            let Some(bucket) = bucket else { continue };
            for decl in declarations {
                bucket.push(SignalSig {
                    name: decl.name.clone(),
                    dimensions: decl
                        .dimensions
                        .iter()
                        .map(|d| resolve_dimension(d, &template.params, known_params))
                        .collect(),
                });
            }
        }
    }

    CircomTemplateEntry {
        name: template.name.clone(),
        params: template.params.clone(),
        inputs,
        outputs,
    }
}

/// Result of inlining a Circom template into a parent circuit body.
#[derive(Clone, Debug)]
pub struct TemplateInstantiation {
    /// The circuit nodes to append to the parent body, in order.
    ///
    /// Contains the Let bindings that wire signal inputs to the
    /// sub-template's mangled signal names, followed by the mangled
    /// template body itself.
    pub body: Vec<CircuitNode>,
    /// One entry per declared signal output of the template.
    ///
    /// For scalar outputs the value is a `CircuitExpr::Var` pointing
    /// at the mangled output name in the parent's scope. For array
    /// outputs, the map contains one entry per element with the
    /// suffixed name (e.g. `out_0`, `out_1`, ...).
    pub outputs: HashMap<String, CircuitExpr>,
}

/// Reason an instantiation was rejected.
#[derive(Clone, Debug)]
pub enum InstantiationError {
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
    /// An input signal was not wired by the caller.
    MissingSignalInput { template: String, signal: String },
    /// An array-valued signal output had an unresolved dimension
    /// (the caller did not pass a concrete value for a template
    /// parameter referenced by the output's dimension).
    UnresolvedOutputDimension { template: String, signal: String },
    /// The underlying lowering step failed.
    Lowering(String),
}

impl std::fmt::Display for InstantiationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnknownTemplate { name, available } => {
                write!(
                    f,
                    "circom library has no template `{name}`; available: {}",
                    available.join(", ")
                )
            }
            Self::ParamCountMismatch {
                template,
                expected,
                got,
            } => write!(
                f,
                "template `{template}` expects {expected} template parameter(s), got {got}"
            ),
            Self::MissingSignalInput { template, signal } => write!(
                f,
                "template `{template}` requires signal input `{signal}` which was not provided"
            ),
            Self::UnresolvedOutputDimension { template, signal } => write!(
                f,
                "output `{signal}` of template `{template}` has an unresolved array dimension"
            ),
            Self::Lowering(msg) => write!(f, "lowering failed: {msg}"),
        }
    }
}

impl std::error::Error for InstantiationError {}

/// Instantiate a Circom template into a parent circuit body.
///
/// Lowering happens on demand against the library's own AST. `template_args`
/// bind template parameters in declaration order; `signal_inputs` wires
/// each declared input signal to an expression from the caller's scope
/// (typically a `CircuitExpr::Var` referencing an `.ach`-side binding,
/// or a `CircuitExpr::Const` for compile-time-known values, which are
/// propagated through the sub-template for O1/O2-friendly constraint
/// generation).
///
/// Name mangling: all signals and locals inside the inlined body are
/// prefixed with `parent_prefix` + `_`. The returned
/// [`TemplateInstantiation::outputs`] map uses those mangled names so
/// callers can emit `result.out` access.
pub fn instantiate_template_into(
    library: &CircomLibrary,
    template_name: &str,
    template_args: &[FieldConst],
    signal_inputs: &HashMap<String, CircuitExpr>,
    parent_prefix: &str,
    span: &Span,
) -> Result<TemplateInstantiation, InstantiationError> {
    // 1. Locate the template in the library's AST.
    let template = library
        .program
        .definitions
        .iter()
        .find_map(|d| match d {
            ast::Definition::Template(t) if t.name == template_name => Some(t),
            _ => None,
        })
        .ok_or_else(|| InstantiationError::UnknownTemplate {
            name: template_name.to_string(),
            available: library.templates.keys().cloned().collect::<Vec<_>>(),
        })?;

    if template_args.len() != template.params.len() {
        return Err(InstantiationError::ParamCountMismatch {
            template: template_name.to_string(),
            expected: template.params.len(),
            got: template_args.len(),
        });
    }

    // 2. Re-extract metadata with the concrete template args folded in so
    //    that output dimensions can be enumerated as scalar names.
    let mut known_params = HashMap::new();
    for (name, fc) in template.params.iter().zip(template_args.iter()) {
        known_params.insert(name.clone(), *fc);
    }
    let entry = extract_template_metadata(template, &known_params);

    // 3. Wire signal inputs: emit a Let binding per input, splitting
    //    compile-time constants into `const_inputs` for propagation.
    let mut body = Vec::new();
    let mut const_inputs: HashMap<String, FieldConst> = HashMap::new();

    for input in &entry.inputs {
        if !input.is_scalar() {
            // TODO (Phase 1.4+): support array-valued inputs by expanding
            // to one Let per element. For now only scalars are supported.
            return Err(InstantiationError::Lowering(format!(
                "array signal inputs are not yet supported; `{}.{}` is an array",
                template_name, input.name
            )));
        }
        let expr = signal_inputs.get(&input.name).ok_or_else(|| {
            InstantiationError::MissingSignalInput {
                template: template_name.to_string(),
                signal: input.name.clone(),
            }
        })?;

        // Propagate compile-time-known inputs into the sub-template
        // so the lowerer emits `Const` instead of `Input` for them.
        if let CircuitExpr::Const(fc) = expr {
            const_inputs.insert(input.name.clone(), *fc);
        }

        let mangled = format!("{parent_prefix}_{}", input.name);
        body.push(CircuitNode::Let {
            name: mangled,
            value: expr.clone(),
            span: None,
        });
    }

    // 4. Build a fresh LoweringContext bound to the library's program and
    //    inline the template body.
    let mut ctx = LoweringContext::from_program(&library.program);
    let template_arg_exprs: Vec<CircuitExpr> = template_args
        .iter()
        .map(|fc| CircuitExpr::Const(*fc))
        .collect();

    let inlined = inline_component_body_with_const_inputs(
        parent_prefix,
        template,
        &template_arg_exprs,
        &HashMap::new(), // array_args: none for now
        &const_inputs,
        &mut ctx,
        span,
    )
    .map_err(|e| InstantiationError::Lowering(e.to_string()))?;

    body.extend(inlined);

    // 5. Build the outputs map. Scalar outputs map to a single Var;
    //    array outputs produce one entry per element using the stride
    //    encoding the rest of the lowering pipeline already uses
    //    (`name_i`, or for multi-dim `name_i_j...`). Dimensions must be
    //    resolvable against the concrete template args.
    let mut outputs = HashMap::new();
    for out in &entry.outputs {
        if out.is_scalar() {
            outputs.insert(
                out.name.clone(),
                CircuitExpr::Var(format!("{parent_prefix}_{}", out.name)),
            );
            continue;
        }
        let dims = resolve_output_dims(&out.dimensions).ok_or_else(|| {
            InstantiationError::UnresolvedOutputDimension {
                template: template_name.to_string(),
                signal: out.name.clone(),
            }
        })?;
        for index in iter_multi_index(&dims) {
            let suffix = index
                .iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join("_");
            let key = format!("{}_{}", out.name, suffix);
            outputs.insert(
                key.clone(),
                CircuitExpr::Var(format!("{parent_prefix}_{key}")),
            );
        }
    }

    Ok(TemplateInstantiation { body, outputs })
}

/// Reason a VM-mode witness evaluation was rejected.
#[derive(Debug)]
pub enum WitnessEvalError {
    /// The requested template does not exist in the library.
    UnknownTemplate {
        name: String,
        available: Vec<String>,
    },
    /// Template argument count does not match `template.params`.
    ParamCountMismatch {
        template: String,
        expected: usize,
        got: usize,
    },
    /// Lowering to ProveIR failed.
    Lowering(String),
    /// Witness computation failed (assertion, missing input, etc.).
    Witness(WitnessError),
    /// An output's array dimension could not be resolved from the template
    /// parameters — typically means the caller passed the wrong captures
    /// or the template has an unsupported symbolic dimension.
    UnresolvedOutputDimension { template: String, signal: String },
    /// Output signal value was not populated by the witness hint pass.
    /// Usually indicates that the template body relies on values this
    /// evaluator cannot reconstruct off-circuit.
    MissingOutput { template: String, signal: String },
}

impl std::fmt::Display for WitnessEvalError {
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
            Self::Lowering(msg) => write!(f, "lowering failed: {msg}"),
            Self::Witness(e) => write!(f, "witness computation failed: {e}"),
            Self::UnresolvedOutputDimension { template, signal } => write!(
                f,
                "output `{signal}` of template `{template}` has an unresolved array dimension"
            ),
            Self::MissingOutput { template, signal } => write!(
                f,
                "witness evaluator did not produce a value for `{template}.{signal}`"
            ),
        }
    }
}

impl std::error::Error for WitnessEvalError {}

/// Evaluate a Circom template in VM mode (witness-only, no constraint
/// generation) against concrete inputs and template parameter values.
///
/// This is the runtime entry point used when an `.ach` file calls an
/// imported Circom template in VM mode, e.g.:
///
/// ```ach
/// import "poseidon.circom" as P
/// let h = P.Poseidon(2)([0p1, 0p2])   // runs this evaluator
/// ```
///
/// `template_args` are the template parameters in declaration order
/// (e.g. `[2]` for `Poseidon(2)`). `signal_inputs` is keyed by raw
/// signal input names — scalar inputs use the declared name, array
/// inputs use the same `name_i` suffix convention as the rest of the
/// lowering pipeline (e.g. `in_0`, `in_1`, ...).
///
/// Returns a map keyed by output name (scalars) or by `name_i` /
/// `name_i_j` (multi-dim arrays).
pub fn evaluate_template_witness<F: FieldBackend>(
    library: &CircomLibrary,
    template_name: &str,
    template_args: &[u64],
    signal_inputs: &HashMap<String, FieldElement<F>>,
) -> Result<HashMap<String, FieldElement<F>>, WitnessEvalError> {
    // 1. Locate the template.
    let template = library
        .program
        .definitions
        .iter()
        .find_map(|d| match d {
            ast::Definition::Template(t) if t.name == template_name => Some(t),
            _ => None,
        })
        .ok_or_else(|| WitnessEvalError::UnknownTemplate {
            name: template_name.to_string(),
            available: library.templates.keys().cloned().collect(),
        })?;

    if template_args.len() != template.params.len() {
        return Err(WitnessEvalError::ParamCountMismatch {
            template: template_name.to_string(),
            expected: template.params.len(),
            got: template_args.len(),
        });
    }

    // 2. Synthesize a throwaway MainComponent whose template_args are
    //    numeric literals, so `lower_template` can seed its own
    //    param_values via the existing code path without us adding a
    //    parallel entry point.
    let synth_span = Span {
        byte_start: 0,
        byte_end: 0,
        line_start: 1,
        col_start: 1,
        line_end: 1,
        col_end: 1,
    };
    let fake_main = ast::MainComponent {
        public_signals: Vec::new(),
        template_name: template.name.clone(),
        template_args: template_args
            .iter()
            .map(|v| ast::Expr::Number {
                value: v.to_string(),
                span: synth_span.clone(),
            })
            .collect(),
        span: synth_span,
    };

    // 3. Lower the template to ProveIR against the synthesized main.
    let lowered = lower_template(template, Some(&fake_main), &library.program)
        .map_err(|e| WitnessEvalError::Lowering(e.to_string()))?;

    // 4. Run the witness hint pass.
    let captures: HashMap<String, u64> = template
        .params
        .iter()
        .zip(template_args.iter())
        .map(|(name, &v)| (name.clone(), v))
        .collect();
    let env = compute_witness_hints_with_captures(&lowered.prove_ir, signal_inputs, &captures)
        .map_err(WitnessEvalError::Witness)?;

    // 5. Extract outputs using metadata re-extracted against the concrete
    //    captures, so array dimensions resolve to Const.
    let mut known_params = HashMap::new();
    for (name, &v) in template.params.iter().zip(template_args.iter()) {
        known_params.insert(name.clone(), FieldConst::from_u64(v));
    }
    let entry = extract_template_metadata(template, &known_params);

    let mut outputs = HashMap::new();
    for out in &entry.outputs {
        if out.is_scalar() {
            match env.get(&out.name) {
                Some(&val) => {
                    outputs.insert(out.name.clone(), val);
                }
                None => {
                    return Err(WitnessEvalError::MissingOutput {
                        template: template_name.to_string(),
                        signal: out.name.clone(),
                    });
                }
            }
            continue;
        }
        let dims = resolve_output_dims(&out.dimensions).ok_or_else(|| {
            WitnessEvalError::UnresolvedOutputDimension {
                template: template_name.to_string(),
                signal: out.name.clone(),
            }
        })?;
        for index in iter_multi_index(&dims) {
            let suffix = index
                .iter()
                .map(|i| i.to_string())
                .collect::<Vec<_>>()
                .join("_");
            let key = format!("{}_{}", out.name, suffix);
            match env.get(&key) {
                Some(&val) => {
                    outputs.insert(key, val);
                }
                None => {
                    return Err(WitnessEvalError::MissingOutput {
                        template: template_name.to_string(),
                        signal: key,
                    });
                }
            }
        }
    }

    Ok(outputs)
}

fn resolve_output_dims(dims: &[DimensionExpr]) -> Option<Vec<u64>> {
    let mut out = Vec::with_capacity(dims.len());
    for d in dims {
        match d {
            DimensionExpr::Const(n) => out.push(*n),
            _ => return None,
        }
    }
    Some(out)
}

fn iter_multi_index(dims: &[u64]) -> Vec<Vec<u64>> {
    let mut result = vec![Vec::new()];
    for &d in dims {
        let mut next = Vec::with_capacity(result.len() * d as usize);
        for prefix in &result {
            for i in 0..d {
                let mut p = prefix.clone();
                p.push(i);
                next.push(p);
            }
        }
        result = next;
    }
    result
}

fn resolve_dimension(
    expr: &ast::Expr,
    template_params: &[String],
    known_params: &HashMap<String, FieldConst>,
) -> DimensionExpr {
    // 1. Literal compile-time constant.
    if let Some(n) = const_eval_u64(expr) {
        return DimensionExpr::Const(n);
    }
    // 2. Resolvable against already-known params.
    if !known_params.is_empty() {
        if let Some(n) = const_eval_with_params(expr, known_params).and_then(|fc| fc.to_u64()) {
            return DimensionExpr::Const(n);
        }
    }
    // 3. Simple reference to an as-yet unresolved template parameter.
    if let ast::Expr::Ident { name, .. } = expr {
        if template_params.iter().any(|p| p == name) {
            return DimensionExpr::Param(name.clone());
        }
    }
    // 4. Fallback: preserve the raw expression.
    DimensionExpr::Expr(Box::new(expr.clone()))
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

    fn parse_template(src: &str, name: &str) -> ast::TemplateDef {
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

    #[test]
    fn extract_metadata_scalar_signals() {
        let t = parse_template(
            r#"
            template Pair() {
                signal input a;
                signal input b;
                signal output c;
                c <== a + b;
            }
            "#,
            "Pair",
        );
        let meta = extract_template_metadata(&t, &HashMap::new());
        assert_eq!(meta.name, "Pair");
        assert!(meta.params.is_empty());
        assert_eq!(meta.inputs.len(), 2);
        assert!(meta.inputs[0].is_scalar());
        assert_eq!(meta.inputs[0].name, "a");
        assert_eq!(meta.inputs[1].name, "b");
        assert_eq!(meta.outputs.len(), 1);
        assert_eq!(meta.outputs[0].name, "c");
        assert!(meta.outputs[0].is_scalar());
    }

    #[test]
    fn extract_metadata_parametric_output() {
        let t = parse_template(
            r#"
            template Num2Bits(n) {
                signal input in;
                signal output out[n];
            }
            "#,
            "Num2Bits",
        );
        let meta = extract_template_metadata(&t, &HashMap::new());
        assert_eq!(meta.params, vec!["n".to_string()]);
        assert_eq!(meta.outputs.len(), 1);
        let out = &meta.outputs[0];
        assert_eq!(out.dimensions.len(), 1);
        match &out.dimensions[0] {
            DimensionExpr::Param(p) => assert_eq!(p, "n"),
            other => panic!("expected Param, got {other:?}"),
        }
    }

    #[test]
    fn extract_metadata_known_params_folded_to_const() {
        let t = parse_template(
            r#"
            template T(n) {
                signal input in[n];
                signal output out[n];
            }
            "#,
            "T",
        );
        let mut known = HashMap::new();
        known.insert("n".to_string(), FieldConst::from_u64(8));
        let meta = extract_template_metadata(&t, &known);
        assert!(matches!(
            meta.inputs[0].dimensions[0],
            DimensionExpr::Const(8)
        ));
        assert!(matches!(
            meta.outputs[0].dimensions[0],
            DimensionExpr::Const(8)
        ));
    }

    #[test]
    fn extract_metadata_literal_array_dim_is_const() {
        let t = parse_template(
            r#"
            template Hasher() {
                signal input msg[16];
                signal output hash;
            }
            "#,
            "Hasher",
        );
        let meta = extract_template_metadata(&t, &HashMap::new());
        assert!(matches!(
            meta.inputs[0].dimensions[0],
            DimensionExpr::Const(16)
        ));
    }

    #[test]
    fn extract_metadata_computed_expr_dim_preserved() {
        let t = parse_template(
            r#"
            template T(n) {
                signal input in[n + 1];
                signal output out;
            }
            "#,
            "T",
        );
        // With no known params, `n + 1` can't fold and isn't a plain Ident,
        // so we expect the raw Expr variant.
        let meta = extract_template_metadata(&t, &HashMap::new());
        assert!(matches!(
            meta.inputs[0].dimensions[0],
            DimensionExpr::Expr(_)
        ));
        // With a known param, it should fold to a const.
        let mut known = HashMap::new();
        known.insert("n".to_string(), FieldConst::from_u64(4));
        let meta = extract_template_metadata(&t, &known);
        assert!(matches!(
            meta.inputs[0].dimensions[0],
            DimensionExpr::Const(5)
        ));
    }

    fn make_library(src: &str) -> CircomLibrary {
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
        }
    }

    #[test]
    fn instantiate_unknown_template_errors() {
        let lib = make_library(
            r#"
            template Square() {
                signal input x;
                signal output y;
                y <== x * x;
            }
            "#,
        );
        let span = dummy_span();
        let result = instantiate_template_into(&lib, "Cube", &[], &HashMap::new(), "c0", &span);
        assert!(matches!(
            result,
            Err(InstantiationError::UnknownTemplate { .. })
        ));
    }

    #[test]
    fn instantiate_param_count_mismatch() {
        let lib = make_library(
            r#"
            template Num2Bits(n) {
                signal input in;
                signal output out[n];
            }
            "#,
        );
        let span = dummy_span();
        // Missing the `n` argument.
        let result = instantiate_template_into(&lib, "Num2Bits", &[], &HashMap::new(), "c0", &span);
        assert!(matches!(
            result,
            Err(InstantiationError::ParamCountMismatch {
                expected: 1,
                got: 0,
                ..
            })
        ));
    }

    #[test]
    fn instantiate_missing_signal_input() {
        let lib = make_library(
            r#"
            template Square() {
                signal input x;
                signal output y;
                y <== x * x;
            }
            "#,
        );
        let span = dummy_span();
        let result = instantiate_template_into(&lib, "Square", &[], &HashMap::new(), "c0", &span);
        assert!(matches!(
            result,
            Err(InstantiationError::MissingSignalInput { .. })
        ));
    }

    #[test]
    fn instantiate_scalar_template_produces_body_and_output() {
        let lib = make_library(
            r#"
            template Square() {
                signal input x;
                signal output y;
                y <== x * x;
            }
            "#,
        );
        let span = dummy_span();
        let mut inputs = HashMap::new();
        inputs.insert("x".to_string(), CircuitExpr::Var("ach_x".to_string()));

        let inst = instantiate_template_into(&lib, "Square", &[], &inputs, "c0", &span)
            .expect("instantiation should succeed");

        // First node is the Let wiring the input.
        match &inst.body[0] {
            CircuitNode::Let { name, value, .. } => {
                assert_eq!(name, "c0_x");
                assert!(matches!(value, CircuitExpr::Var(v) if v == "ach_x"));
            }
            other => panic!("expected Let, got {other:?}"),
        }
        // Output is mangled and available in the outputs map.
        assert_eq!(inst.outputs.len(), 1);
        let y = inst.outputs.get("y").expect("y output");
        assert!(matches!(y, CircuitExpr::Var(v) if v == "c0_y"));
        // The body must contain more than just the Let (template body
        // produces additional nodes).
        assert!(inst.body.len() >= 2);
    }

    #[test]
    fn evaluate_witness_square_scalar() {
        use memory::Bn254Fr;
        let lib = make_library(
            r#"
            template Square() {
                signal input x;
                signal output y;
                y <== x * x;
            }
            "#,
        );
        let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
        inputs.insert("x".to_string(), FieldElement::<Bn254Fr>::from_u64(7));
        let outputs = evaluate_template_witness::<Bn254Fr>(&lib, "Square", &[], &inputs)
            .expect("eval should succeed");
        assert_eq!(outputs.len(), 1);
        let y = outputs.get("y").expect("y output");
        assert_eq!(*y, FieldElement::<Bn254Fr>::from_u64(49));
    }

    #[test]
    fn evaluate_witness_num2bits_array_output() {
        use memory::Bn254Fr;
        let lib = make_library(
            r#"
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
            "#,
        );
        let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
        // 13 = 0b1101 → bits: [1, 0, 1, 1] LSB first
        inputs.insert("in".to_string(), FieldElement::<Bn254Fr>::from_u64(13));
        let outputs = evaluate_template_witness::<Bn254Fr>(&lib, "Num2Bits", &[4], &inputs)
            .expect("eval should succeed");
        assert_eq!(outputs.len(), 4);
        let expected = [1u64, 0, 1, 1];
        for (i, bit) in expected.iter().enumerate() {
            let key = format!("out_{i}");
            let got = outputs.get(&key).expect("output present");
            assert_eq!(*got, FieldElement::<Bn254Fr>::from_u64(*bit), "bit {i}");
        }
    }

    #[test]
    fn evaluate_witness_unknown_template_errors() {
        use memory::Bn254Fr;
        let lib = make_library(
            r#"
            template Square() {
                signal input x;
                signal output y;
                y <== x * x;
            }
            "#,
        );
        let result = evaluate_template_witness::<Bn254Fr>(&lib, "Cube", &[], &HashMap::new());
        assert!(matches!(
            result,
            Err(WitnessEvalError::UnknownTemplate { .. })
        ));
    }

    #[test]
    fn evaluate_witness_param_count_mismatch() {
        use memory::Bn254Fr;
        let lib = make_library(
            r#"
            template Num2Bits(n) {
                signal input in;
                signal output out[n];
            }
            "#,
        );
        let mut inputs: HashMap<String, FieldElement<Bn254Fr>> = HashMap::new();
        inputs.insert("in".to_string(), FieldElement::<Bn254Fr>::from_u64(0));
        let result = evaluate_template_witness::<Bn254Fr>(&lib, "Num2Bits", &[], &inputs);
        assert!(matches!(
            result,
            Err(WitnessEvalError::ParamCountMismatch {
                expected: 1,
                got: 0,
                ..
            })
        ));
    }

    #[test]
    fn instantiate_parametric_array_output() {
        let lib = make_library(
            r#"
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
            "#,
        );
        let span = dummy_span();
        let mut inputs = HashMap::new();
        inputs.insert("in".to_string(), CircuitExpr::Var("x".to_string()));

        let inst = instantiate_template_into(
            &lib,
            "Num2Bits",
            &[FieldConst::from_u64(4)],
            &inputs,
            "c1",
            &span,
        )
        .expect("Num2Bits(4) should instantiate");

        // Four scalar outputs: out_0..out_3 as c1_out_{i}.
        for i in 0..4 {
            let key = format!("out_{i}");
            let expected = format!("c1_out_{i}");
            match inst.outputs.get(&key).expect("output present") {
                CircuitExpr::Var(v) => assert_eq!(v, &expected),
                other => panic!("expected Var, got {other:?}"),
            }
        }
        assert_eq!(inst.outputs.len(), 4);
    }

    #[test]
    fn extract_metadata_intermediate_signal_skipped() {
        let t = parse_template(
            r#"
            template T() {
                signal input a;
                signal tmp;
                signal output c;
                tmp <== a * a;
                c <== tmp + 1;
            }
            "#,
            "T",
        );
        let meta = extract_template_metadata(&t, &HashMap::new());
        assert_eq!(meta.inputs.len(), 1);
        assert_eq!(meta.outputs.len(), 1);
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
