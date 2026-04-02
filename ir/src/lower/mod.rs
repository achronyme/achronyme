use std::collections::{HashMap, HashSet};
use std::path::PathBuf;

use achronyme_parser::ast::*;
use achronyme_parser::parse_program as ast_parse_program;
use memory::{Bn254Fr, FieldBackend, FieldElement};

use crate::error::{span_box, IrError, OptSpan};
use crate::types::{Instruction, IrProgram, IrType, SsaVar, Visibility};

mod builtins;
mod exprs;
mod functions;
mod module;
mod stmts;

/// Maximum number of iterations allowed when statically unrolling a `for` loop.
/// Prevents DoS via `for i in 0..1000000` which would generate millions of IR instructions.
pub const MAX_UNROLL_ITERATIONS: u64 = 10_000;

/// Convert an AST span to a boxed SpanRange for error reporting.
pub(super) fn to_ir_span(span: &Span) -> OptSpan {
    span_box(Some(achronyme_parser::SpanRange::from(span)))
}

/// A value in the lowering environment: either a single SSA variable or an array.
#[derive(Clone, Debug)]
pub(super) enum EnvValue {
    Scalar(SsaVar),
    Array(Vec<SsaVar>),
}

/// A user-defined function stored for inlining.
#[derive(Clone, Debug)]
pub(super) struct FnDef {
    pub(super) params: Vec<TypedParam>,
    pub(super) body: Block,
    pub(super) return_type: Option<TypeAnnotation>,
}

/// Convert a `TypeAnnotation` to an `IrType` (scalar types only).
///
/// ```
/// use achronyme_parser::ast::TypeAnnotation;
/// use ir::IrLowering;
///
/// // This is a public helper used during lowering
/// let prog = IrLowering::lower_circuit("assert_eq(x, y)", &["x"], &["y"]).unwrap();
/// assert!(!prog.instructions.is_empty());
/// ```
pub(super) fn annotation_to_ir_type(ann: &TypeAnnotation) -> IrType {
    match ann.base {
        achronyme_parser::ast::BaseType::Field => IrType::Field,
        achronyme_parser::ast::BaseType::Bool => IrType::Bool,
        achronyme_parser::ast::BaseType::Int | achronyme_parser::ast::BaseType::String => {
            unreachable!("type `{}` is not valid in circuit context", ann.base)
        }
    }
}

/// Check if an inferred type is compatible with a declared type annotation.
/// `Bool` is a subtype of `Field` (booleans are 0/1 field elements).
pub(super) fn type_compatible(declared: IrType, inferred: IrType) -> bool {
    match (declared, inferred) {
        (IrType::Field, IrType::Bool) => true, // Bool is subtype of Field
        (a, b) => a == b,
    }
}

/// Parse declaration specs like `["x", "path[3]"]` into `[(name, optional_size)]`.
fn parse_decl_specs(specs: &[&str]) -> Result<Vec<(String, Option<usize>)>, IrError> {
    let mut result = Vec::new();
    for spec in specs {
        if let Some(bracket_pos) = spec.find('[') {
            let name = spec[..bracket_pos].to_string();
            let size_str = spec[bracket_pos + 1..].trim_end_matches(']');
            let size: usize = size_str
                .parse()
                .map_err(|_| IrError::parse_error(format!("invalid array size in `{spec}`")))?;
            result.push((name, Some(size)));
        } else {
            result.push((spec.to_string(), None));
        }
    }
    Ok(result)
}

/// Try to extract a small u64 from a FieldElement.
pub(super) fn field_to_u64<F: FieldBackend>(fe: &FieldElement<F>) -> Option<u64> {
    let limbs = fe.to_canonical();
    if limbs[1] != 0 || limbs[2] != 0 || limbs[3] != 0 {
        return None;
    }
    Some(limbs[0])
}

/// Lowers an Achronyme AST into an SSA IR program.
pub struct IrLowering<F: FieldBackend = Bn254Fr> {
    pub(super) program: IrProgram<F>,
    /// Maps variable names to their current value (scalar or array).
    pub(super) env: HashMap<String, EnvValue>,
    /// User-defined functions, inlined at each call site.
    pub(super) fn_table: HashMap<String, FnDef>,
    /// Tracks active function calls to detect recursion.
    pub(super) call_stack: HashSet<String>,
    /// Directory of the file being compiled (for resolving relative imports).
    pub base_path: Option<PathBuf>,
    /// Canonical paths of modules currently being loaded (cycle detection).
    pub(super) loading_modules: HashSet<PathBuf>,
    /// Canonical paths of modules already loaded → alias used for registration.
    pub(super) loaded_modules: HashMap<PathBuf, String>,
    /// Module prefix for resolving unqualified function calls during inlining.
    /// When inlining `mod::func`, this is set to `"mod"` so that calls to
    /// `helper()` inside the body resolve to `mod::helper`.
    pub(super) fn_call_prefix: Option<String>,
}

impl<F: FieldBackend> Default for IrLowering<F> {
    fn default() -> Self {
        Self::new()
    }
}

impl<F: FieldBackend> IrLowering<F> {
    pub fn new() -> Self {
        Self {
            program: IrProgram::new(),
            env: HashMap::new(),
            fn_table: HashMap::new(),
            call_stack: HashSet::new(),
            base_path: None,
            loading_modules: HashSet::new(),
            loaded_modules: HashMap::new(),
            fn_call_prefix: None,
        }
    }

    /// Record the source span for an input variable declaration.
    pub(super) fn record_input_span(&mut self, name: &str, span: &Span) {
        use achronyme_parser::diagnostic::SpanRange;
        self.program.input_spans.insert(
            name.to_string(),
            SpanRange::new(
                span.byte_start,
                span.byte_end,
                span.line_start,
                span.col_start,
                span.line_end,
                span.col_end,
            ),
        );
    }

    /// Declare a public input and emit an `Input` instruction.
    pub fn declare_public(&mut self, name: &str) -> SsaVar {
        let v = self.program.fresh_var();
        self.program.push(Instruction::Input {
            result: v,
            name: name.to_string(),
            visibility: Visibility::Public,
        });
        self.program.set_name(v, name.to_string());
        self.env.insert(name.to_string(), EnvValue::Scalar(v));
        v
    }

    /// Declare a witness input and emit an `Input` instruction.
    pub fn declare_witness(&mut self, name: &str) -> SsaVar {
        let v = self.program.fresh_var();
        self.program.push(Instruction::Input {
            result: v,
            name: name.to_string(),
            visibility: Visibility::Witness,
        });
        self.program.set_name(v, name.to_string());
        self.env.insert(name.to_string(), EnvValue::Scalar(v));
        v
    }

    /// Declare a public array of N inputs: `{name}_0` .. `{name}_{N-1}`.
    pub fn declare_public_array(&mut self, name: &str, size: usize) -> Vec<SsaVar> {
        let vars: Vec<SsaVar> = (0..size)
            .map(|i| {
                let elem_name = format!("{name}_{i}");
                let v = self.program.fresh_var();
                self.program.push(Instruction::Input {
                    result: v,
                    name: elem_name.clone(),
                    visibility: Visibility::Public,
                });
                self.program.set_name(v, elem_name);
                v
            })
            .collect();
        self.env
            .insert(name.to_string(), EnvValue::Array(vars.clone()));
        vars
    }

    /// Declare a witness array of N inputs: `{name}_0` .. `{name}_{N-1}`.
    pub fn declare_witness_array(&mut self, name: &str, size: usize) -> Vec<SsaVar> {
        let vars: Vec<SsaVar> = (0..size)
            .map(|i| {
                let elem_name = format!("{name}_{i}");
                let v = self.program.fresh_var();
                self.program.push(Instruction::Input {
                    result: v,
                    name: elem_name.clone(),
                    visibility: Visibility::Witness,
                });
                self.program.set_name(v, elem_name);
                v
            })
            .collect();
        self.env
            .insert(name.to_string(), EnvValue::Array(vars.clone()));
        vars
    }

    /// Parse and lower an Achronyme source string into an IR program.
    /// Public/witness inputs must be declared before calling this.
    pub fn lower(mut self, source: &str) -> Result<IrProgram<F>, IrError> {
        let (program, parse_errors) = ast_parse_program(source);
        if let Some(err) = parse_errors
            .iter()
            .find(|d| d.severity == achronyme_parser::Severity::Error)
        {
            return Err(IrError::ParseError(Box::new(err.clone())));
        }
        self.lower_program(&program)?;
        Ok(self.program)
    }

    /// Convenience: declare inputs and lower in one call.
    /// Names can include array syntax like `"path[3]"` to declare `path_0, path_1, path_2`.
    ///
    /// ```
    /// use ir::IrLowering;
    ///
    /// let prog = IrLowering::lower_circuit(
    ///     "assert_eq(x * y, z)",
    ///     &["z"],
    ///     &["x", "y"],
    /// ).unwrap();
    /// assert!(!prog.instructions.is_empty());
    /// ```
    /// Convenience: declare inputs, set base_path, and lower in one call.
    pub fn lower_circuit_with_base(
        source: &str,
        public: &[&str],
        witness: &[&str],
        base_path: PathBuf,
    ) -> Result<IrProgram<F>, IrError> {
        let pub_decls = parse_decl_specs(public)?;
        let wit_decls = parse_decl_specs(witness)?;

        let mut seen = HashSet::new();
        for (name, size) in pub_decls.iter().chain(wit_decls.iter()) {
            if let Some(n) = size {
                for i in 0..*n {
                    let flat = format!("{name}_{i}");
                    if !seen.insert(flat.clone()) {
                        return Err(IrError::DuplicateInput(flat));
                    }
                }
            } else if !seen.insert(name.clone()) {
                return Err(IrError::DuplicateInput(name.clone()));
            }
        }

        let mut lowering = IrLowering::new();
        lowering.base_path = Some(base_path);
        for (name, size) in &pub_decls {
            if let Some(n) = size {
                lowering.declare_public_array(name, *n);
            } else {
                lowering.declare_public(name);
            }
        }
        for (name, size) in &wit_decls {
            if let Some(n) = size {
                lowering.declare_witness_array(name, *n);
            } else {
                lowering.declare_witness(name);
            }
        }
        lowering.lower(source)
    }

    pub fn lower_circuit(
        source: &str,
        public: &[&str],
        witness: &[&str],
    ) -> Result<IrProgram<F>, IrError> {
        Self::lower_circuit_with_base(source, public, witness, PathBuf::from("."))
    }

    /// Parse a self-contained circuit source that uses in-source `public`/`witness`
    /// declarations. Two-pass: first collects declaration names (to ensure correct
    /// wire ordering: public first, then witness), then processes remaining statements.
    ///
    /// ```
    /// use ir::IrLowering;
    ///
    /// let (pub_names, wit_names, prog) = IrLowering::lower_self_contained(
    ///     "public x\nwitness y\nassert_eq(x, y)"
    /// ).unwrap();
    /// assert_eq!(pub_names, vec!["x"]);
    /// assert_eq!(wit_names, vec!["y"]);
    /// ```
    #[allow(clippy::type_complexity)]
    pub fn lower_self_contained(
        source: &str,
    ) -> Result<(Vec<String>, Vec<String>, IrProgram<F>), IrError> {
        Self::lower_self_contained_with_base(source, PathBuf::from("."))
    }

    /// Like `lower_self_contained` but with a base path for module resolution.
    #[allow(clippy::type_complexity)]
    pub fn lower_self_contained_with_base(
        source: &str,
        base_path: PathBuf,
    ) -> Result<(Vec<String>, Vec<String>, IrProgram<F>), IrError> {
        let (ast_program, parse_errors) = ast_parse_program(source);
        if let Some(err) = parse_errors
            .iter()
            .find(|d| d.severity == achronyme_parser::Severity::Error)
        {
            return Err(IrError::ParseError(Box::new(err.clone())));
        }

        let mut pub_decls: Vec<(String, Option<usize>, Option<TypeAnnotation>, Span)> = Vec::new();
        let mut wit_decls: Vec<(String, Option<usize>, Option<TypeAnnotation>, Span)> = Vec::new();
        for stmt in &ast_program.stmts {
            match stmt {
                Stmt::PublicDecl { names, span } => {
                    for decl in names {
                        pub_decls.push((
                            decl.name.clone(),
                            decl.array_size,
                            decl.type_ann.clone(),
                            span.clone(),
                        ));
                    }
                }
                Stmt::WitnessDecl { names, span } => {
                    for decl in names {
                        wit_decls.push((
                            decl.name.clone(),
                            decl.array_size,
                            decl.type_ann.clone(),
                            span.clone(),
                        ));
                    }
                }
                _ => {}
            }
        }

        let mut pub_names = Vec::new();
        for (name, size, _, _) in &pub_decls {
            if let Some(n) = size {
                for i in 0..*n {
                    pub_names.push(format!("{name}_{i}"));
                }
            } else {
                pub_names.push(name.clone());
            }
        }
        let mut wit_names = Vec::new();
        for (name, size, _, _) in &wit_decls {
            if let Some(n) = size {
                for i in 0..*n {
                    wit_names.push(format!("{name}_{i}"));
                }
            } else {
                wit_names.push(name.clone());
            }
        }

        let mut seen = HashSet::new();
        for name in pub_names.iter().chain(wit_names.iter()) {
            if !seen.insert(name.as_str()) {
                return Err(IrError::DuplicateInput(name.clone()));
            }
        }

        let mut lowering = IrLowering::new();
        lowering.base_path = Some(base_path);
        for (name, size, type_ann, span) in &pub_decls {
            lowering.record_input_span(name, span);
            if let Some(n) = size {
                let vars = lowering.declare_public_array(name, *n);
                if let Some(ann) = type_ann {
                    lowering.enforce_input_type_ann(ann, &vars);
                }
            } else {
                let v = lowering.declare_public(name);
                if let Some(ann) = type_ann {
                    lowering.enforce_input_type_ann(ann, &[v]);
                }
            }
        }
        for (name, size, type_ann, span) in &wit_decls {
            lowering.record_input_span(name, span);
            if let Some(n) = size {
                let vars = lowering.declare_witness_array(name, *n);
                if let Some(ann) = type_ann {
                    lowering.enforce_input_type_ann(ann, &vars);
                }
            } else {
                let v = lowering.declare_witness(name);
                if let Some(ann) = type_ann {
                    lowering.enforce_input_type_ann(ann, &[v]);
                }
            }
        }

        for stmt in &ast_program.stmts {
            match stmt {
                Stmt::PublicDecl { .. } | Stmt::WitnessDecl { .. } => {}
                _ => {
                    lowering.lower_stmt(stmt)?;
                }
            }
        }

        Ok((pub_names, wit_names, lowering.program))
    }
}
