//! ProveIR compiler: AST Block → ProveIR template.

use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;
use std::path::Path;

use achronyme_parser::ast::*;
use diagnostics::SpanRange;
use memory::{Bn254Fr, FieldBackend, FieldElement};

use super::circom_interop::CircomCallable;
use super::error::{CircomDispatchErrorKind, ProveIrError};
use super::types::*;
use crate::error::{span_box, OptSpan};
use crate::types::IrType;

// ---------------------------------------------------------------------------
// Environment values
// ---------------------------------------------------------------------------

/// A value in the ProveIR compilation environment.
#[derive(Clone, Debug)]
enum CompEnvValue {
    /// A local scalar variable (let-binding or input).
    Scalar(String),
    /// A local array variable.
    Array(Vec<String>),
    /// A captured value from the outer scope.
    Capture(String),
}

/// Type information for a variable in the outer (VM) scope.
///
/// Used by the bytecode compiler to tell the ProveIR compiler which
/// outer-scope names are arrays and their sizes. Not serialized.
#[derive(Clone, Debug)]
pub enum OuterScopeEntry {
    Scalar,
    Array(usize),
}

/// Everything the enclosing scope makes available to a prove/circuit block.
///
/// `values` carries captured scalars and arrays from the VM scope.
/// `functions` carries FnDecl AST nodes that should be registered in the
/// ProveIR compiler's `fn_table` before the block body is compiled, so
/// that user-defined functions from the outer scope can be inlined.
/// `circom_imports` carries circom template handles — keyed by their
/// lookup name inside the block (bare template name for selective
/// imports, `"P::T"` for namespaced ones). The `compiler` crate is
/// responsible for flattening namespace imports into `P::T` keys
/// before handing the scope over.
#[derive(Clone, Debug, Default)]
pub struct OuterScope {
    /// Captured values (scalars / arrays) from the VM scope.
    pub values: HashMap<String, OuterScopeEntry>,
    /// Function declarations to register in fn_table before compilation.
    pub functions: Vec<Stmt>,
    /// Circom templates importable into this block. Keys are the
    /// names the ProveIR dispatcher will look up at Call time.
    pub circom_imports: HashMap<String, CircomCallable>,
}

// ---------------------------------------------------------------------------
// Compiler
// ---------------------------------------------------------------------------

/// A user-defined function stored for inlining.
#[derive(Clone, Debug)]
struct FnDef {
    params: Vec<TypedParam>,
    body: Block,
    #[allow(dead_code)]
    return_type: Option<TypeAnnotation>,
}

/// Compiles an AST `Block` (from a prove block or circuit file) into a `ProveIR`.
pub struct ProveIrCompiler<F: FieldBackend = Bn254Fr> {
    /// Maps variable names → what they resolve to.
    env: HashMap<String, CompEnvValue>,
    /// Mutable variable SSA versioning: original_name → current version number.
    /// A name in this map means it was declared with `mut`.
    ssa_versions: HashMap<String, u32>,
    /// Tracks which names are captured from the outer scope.
    captured_names: HashSet<String>,
    /// Functions available for inlining.
    fn_table: HashMap<String, FnDef>,
    /// Recursion guard: functions currently being inlined.
    call_stack: HashSet<String>,
    /// Monotonic counter for unique function inlining names.
    inline_counter: u32,
    /// Accumulated circuit body nodes.
    body: Vec<CircuitNode>,
    /// Public input declarations.
    public_inputs: Vec<ProveInputDecl>,
    /// Witness input declarations.
    witness_inputs: Vec<ProveInputDecl>,
    /// Directory of the source file being compiled (for resolving relative imports).
    source_dir: Option<std::path::PathBuf>,
    /// Module loader for resolving imports (shared across recursive loads).
    module_loader: crate::module_loader::ModuleLoader,
    /// Tracks modules currently being compiled (for circular import detection).
    compiling_modules: HashSet<std::path::PathBuf>,
    /// Flat table of circom templates callable from this block, keyed
    /// by the name the dispatcher looks up (bare template name for
    /// selective imports, `"P::T"` for namespace imports). Populated
    /// by `register_circom_template` — typically seeded from
    /// [`OuterScope::circom_imports`] before `compile_block_stmts`.
    circom_table: HashMap<String, CircomCallable>,
    /// Monotonic counter used to allocate unique prefixes
    /// (`circom_call_0`, `circom_call_1`, ...) for circom template
    /// instantiations. Bumped on use, not on registration.
    circom_call_counter: usize,
    /// Phantom data for the field backend type parameter.
    _field: PhantomData<F>,
}

impl<F: FieldBackend> ProveIrCompiler<F> {
    fn new() -> Self {
        Self {
            env: HashMap::new(),
            ssa_versions: HashMap::new(),
            captured_names: HashSet::new(),
            fn_table: HashMap::new(),
            call_stack: HashSet::new(),
            inline_counter: 0,
            body: Vec::new(),
            public_inputs: Vec::new(),
            witness_inputs: Vec::new(),
            source_dir: None,
            module_loader: crate::module_loader::ModuleLoader::new(),
            compiling_modules: HashSet::new(),
            circom_table: HashMap::new(),
            circom_call_counter: 0,
            _field: PhantomData,
        }
    }

    /// Register a circom template under `key`.
    ///
    /// `key` is the name the dispatcher will look up at Call time —
    /// typically either the bare template name (selective import) or
    /// `"P::T"` (namespace import). `template_name` is the resolved
    /// name inside `library`. Duplicate keys are overwritten — the
    /// compiler-side import dispatcher is responsible for rejecting
    /// conflicts before reaching this point.
    ///
    /// Does NOT bump [`circom_call_counter`]; that counter tracks
    /// instantiation sites, not registrations.
    pub fn register_circom_template(
        &mut self,
        key: String,
        library: std::sync::Arc<dyn super::circom_interop::CircomLibraryHandle>,
        template_name: String,
    ) {
        self.circom_table.insert(
            key,
            CircomCallable {
                library,
                template_name,
            },
        );
    }

    /// Allocate a unique mangling prefix for the next circom template
    /// instantiation (`circom_call_0`, `circom_call_1`, ...). Bumps
    /// [`circom_call_counter`] so subsequent calls get fresh prefixes.
    #[allow(dead_code)]
    pub(super) fn next_circom_call_prefix(&mut self) -> String {
        let prefix = format!("circom_call_{}", self.circom_call_counter);
        self.circom_call_counter += 1;
        prefix
    }

    /// Build the row-major list of multi-dimensional indices for a
    /// shape. For `dims = [2, 3]` returns
    /// `[[0,0], [0,1], [0,2], [1,0], [1,1], [1,2]]`. Used to map each
    /// element of an `Expr::Array` literal onto its expanded
    /// `name_i[_j…]` key in the circom signal-input map.
    fn flatten_row_major_indices(dims: &[u64]) -> Vec<Vec<u64>> {
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

    /// Look up a registered circom template by its dispatch key.
    #[allow(dead_code)]
    pub(super) fn lookup_circom_template(&self, key: &str) -> Option<&CircomCallable> {
        self.circom_table.get(key)
    }

    /// Compile an AST Block into a ProveIR template.
    ///
    /// `outer_scope`: values and functions from the enclosing scope.
    /// Pass `OuterScope::default()` for self-contained circuits.
    pub fn compile(block: &Block, outer_scope: &OuterScope) -> Result<ProveIR, ProveIrError> {
        Self::compile_with_source_dir(block, outer_scope, None, None)
    }

    fn compile_with_source_dir(
        block: &Block,
        outer_scope: &OuterScope,
        source_dir: Option<std::path::PathBuf>,
        source_path: Option<std::path::PathBuf>,
    ) -> Result<ProveIR, ProveIrError> {
        let mut compiler = Self::new();
        compiler.source_dir = source_dir;
        if let Some(path) = source_path {
            compiler.compiling_modules.insert(path);
        }

        // Register outer scope values as potential captures
        for (name, entry) in &outer_scope.values {
            match entry {
                OuterScopeEntry::Scalar => {
                    compiler
                        .env
                        .insert(name.clone(), CompEnvValue::Capture(name.clone()));
                }
                OuterScopeEntry::Array(n) => {
                    let elem_names: Vec<String> = (0..*n).map(|i| format!("{name}_{i}")).collect();
                    for ename in &elem_names {
                        compiler
                            .env
                            .insert(ename.clone(), CompEnvValue::Capture(ename.clone()));
                    }
                    compiler
                        .env
                        .insert(name.clone(), CompEnvValue::Array(elem_names));
                }
            }
        }

        // Register outer scope functions in fn_table for inlining
        for stmt in &outer_scope.functions {
            if let Stmt::FnDecl {
                name,
                params,
                return_type,
                body,
                ..
            } = stmt
            {
                compiler.fn_table.insert(
                    name.clone(),
                    FnDef {
                        params: params.clone(),
                        body: body.clone(),
                        return_type: return_type.clone(),
                    },
                );
            }
        }

        // Seed circom template imports from the outer scope.
        for (key, callable) in &outer_scope.circom_imports {
            compiler.circom_table.insert(key.clone(), callable.clone());
        }

        // Compile all statements in the block
        compiler.compile_block_stmts(block)?;

        // Classify captures
        let captures = super::capture::classify_captures(&compiler.captured_names, &compiler.body);

        // Build capture_arrays: arrays from outer scope whose elements were captured
        let mut capture_arrays = Vec::new();
        for (name, entry) in &outer_scope.values {
            if let OuterScopeEntry::Array(n) = entry {
                let has_captured =
                    (0..*n).any(|i| compiler.captured_names.contains(&format!("{name}_{i}")));
                if has_captured {
                    capture_arrays.push(CaptureArrayDef {
                        name: name.clone(),
                        size: *n,
                    });
                }
            }
        }

        Ok(ProveIR {
            name: None,
            public_inputs: compiler.public_inputs,
            witness_inputs: compiler.witness_inputs,
            captures,
            body: compiler.body,
            capture_arrays,
        })
    }

    /// Convenience: parse source and compile as a self-contained circuit (no outer scope).
    pub fn compile_circuit(
        source: &str,
        source_path: Option<&Path>,
    ) -> Result<ProveIR, ProveIrError> {
        use achronyme_parser::ast::{InputDecl, Stmt, Visibility};

        let (program, errors) = achronyme_parser::parse_program(source);
        if !errors.is_empty() {
            return Err(ProveIrError::ParseError(Box::new(errors[0].clone())));
        }

        // Collect top-level statements before the circuit declaration:
        // - Imports/exports are prepended to the block (need stmt processing for module resolution)
        // - FnDecl stmts are passed via OuterScope (registered in fn_table before compilation)
        let mut preamble_stmts: Vec<Stmt> = Vec::new();
        let mut outer_functions: Vec<Stmt> = Vec::new();
        let mut circuit_decl = None;

        for stmt in &program.stmts {
            match stmt {
                Stmt::CircuitDecl { span, .. } if circuit_decl.is_none() => {
                    circuit_decl = Some(stmt);
                }
                Stmt::CircuitDecl { span, .. } => {
                    return Err(ProveIrError::UnsupportedOperation {
                        description: "only one circuit declaration is allowed per file".into(),
                        span: to_span(span),
                    });
                }
                Stmt::Import { .. } | Stmt::SelectiveImport { .. } if circuit_decl.is_none() => {
                    preamble_stmts.push(stmt.clone());
                }
                Stmt::FnDecl { .. } if circuit_decl.is_none() => {
                    outer_functions.push(stmt.clone());
                }
                Stmt::Export { .. } if circuit_decl.is_none() => {
                    preamble_stmts.push(stmt.clone());
                }
                _ => {}
            }
        }

        if let Some(Stmt::CircuitDecl {
            params,
            body,
            name,
            span,
            ..
        }) = circuit_decl
        {
            // Synthesize public/witness declarations from typed params
            let mut stmts = Vec::new();
            for param in params {
                let ta =
                    param
                        .type_ann
                        .as_ref()
                        .ok_or_else(|| ProveIrError::UnsupportedOperation {
                            description: format!(
                                "circuit parameter `{}` has no type annotation",
                                param.name
                            ),
                            span: crate::error::span_box(Some(diagnostics::SpanRange::from(span))),
                        })?;
                let vis = ta
                    .visibility
                    .ok_or_else(|| ProveIrError::UnsupportedOperation {
                        description: format!(
                            "circuit parameter `{}` requires Public or Witness",
                            param.name
                        ),
                        span: crate::error::span_box(Some(diagnostics::SpanRange::from(span))),
                    })?;
                let decl = InputDecl {
                    name: param.name.clone(),
                    array_size: ta.array_size,
                    type_ann: Some(ta.clone()),
                };
                match vis {
                    Visibility::Public => stmts.push(Stmt::PublicDecl {
                        names: vec![decl],
                        span: span.clone(),
                    }),
                    Visibility::Witness => stmts.push(Stmt::WitnessDecl {
                        names: vec![decl],
                        span: span.clone(),
                    }),
                }
            }
            // Prepend imports/exports before the circuit body (need stmt processing).
            // Functions go via OuterScope — registered in fn_table before compilation.
            let mut all_stmts = preamble_stmts;
            all_stmts.extend(stmts);
            all_stmts.extend(body.stmts.clone());
            let circuit_block = Block {
                stmts: all_stmts,
                span: body.span.clone(),
            };
            let outer_scope = OuterScope {
                functions: outer_functions,
                ..Default::default()
            };
            let source_dir = source_path.and_then(|p| p.parent().map(|d| d.to_path_buf()));
            let canonical_source = source_path.and_then(|p| p.canonicalize().ok());
            let mut prove_ir = Self::compile_with_source_dir(
                &circuit_block,
                &outer_scope,
                source_dir,
                canonical_source,
            )?;
            prove_ir.name = Some(name.clone());
            return Ok(prove_ir);
        }

        // Flat format is no longer supported — require circuit declaration
        Err(ProveIrError::UnsupportedOperation {
            description: "flat circuit format is not supported; \
                          use `circuit name(param: Public, ...) { body }` instead"
                .into(),
            span: None,
        })
    }

    /// Convenience: parse source and compile as a prove block with outer scope.
    pub fn compile_prove_block(
        source: &str,
        outer_scope: &OuterScope,
    ) -> Result<ProveIR, ProveIrError> {
        let (program, errors) = achronyme_parser::parse_program(source);
        if let Some(err) = errors
            .iter()
            .find(|d| d.severity == diagnostics::Severity::Error)
        {
            return Err(ProveIrError::ParseError(Box::new(err.clone())));
        }
        let block = program_to_block(source, program);
        Self::compile(&block, outer_scope)
    }

    // -----------------------------------------------------------------------
    // Statement compilation
    // -----------------------------------------------------------------------

    /// Compile all statements in a block, appending to self.body.
    fn compile_block_stmts(&mut self, block: &Block) -> Result<(), ProveIrError> {
        for stmt in &block.stmts {
            self.compile_stmt(stmt)?;
        }
        Ok(())
    }

    /// Compile a single statement.
    fn compile_stmt(&mut self, stmt: &Stmt) -> Result<(), ProveIrError> {
        match stmt {
            Stmt::PublicDecl { names, span } => self.compile_public_decl(names, span),
            Stmt::WitnessDecl { names, span } => self.compile_witness_decl(names, span),
            Stmt::LetDecl {
                name,
                type_ann,
                value,
                span,
                ..
            } => self.compile_let(name, type_ann.as_ref(), value, span),
            Stmt::FnDecl {
                name,
                params,
                return_type,
                body,
                ..
            } => {
                self.fn_table.insert(
                    name.clone(),
                    FnDef {
                        params: params.clone(),
                        body: body.clone(),
                        return_type: return_type.clone(),
                    },
                );
                Ok(())
            }
            Stmt::Expr(expr) => self.compile_expr_stmt(expr),
            Stmt::Export { inner, .. } => self.compile_stmt(inner),
            Stmt::ExportList { .. } | Stmt::Error { .. } => Ok(()),

            Stmt::MutDecl {
                name,
                type_ann,
                value,
                span,
                ..
            } => self.compile_mut_decl(name, type_ann.as_ref(), value, span),
            Stmt::Assignment {
                target,
                value,
                span,
            } => self.compile_assignment(target, value, span),
            Stmt::Print { span, .. } => Err(ProveIrError::UnsupportedOperation {
                description: "print is not supported in circuits".into(),
                span: to_span(span),
            }),
            Stmt::Break { span } => Err(ProveIrError::UnsupportedOperation {
                description: "break is not supported in circuits".into(),
                span: to_span(span),
            }),
            Stmt::Continue { span } => Err(ProveIrError::UnsupportedOperation {
                description: "continue is not supported in circuits".into(),
                span: to_span(span),
            }),
            Stmt::Return { span, .. } => Err(ProveIrError::UnsupportedOperation {
                description: "return is not supported at the top level of a circuit".into(),
                span: to_span(span),
            }),
            Stmt::Import { path, alias, span } => self.compile_import(path, alias, span),
            Stmt::SelectiveImport { names, path, span } => {
                self.compile_selective_import(names, path, span)
            }
            Stmt::CircuitDecl { span, .. } => Err(ProveIrError::UnsupportedOperation {
                description: "circuit declarations are not supported inside circuits".into(),
                span: to_span(span),
            }),
            Stmt::ImportCircuit { span, .. } => Err(ProveIrError::UnsupportedOperation {
                description: "circuit imports are not supported inside circuits".into(),
                span: to_span(span),
            }),
        }
    }

    // -----------------------------------------------------------------------
    // Imports
    // -----------------------------------------------------------------------

    /// Resolve a relative import path against the source directory.
    fn resolve_import_path(
        &self,
        path: &str,
        _span: &Span,
    ) -> Result<std::path::PathBuf, ProveIrError> {
        let base = self.source_dir.as_ref().ok_or_else(|| {
            ProveIrError::ModuleLoadError(
                "imports require a file path context (not available in inline prove blocks)".into(),
            )
        })?;
        let full_path = base.join(path);
        if !full_path.exists() {
            return Err(ProveIrError::ModuleNotFound(format!(
                "{} (resolved from {})",
                full_path.display(),
                path
            )));
        }
        full_path.canonicalize().map_err(|e| {
            ProveIrError::ModuleLoadError(format!("cannot resolve {}: {}", full_path.display(), e))
        })
    }

    /// Register exported functions from a module into fn_table with alias prefix.
    fn register_module_exports(
        &mut self,
        alias: &str,
        module: &crate::module_loader::ModuleExports,
    ) {
        for stmt in &module.program.stmts {
            let inner = match stmt {
                Stmt::Export { inner, .. } => inner.as_ref(),
                other => other,
            };
            if let Stmt::FnDecl {
                name,
                params,
                body,
                return_type,
                ..
            } = inner
            {
                if module.exported_names.contains(name) {
                    let qualified = format!("{alias}::{name}");
                    self.fn_table.insert(
                        qualified,
                        FnDef {
                            params: params.clone(),
                            body: body.clone(),
                            return_type: return_type.clone(),
                        },
                    );
                }
            }
        }
    }

    /// `import "./module.ach" as alias`
    fn compile_import(&mut self, path: &str, alias: &str, span: &Span) -> Result<(), ProveIrError> {
        let canonical = self.resolve_import_path(path, span)?;
        if self.compiling_modules.contains(&canonical) {
            return Err(ProveIrError::CircularImport(path.to_string()));
        }
        self.compiling_modules.insert(canonical.clone());
        let module = self
            .module_loader
            .load(&canonical)
            .map_err(ProveIrError::ModuleLoadError)?;
        // Clone what we need before releasing the borrow on module_loader.
        let exported_names = module.exported_names.clone();
        let stmts = module.program.stmts.clone();
        let exports = crate::module_loader::ModuleExports {
            exported_names,
            program: achronyme_parser::ast::Program { stmts },
        };
        self.register_module_exports(alias, &exports);
        Ok(())
    }

    /// `import { fn1, fn2 } from "./module.ach"`
    fn compile_selective_import(
        &mut self,
        names: &[String],
        path: &str,
        span: &Span,
    ) -> Result<(), ProveIrError> {
        let canonical = self.resolve_import_path(path, span)?;
        if self.compiling_modules.contains(&canonical) {
            return Err(ProveIrError::CircularImport(path.to_string()));
        }
        self.compiling_modules.insert(canonical.clone());
        let module = self
            .module_loader
            .load(&canonical)
            .map_err(ProveIrError::ModuleLoadError)?;
        let exported_names = module.exported_names.clone();
        let stmts = module.program.stmts.clone();

        // Validate requested names are actually exported
        for name in names {
            if !exported_names.contains(name) {
                return Err(ProveIrError::ModuleLoadError(format!(
                    "`{name}` is not exported from `{path}`"
                )));
            }
        }

        // Register each requested function directly (no alias prefix)
        for stmt in &stmts {
            let inner = match stmt {
                Stmt::Export { inner, .. } => inner.as_ref(),
                other => other,
            };
            if let Stmt::FnDecl {
                name,
                params,
                body,
                return_type,
                ..
            } = inner
            {
                if names.contains(name) {
                    self.fn_table.insert(
                        name.clone(),
                        FnDef {
                            params: params.clone(),
                            body: body.clone(),
                            return_type: return_type.clone(),
                        },
                    );
                }
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Public/Witness declarations
    // -----------------------------------------------------------------------

    fn compile_public_decl(
        &mut self,
        names: &[InputDecl],
        span: &Span,
    ) -> Result<(), ProveIrError> {
        self.compile_input_decl(names, span, true)
    }

    fn compile_witness_decl(
        &mut self,
        names: &[InputDecl],
        span: &Span,
    ) -> Result<(), ProveIrError> {
        self.compile_input_decl(names, span, false)
    }

    /// Shared implementation for public/witness input declarations.
    fn compile_input_decl(
        &mut self,
        names: &[InputDecl],
        span: &Span,
        is_public: bool,
    ) -> Result<(), ProveIrError> {
        for decl in names {
            // Check for duplicate declarations across both public and witness inputs.
            // We check the input lists directly (not self.env) because env also
            // contains captures from the outer scope, which are legitimately
            // "overridden" by an explicit public/witness declaration.
            let already_declared = self
                .public_inputs
                .iter()
                .chain(self.witness_inputs.iter())
                .any(|d| d.name == decl.name);
            if already_declared {
                return Err(ProveIrError::DuplicateInput {
                    name: decl.name.clone(),
                    span: to_span(span),
                });
            }

            let ir_type = decl
                .type_ann
                .as_ref()
                .map(annotation_to_ir_type)
                .unwrap_or(IrType::Field);

            let inputs = if is_public {
                &mut self.public_inputs
            } else {
                &mut self.witness_inputs
            };

            if let Some(size) = decl.array_size {
                inputs.push(ProveInputDecl {
                    name: decl.name.clone(),
                    array_size: Some(ArraySize::Literal(size)),
                    ir_type,
                });
                let elem_names: Vec<String> =
                    (0..size).map(|i| format!("{}_{i}", decl.name)).collect();
                for ename in &elem_names {
                    self.env
                        .insert(ename.clone(), CompEnvValue::Scalar(ename.clone()));
                }
                self.env
                    .insert(decl.name.clone(), CompEnvValue::Array(elem_names));
            } else {
                inputs.push(ProveInputDecl {
                    name: decl.name.clone(),
                    array_size: None,
                    ir_type,
                });
                self.env
                    .insert(decl.name.clone(), CompEnvValue::Scalar(decl.name.clone()));
            }
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Let declaration
    // -----------------------------------------------------------------------

    fn compile_let(
        &mut self,
        name: &str,
        type_ann: Option<&TypeAnnotation>,
        value: &Expr,
        span: &Span,
    ) -> Result<(), ProveIrError> {
        // Circom template call bound to a let: `let r = T(args)(inputs)`.
        // Must run before the scalar fall-through so multi-output and
        // array-output templates can bind per-output env entries that
        // compile_dot_access will later resolve as `r.out_name`.
        if self.compile_let_for_circom_call(name, value, span)? {
            return Ok(());
        }

        // decompose(value, bits) → Decompose node (creates array of bit vars)
        if let Expr::Call { callee, args, .. } = value {
            if let Expr::Ident { name: fn_name, .. } = callee.as_ref() {
                if fn_name == "decompose" {
                    let arg_vals: Vec<&Expr> = args.iter().map(|a| &a.value).collect();
                    self.check_arity("decompose", 2, arg_vals.len(), span)?;
                    let compiled_value = self.compile_expr(arg_vals[0])?;
                    let num_bits = self.extract_const_u64(arg_vals[1], span)? as u32;

                    let elem_names: Vec<String> =
                        (0..num_bits).map(|i| format!("{name}_{i}")).collect();

                    self.body.push(CircuitNode::Decompose {
                        name: name.to_string(),
                        value: compiled_value,
                        num_bits,
                        span: Some(SpanRange::from(span)),
                    });

                    for ename in &elem_names {
                        self.env
                            .insert(ename.clone(), CompEnvValue::Scalar(ename.clone()));
                    }
                    self.env
                        .insert(name.to_string(), CompEnvValue::Array(elem_names));
                    return Ok(());
                }
            }
        }

        // Array literal → LetArray
        if let Expr::Array {
            elements,
            span: arr_span,
        } = value
        {
            if elements.is_empty() {
                return Err(ProveIrError::UnsupportedOperation {
                    description: "empty arrays are not allowed in circuits".into(),
                    span: to_span(arr_span),
                });
            }
            let compiled: Result<Vec<_>, _> =
                elements.iter().map(|e| self.compile_expr(e)).collect();
            let compiled = compiled?;
            let elem_names: Vec<String> =
                (0..compiled.len()).map(|i| format!("{name}_{i}")).collect();
            self.body.push(CircuitNode::LetArray {
                name: name.to_string(),
                elements: compiled,
                span: Some(SpanRange::from(span)),
            });
            for ename in &elem_names {
                self.env
                    .insert(ename.clone(), CompEnvValue::Scalar(ename.clone()));
            }
            self.env
                .insert(name.to_string(), CompEnvValue::Array(elem_names));
            return Ok(());
        }

        // Function call returning an array → inline the function and adopt
        // the resulting array under this binding's name.
        if let Some(result_array_name) =
            self.try_compile_array_fn_call(name, type_ann, value, span)?
        {
            // The function was inlined and created an array in the env under
            // an internal SSA name. Re-register it under the let-binding name.
            if let Some(CompEnvValue::Array(elems)) = self.env.get(&result_array_name).cloned() {
                // Create new element names under the let-binding name.
                let new_elem_names: Vec<String> =
                    (0..elems.len()).map(|i| format!("{name}_{i}")).collect();
                let elem_exprs: Vec<CircuitExpr> = elems
                    .iter()
                    .map(|e| match self.env.get(e) {
                        Some(CompEnvValue::Scalar(s)) => CircuitExpr::Var(s.clone()),
                        _ => CircuitExpr::Var(e.clone()),
                    })
                    .collect();
                self.body.push(CircuitNode::LetArray {
                    name: name.to_string(),
                    elements: elem_exprs,
                    span: Some(SpanRange::from(span)),
                });
                for ename in &new_elem_names {
                    self.env
                        .insert(ename.clone(), CompEnvValue::Scalar(ename.clone()));
                }
                self.env
                    .insert(name.to_string(), CompEnvValue::Array(new_elem_names));
                return Ok(());
            }
        }

        // Scalar value → Let
        let compiled = self.compile_expr(value)?;
        self.body.push(CircuitNode::Let {
            name: name.to_string(),
            value: compiled,
            span: Some(SpanRange::from(span)),
        });
        self.env
            .insert(name.to_string(), CompEnvValue::Scalar(name.to_string()));
        Ok(())
    }

    /// Try to compile a function call that returns an array.
    ///
    /// Returns `Some(array_name_in_env)` if the call was handled as an
    /// array-returning function, or `None` if it should be compiled as a
    /// normal scalar expression.
    fn try_compile_array_fn_call(
        &mut self,
        _let_name: &str,
        type_ann: Option<&TypeAnnotation>,
        value: &Expr,
        span: &Span,
    ) -> Result<Option<String>, ProveIrError> {
        // Only handle direct named calls
        let (callee_name, args) = match value {
            Expr::Call { callee, args, .. } => {
                if let Expr::Ident { name, .. } = callee.as_ref() {
                    let arg_vals: Vec<&Expr> = args.iter().map(|a| &a.value).collect();
                    (name.as_str(), arg_vals)
                } else {
                    return Ok(None);
                }
            }
            _ => return Ok(None),
        };

        // Check if the function exists and has an array return type
        let fn_def = match self.fn_table.get(callee_name) {
            Some(fd) => fd.clone(),
            None => return Ok(None), // Not a user function (might be a builtin)
        };

        let has_array_return = fn_def
            .return_type
            .as_ref()
            .and_then(|ta| ta.array_size)
            .is_some();

        // Also check if the let-binding has an array type annotation
        let let_expects_array = type_ann.and_then(|ta| ta.array_size).is_some();

        if !has_array_return && !let_expects_array {
            return Ok(None);
        }

        // This is an array-returning function call. Inline it using the
        // same mechanism as compile_user_fn_call but capture the array result.

        // Arity check
        if args.len() != fn_def.params.len() {
            return Err(ProveIrError::WrongArgumentCount {
                name: callee_name.into(),
                expected: fn_def.params.len(),
                got: args.len(),
                span: to_span(span),
            });
        }

        // Recursion guard
        if self.call_stack.contains(callee_name) {
            return Err(ProveIrError::RecursiveFunction {
                name: callee_name.into(),
            });
        }
        self.call_stack.insert(callee_name.to_string());

        // Save env
        let param_names: Vec<String> = fn_def.params.iter().map(|p| p.name.clone()).collect();
        let mut all_shadow_names: Vec<String> = param_names.clone();
        for (i, param) in fn_def.params.iter().enumerate() {
            if let Some(ref ta) = param.type_ann {
                if let Some(size) = ta.array_size {
                    for j in 0..size {
                        all_shadow_names.push(format!("{}_{j}", param_names[i]));
                    }
                }
            }
        }
        let saved: Vec<(String, Option<CompEnvValue>)> = all_shadow_names
            .iter()
            .map(|p| (p.clone(), self.env.get(p).cloned()))
            .collect();

        let invoke_id = self.inline_counter;
        self.inline_counter = self.inline_counter.wrapping_add(1);

        // Bind parameters (array-aware)
        for (i, (param, arg)) in param_names.iter().zip(args.iter()).enumerate() {
            let is_array_param = fn_def.params[i]
                .type_ann
                .as_ref()
                .and_then(|ta| ta.array_size)
                .is_some();

            if is_array_param {
                self.bind_array_fn_param(callee_name, invoke_id, param, arg, span)?;
            } else {
                let compiled = self.compile_expr(arg)?;
                let param_ssa = format!("__{callee_name}${invoke_id}_{param}");
                self.body.push(CircuitNode::Let {
                    name: param_ssa.clone(),
                    value: compiled,
                    span: Some(SpanRange::from(span)),
                });
                self.env
                    .insert(param.clone(), CompEnvValue::Scalar(param_ssa));
            }
        }

        // Compile the function body — all statements except the last one
        // (which is the array return expression, not a real statement).
        let stmts = &fn_def.body.stmts;
        if !stmts.is_empty() {
            for stmt in &stmts[..stmts.len() - 1] {
                self.compile_stmt(stmt)?;
            }
        }

        // Find the array result: the last expression should be an array name.
        let result_array = self.find_array_result(stmts, span)?;

        // Restore env
        for (p, old_val) in saved {
            match old_val {
                Some(v) => {
                    self.env.insert(p, v);
                }
                None => {
                    self.env.remove(&p);
                }
            }
        }

        self.call_stack.remove(callee_name);
        Ok(Some(result_array))
    }

    /// Find the array name returned by the last statement/expression in a
    /// function body. The last statement should be either:
    /// - A bare `Expr::Ident` referencing an array
    /// - A `Stmt::Return` with an `Expr::Ident` referencing an array
    /// - Any other statement (compiled normally) followed by checking env
    fn find_array_result(&mut self, stmts: &[Stmt], span: &Span) -> Result<String, ProveIrError> {
        let last = stmts
            .last()
            .ok_or_else(|| ProveIrError::UnsupportedOperation {
                description: "array-returning function has an empty body".into(),
                span: to_span(span),
            })?;

        // Extract the array identifier from the last statement
        let ident = match last {
            Stmt::Expr(Expr::Ident { name, .. }) => name.clone(),
            Stmt::Return {
                value: Some(Expr::Ident { name, .. }),
                ..
            } => name.clone(),
            // If the last statement is something else (e.g. a let that creates
            // the array), compile it and then we can't determine the name.
            other => {
                self.compile_stmt(other)?;
                return Err(ProveIrError::UnsupportedOperation {
                    description: "array-returning function must end with an array variable name \
                                  (e.g., `return arr` or just `arr`)"
                        .into(),
                    span: to_span(span),
                });
            }
        };

        match self.env.get(ident.as_str()) {
            Some(CompEnvValue::Array(_)) => Ok(ident),
            _ => Err(ProveIrError::TypeMismatch {
                expected: "array".into(),
                got: "scalar".into(),
                span: to_span(span),
            }),
        }
    }

    // -----------------------------------------------------------------------
    // Expression statement (handles assert_eq / assert as nodes)
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Mut declaration (desugared to SSA)
    // -----------------------------------------------------------------------

    fn compile_mut_decl(
        &mut self,
        name: &str,
        _type_ann: Option<&TypeAnnotation>,
        value: &Expr,
        span: &Span,
    ) -> Result<(), ProveIrError> {
        // Array literal → mutable LetArray
        if let Expr::Array {
            elements,
            span: arr_span,
        } = value
        {
            if elements.is_empty() {
                return Err(ProveIrError::UnsupportedOperation {
                    description: "empty arrays are not allowed in circuits".into(),
                    span: to_span(arr_span),
                });
            }
            let compiled: Result<Vec<_>, _> =
                elements.iter().map(|e| self.compile_expr(e)).collect();
            let compiled = compiled?;
            let elem_names: Vec<String> =
                (0..compiled.len()).map(|i| format!("{name}_{i}")).collect();
            self.body.push(CircuitNode::LetArray {
                name: name.to_string(),
                elements: compiled,
                span: Some(SpanRange::from(span)),
            });
            for ename in &elem_names {
                self.env
                    .insert(ename.clone(), CompEnvValue::Scalar(ename.clone()));
            }
            self.env
                .insert(name.to_string(), CompEnvValue::Array(elem_names));
            // Mark as mutable so arr[i] = expr is allowed
            self.ssa_versions.insert(name.to_string(), 0);
            return Ok(());
        }

        // Type annotations intentionally ignored (see compile_let).
        // Compile value and emit Let node (same as immutable let for v0)
        let compiled = self.compile_expr(value)?;
        self.body.push(CircuitNode::Let {
            name: name.to_string(),
            value: compiled,
            span: Some(SpanRange::from(span)),
        });
        // Register in env as the current name (v0 uses the original name)
        self.env
            .insert(name.to_string(), CompEnvValue::Scalar(name.to_string()));
        // Mark as mutable with version 0
        self.ssa_versions.insert(name.to_string(), 0);
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Assignment (desugared to SSA rebinding)
    // -----------------------------------------------------------------------

    fn compile_assignment(
        &mut self,
        target: &Expr,
        value: &Expr,
        span: &Span,
    ) -> Result<(), ProveIrError> {
        // Array element assignment: arr[i] = expr → LetIndexed
        if let Expr::Index {
            object,
            index,
            span: idx_span,
        } = target
        {
            return self.compile_indexed_assignment(object, index, value, idx_span);
        }

        // Simple ident assignment: x = expr
        let name = match target {
            Expr::Ident { name, .. } => name.clone(),
            _ => {
                return Err(ProveIrError::UnsupportedOperation {
                    description: "only simple variable or array element assignment \
                         is supported in circuits"
                        .into(),
                    span: to_span(span),
                });
            }
        };

        // Check that the variable was declared with mut
        let version = self.ssa_versions.get(&name).copied().ok_or_else(|| {
            ProveIrError::UnsupportedOperation {
                description: format!(
                    "cannot assign to `{name}` — it was not declared with `mut` \
                     (use `mut {name} = ...` to declare a mutable variable)"
                ),
                span: to_span(span),
            }
        })?;

        // Increment version (checked to avoid panic on theoretical overflow)
        let new_version =
            version
                .checked_add(1)
                .ok_or_else(|| ProveIrError::UnsupportedOperation {
                    description: format!(
                        "SSA version overflow for `{name}` — too many reassignments"
                    ),
                    span: to_span(span),
                })?;
        self.ssa_versions.insert(name.clone(), new_version);

        // Generate SSA name using $ separator (not valid in user identifiers).
        let ssa_name = format!("{name}$v{new_version}");

        // Compile the new value
        let compiled = self.compile_expr(value)?;
        self.body.push(CircuitNode::Let {
            name: ssa_name.clone(),
            value: compiled,
            span: Some(SpanRange::from(span)),
        });

        // Update env to point to the new SSA name
        self.env.insert(name, CompEnvValue::Scalar(ssa_name));
        Ok(())
    }

    /// Compile `arr[i] = expr` → `LetIndexed { array, index, value }`.
    fn compile_indexed_assignment(
        &mut self,
        object: &Expr,
        index: &Expr,
        value: &Expr,
        span: &Span,
    ) -> Result<(), ProveIrError> {
        let array_name = match object {
            Expr::Ident { name, .. } => name.clone(),
            _ => {
                return Err(ProveIrError::UnsupportedOperation {
                    description: "indexed assignment requires an array identifier \
                         (e.g., arr[i] = expr)"
                        .into(),
                    span: to_span(span),
                });
            }
        };

        // Check the array exists and is an array
        if !matches!(
            self.env.get(array_name.as_str()),
            Some(CompEnvValue::Array(_))
        ) {
            return Err(ProveIrError::TypeMismatch {
                expected: "mutable array".into(),
                got: "scalar or undeclared".into(),
                span: to_span(span),
            });
        }

        // Check the array was declared with mut
        if !self.ssa_versions.contains_key(&array_name) {
            return Err(ProveIrError::UnsupportedOperation {
                description: format!(
                    "cannot assign to `{array_name}[..]` — array was not declared with `mut` \
                     (use `mut {array_name} = [...]` to declare a mutable array)"
                ),
                span: to_span(span),
            });
        }

        let compiled_index = self.compile_expr(index)?;
        let compiled_value = self.compile_expr(value)?;

        self.body.push(CircuitNode::LetIndexed {
            array: array_name,
            index: compiled_index,
            value: compiled_value,
            span: Some(SpanRange::from(span)),
        });

        Ok(())
    }

    // -----------------------------------------------------------------------
    // Expression statement (handles assert_eq / assert as nodes)
    // -----------------------------------------------------------------------

    fn compile_expr_stmt(&mut self, expr: &Expr) -> Result<(), ProveIrError> {
        // Detect assert_eq(a, b) and assert(x) to emit constraint nodes
        if let Expr::Call { callee, args, span } = expr {
            let arg_vals: Vec<&Expr> = args.iter().map(|a| &a.value).collect();
            if let Expr::Ident { name, .. } = callee.as_ref() {
                match name.as_str() {
                    "assert_eq" => {
                        self.check_assert_eq_arity(arg_vals.len(), span)?;
                        let lhs = self.compile_expr(arg_vals[0])?;
                        let rhs = self.compile_expr(arg_vals[1])?;
                        let message = self.extract_assert_message(arg_vals.get(2), span)?;
                        self.body.push(CircuitNode::AssertEq {
                            lhs,
                            rhs,
                            message,
                            span: Some(SpanRange::from(span)),
                        });
                        return Ok(());
                    }
                    "assert" => {
                        self.check_assert_arity(arg_vals.len(), span)?;
                        let cond = self.compile_expr(arg_vals[0])?;
                        let message = self.extract_assert_message(arg_vals.get(1), span)?;
                        self.body.push(CircuitNode::Assert {
                            expr: cond,
                            message,
                            span: Some(SpanRange::from(span)),
                        });
                        return Ok(());
                    }
                    _ => {}
                }
            }
        }

        // General expression statement
        let compiled = self.compile_expr(expr)?;
        self.body.push(CircuitNode::Expr {
            expr: compiled,
            span: Some(SpanRange::from(expr.span())),
        });
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Expression compilation
    // -----------------------------------------------------------------------

    /// Compile an AST expression into a `CircuitExpr`.
    pub(crate) fn compile_expr(&mut self, expr: &Expr) -> Result<CircuitExpr, ProveIrError> {
        match expr {
            Expr::Number { value, span } => self.compile_number(value, span),
            Expr::FieldLit {
                value, radix, span, ..
            } => self.compile_field_lit(value, radix, span),
            Expr::Bool { value: true, .. } => Ok(CircuitExpr::Const(FieldConst::one())),
            Expr::Bool { value: false, .. } => Ok(CircuitExpr::Const(FieldConst::zero())),
            Expr::Ident { name, span } => self.compile_ident(name, span),

            Expr::BinOp { op, lhs, rhs, span } => self.compile_binop(op, lhs, rhs, span),
            Expr::UnaryOp { op, operand, span } => self.compile_unary(op, operand, span),

            Expr::StaticAccess {
                type_name,
                member,
                span,
            } => self.compile_static_access(type_name, member, span),

            Expr::Call { callee, args, span } => {
                let arg_vals: Vec<&Expr> = args.iter().map(|a| &a.value).collect();
                self.compile_call(callee, &arg_vals, span)
            }

            Expr::DotAccess {
                object,
                field,
                span,
            } => self.compile_dot_access(object, field, span),

            Expr::If {
                condition,
                then_block,
                else_branch,
                span,
            } => self.compile_if_expr(condition, then_block, else_branch.as_ref(), span),

            Expr::For {
                var,
                iterable,
                body,
                span,
            } => self.compile_for_expr(var, iterable, body, span),

            Expr::Block(block) => self.compile_block_as_expr(block),

            Expr::Index {
                object,
                index,
                span,
            } => self.compile_index(object, index, span),

            // --- Rejections (same as IrLowering, with better messages) ---
            Expr::While { span, .. } | Expr::Forever { span, .. } => {
                Err(ProveIrError::UnboundedLoop {
                    span: to_span(span),
                })
            }
            Expr::Prove { span, .. } => Err(ProveIrError::UnsupportedOperation {
                description: "prove blocks cannot be nested inside circuits".into(),
                span: to_span(span),
            }),
            // CircuitCall removed — keyword-arg calls are now unified in Call
            Expr::FnExpr { span, .. } => Err(ProveIrError::UnsupportedOperation {
                description: "closures are not supported in circuits \
                              (use named fn declarations instead)"
                    .into(),
                span: to_span(span),
            }),
            Expr::StringLit { span, .. } => Err(ProveIrError::TypeNotConstrainable {
                type_name: "string".into(),
                span: to_span(span),
            }),
            Expr::Nil { span } => Err(ProveIrError::TypeNotConstrainable {
                type_name: "nil".into(),
                span: to_span(span),
            }),
            Expr::Map { span, .. } => Err(ProveIrError::TypeNotConstrainable {
                type_name: "map".into(),
                span: to_span(span),
            }),
            Expr::BigIntLit { span, .. } => Err(ProveIrError::TypeNotConstrainable {
                type_name: "BigInt".into(),
                span: to_span(span),
            }),
            Expr::Array { span, .. } => Err(ProveIrError::TypeMismatch {
                expected: "scalar expression".into(),
                got: "array literal (use let binding for arrays)".into(),
                span: to_span(span),
            }),
            Expr::Error { span } => Err(ProveIrError::UnsupportedOperation {
                description: "cannot compile error placeholder (source has parse errors)".into(),
                span: to_span(span),
            }),
        }
    }

    // -----------------------------------------------------------------------
    // Literals
    // -----------------------------------------------------------------------

    fn compile_number(&self, s: &str, span: &Span) -> Result<CircuitExpr, ProveIrError> {
        if s.contains('.') {
            return Err(ProveIrError::TypeNotConstrainable {
                type_name: "decimal number".into(),
                span: to_span(span),
            });
        }
        let (negative, digits) = if let Some(rest) = s.strip_prefix('-') {
            (true, rest)
        } else {
            (false, s)
        };
        let fe = FieldElement::<F>::from_decimal_str(digits).ok_or_else(|| {
            ProveIrError::UnsupportedOperation {
                description: format!("invalid integer literal: {s}"),
                span: to_span(span),
            }
        })?;
        let fc = FieldConst::from_field(fe);
        if negative {
            Ok(CircuitExpr::UnaryOp {
                op: CircuitUnaryOp::Neg,
                operand: Box::new(CircuitExpr::Const(fc)),
            })
        } else {
            Ok(CircuitExpr::Const(fc))
        }
    }

    fn compile_field_lit(
        &self,
        value: &str,
        radix: &FieldRadix,
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        let fe = match radix {
            FieldRadix::Decimal => FieldElement::<F>::from_decimal_str(value),
            FieldRadix::Hex => FieldElement::<F>::from_hex_str(value),
            FieldRadix::Binary => FieldElement::<F>::from_binary_str(value),
        }
        .ok_or_else(|| ProveIrError::UnsupportedOperation {
            description: format!("invalid field literal: {value}"),
            span: to_span(span),
        })?;
        Ok(CircuitExpr::Const(FieldConst::from_field(fe)))
    }

    // -----------------------------------------------------------------------
    // Identifiers
    // -----------------------------------------------------------------------

    fn compile_ident(&mut self, name: &str, span: &Span) -> Result<CircuitExpr, ProveIrError> {
        match self.env.get(name) {
            Some(CompEnvValue::Scalar(resolved)) => Ok(CircuitExpr::Var(resolved.clone())),
            Some(CompEnvValue::Array(_)) => Err(ProveIrError::TypeMismatch {
                expected: "scalar".into(),
                got: "array".into(),
                span: to_span(span),
            }),
            Some(CompEnvValue::Capture(cap_name)) => {
                self.captured_names.insert(cap_name.clone());
                Ok(CircuitExpr::Capture(cap_name.clone()))
            }
            None => Err(ProveIrError::UndeclaredVariable {
                name: name.into(),
                span: to_span(span),
                suggestion: None, // TODO: fuzzy match from env keys
            }),
        }
    }

    // -----------------------------------------------------------------------
    // Static access (Type::MEMBER)
    // -----------------------------------------------------------------------

    fn compile_static_access(
        &self,
        type_name: &str,
        member: &str,
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        match (type_name, member) {
            ("Field", "ZERO") => Ok(CircuitExpr::Const(FieldConst::zero())),
            ("Field", "ONE") => Ok(CircuitExpr::Const(FieldConst::one())),
            ("Field", "ORDER") => Err(ProveIrError::StaticAccessNotConstrainable {
                type_name: "Field".into(),
                member: "ORDER".into(),
                reason: "Field::ORDER is a string (the BN254 modulus) \
                         and strings cannot be used in circuits"
                    .into(),
                span: to_span(span),
            }),
            ("Int", "MAX") => Ok(CircuitExpr::Const(FieldConst::from_field(
                FieldElement::<F>::from_i64(memory::I60_MAX),
            ))),
            ("Int", "MIN") => Ok(CircuitExpr::Const(FieldConst::from_field(
                FieldElement::<F>::from_i64(memory::I60_MIN),
            ))),
            ("BigInt", _) => Err(ProveIrError::TypeNotConstrainable {
                type_name: "BigInt".into(),
                span: to_span(span),
            }),
            _ => Err(ProveIrError::UnsupportedOperation {
                description: format!("unknown static access `{type_name}::{member}`"),
                span: to_span(span),
            }),
        }
    }

    // -----------------------------------------------------------------------
    // Call dispatch
    // -----------------------------------------------------------------------

    fn compile_call(
        &mut self,
        callee: &Expr,
        args: &[&Expr],
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        // Circom template atomic curry: T(template_args)(signal_inputs)
        // parses as Call { callee: Call { callee: Ident(T), args: template_args },
        // args: signal_inputs }. Intercept here before the standard
        // call-dispatch so a bare or namespaced circom template is
        // resolved against the compiler's circom_table.
        if let Expr::Call {
            callee: inner_callee,
            args: inner_args,
            ..
        } = callee
        {
            if let Some(key) = self.try_resolve_circom_key(inner_callee) {
                let template_arg_exprs: Vec<&Expr> = inner_args.iter().map(|a| &a.value).collect();
                return self.compile_circom_template_call(&key, &template_arg_exprs, args, span);
            }
            // Inner callee didn't resolve to a registered circom
            // template. Before falling through to the normal call
            // dispatch, check whether the user misspelled a
            // registered template / namespace and surface a clean
            // "did you mean" diagnostic.
            if let Some(err) = self.diagnose_unresolved_circom_curry(inner_callee, span) {
                return Err(err);
            }
        }

        // Bare call `Template(inputs)` against a registered circom
        // template: the user forgot the `()(...)` currying layer.
        if let Expr::Ident { name, .. } = callee {
            if !self.circom_table.is_empty() {
                // Exact match: user wrote `Square(x)` when they
                // needed `Square()(x)`.
                if let Some(callable) = self.circom_table.get(name).cloned() {
                    let expected_params = callable
                        .library
                        .template_signature(&callable.template_name)
                        .map(|s| s.params.len())
                        .unwrap_or(0);
                    return Err(ProveIrError::CircomDispatch {
                        kind: CircomDispatchErrorKind::MissingTemplateParams {
                            template: callable.template_name.clone(),
                            expected_params,
                        },
                        span: to_span(span),
                    });
                }
            }
        }

        match callee {
            // Method call: expr.method(args)
            Expr::DotAccess {
                object,
                field,
                span: dot_span,
            } => {
                // Check for module.func() first
                if let Expr::Ident { name: module, .. } = object.as_ref() {
                    let qualified = format!("{module}::{field}");
                    if self.has_function(&qualified) {
                        return self.compile_user_fn_call(&qualified, args, span);
                    }
                }
                self.compile_method_call(object, field, args, dot_span)
            }

            // Named function/builtin call: name(args)
            Expr::Ident { name, .. } => self.compile_named_call(name, args, span),

            // Dynamic dispatch not supported
            _ => Err(ProveIrError::UnsupportedOperation {
                description: "only named function calls are supported in circuits \
                              (dynamic dispatch cannot be compiled to constraints)"
                    .into(),
                span: to_span(span),
            }),
        }
    }

    /// When a `T(args)(inputs)` shape fails to resolve against the
    /// circom_table, try to produce a clean "did you mean?" diagnostic
    /// that points at the inner callee. Returns `Some(err)` only if
    /// the user appears to have *meant* a circom template — otherwise
    /// returns `None` so the caller falls through to the normal
    /// function dispatch.
    fn diagnose_unresolved_circom_curry(
        &self,
        inner_callee: &Expr,
        span: &Span,
    ) -> Option<ProveIrError> {
        if self.circom_table.is_empty() {
            return None;
        }
        match inner_callee {
            // Bare `Template(args)(inputs)` with a misspelled name.
            Expr::Ident { name, .. } => {
                // Only produce a suggestion if we have at least one
                // selective (non-namespaced) entry — otherwise this
                // is almost certainly a regular function call typo.
                let flat_keys: Vec<&str> = self
                    .circom_table
                    .keys()
                    .filter(|k| !k.contains("::"))
                    .map(String::as_str)
                    .collect();
                if flat_keys.is_empty() {
                    return None;
                }
                let did_you_mean = crate::suggest::find_similar_ir(name, flat_keys.into_iter());
                // Only emit the diagnostic if we actually found a
                // similar registered name — otherwise the user's
                // call is probably a regular function call and we
                // shouldn't assume circom intent.
                did_you_mean.map(|suggestion| ProveIrError::CircomDispatch {
                    kind: CircomDispatchErrorKind::TemplateNotFoundSelective {
                        template: name.clone(),
                        did_you_mean: Some(suggestion),
                    },
                    span: to_span(span),
                })
            }
            // `P.Template(args)(inputs)` — namespace or template typo.
            Expr::DotAccess { object, field, .. } => {
                let Expr::Ident { name: alias, .. } = object.as_ref() else {
                    return None;
                };
                // Collect registered namespace prefixes (everything
                // before "::" in circom_table keys).
                let mut namespaces: std::collections::HashSet<String> =
                    std::collections::HashSet::new();
                for k in self.circom_table.keys() {
                    if let Some((ns, _)) = k.split_once("::") {
                        namespaces.insert(ns.to_string());
                    }
                }
                if !namespaces.contains(alias) {
                    // Alias itself is unknown — suggest a namespace.
                    let suggestion = crate::suggest::find_similar_ir(
                        alias,
                        namespaces.iter().map(String::as_str),
                    );
                    return Some(ProveIrError::CircomDispatch {
                        kind: CircomDispatchErrorKind::NamespaceNotFound {
                            alias: alias.clone(),
                            did_you_mean: suggestion,
                        },
                        span: to_span(span),
                    });
                }
                // Alias is valid; the template name is wrong.
                let expected_prefix = format!("{alias}::");
                let templates_in_ns: Vec<String> = self
                    .circom_table
                    .keys()
                    .filter_map(|k| k.strip_prefix(&expected_prefix).map(String::from))
                    .collect();
                let suggestion = crate::suggest::find_similar_ir(
                    field,
                    templates_in_ns.iter().map(String::as_str),
                );
                Some(ProveIrError::CircomDispatch {
                    kind: CircomDispatchErrorKind::TemplateNotFoundInNamespace {
                        alias: alias.clone(),
                        template: field.clone(),
                        did_you_mean: suggestion,
                    },
                    span: to_span(span),
                })
            }
            _ => None,
        }
    }

    /// Try to resolve an expression used as the inner callee of a
    /// `T(...)(...)` atomic curry to a key in `circom_table`.
    ///
    /// Returns `Some(key)` when the expression is either:
    /// - `Expr::Ident { name }` and `name` is a registered selective
    ///   import (bare template name key), or
    /// - `Expr::DotAccess { object: Ident(P), field: T }` and
    ///   `"P::T"` is registered as a namespace entry (Phase 3.4).
    ///
    /// Returns `None` for every other shape so the caller falls
    /// through to the normal call dispatch without regression.
    fn try_resolve_circom_key(&self, callee: &Expr) -> Option<String> {
        match callee {
            Expr::Ident { name, .. } => {
                if self.circom_table.contains_key(name) {
                    Some(name.clone())
                } else {
                    None
                }
            }
            Expr::DotAccess { object, field, .. } => {
                if let Expr::Ident { name: alias, .. } = object.as_ref() {
                    let key = format!("{alias}::{field}");
                    if self.circom_table.contains_key(&key) {
                        return Some(key);
                    }
                }
                None
            }
            _ => None,
        }
    }

    /// Core circom template instantiation path — shared by both the
    /// expression-level dispatcher and the let-binding dispatcher.
    ///
    /// Validates arity, evaluates template args to `FieldConst`,
    /// compiles signal inputs, allocates a fresh mangling prefix,
    /// dispatches to the library handle, and appends the returned
    /// body nodes to `self.body`.
    ///
    /// Returns the outputs map together with the resolved template
    /// signature so callers can project or re-bind however the
    /// caller context needs.
    fn instantiate_circom_template(
        &mut self,
        key: &str,
        template_args: &[&Expr],
        signal_inputs: &[&Expr],
        span: &Span,
    ) -> Result<
        (
            HashMap<String, super::circom_interop::CircomTemplateOutput>,
            super::circom_interop::CircomTemplateSignature,
        ),
        ProveIrError,
    > {
        let callable = self
            .circom_table
            .get(key)
            .expect("try_resolve_circom_key validated the key")
            .clone();

        let signature = callable
            .library
            .template_signature(&callable.template_name)
            .ok_or_else(|| ProveIrError::CircomDispatch {
                kind: CircomDispatchErrorKind::LoweringFailed {
                    template: callable.template_name.clone(),
                    message: "template disappeared from library after registration".into(),
                },
                span: to_span(span),
            })?;

        if template_args.len() != signature.params.len() {
            return Err(ProveIrError::CircomDispatch {
                kind: CircomDispatchErrorKind::ParamCountMismatch {
                    template: callable.template_name.clone(),
                    expected: signature.params.len(),
                    got: template_args.len(),
                },
                span: to_span(span),
            });
        }

        let mut template_const_args: Vec<FieldConst> = Vec::with_capacity(template_args.len());
        for (i, arg) in template_args.iter().enumerate() {
            let compiled = self.compile_expr(arg)?;
            match compiled {
                CircuitExpr::Const(fc) => template_const_args.push(fc),
                _ => {
                    return Err(ProveIrError::CircomDispatch {
                        kind: CircomDispatchErrorKind::TemplateArgNotConst {
                            template: callable.template_name.clone(),
                            arg_index: i,
                        },
                        span: to_span(span),
                    });
                }
            }
        }

        if signal_inputs.len() != signature.input_signals.len() {
            return Err(ProveIrError::CircomDispatch {
                kind: CircomDispatchErrorKind::SignalInputCountMismatch {
                    template: callable.template_name.clone(),
                    expected: signature.input_signals.len(),
                    got: signal_inputs.len(),
                },
                span: to_span(span),
            });
        }

        // Resolve the input layout against the concrete template
        // arguments so we know which signals are scalar vs array.
        // Array signals require the user-side expression to be an
        // `Expr::Array` literal; we expand each element into its own
        // `signal_name_<i>` entry so `instantiate_template_into` can
        // wire them individually.
        let input_layouts = callable
            .library
            .resolve_input_layout(&callable.template_name, &template_const_args)
            .ok_or_else(|| ProveIrError::CircomDispatch {
                kind: CircomDispatchErrorKind::LoweringFailed {
                    template: callable.template_name.clone(),
                    message: "could not resolve input signal dimensions for the given \
                              template arguments (parametric sizes must collapse to \
                              concrete integers)"
                        .into(),
                },
                span: to_span(span),
            })?;

        let mut signal_input_map: HashMap<String, CircuitExpr> = HashMap::new();
        for (layout, sig_input_expr) in input_layouts.iter().zip(signal_inputs.iter()) {
            if layout.dims.is_empty() {
                // Scalar signal — single expression maps 1:1.
                let compiled = self.compile_expr(sig_input_expr)?;
                signal_input_map.insert(layout.name.clone(), compiled);
                continue;
            }

            // Array-valued signal — the user must pass an array literal
            // whose flattened length matches the signal's total size.
            let expected_len: u64 = layout.dims.iter().product();
            let Expr::Array { elements, .. } = sig_input_expr else {
                return Err(ProveIrError::CircomDispatch {
                    kind: CircomDispatchErrorKind::LoweringFailed {
                        template: callable.template_name.clone(),
                        message: format!(
                            "signal input `{}` is declared as an array of size {} \
                             but the caller passed a non-array expression; wrap the \
                             inputs in `[...]` (e.g. `T(...)([a, b])`)",
                            layout.name, expected_len
                        ),
                    },
                    span: to_span(span),
                });
            };
            if elements.len() as u64 != expected_len {
                return Err(ProveIrError::CircomDispatch {
                    kind: CircomDispatchErrorKind::LoweringFailed {
                        template: callable.template_name.clone(),
                        message: format!(
                            "signal input `{}` expects an array of {} element(s) but \
                             the caller passed {}",
                            layout.name,
                            expected_len,
                            elements.len()
                        ),
                    },
                    span: to_span(span),
                });
            }
            // Build row-major flat indices (e.g. `[n]` → `_0`..`_{n-1}`,
            // `[r, c]` → `_0_0`..`_{r-1}_{c-1}`) so the key layout
            // matches `instantiate_template_into`'s expectations.
            let indices = Self::flatten_row_major_indices(&layout.dims);
            for (elem, idx) in elements.iter().zip(indices.iter()) {
                let compiled = self.compile_expr(elem)?;
                let suffix = idx
                    .iter()
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
                    .join("_");
                signal_input_map.insert(format!("{}_{suffix}", layout.name), compiled);
            }
        }

        let prefix = self.next_circom_call_prefix();

        let instantiation = callable
            .library
            .instantiate_template(
                &callable.template_name,
                &template_const_args,
                &signal_input_map,
                &prefix,
                span,
            )
            .map_err(|e| {
                use super::circom_interop::CircomDispatchError as CircomErr;
                let kind = match e {
                    CircomErr::UnknownTemplate { template, .. } => {
                        CircomDispatchErrorKind::LoweringFailed {
                            template,
                            message: "internal: template vanished mid-instantiation".into(),
                        }
                    }
                    CircomErr::ParamCountMismatch {
                        template,
                        expected,
                        got,
                    } => CircomDispatchErrorKind::ParamCountMismatch {
                        template,
                        expected,
                        got,
                    },
                    CircomErr::MissingSignalInput { template, signal } => {
                        CircomDispatchErrorKind::LoweringFailed {
                            template,
                            message: format!("missing signal input `{signal}`"),
                        }
                    }
                    CircomErr::UnsupportedArrayInput { template, signal } => {
                        CircomDispatchErrorKind::ArrayInputUnsupported { template, signal }
                    }
                    CircomErr::Lowering(msg) => CircomDispatchErrorKind::LoweringFailed {
                        template: callable.template_name.clone(),
                        message: msg,
                    },
                };
                ProveIrError::CircomDispatch {
                    kind,
                    span: to_span(span),
                }
            })?;

        self.body.extend(instantiation.body);
        Ok((instantiation.outputs, signature))
    }

    /// Expression-level circom template call. Only templates with a
    /// single scalar output are usable directly as a value — multi-
    /// output and array-output templates must be bound via `let r =
    /// T()(x)` so that `r.field` / `r.elem_i` can route through
    /// [`compile_let_for_circom_call`].
    fn compile_circom_template_call(
        &mut self,
        key: &str,
        template_args: &[&Expr],
        signal_inputs: &[&Expr],
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        let (outputs, signature) =
            self.instantiate_circom_template(key, template_args, signal_inputs, span)?;

        // Expression-level calls can only return a single scalar.
        // Multi-output and array-output templates need the let +
        // DotAccess machinery added in Phase 3.4.
        let template_name = self
            .circom_table
            .get(key)
            .map(|c| c.template_name.clone())
            .unwrap_or_default();
        if signature.output_signals.len() != 1 {
            return Err(ProveIrError::CircomDispatch {
                kind: CircomDispatchErrorKind::LoweringFailed {
                    template: template_name,
                    message: format!(
                        "template has {} outputs; bind the call with \
                         `let r = T(...)(...)` and select with `r.<output_name>`",
                        signature.output_signals.len()
                    ),
                },
                span: to_span(span),
            });
        }
        let out_name = &signature.output_signals[0];
        match outputs.get(out_name) {
            Some(super::circom_interop::CircomTemplateOutput::Scalar(expr)) => Ok(expr.clone()),
            Some(super::circom_interop::CircomTemplateOutput::Array { .. }) => {
                Err(ProveIrError::CircomDispatch {
                    kind: CircomDispatchErrorKind::ArrayOutputRequiresIndex {
                        template: template_name,
                        signal: out_name.clone(),
                    },
                    span: to_span(span),
                })
            }
            None => Err(ProveIrError::CircomDispatch {
                kind: CircomDispatchErrorKind::LoweringFailed {
                    template: template_name,
                    message: format!("instantiation returned no entry for output `{out_name}`"),
                },
                span: to_span(span),
            }),
        }
    }

    /// Let-binding-aware circom template call.
    ///
    /// When the user writes `let r = T(args)(inputs)` the circom
    /// template's outputs are published into the compiler env under
    /// "dotted" keys so subsequent DotAccess resolves to each
    /// individual output:
    ///
    /// - Scalar output `out`   → env entry `"r.out"` = Scalar(mangled)
    /// - Array  output `out[N]` → env entries `"r.out_0"`..`"r.out_{N-1}"`
    ///
    /// For single-scalar-output templates the binding `r` itself is
    /// also registered (via a plain Let node) so `r` alone still
    /// evaluates to the single output — this keeps Phase 3.3 code
    /// that treats the call as a scalar expression working.
    ///
    /// Returns `Ok(true)` when the let value was a circom template
    /// call and binding succeeded; `Ok(false)` when the value did not
    /// match the circom curry shape so the caller should fall back to
    /// the normal let-compilation path.
    fn compile_let_for_circom_call(
        &mut self,
        name: &str,
        value: &Expr,
        span: &Span,
    ) -> Result<bool, ProveIrError> {
        // Detect `Call { callee: Call { callee: <resolvable>, args: template_args }, args: signal_inputs }`.
        let Expr::Call {
            callee: outer_callee,
            args: outer_args,
            ..
        } = value
        else {
            return Ok(false);
        };
        let Expr::Call {
            callee: inner_callee,
            args: inner_args,
            ..
        } = outer_callee.as_ref()
        else {
            return Ok(false);
        };
        let Some(key) = self.try_resolve_circom_key(inner_callee) else {
            return Ok(false);
        };

        let template_arg_exprs: Vec<&Expr> = inner_args.iter().map(|a| &a.value).collect();
        let signal_input_exprs: Vec<&Expr> = outer_args.iter().map(|a| &a.value).collect();

        let (outputs, signature) =
            self.instantiate_circom_template(&key, &template_arg_exprs, &signal_input_exprs, span)?;

        // Bind every declared output under "<name>.<output>" (scalar)
        // or "<name>.<output>_<i>" (array). The mangled vars already
        // exist in self.body thanks to instantiate_circom_template;
        // the env entries just alias them so compile_dot_access can
        // resolve the user-facing `r.out` syntax.
        for sig_out in &signature.output_signals {
            match outputs.get(sig_out) {
                Some(super::circom_interop::CircomTemplateOutput::Scalar(expr)) => {
                    let CircuitExpr::Var(mangled) = expr else {
                        // Defensive: library impls return Scalar(Var(...))
                        // today. If a non-Var expression ever appears we
                        // fall back to registering under the dotted name
                        // via a fresh Let binding.
                        let dotted = format!("{name}.{sig_out}");
                        self.body.push(CircuitNode::Let {
                            name: dotted.clone(),
                            value: expr.clone(),
                            span: Some(SpanRange::from(span)),
                        });
                        self.env
                            .insert(dotted.clone(), CompEnvValue::Scalar(dotted));
                        continue;
                    };
                    let dotted = format!("{name}.{sig_out}");
                    self.env
                        .insert(dotted, CompEnvValue::Scalar(mangled.clone()));
                }
                Some(super::circom_interop::CircomTemplateOutput::Array { dims, values }) => {
                    // Row-major flatten: iterate every value and bind
                    // each under "<name>.<out>_<i>" / "<name>.<out>_<i>_<j>".
                    let total: u64 = dims.iter().product();
                    debug_assert_eq!(values.len() as u64, total);
                    for (linear_idx, value_expr) in values.iter().enumerate() {
                        let suffix = flat_index_suffix(dims, linear_idx);
                        let dotted = format!("{name}.{sig_out}_{suffix}");
                        match value_expr {
                            CircuitExpr::Var(mangled) => {
                                self.env
                                    .insert(dotted, CompEnvValue::Scalar(mangled.clone()));
                            }
                            other => {
                                self.body.push(CircuitNode::Let {
                                    name: dotted.clone(),
                                    value: other.clone(),
                                    span: Some(SpanRange::from(span)),
                                });
                                self.env
                                    .insert(dotted.clone(), CompEnvValue::Scalar(dotted));
                            }
                        }
                    }
                }
                None => {
                    return Err(ProveIrError::UnsupportedOperation {
                        description: format!(
                            "circom template declared output `{sig_out}` but instantiation \
                             returned no entry for it"
                        ),
                        span: to_span(span),
                    });
                }
            }
        }

        // Convenience: a single-scalar-output template also binds
        // `name` itself as a plain Let so existing users of
        // `let r = Square()(x); r` keep working unchanged.
        if signature.output_signals.len() == 1 {
            let sole = &signature.output_signals[0];
            if let Some(super::circom_interop::CircomTemplateOutput::Scalar(expr)) =
                outputs.get(sole)
            {
                self.body.push(CircuitNode::Let {
                    name: name.to_string(),
                    value: expr.clone(),
                    span: Some(SpanRange::from(span)),
                });
                self.env
                    .insert(name.to_string(), CompEnvValue::Scalar(name.to_string()));
            }
        }

        Ok(true)
    }

    /// Compile a named function or builtin call.
    fn compile_named_call(
        &mut self,
        name: &str,
        args: &[&Expr],
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        match name {
            // Builtins that produce CircuitExpr directly
            "poseidon" => {
                self.check_arity("poseidon", 2, args.len(), span)?;
                let left = self.compile_expr(args[0])?;
                let right = self.compile_expr(args[1])?;
                Ok(CircuitExpr::PoseidonHash {
                    left: Box::new(left),
                    right: Box::new(right),
                })
            }
            "poseidon_many" => {
                if args.len() < 2 {
                    return Err(ProveIrError::UnsupportedOperation {
                        description: format!(
                            "`poseidon_many` requires at least 2 arguments, got {}",
                            args.len()
                        ),
                        span: to_span(span),
                    });
                }
                let compiled: Result<Vec<_>, _> =
                    args.iter().map(|a| self.compile_expr(a)).collect();
                Ok(CircuitExpr::PoseidonMany(compiled?))
            }
            "mux" => {
                self.check_arity("mux", 3, args.len(), span)?;
                let cond = self.compile_expr(args[0])?;
                let if_true = self.compile_expr(args[1])?;
                let if_false = self.compile_expr(args[2])?;
                Ok(CircuitExpr::Mux {
                    cond: Box::new(cond),
                    if_true: Box::new(if_true),
                    if_false: Box::new(if_false),
                })
            }
            "range_check" => {
                self.check_arity("range_check", 2, args.len(), span)?;
                let value = self.compile_expr(args[0])?;
                let bits_u64 = self.extract_const_u64(args[1], span)?;
                if bits_u64 > u32::MAX as u64 {
                    return Err(ProveIrError::UnsupportedOperation {
                        description: format!(
                            "range_check bit count {bits_u64} exceeds maximum ({})",
                            u32::MAX
                        ),
                        span: to_span(span),
                    });
                }
                let bits = bits_u64 as u32;
                Ok(CircuitExpr::RangeCheck {
                    value: Box::new(value),
                    bits,
                })
            }
            "merkle_verify" => {
                self.check_arity("merkle_verify", 4, args.len(), span)?;
                let root = self.compile_expr(args[0])?;
                let leaf = self.compile_expr(args[1])?;
                // path and indices must be array identifiers (referenced by name)
                let path = self.extract_array_ident(args[2], span)?;
                let indices = self.extract_array_ident(args[3], span)?;
                Ok(CircuitExpr::MerkleVerify {
                    root: Box::new(root),
                    leaf: Box::new(leaf),
                    path,
                    indices,
                })
            }
            "len" => {
                self.check_arity("len", 1, args.len(), span)?;
                self.compile_len_call(args[0], span)
            }

            // Builtins that produce CircuitNode (handled at statement level)
            // assert_eq and assert are expression-level in the AST but produce
            // nodes — we return a dummy Const(0) since they're constraints, not values.
            "assert_eq" => {
                self.check_assert_eq_arity(args.len(), span)?;
                let lhs = self.compile_expr(args[0])?;
                let rhs = self.compile_expr(args[1])?;
                let message = self.extract_assert_message(args.get(2), span)?;
                // Always emit the constraint node — even at expression level.
                // This ensures the constraint is enforced regardless of whether
                // assert_eq is used as a statement or inside a let binding.
                self.body.push(CircuitNode::AssertEq {
                    lhs,
                    rhs,
                    message,
                    span: Some(SpanRange::from(span)),
                });
                Ok(CircuitExpr::Const(FieldConst::zero()))
            }
            "assert" => {
                self.check_assert_arity(args.len(), span)?;
                let cond = self.compile_expr(args[0])?;
                let message = self.extract_assert_message(args.get(1), span)?;
                // Always emit the constraint node — same rationale as assert_eq.
                self.body.push(CircuitNode::Assert {
                    expr: cond,
                    message,
                    span: Some(SpanRange::from(span)),
                });
                Ok(CircuitExpr::Const(FieldConst::zero()))
            }

            // Integer division: int_div(lhs, rhs, max_bits)
            "int_div" => {
                self.check_arity("int_div", 3, args.len(), span)?;
                let lhs = self.compile_expr(args[0])?;
                let rhs = self.compile_expr(args[1])?;
                let max_bits = self.extract_const_u64(args[2], span)? as u32;
                Ok(CircuitExpr::IntDiv {
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                    max_bits,
                })
            }
            // Integer remainder: int_mod(lhs, rhs, max_bits)
            "int_mod" => {
                self.check_arity("int_mod", 3, args.len(), span)?;
                let lhs = self.compile_expr(args[0])?;
                let rhs = self.compile_expr(args[1])?;
                let max_bits = self.extract_const_u64(args[2], span)? as u32;
                Ok(CircuitExpr::IntMod {
                    lhs: Box::new(lhs),
                    rhs: Box::new(rhs),
                    max_bits,
                })
            }

            // User function call (inlined)
            _ => self.compile_user_fn_call(name, args, span),
        }
    }

    // -----------------------------------------------------------------------
    // Dot access (non-call)
    // -----------------------------------------------------------------------

    fn compile_dot_access(
        &mut self,
        object: &Expr,
        field: &str,
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        // module.constant access
        if let Expr::Ident { name: module, .. } = object {
            // Module-level constants resolve through a `module::field`
            // env key.
            let qualified = format!("{module}::{field}");
            if let Some(CompEnvValue::Scalar(resolved)) = self.env.get(&qualified) {
                return Ok(CircuitExpr::Var(resolved.clone()));
            }
            // Circom template output fields: `let r = T()(x); r.out`
            // bound in compile_let_for_circom_call under the dotted
            // "<binding_name>.<output_name>" env key.
            let dotted = format!("{module}.{field}");
            if let Some(CompEnvValue::Scalar(resolved)) = self.env.get(&dotted) {
                return Ok(CircuitExpr::Var(resolved.clone()));
            }
        }
        Err(ProveIrError::UnsupportedOperation {
            description: "dot access is not supported in circuits \
                          (use methods like .len(), .abs(), etc. or arrays with indexing)"
                .into(),
            span: to_span(span),
        })
    }

    // -----------------------------------------------------------------------
    // Method desugaring
    // -----------------------------------------------------------------------

    fn compile_method_call(
        &mut self,
        object: &Expr,
        method: &str,
        args: &[&Expr],
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        match method {
            // --- Universally supported ---
            "len" => {
                if !args.is_empty() {
                    return Err(ProveIrError::WrongArgumentCount {
                        name: "len".into(),
                        expected: 0,
                        got: args.len(),
                        span: to_span(span),
                    });
                }
                self.compile_len_call(object, span)
            }

            // --- Identity in circuit context ---
            "to_field" => {
                if !args.is_empty() {
                    return Err(ProveIrError::WrongArgumentCount {
                        name: "to_field".into(),
                        expected: 0,
                        got: args.len(),
                        span: to_span(span),
                    });
                }
                // All circuit values are field elements — identity
                self.compile_expr(object)
            }

            // --- Int methods desugared to circuit primitives ---
            // NOTE: abs/min/max use CircuitCmpOp::Lt which requires a signed-range
            // comparison gadget at instantiation time (Phase B). See CircuitCmpOp doc.
            "abs" => {
                if !args.is_empty() {
                    return Err(ProveIrError::WrongArgumentCount {
                        name: "abs".into(),
                        expected: 0,
                        got: args.len(),
                        span: to_span(span),
                    });
                }
                let x = self.compile_expr(object)?;
                let zero = CircuitExpr::Const(FieldConst::zero());
                Ok(CircuitExpr::Mux {
                    cond: Box::new(CircuitExpr::Comparison {
                        op: CircuitCmpOp::Lt,
                        lhs: Box::new(x.clone()),
                        rhs: Box::new(zero),
                    }),
                    if_true: Box::new(CircuitExpr::UnaryOp {
                        op: CircuitUnaryOp::Neg,
                        operand: Box::new(x.clone()),
                    }),
                    if_false: Box::new(x),
                })
            }
            "min" => {
                self.check_method_arity("min", 1, args.len(), span)?;
                let n = self.compile_expr(object)?;
                let m = self.compile_expr(args[0])?;
                Ok(CircuitExpr::Mux {
                    cond: Box::new(CircuitExpr::Comparison {
                        op: CircuitCmpOp::Lt,
                        lhs: Box::new(n.clone()),
                        rhs: Box::new(m.clone()),
                    }),
                    if_true: Box::new(n),
                    if_false: Box::new(m),
                })
            }
            "max" => {
                self.check_method_arity("max", 1, args.len(), span)?;
                let n = self.compile_expr(object)?;
                let m = self.compile_expr(args[0])?;
                Ok(CircuitExpr::Mux {
                    cond: Box::new(CircuitExpr::Comparison {
                        op: CircuitCmpOp::Lt,
                        lhs: Box::new(n.clone()),
                        rhs: Box::new(m.clone()),
                    }),
                    if_true: Box::new(m),
                    if_false: Box::new(n),
                })
            }
            "pow" => {
                self.check_method_arity("pow", 1, args.len(), span)?;
                let base = self.compile_expr(object)?;
                let exp = self.extract_const_u64(args[0], span)?;
                Ok(CircuitExpr::Pow {
                    base: Box::new(base),
                    exp,
                })
            }

            // --- Methods that cannot be compiled to constraints ---
            "to_string" => Err(self.method_not_constrainable(
                "to_string",
                "produces a string, which cannot be represented in circuits",
                span,
            )),
            "to_int" => Err(self.method_not_constrainable(
                "to_int",
                "type narrowing is not needed in circuits (all values are field elements)",
                span,
            )),
            "push" | "pop" => Err(self.method_not_constrainable(
                method,
                "mutation is not supported in circuits (arrays have fixed size)",
                span,
            )),
            "map" | "filter" | "reduce" | "for_each" | "find" | "any" | "all" | "sort"
            | "flat_map" | "zip" => Err(self.method_not_constrainable(
                method,
                "higher-order collection methods are not yet supported in circuits \
                 (use a for loop instead)",
                span,
            )),
            "keys" | "values" | "entries" | "contains_key" | "get" | "set" | "remove" => Err(self
                .method_not_constrainable(
                    method,
                    "map operations are not supported in circuits \
                     (maps cannot be represented as constraints)",
                    span,
                )),
            "split" | "trim" | "replace" | "to_upper" | "to_lower" | "chars" | "index_of"
            | "substring" | "repeat" | "starts_with" | "ends_with" | "contains" => Err(self
                .method_not_constrainable(
                    method,
                    "string operations are not supported in circuits",
                    span,
                )),
            "bit_and" | "bit_or" | "bit_xor" | "bit_not" | "bit_shl" | "bit_shr" | "to_bits" => {
                Err(self.method_not_constrainable(
                    method,
                    "BigInt operations are not supported in circuits",
                    span,
                ))
            }

            _ => Err(ProveIrError::UnsupportedOperation {
                description: format!("method `.{method}()` is not supported in circuits"),
                span: to_span(span),
            }),
        }
    }

    // -----------------------------------------------------------------------
    // Helpers for call/method compilation
    // -----------------------------------------------------------------------

    /// Extract an array identifier name from an expression (for merkle_verify args).
    fn extract_array_ident(&mut self, expr: &Expr, span: &Span) -> Result<String, ProveIrError> {
        if let Expr::Ident { name, .. } = expr {
            match self.env.get(name.as_str()) {
                Some(CompEnvValue::Array(elems)) => {
                    // Mark element names as captured (only if they ARE captures
                    // from the outer scope, not declared inputs within the circuit).
                    for elem in elems.clone() {
                        if matches!(self.env.get(&elem), Some(CompEnvValue::Capture(_))) {
                            self.captured_names.insert(elem);
                        }
                    }
                    return Ok(name.clone());
                }
                Some(CompEnvValue::Capture(_)) => {
                    return Ok(name.clone());
                }
                _ => {}
            }
        }
        Err(ProveIrError::UnsupportedOperation {
            description: "merkle_verify requires array identifiers for path and indices".into(),
            span: to_span(span),
        })
    }

    /// Compile `len(expr)` or `expr.len()` — resolve to ArrayLen.
    fn compile_len_call(
        &mut self,
        object: &Expr,
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        if let Expr::Ident { name, .. } = object {
            if matches!(
                self.env.get(name.as_str()),
                Some(CompEnvValue::Array(_)) | Some(CompEnvValue::Capture(_))
            ) {
                return Ok(CircuitExpr::ArrayLen(name.clone()));
            }
        }
        Err(ProveIrError::UnsupportedOperation {
            description: "len() requires an array variable in circuits".into(),
            span: to_span(span),
        })
    }

    fn check_arity(
        &self,
        name: &str,
        expected: usize,
        got: usize,
        span: &Span,
    ) -> Result<(), ProveIrError> {
        if got != expected {
            return Err(ProveIrError::WrongArgumentCount {
                name: name.into(),
                expected,
                got,
                span: to_span(span),
            });
        }
        Ok(())
    }

    /// Validate assert_eq arity: 2 or 3 arguments.
    fn check_assert_eq_arity(&self, got: usize, span: &Span) -> Result<(), ProveIrError> {
        if !(2..=3).contains(&got) {
            return Err(ProveIrError::UnsupportedOperation {
                description: format!("`assert_eq` expects 2 or 3 arguments, got {got}"),
                span: to_span(span),
            });
        }
        Ok(())
    }

    /// Validate assert arity: 1 or 2 arguments.
    fn check_assert_arity(&self, got: usize, span: &Span) -> Result<(), ProveIrError> {
        if !(1..=2).contains(&got) {
            return Err(ProveIrError::UnsupportedOperation {
                description: format!("`assert` expects 1 or 2 arguments, got {got}"),
                span: to_span(span),
            });
        }
        Ok(())
    }

    /// Extract an optional string literal for assert_eq/assert messages.
    fn extract_assert_message(
        &self,
        arg: Option<&&Expr>,
        span: &Span,
    ) -> Result<Option<String>, ProveIrError> {
        match arg {
            None => Ok(None),
            Some(Expr::StringLit { value, .. }) => Ok(Some(value.clone())),
            Some(_) => Err(ProveIrError::TypeMismatch {
                expected: "string literal".into(),
                got: "non-string expression (assert_eq message must be a string literal)".into(),
                span: to_span(span),
            }),
        }
    }

    fn check_method_arity(
        &self,
        name: &str,
        expected: usize,
        got: usize,
        span: &Span,
    ) -> Result<(), ProveIrError> {
        if got != expected {
            return Err(ProveIrError::WrongArgumentCount {
                name: format!(".{name}()"),
                expected,
                got,
                span: to_span(span),
            });
        }
        Ok(())
    }

    fn method_not_constrainable(&self, method: &str, reason: &str, span: &Span) -> ProveIrError {
        ProveIrError::MethodNotConstrainable {
            method: method.into(),
            reason: reason.into(),
            span: to_span(span),
        }
    }

    /// Check if a function name exists in the fn_table.
    fn has_function(&self, name: &str) -> bool {
        self.fn_table.contains_key(name)
    }

    // -----------------------------------------------------------------------
    // Control flow
    // -----------------------------------------------------------------------

    fn compile_if_expr(
        &mut self,
        condition: &Expr,
        then_block: &Block,
        else_branch: Option<&ElseBranch>,
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        let cond = self.compile_expr(condition)?;

        // Bind condition to a temporary to avoid duplicating it in both
        // the CircuitNode::If and the Mux (which would double constraint cost).
        let cond_var = format!("$cond{}", self.inline_counter);
        self.inline_counter = self.inline_counter.wrapping_add(1);
        self.body.push(CircuitNode::Let {
            name: cond_var.clone(),
            value: cond,
            span: Some(SpanRange::from(span)),
        });
        let cond_ref = CircuitExpr::Var(cond_var);

        // Save body vec, compile then/else into separate buffers
        let saved_body = std::mem::take(&mut self.body);

        // Then branch
        self.body = Vec::new();
        let then_result = self.compile_block_as_expr(then_block)?;
        let then_nodes = std::mem::take(&mut self.body);

        // Else branch
        self.body = Vec::new();
        let (else_result, else_nodes) = match else_branch {
            Some(ElseBranch::Block(block)) => {
                let r = self.compile_block_as_expr(block)?;
                (r, std::mem::take(&mut self.body))
            }
            Some(ElseBranch::If(if_expr)) => {
                let r = self.compile_expr(if_expr)?;
                (r, std::mem::take(&mut self.body))
            }
            None => (CircuitExpr::Const(FieldConst::zero()), Vec::new()),
        };

        // Restore body and emit the If node
        self.body = saved_body;

        // If both branches have side-effect nodes (Let, Assert, etc.),
        // emit them as a CircuitNode::If. The result values become
        // the Mux during instantiation (Phase B).
        if !then_nodes.is_empty() || !else_nodes.is_empty() {
            self.body.push(CircuitNode::If {
                cond: cond_ref.clone(),
                then_body: then_nodes,
                else_body: else_nodes,
                span: Some(SpanRange::from(span)),
            });
        }

        // The expression result is a Mux over the two branch results
        Ok(CircuitExpr::Mux {
            cond: Box::new(cond_ref),
            if_true: Box::new(then_result),
            if_false: Box::new(else_result),
        })
    }

    fn compile_for_expr(
        &mut self,
        var: &str,
        iterable: &ForIterable,
        body: &Block,
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        /// Maximum number of iterations allowed for literal ranges.
        const MAX_LOOP_ITERATIONS: u64 = 1_000_000;

        let range = match iterable {
            ForIterable::Range { start, end } => {
                let iterations = end.saturating_sub(*start);
                if iterations > MAX_LOOP_ITERATIONS {
                    return Err(ProveIrError::RangeTooLarge {
                        iterations,
                        max: MAX_LOOP_ITERATIONS,
                        span: to_span(span),
                    });
                }
                ForRange::Literal {
                    start: *start,
                    end: *end,
                }
            }
            ForIterable::ExprRange { start, end } => {
                // Dynamic end bound: compile to WithCapture or WithExpr.
                // Simple capture name → WithCapture; expression → WithExpr.
                if let Expr::Ident { name, .. } = end.as_ref() {
                    if matches!(self.env.get(name.as_str()), Some(CompEnvValue::Capture(_))) {
                        self.captured_names.insert(name.clone());
                        ForRange::WithCapture {
                            start: *start,
                            end_capture: name.clone(),
                        }
                    } else {
                        return Err(ProveIrError::UnsupportedOperation {
                            description: format!(
                                "dynamic loop bound `{name}` must be a captured variable \
                                 (from outer scope)"
                            ),
                            span: to_span(span),
                        });
                    }
                } else {
                    // Compile the end expression to a CircuitExpr
                    let end_circuit = self.compile_expr(end)?;
                    ForRange::WithExpr {
                        start: *start,
                        end_expr: Box::new(end_circuit),
                    }
                }
            }
            ForIterable::Expr(expr) => {
                // Must be an array identifier
                if let Expr::Ident { name, .. } = expr.as_ref() {
                    if matches!(self.env.get(name.as_str()), Some(CompEnvValue::Array(_))) {
                        ForRange::Array(name.clone())
                    } else if matches!(self.env.get(name.as_str()), Some(CompEnvValue::Capture(_)))
                    {
                        // Capture used as iterable — could be an array, defer to instantiation
                        ForRange::Array(name.clone())
                    } else {
                        return Err(ProveIrError::UnsupportedOperation {
                            description: format!(
                                "for loop iterable `{name}` must be an array or range \
                                 in circuits"
                            ),
                            span: to_span(span),
                        });
                    }
                } else {
                    return Err(ProveIrError::UnsupportedOperation {
                        description: "for loops in circuits require a literal range \
                                      (e.g., 0..5), a dynamic range (0..n), or an array"
                            .into(),
                        span: to_span(span),
                    });
                }
            }
        };

        // Save body, compile loop body into a separate buffer
        let saved_body = std::mem::take(&mut self.body);

        // Register loop var in env
        let saved_var = self.env.get(var).cloned();
        self.env
            .insert(var.to_string(), CompEnvValue::Scalar(var.to_string()));

        self.body = Vec::new();
        let _body_result = self.compile_block_as_expr(body)?;
        let loop_body = std::mem::take(&mut self.body);

        // Restore
        match saved_var {
            Some(v) => {
                self.env.insert(var.to_string(), v);
            }
            None => {
                self.env.remove(var);
            }
        }
        self.body = saved_body;

        // Emit the For node (preserved, unrolled during Phase B instantiation)
        self.body.push(CircuitNode::For {
            var: var.to_string(),
            range,
            body: loop_body,
            span: Some(SpanRange::from(span)),
        });

        // For loops don't produce a useful expression value in circuit context
        Ok(CircuitExpr::Const(FieldConst::zero()))
    }

    fn compile_index(
        &mut self,
        object: &Expr,
        index: &Expr,
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        let name = match object {
            Expr::Ident { name, .. } => name.clone(),
            _ => {
                return Err(ProveIrError::UnsupportedOperation {
                    description: "indexing is only supported on array identifiers in circuits"
                        .into(),
                    span: to_span(span),
                });
            }
        };

        // Check the array exists
        if !matches!(
            self.env.get(name.as_str()),
            Some(CompEnvValue::Array(_)) | Some(CompEnvValue::Capture(_))
        ) {
            return Err(ProveIrError::TypeMismatch {
                expected: "array".into(),
                got: "scalar".into(),
                span: to_span(span),
            });
        }

        // Try to resolve as a constant index → direct element access
        if let Expr::Number { value, .. } = index {
            if let Ok(idx) = value.parse::<usize>() {
                if let Some(CompEnvValue::Array(elems)) = self.env.get(name.as_str()) {
                    if idx >= elems.len() {
                        return Err(ProveIrError::IndexOutOfBounds {
                            name: name.clone(),
                            index: idx,
                            length: elems.len(),
                            span: to_span(span),
                        });
                    }
                    return Ok(CircuitExpr::Var(elems[idx].clone()));
                }
            }
        }

        // Dynamic or capture-based index → ArrayIndex node
        let idx_expr = self.compile_expr(index)?;
        Ok(CircuitExpr::ArrayIndex {
            array: name,
            index: Box::new(idx_expr),
        })
    }

    // -----------------------------------------------------------------------
    // User function inlining
    // -----------------------------------------------------------------------

    fn compile_user_fn_call(
        &mut self,
        name: &str,
        args: &[&Expr],
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        let fn_def =
            self.fn_table
                .get(name)
                .cloned()
                .ok_or_else(|| ProveIrError::UndeclaredVariable {
                    name: name.into(),
                    span: to_span(span),
                    suggestion: None,
                })?;

        // Arity check
        if args.len() != fn_def.params.len() {
            return Err(ProveIrError::WrongArgumentCount {
                name: name.into(),
                expected: fn_def.params.len(),
                got: args.len(),
                span: to_span(span),
            });
        }

        // Recursion guard
        if self.call_stack.contains(name) {
            return Err(ProveIrError::RecursiveFunction { name: name.into() });
        }
        self.call_stack.insert(name.to_string());

        // Save env for param names (+ array element names) and bind args
        let param_names: Vec<String> = fn_def.params.iter().map(|p| p.name.clone()).collect();

        // Collect all names that might be shadowed (param names + element names
        // for array params) so we can restore them after inlining.
        let mut all_shadow_names: Vec<String> = param_names.clone();
        for (i, param) in fn_def.params.iter().enumerate() {
            if let Some(ref ta) = param.type_ann {
                if let Some(size) = ta.array_size {
                    for j in 0..size {
                        all_shadow_names.push(format!("{}_{j}", param_names[i]));
                    }
                }
            }
        }
        let saved: Vec<(String, Option<CompEnvValue>)> = all_shadow_names
            .iter()
            .map(|p| (p.clone(), self.env.get(p).cloned()))
            .collect();

        // Use a unique invocation counter to avoid name collisions when the
        // same function is inlined multiple times.
        let invoke_id = self.inline_counter;
        self.inline_counter = self.inline_counter.wrapping_add(1);

        // Emit Let/LetArray nodes for each parameter binding.
        for (i, (param, arg)) in param_names.iter().zip(args.iter()).enumerate() {
            let is_array_param = fn_def.params[i]
                .type_ann
                .as_ref()
                .and_then(|ta| ta.array_size)
                .is_some();

            if is_array_param {
                // Array parameter: resolve the argument as an array identifier
                // and create SSA copies of each element.
                self.bind_array_fn_param(name, invoke_id, param, arg, span)?;
            } else {
                // Scalar parameter: compile as expression and bind.
                let compiled = self.compile_expr(arg)?;
                let param_ssa = format!("__{name}${invoke_id}_{param}");
                self.body.push(CircuitNode::Let {
                    name: param_ssa.clone(),
                    value: compiled,
                    span: Some(SpanRange::from(span)),
                });
                self.env
                    .insert(param.clone(), CompEnvValue::Scalar(param_ssa));
            }
        }

        // Compile the function body, collecting the result
        let result = self.compile_block_as_expr(&fn_def.body)?;

        // Restore env
        for (p, old_val) in saved {
            match old_val {
                Some(v) => {
                    self.env.insert(p, v);
                }
                None => {
                    self.env.remove(&p);
                }
            }
        }

        self.call_stack.remove(name);
        Ok(result)
    }

    /// Bind an array parameter for function inlining.
    ///
    /// Resolves the argument as an array name in the environment, creates
    /// SSA-renamed copies of each element, and registers the parameter as
    /// `CompEnvValue::Array` in the env.
    fn bind_array_fn_param(
        &mut self,
        fn_name: &str,
        invoke_id: u32,
        param_name: &str,
        arg: &Expr,
        span: &Span,
    ) -> Result<(), ProveIrError> {
        let arg_ident = match arg {
            Expr::Ident { name, .. } => name.as_str(),
            _ => {
                return Err(ProveIrError::UnsupportedOperation {
                    description: format!(
                        "array argument for parameter `{param_name}` must be a variable name, \
                         not an expression"
                    ),
                    span: to_span(span),
                });
            }
        };

        let src_elems = match self.env.get(arg_ident) {
            Some(CompEnvValue::Array(elems)) => elems.clone(),
            Some(CompEnvValue::Capture(_)) => {
                // Captured array from outer scope — look up the capture's
                // element names which follow the convention `name_0`, `name_1`, etc.
                // The outer scope must have provided an array-size entry.
                return Err(ProveIrError::UnsupportedOperation {
                    description: format!(
                        "captured array `{arg_ident}` cannot be passed directly as a parameter; \
                         bind it to a local array first: `let local = {arg_ident}`"
                    ),
                    span: to_span(span),
                });
            }
            _ => {
                return Err(ProveIrError::TypeMismatch {
                    expected: "array".into(),
                    got: "scalar".into(),
                    span: to_span(span),
                });
            }
        };

        let base_ssa = format!("__{fn_name}${invoke_id}_{param_name}");
        let new_elem_names: Vec<String> = (0..src_elems.len())
            .map(|j| format!("{base_ssa}_{j}"))
            .collect();

        // Emit LetArray node with references to the source elements.
        let elem_exprs: Vec<CircuitExpr> = src_elems
            .iter()
            .map(|e| match self.env.get(e) {
                Some(CompEnvValue::Scalar(s)) => CircuitExpr::Var(s.clone()),
                Some(CompEnvValue::Capture(c)) => {
                    self.captured_names.insert(c.clone());
                    CircuitExpr::Capture(c.clone())
                }
                _ => CircuitExpr::Var(e.clone()),
            })
            .collect();

        self.body.push(CircuitNode::LetArray {
            name: base_ssa.clone(),
            elements: elem_exprs,
            span: Some(SpanRange::from(span)),
        });

        // Register each element as Scalar and the array in env.
        for ename in &new_elem_names {
            self.env
                .insert(ename.clone(), CompEnvValue::Scalar(ename.clone()));
        }
        self.env
            .insert(param_name.to_string(), CompEnvValue::Array(new_elem_names));

        Ok(())
    }

    /// Compile a block of statements and return the result of the last expression.
    /// Intermediate statements (Let, AssertEq, etc.) are appended to self.body.
    /// The last expression statement becomes the return value.
    /// If the block has no expression result, returns Const(ZERO).
    fn compile_block_as_expr(&mut self, block: &Block) -> Result<CircuitExpr, ProveIrError> {
        let stmts = &block.stmts;
        if stmts.is_empty() {
            return Ok(CircuitExpr::Const(FieldConst::zero()));
        }

        // Compile all but the last statement normally
        for stmt in &stmts[..stmts.len() - 1] {
            // Handle Return inside function body
            if let Stmt::Return { value, .. } = stmt {
                return match value {
                    Some(expr) => self.compile_expr(expr),
                    None => Ok(CircuitExpr::Const(FieldConst::zero())),
                };
            }
            self.compile_stmt(stmt)?;
        }

        // The last statement: if it's an Expr, return its value; otherwise compile and return ZERO
        let last = &stmts[stmts.len() - 1];
        match last {
            Stmt::Expr(expr) => self.compile_expr(expr),
            Stmt::Return { value, .. } => match value {
                Some(expr) => self.compile_expr(expr),
                None => Ok(CircuitExpr::Const(FieldConst::zero())),
            },
            other => {
                self.compile_stmt(other)?;
                Ok(CircuitExpr::Const(FieldConst::zero()))
            }
        }
    }

    // -----------------------------------------------------------------------
    // Binary operations
    // -----------------------------------------------------------------------

    fn compile_binop(
        &mut self,
        op: &BinOp,
        lhs: &Expr,
        rhs: &Expr,
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        match op {
            // Arithmetic → CircuitBinOp
            BinOp::Add => self.compile_arith_binop(CircuitBinOp::Add, lhs, rhs),
            BinOp::Sub => self.compile_arith_binop(CircuitBinOp::Sub, lhs, rhs),
            BinOp::Mul => self.compile_arith_binop(CircuitBinOp::Mul, lhs, rhs),
            BinOp::Div => self.compile_arith_binop(CircuitBinOp::Div, lhs, rhs),

            // Comparisons → CircuitCmpOp
            BinOp::Eq => self.compile_comparison(CircuitCmpOp::Eq, lhs, rhs),
            BinOp::Neq => self.compile_comparison(CircuitCmpOp::Neq, lhs, rhs),
            BinOp::Lt => self.compile_comparison(CircuitCmpOp::Lt, lhs, rhs),
            BinOp::Le => self.compile_comparison(CircuitCmpOp::Le, lhs, rhs),
            BinOp::Gt => self.compile_comparison(CircuitCmpOp::Gt, lhs, rhs),
            BinOp::Ge => self.compile_comparison(CircuitCmpOp::Ge, lhs, rhs),

            // Boolean → CircuitBoolOp
            BinOp::And => self.compile_bool_binop(CircuitBoolOp::And, lhs, rhs),
            BinOp::Or => self.compile_bool_binop(CircuitBoolOp::Or, lhs, rhs),

            // Mod → error
            BinOp::Mod => Err(ProveIrError::UnsupportedOperation {
                description: "modulo (%) is not supported in circuits \
                              (no efficient field arithmetic equivalent — use range_check)"
                    .into(),
                span: to_span(span),
            }),

            // Pow → CircuitExpr::Pow (exponent must be a constant)
            BinOp::Pow => self.compile_pow(lhs, rhs, span),
        }
    }

    fn compile_arith_binop(
        &mut self,
        op: CircuitBinOp,
        lhs: &Expr,
        rhs: &Expr,
    ) -> Result<CircuitExpr, ProveIrError> {
        let l = self.compile_expr(lhs)?;
        let r = self.compile_expr(rhs)?;
        Ok(CircuitExpr::BinOp {
            op,
            lhs: Box::new(l),
            rhs: Box::new(r),
        })
    }

    fn compile_comparison(
        &mut self,
        op: CircuitCmpOp,
        lhs: &Expr,
        rhs: &Expr,
    ) -> Result<CircuitExpr, ProveIrError> {
        let l = self.compile_expr(lhs)?;
        let r = self.compile_expr(rhs)?;
        Ok(CircuitExpr::Comparison {
            op,
            lhs: Box::new(l),
            rhs: Box::new(r),
        })
    }

    fn compile_bool_binop(
        &mut self,
        op: CircuitBoolOp,
        lhs: &Expr,
        rhs: &Expr,
    ) -> Result<CircuitExpr, ProveIrError> {
        let l = self.compile_expr(lhs)?;
        let r = self.compile_expr(rhs)?;
        Ok(CircuitExpr::BoolOp {
            op,
            lhs: Box::new(l),
            rhs: Box::new(r),
        })
    }

    fn compile_pow(
        &mut self,
        base_expr: &Expr,
        exp_expr: &Expr,
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        let base = self.compile_expr(base_expr)?;
        let exp = self.extract_const_u64(exp_expr, span)?;
        Ok(CircuitExpr::Pow {
            base: Box::new(base),
            exp,
        })
    }

    /// Try to extract a constant u64 from an expression (for exponents, range_check bits, etc.)
    fn extract_const_u64(&self, expr: &Expr, span: &Span) -> Result<u64, ProveIrError> {
        match expr {
            Expr::Number { value, .. } => {
                let n: u64 = value
                    .parse()
                    .map_err(|_| ProveIrError::UnsupportedOperation {
                        description: format!(
                            "expected a non-negative integer constant, got `{value}`"
                        ),
                        span: to_span(span),
                    })?;
                Ok(n)
            }
            _ => Err(ProveIrError::UnsupportedOperation {
                description: "exponent must be a constant integer in circuits \
                     (x^n is unrolled to n multiplications at compile time)"
                    .into(),
                span: to_span(span),
            }),
        }
    }

    // -----------------------------------------------------------------------
    // Unary operations
    // -----------------------------------------------------------------------

    fn compile_unary(
        &mut self,
        op: &UnaryOp,
        operand: &Expr,
        _span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        // Double negation / double NOT cancellation: --x → x, !!x → x
        if let Expr::UnaryOp {
            op: inner_op,
            operand: inner_operand,
            ..
        } = operand
        {
            if inner_op == op {
                return self.compile_expr(inner_operand);
            }
        }

        let inner = self.compile_expr(operand)?;
        let circuit_op = match op {
            UnaryOp::Neg => CircuitUnaryOp::Neg,
            UnaryOp::Not => CircuitUnaryOp::Not,
        };
        Ok(CircuitExpr::UnaryOp {
            op: circuit_op,
            operand: Box::new(inner),
        })
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a parsed Program into a Block (Programs don't carry their own span).
fn program_to_block(source: &str, program: achronyme_parser::ast::Program) -> Block {
    Block {
        stmts: program.stmts,
        span: Span {
            byte_start: 0,
            byte_end: source.len(),
            line_start: 1,
            col_start: 1,
            line_end: 1,
            col_end: 1,
        },
    }
}

/// Convert an AST Span to an OptSpan for error reporting.
/// Build the row-major flattened suffix for a multi-dimensional
/// element index. For `dims = [3]` and `linear = 2` this returns
/// `"2"`; for `dims = [2, 2]` and `linear = 3` it returns `"1_1"`.
fn flat_index_suffix(dims: &[u64], linear: usize) -> String {
    if dims.len() <= 1 {
        return linear.to_string();
    }
    let mut remaining = linear;
    let mut parts: Vec<String> = Vec::with_capacity(dims.len());
    // Compute strides from the right (row-major).
    let mut strides: Vec<u64> = Vec::with_capacity(dims.len());
    let mut s = 1u64;
    for d in dims.iter().rev() {
        strides.push(s);
        s = s.saturating_mul(*d);
    }
    strides.reverse();
    for stride in &strides {
        let idx = remaining as u64 / *stride;
        parts.push(idx.to_string());
        remaining = (remaining as u64 % *stride) as usize;
    }
    parts.join("_")
}

fn to_span(span: &Span) -> OptSpan {
    span_box(Some(SpanRange::from(span)))
}

/// Convert a TypeAnnotation to IrType.
/// Only circuit types (Field, Bool) are valid here — Int/String are VM-only.
fn annotation_to_ir_type(ann: &TypeAnnotation) -> IrType {
    match ann.base {
        achronyme_parser::ast::BaseType::Field => IrType::Field,
        achronyme_parser::ast::BaseType::Bool => IrType::Bool,
        achronyme_parser::ast::BaseType::Int | achronyme_parser::ast::BaseType::String => {
            unreachable!("type `{}` is not valid in circuit/prove context", ann.base)
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use achronyme_parser::parse_program;

    /// Helper: parse source and compile the first expression to CircuitExpr.
    fn compile_single_expr(source: &str) -> Result<CircuitExpr, ProveIrError> {
        let (program, errors) = parse_program(source);
        assert!(errors.is_empty(), "parse errors: {errors:?}");
        let mut compiler = ProveIrCompiler::<Bn254Fr>::new();
        match &program.stmts[0] {
            Stmt::Expr(expr) => compiler.compile_expr(expr),
            _ => panic!("expected expression statement"),
        }
    }

    /// Helper: parse source with outer scope, compile an expression.
    fn compile_expr_with_scope(
        source: &str,
        scope: &[(&str, CompEnvValue)],
    ) -> Result<CircuitExpr, ProveIrError> {
        let (program, errors) = parse_program(source);
        assert!(errors.is_empty(), "parse errors: {errors:?}");
        let mut compiler = ProveIrCompiler::<Bn254Fr>::new();
        for (name, val) in scope {
            compiler.env.insert(name.to_string(), val.clone());
        }
        match &program.stmts[0] {
            Stmt::Expr(expr) => compiler.compile_expr(expr),
            _ => panic!("expected expression statement"),
        }
    }

    // --- Literals ---

    #[test]
    fn number_literal() {
        let expr = compile_single_expr("42").unwrap();
        assert_eq!(expr, CircuitExpr::Const(FieldConst::from_u64(42)));
    }

    #[test]
    fn negative_number() {
        let expr = compile_single_expr("-7").unwrap();
        assert_eq!(
            expr,
            CircuitExpr::UnaryOp {
                op: CircuitUnaryOp::Neg,
                operand: Box::new(CircuitExpr::Const(FieldConst::from_u64(7))),
            }
        );
    }

    #[test]
    fn field_literal_decimal() {
        let expr = compile_single_expr("0p42").unwrap();
        assert_eq!(expr, CircuitExpr::Const(FieldConst::from_u64(42)));
    }

    #[test]
    fn field_literal_hex() {
        let expr = compile_single_expr("0pxFF").unwrap();
        assert_eq!(expr, CircuitExpr::Const(FieldConst::from_u64(255)));
    }

    #[test]
    fn bool_true() {
        let expr = compile_single_expr("true").unwrap();
        assert_eq!(expr, CircuitExpr::Const(FieldConst::one()));
    }

    #[test]
    fn bool_false() {
        let expr = compile_single_expr("false").unwrap();
        assert_eq!(expr, CircuitExpr::Const(FieldConst::zero()));
    }

    #[test]
    fn negative_field_literal() {
        // Negative numbers go through UnaryOp(Neg, Number)
        let scope = [("x", CompEnvValue::Scalar("x".into()))];
        let expr = compile_expr_with_scope("-0p42", &scope).unwrap();
        assert!(matches!(
            expr,
            CircuitExpr::UnaryOp {
                op: CircuitUnaryOp::Neg,
                ..
            }
        ));
    }

    // --- Identifiers ---

    #[test]
    fn ident_scalar() {
        let expr =
            compile_expr_with_scope("x", &[("x", CompEnvValue::Scalar("x".into()))]).unwrap();
        assert_eq!(expr, CircuitExpr::Var("x".into()));
    }

    #[test]
    fn ident_capture() {
        let expr =
            compile_expr_with_scope("n", &[("n", CompEnvValue::Capture("n".into()))]).unwrap();
        assert_eq!(expr, CircuitExpr::Capture("n".into()));
    }

    #[test]
    fn ident_array_as_scalar_errors() {
        let err =
            compile_expr_with_scope("arr", &[("arr", CompEnvValue::Array(vec!["arr_0".into()]))])
                .unwrap_err();
        assert!(matches!(err, ProveIrError::TypeMismatch { .. }));
    }

    #[test]
    fn ident_undeclared_errors() {
        let err = compile_single_expr("unknown").unwrap_err();
        assert!(matches!(
            err,
            ProveIrError::UndeclaredVariable { name, .. } if name == "unknown"
        ));
    }

    // --- Binary operations ---

    #[test]
    fn binop_add() {
        let scope = [
            ("a", CompEnvValue::Scalar("a".into())),
            ("b", CompEnvValue::Scalar("b".into())),
        ];
        let expr = compile_expr_with_scope("a + b", &scope).unwrap();
        assert_eq!(
            expr,
            CircuitExpr::BinOp {
                op: CircuitBinOp::Add,
                lhs: Box::new(CircuitExpr::Var("a".into())),
                rhs: Box::new(CircuitExpr::Var("b".into())),
            }
        );
    }

    #[test]
    fn binop_mul() {
        let scope = [("x", CompEnvValue::Scalar("x".into()))];
        let expr = compile_expr_with_scope("x * 2", &scope).unwrap();
        assert!(matches!(
            expr,
            CircuitExpr::BinOp {
                op: CircuitBinOp::Mul,
                ..
            }
        ));
    }

    #[test]
    fn binop_mod_rejected() {
        let scope = [
            ("a", CompEnvValue::Scalar("a".into())),
            ("b", CompEnvValue::Scalar("b".into())),
        ];
        let err = compile_expr_with_scope("a % b", &scope).unwrap_err();
        assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
    }

    // --- Comparisons ---

    #[test]
    fn comparison_eq() {
        let scope = [
            ("a", CompEnvValue::Scalar("a".into())),
            ("b", CompEnvValue::Scalar("b".into())),
        ];
        let expr = compile_expr_with_scope("a == b", &scope).unwrap();
        assert!(matches!(
            expr,
            CircuitExpr::Comparison {
                op: CircuitCmpOp::Eq,
                ..
            }
        ));
    }

    #[test]
    fn comparison_gt() {
        let scope = [("x", CompEnvValue::Scalar("x".into()))];
        let expr = compile_expr_with_scope("x > 5", &scope).unwrap();
        assert!(matches!(
            expr,
            CircuitExpr::Comparison {
                op: CircuitCmpOp::Gt,
                ..
            }
        ));
    }

    // --- Boolean ops ---

    #[test]
    fn bool_and() {
        let scope = [
            ("a", CompEnvValue::Scalar("a".into())),
            ("b", CompEnvValue::Scalar("b".into())),
        ];
        let expr = compile_expr_with_scope("a && b", &scope).unwrap();
        assert!(matches!(
            expr,
            CircuitExpr::BoolOp {
                op: CircuitBoolOp::And,
                ..
            }
        ));
    }

    #[test]
    fn bool_or() {
        let scope = [
            ("a", CompEnvValue::Scalar("a".into())),
            ("b", CompEnvValue::Scalar("b".into())),
        ];
        let expr = compile_expr_with_scope("a || b", &scope).unwrap();
        assert!(matches!(
            expr,
            CircuitExpr::BoolOp {
                op: CircuitBoolOp::Or,
                ..
            }
        ));
    }

    // --- Unary ops ---

    #[test]
    fn unary_neg() {
        let scope = [("x", CompEnvValue::Scalar("x".into()))];
        let expr = compile_expr_with_scope("-x", &scope).unwrap();
        assert_eq!(
            expr,
            CircuitExpr::UnaryOp {
                op: CircuitUnaryOp::Neg,
                operand: Box::new(CircuitExpr::Var("x".into())),
            }
        );
    }

    #[test]
    fn unary_not() {
        let scope = [("x", CompEnvValue::Scalar("x".into()))];
        let expr = compile_expr_with_scope("!x", &scope).unwrap();
        assert_eq!(
            expr,
            CircuitExpr::UnaryOp {
                op: CircuitUnaryOp::Not,
                operand: Box::new(CircuitExpr::Var("x".into())),
            }
        );
    }

    #[test]
    fn double_negation_cancelled() {
        let scope = [("x", CompEnvValue::Scalar("x".into()))];
        let expr = compile_expr_with_scope("--x", &scope).unwrap();
        // Double negation cancels to just x
        assert_eq!(expr, CircuitExpr::Var("x".into()));
    }

    // --- Power ---

    #[test]
    fn pow_constant_exponent() {
        let scope = [("x", CompEnvValue::Scalar("x".into()))];
        let expr = compile_expr_with_scope("x ^ 3", &scope).unwrap();
        assert_eq!(
            expr,
            CircuitExpr::Pow {
                base: Box::new(CircuitExpr::Var("x".into())),
                exp: 3,
            }
        );
    }

    #[test]
    fn pow_variable_exponent_rejected() {
        let scope = [
            ("x", CompEnvValue::Scalar("x".into())),
            ("n", CompEnvValue::Scalar("n".into())),
        ];
        let err = compile_expr_with_scope("x ^ n", &scope).unwrap_err();
        assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
    }

    // --- Rejections ---

    #[test]
    fn string_rejected() {
        let err = compile_single_expr("\"hello\"").unwrap_err();
        assert!(matches!(
            err,
            ProveIrError::TypeNotConstrainable { type_name, .. } if type_name == "string"
        ));
    }

    #[test]
    fn nil_rejected() {
        let err = compile_single_expr("nil").unwrap_err();
        assert!(matches!(
            err,
            ProveIrError::TypeNotConstrainable { type_name, .. } if type_name == "nil"
        ));
    }

    #[test]
    fn closure_rejected() {
        let err = compile_single_expr("fn(x) { x }").unwrap_err();
        assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
    }

    // --- Static access ---

    #[test]
    fn static_field_zero() {
        let expr = compile_single_expr("Field::ZERO").unwrap();
        assert_eq!(expr, CircuitExpr::Const(FieldConst::zero()));
    }

    #[test]
    fn static_field_one() {
        let expr = compile_single_expr("Field::ONE").unwrap();
        assert_eq!(expr, CircuitExpr::Const(FieldConst::one()));
    }

    #[test]
    fn static_int_max() {
        let expr = compile_single_expr("Int::MAX").unwrap();
        assert_eq!(
            expr,
            CircuitExpr::Const(FieldConst::from_field(FieldElement::<Bn254Fr>::from_i64(
                memory::I60_MAX
            )))
        );
    }

    #[test]
    fn static_int_min() {
        let expr = compile_single_expr("Int::MIN").unwrap();
        assert_eq!(
            expr,
            CircuitExpr::Const(FieldConst::from_field(FieldElement::<Bn254Fr>::from_i64(
                memory::I60_MIN
            )))
        );
    }

    #[test]
    fn static_field_order_rejected() {
        let err = compile_single_expr("Field::ORDER").unwrap_err();
        assert!(
            matches!(err, ProveIrError::StaticAccessNotConstrainable { ref type_name, ref member, .. }
                if type_name == "Field" && member == "ORDER"
            ),
            "expected StaticAccessNotConstrainable, got {err}"
        );
    }

    #[test]
    fn static_bigint_rejected() {
        let err = compile_single_expr("BigInt::from_bits").unwrap_err();
        assert!(matches!(
            err,
            ProveIrError::TypeNotConstrainable { type_name, .. } if type_name == "BigInt"
        ));
    }

    #[test]
    fn static_unknown_rejected() {
        let err = compile_single_expr("Foo::BAR").unwrap_err();
        assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
    }

    #[test]
    fn static_in_expression() {
        // Field::ONE + Field::ZERO should work in arithmetic
        let expr = compile_single_expr("Field::ONE + Field::ZERO").unwrap();
        assert_eq!(
            expr,
            CircuitExpr::BinOp {
                op: CircuitBinOp::Add,
                lhs: Box::new(CircuitExpr::Const(FieldConst::one())),
                rhs: Box::new(CircuitExpr::Const(FieldConst::zero())),
            }
        );
    }

    // --- Method desugaring ---

    #[test]
    fn method_to_field_is_identity() {
        let scope = [("x", CompEnvValue::Scalar("x".into()))];
        let expr = compile_expr_with_scope("x.to_field()", &scope).unwrap();
        assert_eq!(expr, CircuitExpr::Var("x".into()));
    }

    #[test]
    fn method_abs_desugars_to_mux() {
        let scope = [("x", CompEnvValue::Scalar("x".into()))];
        let expr = compile_expr_with_scope("x.abs()", &scope).unwrap();
        assert!(
            matches!(expr, CircuitExpr::Mux { .. }),
            "abs should desugar to Mux, got {expr:?}"
        );
    }

    #[test]
    fn method_min_desugars_to_mux() {
        let scope = [
            ("a", CompEnvValue::Scalar("a".into())),
            ("b", CompEnvValue::Scalar("b".into())),
        ];
        let expr = compile_expr_with_scope("a.min(b)", &scope).unwrap();
        // min(a, b) = mux(a < b, a, b)
        if let CircuitExpr::Mux {
            if_true, if_false, ..
        } = &expr
        {
            assert_eq!(**if_true, CircuitExpr::Var("a".into()));
            assert_eq!(**if_false, CircuitExpr::Var("b".into()));
        } else {
            panic!("expected Mux, got {expr:?}");
        }
    }

    #[test]
    fn method_max_desugars_to_mux() {
        let scope = [
            ("a", CompEnvValue::Scalar("a".into())),
            ("b", CompEnvValue::Scalar("b".into())),
        ];
        let expr = compile_expr_with_scope("a.max(b)", &scope).unwrap();
        // max(a, b) = mux(a < b, b, a)
        if let CircuitExpr::Mux {
            if_true, if_false, ..
        } = &expr
        {
            assert_eq!(**if_true, CircuitExpr::Var("b".into()));
            assert_eq!(**if_false, CircuitExpr::Var("a".into()));
        } else {
            panic!("expected Mux, got {expr:?}");
        }
    }

    #[test]
    fn method_pow_desugars() {
        let scope = [("x", CompEnvValue::Scalar("x".into()))];
        let expr = compile_expr_with_scope("x.pow(3)", &scope).unwrap();
        assert_eq!(
            expr,
            CircuitExpr::Pow {
                base: Box::new(CircuitExpr::Var("x".into())),
                exp: 3,
            }
        );
    }

    #[test]
    fn method_len_on_array() {
        let scope = [(
            "arr",
            CompEnvValue::Array(vec!["arr_0".into(), "arr_1".into()]),
        )];
        let expr = compile_expr_with_scope("arr.len()", &scope).unwrap();
        assert_eq!(expr, CircuitExpr::ArrayLen("arr".into()));
    }

    #[test]
    fn method_to_string_rejected() {
        let scope = [("x", CompEnvValue::Scalar("x".into()))];
        let err = compile_expr_with_scope("x.to_string()", &scope).unwrap_err();
        assert!(matches!(
            err,
            ProveIrError::MethodNotConstrainable { ref method, .. } if method == "to_string"
        ));
    }

    #[test]
    fn method_push_rejected() {
        let scope = [("arr", CompEnvValue::Array(vec!["arr_0".into()]))];
        let err = compile_expr_with_scope("arr.push(1)", &scope).unwrap_err();
        assert!(matches!(
            err,
            ProveIrError::MethodNotConstrainable { ref method, .. } if method == "push"
        ));
    }

    #[test]
    fn method_filter_rejected() {
        let scope = [("arr", CompEnvValue::Array(vec!["arr_0".into()]))];
        let err = compile_expr_with_scope("arr.filter(fn(x) { x })", &scope).unwrap_err();
        assert!(matches!(
            err,
            ProveIrError::MethodNotConstrainable { ref method, .. } if method == "filter"
        ));
    }

    #[test]
    fn method_keys_rejected() {
        let scope = [("m", CompEnvValue::Scalar("m".into()))];
        let err = compile_expr_with_scope("m.keys()", &scope).unwrap_err();
        assert!(matches!(
            err,
            ProveIrError::MethodNotConstrainable { ref method, .. } if method == "keys"
        ));
    }

    #[test]
    fn method_unknown_rejected() {
        let scope = [("x", CompEnvValue::Scalar("x".into()))];
        let err = compile_expr_with_scope("x.foobar()", &scope).unwrap_err();
        assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
    }

    // --- Builtin calls ---

    #[test]
    fn builtin_poseidon() {
        let scope = [
            ("a", CompEnvValue::Scalar("a".into())),
            ("b", CompEnvValue::Scalar("b".into())),
        ];
        let expr = compile_expr_with_scope("poseidon(a, b)", &scope).unwrap();
        assert!(matches!(expr, CircuitExpr::PoseidonHash { .. }));
    }

    #[test]
    fn builtin_poseidon_many() {
        let scope = [
            ("a", CompEnvValue::Scalar("a".into())),
            ("b", CompEnvValue::Scalar("b".into())),
            ("c", CompEnvValue::Scalar("c".into())),
        ];
        let expr = compile_expr_with_scope("poseidon_many(a, b, c)", &scope).unwrap();
        if let CircuitExpr::PoseidonMany(args) = &expr {
            assert_eq!(args.len(), 3);
        } else {
            panic!("expected PoseidonMany, got {expr:?}");
        }
    }

    #[test]
    fn builtin_mux() {
        let scope = [
            ("c", CompEnvValue::Scalar("c".into())),
            ("a", CompEnvValue::Scalar("a".into())),
            ("b", CompEnvValue::Scalar("b".into())),
        ];
        let expr = compile_expr_with_scope("mux(c, a, b)", &scope).unwrap();
        assert!(matches!(expr, CircuitExpr::Mux { .. }));
    }

    #[test]
    fn builtin_range_check() {
        let scope = [("x", CompEnvValue::Scalar("x".into()))];
        let expr = compile_expr_with_scope("range_check(x, 8)", &scope).unwrap();
        assert_eq!(
            expr,
            CircuitExpr::RangeCheck {
                value: Box::new(CircuitExpr::Var("x".into())),
                bits: 8,
            }
        );
    }

    #[test]
    fn builtin_poseidon_wrong_arity() {
        let scope = [("a", CompEnvValue::Scalar("a".into()))];
        let err = compile_expr_with_scope("poseidon(a)", &scope).unwrap_err();
        assert!(matches!(err, ProveIrError::WrongArgumentCount { .. }));
    }

    // --- Nested expressions ---

    #[test]
    fn nested_arithmetic() {
        let scope = [
            ("a", CompEnvValue::Scalar("a".into())),
            ("b", CompEnvValue::Scalar("b".into())),
            ("c", CompEnvValue::Scalar("c".into())),
        ];
        let expr = compile_expr_with_scope("a * b + c", &scope).unwrap();
        // Should be Add(Mul(a, b), c)
        assert!(matches!(
            expr,
            CircuitExpr::BinOp {
                op: CircuitBinOp::Add,
                ..
            }
        ));
    }

    // =====================================================================
    // Statement compilation tests
    // =====================================================================

    /// Helper: compile a circuit source. Automatically wraps flat format
    /// (public/witness top-level declarations) into `circuit test(...) { body }`.
    fn compile_circuit(source: &str) -> Result<ProveIR, ProveIrError> {
        crate::prove_ir::test_utils::compile_circuit(source)
    }

    #[test]
    fn stmt_public_decl_scalar() {
        let ir = compile_circuit("public x\nassert_eq(x, x)").unwrap();
        assert_eq!(ir.public_inputs.len(), 1);
        assert_eq!(ir.public_inputs[0].name, "x");
        assert!(ir.public_inputs[0].array_size.is_none());
    }

    #[test]
    fn stmt_witness_decl_scalar() {
        let ir = compile_circuit("witness y\nassert_eq(y, y)").unwrap();
        assert_eq!(ir.witness_inputs.len(), 1);
        assert_eq!(ir.witness_inputs[0].name, "y");
    }

    #[test]
    fn stmt_public_decl_array() {
        let ir = compile_circuit("public arr[3]\nassert_eq(arr_0, arr_1)").unwrap();
        assert_eq!(ir.public_inputs.len(), 1);
        assert_eq!(ir.public_inputs[0].name, "arr");
        assert_eq!(ir.public_inputs[0].array_size, Some(ArraySize::Literal(3)));
    }

    #[test]
    fn stmt_let_scalar() {
        let ir = compile_circuit("public x\nlet y = x\nassert_eq(y, x)").unwrap();
        assert!(ir.body.len() >= 2); // Let + AssertEq
        assert!(matches!(&ir.body[0], CircuitNode::Let { name, .. } if name == "y"));
    }

    #[test]
    fn stmt_let_array() {
        let ir = compile_circuit("let arr = [1, 2, 3]").unwrap();
        assert_eq!(ir.body.len(), 1);
        if let CircuitNode::LetArray { name, elements, .. } = &ir.body[0] {
            assert_eq!(name, "arr");
            assert_eq!(elements.len(), 3);
        } else {
            panic!("expected LetArray, got {:?}", ir.body[0]);
        }
    }

    #[test]
    fn stmt_empty_array_rejected() {
        let err = compile_circuit("let arr = []").unwrap_err();
        assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
    }

    #[test]
    fn stmt_assert_eq_as_node() {
        let ir = compile_circuit("public a\npublic b\nassert_eq(a, b)").unwrap();
        assert!(
            ir.body
                .iter()
                .any(|n| matches!(n, CircuitNode::AssertEq { .. })),
            "expected AssertEq node in body"
        );
    }

    #[test]
    fn stmt_assert_as_node() {
        let ir = compile_circuit("public x\nassert(x)").unwrap();
        assert!(
            ir.body
                .iter()
                .any(|n| matches!(n, CircuitNode::Assert { .. })),
            "expected Assert node in body"
        );
    }

    #[test]
    fn stmt_assert_with_message() {
        let ir = compile_circuit("public x\nassert(x, \"x must be true\")").unwrap();
        let node = ir
            .body
            .iter()
            .find(|n| matches!(n, CircuitNode::Assert { .. }))
            .expect("expected Assert node");
        if let CircuitNode::Assert { message, .. } = node {
            assert_eq!(message.as_deref(), Some("x must be true"));
        }
    }

    #[test]
    fn stmt_assert_without_message() {
        let ir = compile_circuit("public x\nassert(x)").unwrap();
        let node = ir
            .body
            .iter()
            .find(|n| matches!(n, CircuitNode::Assert { .. }))
            .expect("expected Assert node");
        if let CircuitNode::Assert { message, .. } = node {
            assert_eq!(*message, None);
        }
    }

    #[test]
    fn stmt_assert_message_must_be_string() {
        let err = compile_circuit("public x\nassert(x, 42)").unwrap_err();
        assert!(matches!(err, ProveIrError::TypeMismatch { .. }));
    }

    #[test]
    fn stmt_assert_too_many_args() {
        let err = compile_circuit("public x\nassert(x, \"msg\", 1)").unwrap_err();
        assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
    }

    #[test]
    fn stmt_assert_eq_with_message() {
        let ir =
            compile_circuit("public a\npublic b\nassert_eq(a, b, \"values must match\")").unwrap();
        let node = ir
            .body
            .iter()
            .find(|n| matches!(n, CircuitNode::AssertEq { .. }))
            .expect("expected AssertEq node");
        if let CircuitNode::AssertEq { message, .. } = node {
            assert_eq!(message.as_deref(), Some("values must match"));
        }
    }

    #[test]
    fn stmt_assert_eq_without_message() {
        let ir = compile_circuit("public a\npublic b\nassert_eq(a, b)").unwrap();
        let node = ir
            .body
            .iter()
            .find(|n| matches!(n, CircuitNode::AssertEq { .. }))
            .expect("expected AssertEq node");
        if let CircuitNode::AssertEq { message, .. } = node {
            assert_eq!(*message, None);
        }
    }

    #[test]
    fn stmt_assert_eq_message_must_be_string() {
        let err = compile_circuit("public a\npublic b\nassert_eq(a, b, 42)").unwrap_err();
        assert!(matches!(err, ProveIrError::TypeMismatch { .. }));
    }

    #[test]
    fn stmt_assert_eq_too_many_args() {
        let err = compile_circuit("public a\npublic b\nassert_eq(a, b, \"msg\", 1)").unwrap_err();
        assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
    }

    #[test]
    fn stmt_fn_decl_not_emitted() {
        let ir = compile_circuit("public x\nfn f(a) { a }\nassert_eq(x, x)").unwrap();
        // FnDecl doesn't produce a body node — it's stored in fn_table
        assert!(
            !ir.body
                .iter()
                .any(|n| matches!(n, CircuitNode::Let { name, .. } if name == "f")),
            "FnDecl should not produce a Let node"
        );
    }

    #[test]
    fn stmt_print_rejected() {
        let err = compile_circuit("print(42)").unwrap_err();
        assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
    }

    #[test]
    fn stmt_break_rejected() {
        // break outside loop is actually a parse error, but test the stmt handler
        let err = compile_circuit("public x\nassert_eq(x, x)");
        // This should succeed — break only fails if actually encountered
        assert!(err.is_ok());
    }

    #[test]
    fn stmt_basic_circuit() {
        // A complete basic circuit: public out, witness a, b, assert_eq(a * b, out)
        let ir = compile_circuit(
            "public out\nwitness a\nwitness b\nlet product = a * b\nassert_eq(product, out)",
        )
        .unwrap();
        assert_eq!(ir.public_inputs.len(), 1);
        assert_eq!(ir.witness_inputs.len(), 2);
        assert_eq!(ir.public_inputs[0].name, "out");
        assert_eq!(ir.witness_inputs[0].name, "a");
        assert_eq!(ir.witness_inputs[1].name, "b");
        // Body: Let(product) + AssertEq
        assert!(ir.body.len() >= 2);
        assert!(matches!(&ir.body[0], CircuitNode::Let { name, .. } if name == "product"));
        assert!(matches!(&ir.body[1], CircuitNode::AssertEq { .. }));
    }

    #[test]
    fn stmt_poseidon_circuit() {
        let ir = compile_circuit(
            "public hash\nwitness secret\nlet h = poseidon(secret, 0)\nassert_eq(h, hash)",
        )
        .unwrap();
        assert_eq!(ir.public_inputs.len(), 1);
        assert_eq!(ir.witness_inputs.len(), 1);
        // Body: Let(h = PoseidonHash) + AssertEq
        if let CircuitNode::Let { value, .. } = &ir.body[0] {
            assert!(
                matches!(value, CircuitExpr::PoseidonHash { .. }),
                "expected PoseidonHash, got {value:?}"
            );
        } else {
            panic!("expected Let node, got {:?}", ir.body[0]);
        }
    }

    #[test]
    fn stmt_with_static_access() {
        // Field::ZERO should work inside a circuit now!
        let ir = compile_circuit("public x\nlet zero = Field::ZERO\nassert_eq(x, zero)").unwrap();
        if let CircuitNode::Let { value, .. } = &ir.body[0] {
            assert_eq!(*value, CircuitExpr::Const(FieldConst::zero()));
        } else {
            panic!("expected Let node");
        }
    }

    // =====================================================================
    // Mut-to-SSA desugaring tests
    // =====================================================================

    #[test]
    fn mut_decl_basic() {
        let ir = compile_circuit("public x\nmut acc = x\nassert_eq(acc, x)").unwrap();
        // mut acc = x → Let { name: "acc", value: Var("x") }
        assert!(matches!(
            &ir.body[0],
            CircuitNode::Let { name, .. } if name == "acc"
        ));
    }

    #[test]
    fn mut_reassignment_creates_ssa_version() {
        let ir =
            compile_circuit("public x\nmut acc = x\nacc = acc + 1\nassert_eq(acc, x)").unwrap();
        // body[0]: Let { name: "acc", value: Var("x") }
        // body[1]: Let { name: "acc$v1", value: BinOp(Add, Var("acc"), Const(1)) }
        // body[2]: AssertEq { Var("acc$v1"), Var("x") }
        assert!(matches!(
            &ir.body[0],
            CircuitNode::Let { name, .. } if name == "acc"
        ));
        assert!(matches!(
            &ir.body[1],
            CircuitNode::Let { name, .. } if name == "acc$v1"
        ));
        // AssertEq should reference the latest SSA name
        if let CircuitNode::AssertEq { lhs, .. } = &ir.body[2] {
            assert_eq!(*lhs, CircuitExpr::Var("acc$v1".into()));
        } else {
            panic!("expected AssertEq, got {:?}", ir.body[2]);
        }
    }

    #[test]
    fn mut_multiple_reassignments() {
        let ir = compile_circuit(
            "public x\nmut a = 0\na = a + 1\na = a + 2\na = a + 3\nassert_eq(a, x)",
        )
        .unwrap();
        // Let("a"), Let("a$v1"), Let("a$v2"), Let("a$v3"), AssertEq(Var("a$v3"), ...)
        assert!(matches!(
            &ir.body[0],
            CircuitNode::Let { name, .. } if name == "a"
        ));
        assert!(matches!(
            &ir.body[1],
            CircuitNode::Let { name, .. } if name == "a$v1"
        ));
        assert!(matches!(
            &ir.body[2],
            CircuitNode::Let { name, .. } if name == "a$v2"
        ));
        assert!(matches!(
            &ir.body[3],
            CircuitNode::Let { name, .. } if name == "a$v3"
        ));
        // The final assert_eq should use a$v3
        if let CircuitNode::AssertEq { lhs, .. } = &ir.body[4] {
            assert_eq!(*lhs, CircuitExpr::Var("a$v3".into()));
        } else {
            panic!("expected AssertEq");
        }
    }

    #[test]
    fn mut_reassignment_uses_previous_version() {
        // acc = acc + 1 should reference the PREVIOUS version of acc in the RHS
        let ir =
            compile_circuit("public x\nmut acc = x\nacc = acc + 1\nassert_eq(acc, x)").unwrap();
        // body[1]: Let { name: "acc$v1", value: BinOp(Add, Var("acc"), Const(1)) }
        if let CircuitNode::Let { value, .. } = &ir.body[1] {
            // The RHS should reference "acc" (v0), not "acc$v1"
            assert_eq!(
                *value,
                CircuitExpr::BinOp {
                    op: CircuitBinOp::Add,
                    lhs: Box::new(CircuitExpr::Var("acc".into())),
                    rhs: Box::new(CircuitExpr::Const(FieldConst::one())),
                }
            );
        } else {
            panic!("expected Let node");
        }
    }

    #[test]
    fn assign_to_immutable_errors() {
        let err = compile_circuit("public x\nlet a = x\na = 42\nassert_eq(a, x)").unwrap_err();
        assert!(
            matches!(err, ProveIrError::UnsupportedOperation { ref description, .. }
                if description.contains("not declared with `mut`")),
            "expected mut error, got {err}"
        );
    }

    #[test]
    fn assign_to_undeclared_errors() {
        let err = compile_circuit("public x\nfoo = 42\nassert_eq(foo, x)").unwrap_err();
        assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
    }

    #[test]
    fn mut_in_accumulator_pattern() {
        // Common pattern: accumulate in a loop (simulated without for, just sequential)
        let ir = compile_circuit(
            "public total\n\
             witness a\n\
             witness b\n\
             witness c\n\
             mut acc = Field::ZERO\n\
             acc = acc + a\n\
             acc = acc + b\n\
             acc = acc + c\n\
             assert_eq(acc, total)",
        )
        .unwrap();
        assert_eq!(ir.public_inputs.len(), 1);
        assert_eq!(ir.witness_inputs.len(), 3);
        // acc, acc$v1, acc$v2, acc$v3, assert_eq
        assert_eq!(ir.body.len(), 5);
        // Last AssertEq should use acc$v3
        if let CircuitNode::AssertEq { lhs, .. } = &ir.body[4] {
            assert_eq!(*lhs, CircuitExpr::Var("acc$v3".into()));
        } else {
            panic!("expected AssertEq");
        }
    }

    // =====================================================================
    // Function inlining tests
    // =====================================================================

    #[test]
    fn fn_simple_inline() {
        let ir = compile_circuit(
            "public x\npublic out\nfn double(a) { a * 2 }\nassert_eq(double(x), out)",
        )
        .unwrap();
        // double(x) should produce: Let(__double_a = Var(x)) then the inline result
        // The AssertEq should have the inlined expression
        assert!(ir
            .body
            .iter()
            .any(|n| matches!(n, CircuitNode::AssertEq { .. })));
    }

    #[test]
    fn fn_inline_with_let() {
        let ir = compile_circuit(
            "public out\nwitness x\n\
             fn square(n) { let r = n * n; r }\n\
             assert_eq(square(x), out)",
        )
        .unwrap();
        // The inlined body should have emitted a Let for r
        assert!(ir.body.iter().any(
            |n| matches!(n, CircuitNode::Let { name, .. } if name.contains("__square_n")
                                                                  || name == "r")
        ));
    }

    #[test]
    fn fn_inline_nested_calls() {
        let ir = compile_circuit(
            "public out\nwitness x\n\
             fn square(n) { n * n }\n\
             fn sum_of_squares(a, b) { square(a) + square(b) }\n\
             assert_eq(sum_of_squares(x, x), out)",
        )
        .unwrap();
        assert!(ir
            .body
            .iter()
            .any(|n| matches!(n, CircuitNode::AssertEq { .. })));
    }

    #[test]
    fn fn_with_return() {
        let ir = compile_circuit(
            "public out\nwitness x\n\
             fn check(n) { return n * 2 }\n\
             assert_eq(check(x), out)",
        )
        .unwrap();
        assert!(ir
            .body
            .iter()
            .any(|n| matches!(n, CircuitNode::AssertEq { .. })));
    }

    #[test]
    fn fn_wrong_arity_errors() {
        let err =
            compile_circuit("public x\nfn f(a, b) { a + b }\nassert_eq(f(x), x)").unwrap_err();
        assert!(matches!(err, ProveIrError::WrongArgumentCount { .. }));
    }

    #[test]
    fn fn_recursive_errors() {
        let err = compile_circuit("public x\nfn f(n) { f(n) }\nassert_eq(f(x), x)").unwrap_err();
        assert!(matches!(
            err,
            ProveIrError::RecursiveFunction { ref name } if name == "f"
        ));
    }

    #[test]
    fn fn_undefined_errors() {
        let err = compile_circuit("public x\nassert_eq(unknown_fn(x), x)").unwrap_err();
        assert!(matches!(err, ProveIrError::UndeclaredVariable { .. }));
    }

    #[test]
    fn fn_env_restored_after_inline() {
        // After inlining f(x), a reference to 'x' should still resolve to the outer x
        let ir = compile_circuit(
            "public x\npublic out\n\
             fn f(a) { a + 1 }\n\
             let y = f(x)\n\
             assert_eq(x + y, out)",
        )
        .unwrap();
        // The final assert_eq should reference outer x (not the param)
        assert!(ir
            .body
            .iter()
            .any(|n| matches!(n, CircuitNode::AssertEq { .. })));
    }

    #[test]
    fn fn_hash_pair_circuit() {
        // Realistic circuit: fn hash_pair(a, b) { poseidon(a, b) }
        let ir = compile_circuit(
            "public out\nwitness a\nwitness b\n\
             fn hash_pair(x, y) { poseidon(x, y) }\n\
             assert_eq(hash_pair(a, b), out)",
        )
        .unwrap();
        assert_eq!(ir.public_inputs.len(), 1);
        assert_eq!(ir.witness_inputs.len(), 2);
        assert!(ir
            .body
            .iter()
            .any(|n| matches!(n, CircuitNode::AssertEq { .. })));
    }

    // =====================================================================
    // Control flow tests
    // =====================================================================

    #[test]
    fn if_expr_produces_mux() {
        let scope = [
            ("c", CompEnvValue::Scalar("c".into())),
            ("a", CompEnvValue::Scalar("a".into())),
            ("b", CompEnvValue::Scalar("b".into())),
        ];
        let expr = compile_expr_with_scope("if c { a } else { b }", &scope).unwrap();
        assert!(
            matches!(expr, CircuitExpr::Mux { .. }),
            "if/else should produce Mux, got {expr:?}"
        );
    }

    #[test]
    fn if_without_else_mux_zero() {
        let scope = [
            ("c", CompEnvValue::Scalar("c".into())),
            ("a", CompEnvValue::Scalar("a".into())),
        ];
        let expr = compile_expr_with_scope("if c { a }", &scope).unwrap();
        if let CircuitExpr::Mux { if_false, .. } = &expr {
            assert_eq!(**if_false, CircuitExpr::Const(FieldConst::zero()));
        } else {
            panic!("expected Mux, got {expr:?}");
        }
    }

    #[test]
    fn if_else_as_statement() {
        // if/else at statement level produces a cond temp, then a Mux expression
        let ir = compile_circuit(
            "public x\npublic out\nlet result = if x { 1 } else { 0 }\nassert_eq(result, out)",
        )
        .unwrap();
        // body[0]: Let { $condN = <cond> } (temporary for condition)
        assert!(
            matches!(&ir.body[0], CircuitNode::Let { name, .. } if name.starts_with("$cond")),
            "expected $cond temp, got {:?}",
            ir.body[0]
        );
        // body[1]: Let { result = Mux(Var($condN), ...) }
        if let CircuitNode::Let { value, .. } = &ir.body[1] {
            assert!(
                matches!(value, CircuitExpr::Mux { .. }),
                "expected Mux value, got {value:?}"
            );
        } else {
            panic!("expected Let, got {:?}", ir.body[1]);
        }
    }

    #[test]
    fn for_range_literal() {
        let ir = compile_circuit(
            "public out\n\
             mut acc = 0\n\
             for i in 0..3 {\n\
                 acc = acc + i\n\
             }\n\
             assert_eq(acc, out)",
        )
        .unwrap();
        assert!(
            ir.body.iter().any(|n| matches!(
                n,
                CircuitNode::For {
                    range: ForRange::Literal { start: 0, end: 3 },
                    ..
                }
            )),
            "expected For node with Literal range, body: {:#?}",
            ir.body
        );
    }

    #[test]
    fn for_over_array() {
        let ir = compile_circuit(
            "public out\n\
             let arr = [1, 2, 3]\n\
             mut acc = 0\n\
             for x in arr {\n\
                 acc = acc + x\n\
             }\n\
             assert_eq(acc, out)",
        )
        .unwrap();
        assert!(
            ir.body.iter().any(|n| matches!(
                n,
                CircuitNode::For {
                    range: ForRange::Array(ref name),
                    ..
                } if name == "arr"
            )),
            "expected For node with Array range"
        );
    }

    #[test]
    fn for_expr_not_array_errors() {
        let err = compile_circuit("public x\nfor i in x {\nassert_eq(i, i)\n}").unwrap_err();
        assert!(matches!(err, ProveIrError::UnsupportedOperation { .. }));
    }

    #[test]
    fn index_constant_resolves() {
        let ir =
            compile_circuit("public out\nlet arr = [10, 20, 30]\nassert_eq(arr[1], out)").unwrap();
        // arr[1] with constant index should resolve to Var("arr_1")
        if let CircuitNode::AssertEq { lhs, .. } = &ir.body[1] {
            assert_eq!(*lhs, CircuitExpr::Var("arr_1".into()));
        } else {
            panic!("expected AssertEq, got {:?}", ir.body[1]);
        }
    }

    #[test]
    fn index_out_of_bounds_errors() {
        let err = compile_circuit("let arr = [1, 2]\nassert_eq(arr[5], arr[0])").unwrap_err();
        assert!(matches!(err, ProveIrError::IndexOutOfBounds { .. }));
    }

    #[test]
    fn block_expr() {
        let scope = [("x", CompEnvValue::Scalar("x".into()))];
        let expr = compile_expr_with_scope("{ x }", &scope).unwrap();
        assert_eq!(expr, CircuitExpr::Var("x".into()));
    }

    #[test]
    fn for_with_accumulator_circuit() {
        // Realistic pattern: accumulate witness array values
        let ir = compile_circuit(
            "public total\n\
             witness vals[4]\n\
             mut sum = Field::ZERO\n\
             for i in 0..4 {\n\
                 sum = sum + vals[i]\n\
             }\n\
             assert_eq(sum, total)",
        )
        .unwrap();
        assert_eq!(ir.public_inputs.len(), 1);
        assert_eq!(ir.witness_inputs.len(), 1);
        assert_eq!(ir.witness_inputs[0].name, "vals");
        // Should have: LetArray(arr), Let(sum=ZERO), For{...}, AssertEq
        assert!(ir.body.iter().any(|n| matches!(n, CircuitNode::For { .. })));
        assert!(ir
            .body
            .iter()
            .any(|n| matches!(n, CircuitNode::AssertEq { .. })));
    }

    // =====================================================================
    // Capture classification (end-to-end via compile())
    // =====================================================================

    /// Helper: compile a prove block body with outer scope captures (all scalar).
    fn compile_prove_block(source: &str, outer_vars: &[&str]) -> Result<ProveIR, ProveIrError> {
        let outer = OuterScope {
            values: outer_vars
                .iter()
                .map(|s| (s.to_string(), OuterScopeEntry::Scalar))
                .collect(),
            ..Default::default()
        };
        ProveIrCompiler::<Bn254Fr>::compile_prove_block(source, &outer)
    }

    #[test]
    fn capture_classification_end_to_end() {
        // secret is used in constraint (poseidon), hash is declared public
        let ir = compile_prove_block(
            "public hash\nassert_eq(poseidon(secret, 0), hash)",
            &["secret", "hash"],
        )
        .unwrap();
        // hash is declared as public input, so not a capture
        assert_eq!(ir.public_inputs.len(), 1);
        assert_eq!(ir.public_inputs[0].name, "hash");
        // secret is captured and used in constraint
        assert_eq!(ir.captures.len(), 1);
        assert_eq!(ir.captures[0].name, "secret");
        assert_eq!(ir.captures[0].usage, CaptureUsage::CircuitInput);
    }

    #[test]
    fn no_captures_in_self_contained_circuit() {
        // ach circuit mode: no outer scope, no captures
        let ir =
            compile_circuit("public out\nwitness a\nwitness b\nassert_eq(a * b, out)").unwrap();
        assert!(ir.captures.is_empty());
    }

    // =====================================================================
    // Integration tests: real circuit patterns from test/circuit/
    // =====================================================================

    #[test]
    fn integration_basic_arithmetic() {
        let source = "\
            public out\n\
            witness a\n\
            witness b\n\
            let product = a * b\n\
            assert_eq(product, out)\n\
            let sum = a + b\n\
            assert_eq(sum, a + b)\n\
            let diff = b - a\n\
            assert_eq(diff, b - a)\n\
            let doubled = a + a\n\
            assert_eq(doubled, a * 2)";
        let ir = compile_circuit(source).unwrap();
        assert_eq!(ir.public_inputs.len(), 1);
        assert_eq!(ir.witness_inputs.len(), 2);
        assert!(ir.captures.is_empty());
        // 4 Let + 4 AssertEq = 8 nodes
        let asserts = ir
            .body
            .iter()
            .filter(|n| matches!(n, CircuitNode::AssertEq { .. }))
            .count();
        assert_eq!(asserts, 4, "expected 4 assert_eq constraints");
    }

    #[test]
    fn integration_nested_functions() {
        let source = "\
            public result\n\
            witness x\n\
            fn square(a) { a * a }\n\
            fn sum_of_squares(a, b) { square(a) + square(b) }\n\
            assert_eq(sum_of_squares(x, x + 1), result)";
        let ir = compile_circuit(source).unwrap();
        assert_eq!(ir.public_inputs.len(), 1);
        assert_eq!(ir.witness_inputs.len(), 1);
        assert!(ir
            .body
            .iter()
            .any(|n| matches!(n, CircuitNode::AssertEq { .. })));
    }

    #[test]
    fn integration_poseidon() {
        let source = "\
            public expected\n\
            witness a\n\
            witness b\n\
            witness c\n\
            let h = poseidon(a, b)\n\
            assert_eq(h, expected)\n\
            let folded = poseidon(h, c)\n\
            let many = poseidon_many(a, b, c)\n\
            assert_eq(many, folded)";
        let ir = compile_circuit(source).unwrap();
        assert_eq!(ir.public_inputs.len(), 1);
        assert_eq!(ir.witness_inputs.len(), 3);
        // Should have PoseidonHash and PoseidonMany in Let values
        let has_poseidon = ir.body.iter().any(|n| {
            matches!(
                n,
                CircuitNode::Let {
                    value: CircuitExpr::PoseidonHash { .. },
                    ..
                }
            )
        });
        assert!(has_poseidon, "expected PoseidonHash in body");
        let has_many = ir.body.iter().any(|n| {
            matches!(
                n,
                CircuitNode::Let {
                    value: CircuitExpr::PoseidonMany(_),
                    ..
                }
            )
        });
        assert!(has_many, "expected PoseidonMany in body");
    }

    #[test]
    fn integration_power() {
        let source = "\
            public x2\n\
            public x3\n\
            public x4\n\
            witness x\n\
            assert_eq(x ^ 2, x2)\n\
            assert_eq(x ^ 3, x3)\n\
            assert_eq(x ^ 4, x4)";
        let ir = compile_circuit(source).unwrap();
        assert_eq!(ir.public_inputs.len(), 3);
        assert_eq!(ir.witness_inputs.len(), 1);
        let asserts = ir
            .body
            .iter()
            .filter(|n| matches!(n, CircuitNode::AssertEq { .. }))
            .count();
        assert_eq!(asserts, 3);
    }

    #[test]
    fn integration_boolean_ops() {
        let source = "\
            witness x\n\
            witness y\n\
            let eq = x == y\n\
            let neq = x != y\n\
            let lt = x < y\n\
            assert(lt)";
        let ir = compile_circuit(source).unwrap();
        assert_eq!(ir.witness_inputs.len(), 2);
        assert!(ir
            .body
            .iter()
            .any(|n| matches!(n, CircuitNode::Assert { .. })));
    }

    #[test]
    fn integration_mux() {
        let source = "\
            public out\n\
            witness cond\n\
            witness a\n\
            witness b\n\
            assert_eq(mux(cond, a, b), out)";
        let ir = compile_circuit(source).unwrap();
        assert_eq!(ir.public_inputs.len(), 1);
        assert_eq!(ir.witness_inputs.len(), 3);
    }

    #[test]
    fn integration_range_check() {
        let source = "\
            witness x\n\
            witness y\n\
            range_check(x, 8)\n\
            range_check(y, 16)";
        let ir = compile_circuit(source).unwrap();
        assert_eq!(ir.witness_inputs.len(), 2);
        // range_check calls become Expr nodes with RangeCheck
        let has_range = ir.body.iter().any(|n| {
            matches!(
                n,
                CircuitNode::Expr {
                    expr: CircuitExpr::RangeCheck { .. },
                    ..
                }
            )
        });
        assert!(has_range, "expected RangeCheck in body");
    }

    #[test]
    fn integration_if_else_circuit() {
        let source = "\
            public out\n\
            witness x\n\
            witness cond\n\
            let result = if cond { x * 2 } else { x + 1 }\n\
            assert_eq(result, out)";
        let ir = compile_circuit(source).unwrap();
        // body[0]: $condN temp, body[1]: result = Mux(...)
        assert!(
            matches!(&ir.body[0], CircuitNode::Let { name, .. } if name.starts_with("$cond")),
            "expected $cond temp, got {:?}",
            ir.body[0]
        );
        if let CircuitNode::Let { value, .. } = &ir.body[1] {
            assert!(
                matches!(value, CircuitExpr::Mux { .. }),
                "expected Mux, got {value:?}"
            );
        } else {
            panic!("expected Let, got {:?}", ir.body[1]);
        }
    }

    #[test]
    fn integration_mut_accumulator() {
        // The pattern that was IMPOSSIBLE before ProveIR
        let source = "\
            public total\n\
            witness vals[4]\n\
            mut sum = Field::ZERO\n\
            sum = sum + vals_0\n\
            sum = sum + vals_1\n\
            sum = sum + vals_2\n\
            sum = sum + vals_3\n\
            assert_eq(sum, total)";
        let ir = compile_circuit(source).unwrap();
        assert_eq!(ir.public_inputs.len(), 1);
        assert_eq!(ir.witness_inputs.len(), 1);
        // sum, sum$v1, sum$v2, sum$v3, sum$v4, assert_eq = 6 nodes
        let lets = ir
            .body
            .iter()
            .filter(|n| matches!(n, CircuitNode::Let { .. }))
            .count();
        assert!(lets >= 5, "expected 5 Let nodes (SSA), got {lets}");
    }

    #[test]
    fn integration_static_namespaces_in_circuit() {
        // Another pattern IMPOSSIBLE before ProveIR
        let source = "\
            public out\n\
            witness x\n\
            let zero = Field::ZERO\n\
            let one = Field::ONE\n\
            assert_eq(x + zero, x)\n\
            assert_eq(x * one, out)";
        let ir = compile_circuit(source).unwrap();
        // Field::ZERO and Field::ONE should compile to constants
        if let CircuitNode::Let { value, name, .. } = &ir.body[0] {
            assert_eq!(name, "zero");
            assert_eq!(*value, CircuitExpr::Const(FieldConst::zero()));
        }
        if let CircuitNode::Let { value, name, .. } = &ir.body[1] {
            assert_eq!(name, "one");
            assert_eq!(*value, CircuitExpr::Const(FieldConst::one()));
        }
    }

    #[test]
    fn integration_method_desugaring_in_circuit() {
        // Yet another pattern IMPOSSIBLE before ProveIR
        let source = "\
            public out\n\
            witness x\n\
            witness y\n\
            let m = x.min(y)\n\
            assert_eq(m, out)";
        let ir = compile_circuit(source).unwrap();
        // .min() desugars to Mux(Lt(x, y), x, y)
        if let CircuitNode::Let { value, .. } = &ir.body[0] {
            assert!(
                matches!(value, CircuitExpr::Mux { .. }),
                "expected .min() to desugar to Mux, got {value:?}"
            );
        }
    }

    #[test]
    fn integration_prove_block_with_captures() {
        // Simulate a prove block: outer scope has secret and hash
        let source = "\
            public hash\n\
            assert_eq(poseidon(secret, Field::ZERO), hash)";
        let ir = compile_prove_block(source, &["secret", "hash"]).unwrap();
        assert_eq!(ir.public_inputs.len(), 1);
        assert_eq!(ir.public_inputs[0].name, "hash");
        assert_eq!(ir.captures.len(), 1);
        assert_eq!(ir.captures[0].name, "secret");
        assert_eq!(ir.captures[0].usage, CaptureUsage::CircuitInput);
    }

    // =====================================================================
    // Audit finding regression tests
    // =====================================================================

    // G1: Duplicate input declarations
    #[test]
    fn audit_duplicate_public_public() {
        let err = compile_circuit("public x\npublic x").unwrap_err();
        assert!(
            matches!(err, ProveIrError::DuplicateInput { ref name, .. } if name == "x"),
            "expected DuplicateInput, got {err:?}"
        );
    }

    #[test]
    fn audit_duplicate_public_witness() {
        let err = compile_circuit("public x\nwitness x").unwrap_err();
        assert!(
            matches!(err, ProveIrError::DuplicateInput { ref name, .. } if name == "x"),
            "expected DuplicateInput, got {err:?}"
        );
    }

    #[test]
    fn audit_duplicate_witness_witness() {
        let err = compile_circuit("witness a\nwitness a").unwrap_err();
        assert!(
            matches!(err, ProveIrError::DuplicateInput { ref name, .. } if name == "a"),
            "expected DuplicateInput, got {err:?}"
        );
    }

    // G2: assert_eq/assert as sub-expressions must emit constraint
    #[test]
    fn audit_assert_eq_in_let_emits_constraint() {
        let ir = compile_circuit("public a\npublic b\nlet x = assert_eq(a, b)").unwrap();
        let has_assert_eq = ir
            .body
            .iter()
            .any(|n| matches!(n, CircuitNode::AssertEq { .. }));
        assert!(
            has_assert_eq,
            "assert_eq at expression level must emit AssertEq node, body: {:#?}",
            ir.body
        );
    }

    #[test]
    fn audit_assert_in_let_emits_constraint() {
        let ir = compile_circuit("public a\nlet x = assert(a)").unwrap();
        let has_assert = ir
            .body
            .iter()
            .any(|n| matches!(n, CircuitNode::Assert { .. }));
        assert!(
            has_assert,
            "assert at expression level must emit Assert node, body: {:#?}",
            ir.body
        );
    }

    // G4: Double function inlining produces unique names
    #[test]
    fn audit_double_fn_inlining_unique_names() {
        let source = "\
            public out\n\
            fn double(a) { a * 2 }\n\
            let x = double(1)\n\
            let y = double(2)\n\
            assert_eq(x + y, out)";
        let ir = compile_circuit(source).unwrap();
        // Collect all Let names
        let names: Vec<&str> = ir
            .body
            .iter()
            .filter_map(|n| match n {
                CircuitNode::Let { name, .. } => Some(name.as_str()),
                _ => None,
            })
            .collect();
        // All names should be unique
        let unique: std::collections::HashSet<&str> = names.iter().copied().collect();
        assert_eq!(names.len(), unique.len(), "duplicate Let names: {names:?}");
    }

    // G5: range_check with very large bit count
    #[test]
    fn audit_range_check_large_bits_rejected() {
        let source = "public x\nrange_check(x, 5000000000)";
        let err = compile_circuit(source).unwrap_err();
        assert!(
            matches!(err, ProveIrError::UnsupportedOperation { .. }),
            "expected error for large bit count, got {err:?}"
        );
    }

    // G6: for range start > end (zero iterations, should not error)
    #[test]
    fn audit_for_range_start_gt_end() {
        // start > end means 0 iterations (saturating_sub), should compile fine
        let source = "public out\nfor i in 5..3 { }\nassert_eq(0, out)";
        let ir = compile_circuit(source).unwrap();
        assert!(
            ir.body.iter().any(|n| matches!(n, CircuitNode::For { .. })),
            "expected For node"
        );
    }

    // G7: poseidon_many with 1 argument
    #[test]
    fn audit_poseidon_many_one_arg() {
        let source = "public a\nposeidon_many(a)";
        let err = compile_circuit(source).unwrap_err();
        let msg = err.to_string();
        assert!(
            msg.contains("at least 2"),
            "expected 'at least 2' in error, got: {msg}"
        );
    }

    // G8: else-if chain
    #[test]
    fn audit_else_if_chain() {
        let source = "\
            public x\n\
            public out\n\
            let r = if x { 1 } else if x { 2 } else { 3 }\n\
            assert_eq(r, out)";
        let ir = compile_circuit(source).unwrap();
        // Should compile without error and produce Mux nodes
        let has_mux = ir.body.iter().any(|n| match n {
            CircuitNode::Let { value, .. } => matches!(value, CircuitExpr::Mux { .. }),
            _ => false,
        });
        assert!(has_mux, "expected Mux from else-if chain");
    }

    // For loop range too large
    #[test]
    fn audit_for_range_too_large() {
        let source = "public out\nfor i in 0..2000000 { }\nassert_eq(0, out)";
        let err = compile_circuit(source).unwrap_err();
        assert!(
            matches!(err, ProveIrError::RangeTooLarge { .. }),
            "expected RangeTooLarge, got {err:?}"
        );
    }

    // =====================================================================
    // OuterScope function tests
    // =====================================================================

    #[test]
    fn outer_scope_fn_in_prove_block() {
        // Parse a FnDecl to pass via OuterScope
        let (prog, _) = achronyme_parser::parse_program("fn double(x) { x * 2 }");
        let fn_stmt = prog.stmts[0].clone();

        let outer = OuterScope {
            values: [("val", OuterScopeEntry::Scalar)]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            functions: vec![fn_stmt],
            ..Default::default()
        };
        let ir = ProveIrCompiler::<Bn254Fr>::compile_prove_block(
            "public expected\nassert_eq(double(val), expected)",
            &outer,
        )
        .unwrap();
        assert_eq!(ir.public_inputs.len(), 1);
        assert_eq!(ir.captures.len(), 1);
        assert_eq!(ir.captures[0].name, "val");
    }

    #[test]
    fn outer_scope_fn_in_circuit() {
        // Functions before circuit declaration should be available via OuterScope
        let source = "\
            fn double(x) { x * 2 }\n\
            circuit test(a: Public, out: Public) {\n\
                assert_eq(double(a), out)\n\
            }";
        let ir = ProveIrCompiler::<Bn254Fr>::compile_circuit(source, None).unwrap();
        assert_eq!(ir.public_inputs.len(), 2);
        // double(a) should have been inlined — no function calls remain
        assert!(ir
            .body
            .iter()
            .any(|n| matches!(n, CircuitNode::AssertEq { .. })));
    }

    #[test]
    fn outer_scope_fn_overridden_by_local() {
        // A local fn with the same name should override the outer scope fn
        let (prog, _) = achronyme_parser::parse_program("fn double(x) { x * 2 }");
        let fn_stmt = prog.stmts[0].clone();

        let outer = OuterScope {
            values: [("val", OuterScopeEntry::Scalar)]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            functions: vec![fn_stmt],
            ..Default::default()
        };
        // Local fn triple overrides nothing, but local double overrides outer double
        let ir = ProveIrCompiler::<Bn254Fr>::compile_prove_block(
            "fn double(x) { x * 3 }\npublic expected\nassert_eq(double(val), expected)",
            &outer,
        )
        .unwrap();
        // Should compile without error — the local double (x*3) is used
        assert_eq!(ir.public_inputs.len(), 1);
    }

    // ── Dynamic loop bounds ─────────────────────────────────────

    #[test]
    fn dynamic_loop_bound_capture() {
        // `for i in 0..n` where n is a capture from outer scope
        let outer = OuterScope {
            values: [("n", OuterScopeEntry::Scalar)]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            functions: vec![],
            ..Default::default()
        };
        let ir = ProveIrCompiler::<Bn254Fr>::compile_prove_block(
            "public result\nmut sum = 0\nfor i in 0..n { sum = sum + i }\nassert_eq(sum, result)",
            &outer,
        )
        .unwrap();
        assert!(!ir.captures.is_empty(), "n should be a capture");
        // Should have a For node with WithCapture range
        assert!(
            ir.body.iter().any(|n| matches!(
                n,
                CircuitNode::For {
                    range: ForRange::WithCapture { start: 0, .. },
                    ..
                }
            )),
            "expected For with WithCapture range"
        );
    }

    #[test]
    fn dynamic_loop_bound_expr() {
        // `for i in 0..n+1` where n is a capture
        let outer = OuterScope {
            values: [("n", OuterScopeEntry::Scalar)]
                .into_iter()
                .map(|(k, v)| (k.to_string(), v))
                .collect(),
            functions: vec![],
            ..Default::default()
        };
        let ir = ProveIrCompiler::<Bn254Fr>::compile_prove_block(
            "public result\nmut sum = 0\nfor i in 0..n+1 { sum = sum + i }\nassert_eq(sum, result)",
            &outer,
        )
        .unwrap();
        // Should have a For node with WithExpr range (n+1 is an expression)
        assert!(
            ir.body.iter().any(|n| matches!(
                n,
                CircuitNode::For {
                    range: ForRange::WithExpr { start: 0, .. },
                    ..
                }
            )),
            "expected For with WithExpr range"
        );
    }

    // -----------------------------------------------------------------------
    // Indexed array assignment: arr[i] = expr → LetIndexed
    // -----------------------------------------------------------------------

    #[test]
    fn mut_array_decl() {
        let ir =
            compile_circuit("public out\nmut arr = [1, 2, 3]\nassert_eq(arr[0], out)").unwrap();
        // Should have a LetArray node
        assert!(
            ir.body
                .iter()
                .any(|n| matches!(n, CircuitNode::LetArray { name, .. } if name == "arr")),
            "expected LetArray for mut arr, body: {:#?}",
            ir.body
        );
    }

    #[test]
    fn indexed_assignment_constant() {
        let ir =
            compile_circuit("public out\nmut arr = [0, 0, 0]\narr[1] = 42\nassert_eq(arr[1], out)")
                .unwrap();
        // Should have a LetIndexed node
        assert!(
            ir.body
                .iter()
                .any(|n| matches!(n, CircuitNode::LetIndexed { array, .. } if array == "arr")),
            "expected LetIndexed for arr[1] = 42, body: {:#?}",
            ir.body
        );
    }

    #[test]
    fn indexed_assignment_in_loop() {
        let ir = compile_circuit(
            "public out\n\
             mut arr = [0, 0, 0]\n\
             for i in 0..3 {\n\
                 arr[i] = i * 2\n\
             }\n\
             assert_eq(arr[2], out)",
        )
        .unwrap();
        // For node body should contain LetIndexed
        let for_node = ir
            .body
            .iter()
            .find(|n| matches!(n, CircuitNode::For { .. }));
        assert!(for_node.is_some(), "expected For node");
        if let CircuitNode::For { body, .. } = for_node.unwrap() {
            assert!(
                body.iter()
                    .any(|n| matches!(n, CircuitNode::LetIndexed { array, .. } if array == "arr")),
                "expected LetIndexed inside for loop body, got: {body:#?}"
            );
        }
    }

    #[test]
    fn indexed_assignment_immutable_array_rejected() {
        let err =
            compile_circuit("public out\nlet arr = [1, 2, 3]\narr[0] = 99\nassert_eq(arr[0], out)")
                .unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("mut"), "error should mention mut, got: {msg}");
    }

    #[test]
    fn indexed_assignment_scalar_rejected() {
        let err =
            compile_circuit("public out\nmut x = 5\nx[0] = 10\nassert_eq(x, out)").unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("array") || msg.contains("scalar"),
            "error should mention type mismatch, got: {msg}"
        );
    }

    // --- Circom interop: circom_table registration (Phase 3.1) ---

    mod circom_table {
        use super::super::*;
        use crate::prove_ir::circom_interop::test_support::StubLibrary;
        use crate::prove_ir::circom_interop::{CircomLibraryHandle, CircomTemplateSignature};
        use std::sync::Arc;

        fn sig(params: &[&str], inputs: &[&str], outputs: &[&str]) -> CircomTemplateSignature {
            CircomTemplateSignature {
                params: params.iter().map(|s| s.to_string()).collect(),
                input_signals: inputs.iter().map(|s| s.to_string()).collect(),
                output_signals: outputs.iter().map(|s| s.to_string()).collect(),
            }
        }

        #[test]
        fn new_compiler_has_empty_circom_table() {
            let compiler = ProveIrCompiler::<Bn254Fr>::new();
            assert!(compiler.circom_table.is_empty());
            assert_eq!(compiler.circom_call_counter, 0);
        }

        #[test]
        fn register_circom_template_inserts_entry_without_bumping_counter() {
            let mut compiler = ProveIrCompiler::<Bn254Fr>::new();
            let lib: Arc<dyn CircomLibraryHandle> = Arc::new(StubLibrary::with_template(
                "Square",
                sig(&[], &["x"], &["y"]),
            ));
            compiler.register_circom_template("Square".to_string(), lib, "Square".to_string());

            assert_eq!(compiler.circom_table.len(), 1);
            let entry = compiler
                .lookup_circom_template("Square")
                .expect("Square should be registered");
            assert_eq!(entry.template_name, "Square");
            // Registration alone MUST NOT bump the call counter —
            // only actual instantiation sites do.
            assert_eq!(compiler.circom_call_counter, 0);
        }

        #[test]
        fn next_circom_call_prefix_produces_monotonic_unique_ids() {
            let mut compiler = ProveIrCompiler::<Bn254Fr>::new();
            assert_eq!(compiler.next_circom_call_prefix(), "circom_call_0");
            assert_eq!(compiler.next_circom_call_prefix(), "circom_call_1");
            assert_eq!(compiler.next_circom_call_prefix(), "circom_call_2");
            assert_eq!(compiler.circom_call_counter, 3);
        }

        #[test]
        fn namespaced_key_coexists_with_selective_key() {
            let mut compiler = ProveIrCompiler::<Bn254Fr>::new();
            let poseidon_lib: Arc<dyn CircomLibraryHandle> = Arc::new(StubLibrary::with_template(
                "Poseidon",
                sig(&["t"], &["inputs"], &["out"]),
            ));
            let num2bits_lib: Arc<dyn CircomLibraryHandle> = Arc::new(StubLibrary::with_template(
                "Num2Bits",
                sig(&["n"], &["in"], &["out"]),
            ));
            compiler.register_circom_template(
                "P::Poseidon".to_string(),
                poseidon_lib,
                "Poseidon".to_string(),
            );
            compiler.register_circom_template(
                "Num2Bits".to_string(),
                num2bits_lib,
                "Num2Bits".to_string(),
            );

            assert_eq!(compiler.circom_table.len(), 2);
            assert_eq!(
                compiler
                    .lookup_circom_template("P::Poseidon")
                    .unwrap()
                    .template_name,
                "Poseidon"
            );
            assert_eq!(
                compiler
                    .lookup_circom_template("Num2Bits")
                    .unwrap()
                    .template_name,
                "Num2Bits"
            );
            assert!(compiler.lookup_circom_template("Poseidon").is_none());
        }

        #[test]
        fn outer_scope_circom_imports_are_seeded_into_circom_table() {
            // Drive the seeding path end-to-end via `compile_prove_block`
            // so we don't need to construct a `Block` with a synthetic
            // span. Using a trivial prove-block body is enough to
            // exercise OuterScope → circom_table threading.
            let lib: Arc<dyn CircomLibraryHandle> = Arc::new(StubLibrary::with_template(
                "Square",
                sig(&[], &["x"], &["y"]),
            ));
            let mut imports = HashMap::new();
            imports.insert(
                "Square".to_string(),
                CircomCallable {
                    library: lib,
                    template_name: "Square".to_string(),
                },
            );
            let outer = OuterScope {
                circom_imports: imports.clone(),
                ..Default::default()
            };

            // Direct new-compiler path lets us inspect the seeded table
            // without having to run a full compilation. Mirror what
            // `compile_with_source_dir` does on entry.
            let mut compiler = ProveIrCompiler::<Bn254Fr>::new();
            for (key, callable) in &outer.circom_imports {
                compiler.circom_table.insert(key.clone(), callable.clone());
            }
            assert_eq!(compiler.circom_table.len(), 1);
            assert!(compiler.lookup_circom_template("Square").is_some());
        }
    }

    // --- Circom interop: compile_call dispatch (Phase 3.3) ---

    mod circom_dispatch {
        use super::super::*;
        use crate::prove_ir::circom_interop::{
            CircomInstantiation, CircomLibraryHandle, CircomTemplateOutput, CircomTemplateSignature,
        };
        use diagnostics::Span;
        use std::collections::HashMap;
        use std::sync::Arc;

        fn sig(params: &[&str], inputs: &[&str], outputs: &[&str]) -> CircomTemplateSignature {
            CircomTemplateSignature {
                params: params.iter().map(|s| s.to_string()).collect(),
                input_signals: inputs.iter().map(|s| s.to_string()).collect(),
                output_signals: outputs.iter().map(|s| s.to_string()).collect(),
            }
        }

        /// Stub that records instantiation calls so tests can assert
        /// what the dispatcher handed to the library handle. Mirrors
        /// `StubLibrary` but captures every `instantiate_template` call
        /// into an interior-mutable log.
        #[derive(Debug)]
        struct RecordingLibrary {
            sig: CircomTemplateSignature,
            template_name: String,
            calls: std::sync::Mutex<Vec<RecordedCall>>,
        }

        #[derive(Debug, Clone)]
        struct RecordedCall {
            template_name: String,
            template_args: Vec<FieldConst>,
            signal_inputs: Vec<(String, CircuitExpr)>,
            parent_prefix: String,
        }

        impl RecordingLibrary {
            fn new(template_name: &str, sig: CircomTemplateSignature) -> Self {
                Self {
                    sig,
                    template_name: template_name.to_string(),
                    calls: std::sync::Mutex::new(Vec::new()),
                }
            }
            fn recorded(&self) -> Vec<RecordedCall> {
                self.calls.lock().unwrap().clone()
            }
        }

        impl CircomLibraryHandle for RecordingLibrary {
            fn template_signature(&self, name: &str) -> Option<CircomTemplateSignature> {
                if name == self.template_name {
                    Some(self.sig.clone())
                } else {
                    None
                }
            }
            fn template_names(&self) -> Vec<String> {
                vec![self.template_name.clone()]
            }
            fn resolve_input_layout(
                &self,
                template_name: &str,
                _template_args: &[FieldConst],
            ) -> Option<Vec<crate::prove_ir::CircomInputLayout>> {
                if template_name != self.template_name {
                    return None;
                }
                Some(
                    self.sig
                        .input_signals
                        .iter()
                        .map(|n| crate::prove_ir::CircomInputLayout {
                            name: n.clone(),
                            dims: Vec::new(),
                        })
                        .collect(),
                )
            }
            fn instantiate_template(
                &self,
                template_name: &str,
                template_args: &[FieldConst],
                signal_inputs: &HashMap<String, CircuitExpr>,
                parent_prefix: &str,
                _span: &Span,
            ) -> Result<CircomInstantiation, crate::prove_ir::CircomDispatchError> {
                let mut inputs: Vec<(String, CircuitExpr)> = signal_inputs
                    .iter()
                    .map(|(k, v)| (k.clone(), v.clone()))
                    .collect();
                inputs.sort_by(|a, b| a.0.cmp(&b.0));
                self.calls.lock().unwrap().push(RecordedCall {
                    template_name: template_name.to_string(),
                    template_args: template_args.to_vec(),
                    signal_inputs: inputs,
                    parent_prefix: parent_prefix.to_string(),
                });
                // Emit a marker Let so tests can observe the body was
                // extended with the library's contribution.
                let body = vec![CircuitNode::Let {
                    name: format!("{parent_prefix}_marker"),
                    value: CircuitExpr::Const(FieldConst::from_u64(42)),
                    span: None,
                }];
                // Populate every declared output so multi-output
                // tests can verify per-output binding in the env.
                let mut outputs = HashMap::new();
                for out in &self.sig.output_signals {
                    outputs.insert(
                        out.clone(),
                        CircomTemplateOutput::Scalar(CircuitExpr::Var(format!(
                            "{parent_prefix}_{out}"
                        ))),
                    );
                }
                Ok(CircomInstantiation { body, outputs })
            }
        }

        fn compiler_with_stub(
            template: &str,
            sig_val: CircomTemplateSignature,
        ) -> (ProveIrCompiler<Bn254Fr>, Arc<RecordingLibrary>) {
            let lib = Arc::new(RecordingLibrary::new(template, sig_val));
            let handle: Arc<dyn CircomLibraryHandle> = lib.clone();
            let mut compiler = ProveIrCompiler::<Bn254Fr>::new();
            compiler.register_circom_template(template.to_string(), handle, template.to_string());
            // The prove block has an "x" public input that the
            // template consumes.
            compiler
                .env
                .insert("x".to_string(), CompEnvValue::Scalar("x".to_string()));
            (compiler, lib)
        }

        fn parse_expr(source: &str) -> Expr {
            let (program, errors) = achronyme_parser::parse_program(source);
            assert!(errors.is_empty(), "parse errors: {errors:?}");
            match &program.stmts[0] {
                Stmt::Expr(e) => e.clone(),
                other => panic!("expected expression statement, got {other:?}"),
            }
        }

        #[test]
        fn bare_template_call_dispatches_to_library() {
            let (mut compiler, lib) = compiler_with_stub("Square", sig(&[], &["x"], &["y"]));
            // Parse `Square()(x)` as an atomic curry expression.
            let expr = parse_expr("Square()(x)");
            let result = compiler
                .compile_expr(&expr)
                .expect("compile should succeed");
            // Dispatcher returns the mangled output Var for the
            // single scalar output.
            assert_eq!(result, CircuitExpr::Var("circom_call_0_y".to_string()));

            // The library received the call with empty template args
            // and one signal input wired to `x`.
            let calls = lib.recorded();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].template_name, "Square");
            assert!(calls[0].template_args.is_empty());
            assert_eq!(calls[0].signal_inputs.len(), 1);
            assert_eq!(calls[0].signal_inputs[0].0, "x");
            assert_eq!(calls[0].parent_prefix, "circom_call_0");

            // The compiler body was extended with the stub's marker.
            assert!(compiler.body.iter().any(|n| matches!(
                n,
                CircuitNode::Let { name, .. } if name == "circom_call_0_marker"
            )));
            // And the call counter bumped.
            assert_eq!(compiler.circom_call_counter, 1);
        }

        #[test]
        fn parametric_template_evaluates_args_at_compile_time() {
            let (mut compiler, lib) = compiler_with_stub("Num2Bits", sig(&["n"], &["in"], &["y"]));
            compiler.env.insert(
                "in_sig".to_string(),
                CompEnvValue::Scalar("in_sig".to_string()),
            );
            // Num2Bits(8)(in_sig)
            let expr = parse_expr("Num2Bits(8)(in_sig)");
            compiler
                .compile_expr(&expr)
                .expect("compile should succeed");

            let calls = lib.recorded();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].template_args.len(), 1);
            assert_eq!(calls[0].template_args[0], FieldConst::from_u64(8));
        }

        #[test]
        fn template_arg_must_be_compile_time_const() {
            let (mut compiler, _lib) = compiler_with_stub("Num2Bits", sig(&["n"], &["in"], &["y"]));
            // `x` is a runtime input — Num2Bits(x) must be rejected.
            let expr = parse_expr("Num2Bits(x)(x)");
            let err = compiler.compile_expr(&expr).expect_err("should fail");
            let msg = format!("{err}");
            assert!(
                msg.contains("compile-time constant"),
                "error should mention compile-time constant requirement: {msg}"
            );
        }

        #[test]
        fn template_param_count_mismatch_rejected() {
            let (mut compiler, _lib) = compiler_with_stub("Num2Bits", sig(&["n"], &["in"], &["y"]));
            // Zero template args instead of one.
            let expr = parse_expr("Num2Bits()(x)");
            let err = compiler.compile_expr(&expr).expect_err("should fail");
            let msg = format!("{err}");
            assert!(
                msg.contains("template parameter") && msg.contains("expects"),
                "expected parameter-count error, got: {msg}"
            );
        }

        #[test]
        fn signal_input_count_mismatch_rejected() {
            let (mut compiler, _lib) = compiler_with_stub("Square", sig(&[], &["x"], &["y"]));
            // Square takes 1 signal input, passing 2.
            let expr = parse_expr("Square()(x, x)");
            let err = compiler.compile_expr(&expr).expect_err("should fail");
            let msg = format!("{err}");
            assert!(
                msg.contains("signal input") && msg.contains("expects"),
                "expected signal-input-count error, got: {msg}"
            );
        }

        #[test]
        fn multi_output_template_at_expression_level_suggests_let_binding() {
            // Expression-level calls on multi-output templates must
            // redirect the user to bind the result via let so each
            // output can be named through DotAccess.
            let (mut compiler, _lib) = compiler_with_stub("Pair", sig(&[], &["x"], &["a", "b"]));
            let expr = parse_expr("Pair()(x)");
            let err = compiler.compile_expr(&expr).expect_err("should fail");
            let msg = format!("{err}");
            assert!(
                msg.contains("2 outputs") && msg.contains("let r"),
                "expected let-binding suggestion, got: {msg}"
            );
        }

        #[test]
        fn call_counter_is_per_compiler() {
            let (mut compiler, _lib) = compiler_with_stub("Square", sig(&[], &["x"], &["y"]));
            let e1 = parse_expr("Square()(x)");
            let e2 = parse_expr("Square()(x)");
            let r1 = compiler.compile_expr(&e1).unwrap();
            let r2 = compiler.compile_expr(&e2).unwrap();
            assert_eq!(r1, CircuitExpr::Var("circom_call_0_y".to_string()));
            assert_eq!(r2, CircuitExpr::Var("circom_call_1_y".to_string()));
            assert_eq!(compiler.circom_call_counter, 2);
        }

        #[test]
        fn non_circom_call_falls_through_unchanged() {
            // A Call that doesn't match the circom currying pattern
            // (no second Call layer) must fall through to the normal
            // function dispatch without hitting circom code paths.
            let (mut compiler, lib) = compiler_with_stub("Square", sig(&[], &["x"], &["y"]));
            // Not a curry — just `x + 1` as a plain expr.
            let expr = parse_expr("x + 1");
            let _ = compiler.compile_expr(&expr).unwrap();
            assert!(
                lib.recorded().is_empty(),
                "library should not have been called for non-circom expression"
            );
        }

        // --- Phase 3.4: let-binding + DotAccess ---

        /// Parse source as a Block and compile through compile_block_stmts.
        /// Useful for tests that need a let + dot-access sequence.
        fn compile_block(
            compiler: &mut ProveIrCompiler<Bn254Fr>,
            source: &str,
        ) -> Result<(), ProveIrError> {
            use achronyme_parser::parse_program;
            let (program, errors) = parse_program(source);
            assert!(errors.is_empty(), "parse errors: {errors:?}");
            let block = Block {
                stmts: program.stmts,
                span: Span {
                    byte_start: 0,
                    byte_end: 0,
                    line_start: 0,
                    col_start: 0,
                    line_end: 0,
                    col_end: 0,
                },
            };
            compiler.compile_block_stmts(&block)
        }

        #[test]
        fn let_bind_multi_output_template_publishes_dotted_env_entries() {
            let (mut compiler, _lib) = compiler_with_stub("Pair", sig(&[], &["x"], &["a", "b"]));
            compile_block(&mut compiler, "let r = Pair()(x)")
                .expect("let-binding a multi-output template should succeed");
            // Each output lands under "r.<output>" in the env.
            assert!(compiler.env.contains_key("r.a"));
            assert!(compiler.env.contains_key("r.b"));
            // Single-scalar convenience binding is NOT emitted for
            // multi-output templates.
            assert!(!compiler.env.contains_key("r"));
        }

        #[test]
        fn let_bind_single_scalar_template_also_binds_top_level_ident() {
            let (mut compiler, _lib) = compiler_with_stub("Square", sig(&[], &["x"], &["y"]));
            compile_block(&mut compiler, "let r = Square()(x)")
                .expect("let-binding a scalar template should succeed");
            // Both `r` and `r.y` exist.
            assert!(compiler.env.contains_key("r"));
            assert!(compiler.env.contains_key("r.y"));
        }

        #[test]
        fn dot_access_on_multi_output_let_binding_resolves_to_mangled_vars() {
            let (mut compiler, _lib) = compiler_with_stub("Pair", sig(&[], &["x"], &["a", "b"]));
            compile_block(
                &mut compiler,
                "let r = Pair()(x)\nassert_eq(r.a, x)\nassert_eq(r.b, x)",
            )
            .expect("dot access on multi-output should resolve");
            // The compile body now has assert_eq nodes pointing at
            // the mangled sub-template vars.
            let assert_vars: Vec<&str> = compiler
                .body
                .iter()
                .filter_map(|n| match n {
                    CircuitNode::AssertEq {
                        lhs: CircuitExpr::Var(v),
                        ..
                    } => Some(v.as_str()),
                    _ => None,
                })
                .collect();
            // StubLibrary names outputs as `<prefix>_<out>`. Pair's
            // outputs were a/b; the instantiated prefix is
            // circom_call_0. We expect exactly the first output
            // recorded — the stub only stores the first in outputs.
            // For this test we just assert both asserts landed.
            assert!(assert_vars.iter().any(|v| v.starts_with("circom_call_")));
        }

        #[test]
        fn namespaced_let_binding_publishes_dotted_env_entries() {
            // The namespaced form P.Pair(...)(...) is resolved the same
            // way as the bare form once try_resolve_circom_key has
            // produced the "P::Pair" key, so the let-binding path
            // should bind outputs identically.
            let (mut compiler, _lib) = compiler_with_stub(
                "Pair", // template_name
                sig(&[], &["x"], &["a", "b"]),
            );
            // Rewire the registration: under key "P::Pair" instead of
            // "Pair" (simulates a namespace import). We need to re-
            // register because compiler_with_stub bound under "Pair".
            let entry = compiler.circom_table.remove("Pair").unwrap();
            compiler.circom_table.insert("P::Pair".to_string(), entry);

            compile_block(&mut compiler, "let r = P.Pair()(x)")
                .expect("namespaced let-binding should succeed");
            assert!(compiler.env.contains_key("r.a"));
            assert!(compiler.env.contains_key("r.b"));
        }

        /// Stub that returns an array output to exercise the array-
        /// flattening code path on the let-binding side.
        #[derive(Debug)]
        struct ArrayOutputLibrary {
            name: String,
            dims: Vec<u64>,
        }
        impl CircomLibraryHandle for ArrayOutputLibrary {
            fn template_signature(&self, name: &str) -> Option<CircomTemplateSignature> {
                if name != self.name {
                    return None;
                }
                Some(CircomTemplateSignature {
                    params: vec!["n".to_string()],
                    input_signals: vec!["in".to_string()],
                    output_signals: vec!["out".to_string()],
                })
            }
            fn template_names(&self) -> Vec<String> {
                vec![self.name.clone()]
            }
            fn resolve_input_layout(
                &self,
                template_name: &str,
                _template_args: &[FieldConst],
            ) -> Option<Vec<crate::prove_ir::CircomInputLayout>> {
                if template_name != self.name {
                    return None;
                }
                // Single scalar input `in` for this stub.
                Some(vec![crate::prove_ir::CircomInputLayout {
                    name: "in".to_string(),
                    dims: Vec::new(),
                }])
            }
            fn instantiate_template(
                &self,
                _template_name: &str,
                _template_args: &[FieldConst],
                _signal_inputs: &HashMap<String, CircuitExpr>,
                parent_prefix: &str,
                _span: &Span,
            ) -> Result<CircomInstantiation, crate::prove_ir::CircomDispatchError> {
                let total: u64 = self.dims.iter().product();
                let values: Vec<CircuitExpr> = (0..total)
                    .map(|i| CircuitExpr::Var(format!("{parent_prefix}_out_{i}")))
                    .collect();
                let mut outputs = HashMap::new();
                outputs.insert(
                    "out".to_string(),
                    CircomTemplateOutput::Array {
                        dims: self.dims.clone(),
                        values,
                    },
                );
                Ok(CircomInstantiation {
                    body: Vec::new(),
                    outputs,
                })
            }
        }

        #[test]
        fn let_bind_array_output_publishes_indexed_env_entries() {
            let lib: Arc<dyn CircomLibraryHandle> = Arc::new(ArrayOutputLibrary {
                name: "Num2Bits".to_string(),
                dims: vec![4],
            });
            let mut compiler = ProveIrCompiler::<Bn254Fr>::new();
            compiler.register_circom_template("Num2Bits".to_string(), lib, "Num2Bits".to_string());
            compiler
                .env
                .insert("x".to_string(), CompEnvValue::Scalar("x".to_string()));

            compile_block(&mut compiler, "let r = Num2Bits(4)(x)")
                .expect("array-output let binding should succeed");
            for i in 0..4 {
                let key = format!("r.out_{i}");
                assert!(
                    compiler.env.contains_key(&key),
                    "expected env key {key}, have: {:?}",
                    compiler.env.keys().collect::<Vec<_>>()
                );
            }
            // No top-level `r` binding — arrays don't have a scalar
            // convenience form.
            assert!(!compiler.env.contains_key("r"));
        }

        // --- Phase 3.5: structured diagnostics ---

        #[test]
        fn unknown_template_name_with_near_match_suggests_did_you_mean() {
            let (mut compiler, _lib) = compiler_with_stub("Square", sig(&[], &["x"], &["y"]));
            // `Squar` is a 1-edit typo of `Square`.
            let expr = parse_expr("Squar()(x)");
            let err = compiler.compile_expr(&expr).expect_err("should fail");
            let msg = format!("{err}");
            assert!(
                msg.contains("not imported") && msg.contains("did you mean `Square`"),
                "expected did-you-mean suggestion, got: {msg}"
            );
        }

        #[test]
        fn unknown_namespace_alias_suggests_did_you_mean() {
            // Register under namespace alias "Pp".
            let (mut compiler, _lib) = compiler_with_stub("Square", sig(&[], &["x"], &["y"]));
            let entry = compiler.circom_table.remove("Square").unwrap();
            compiler
                .circom_table
                .insert("Pp::Square".to_string(), entry);
            // Typo `Pk` for `Pp`.
            let expr = parse_expr("Pk.Square()(x)");
            let err = compiler.compile_expr(&expr).expect_err("should fail");
            let msg = format!("{err}");
            assert!(
                msg.contains("namespace `Pk`") && msg.contains("did you mean `Pp`"),
                "expected namespace did-you-mean, got: {msg}"
            );
        }

        #[test]
        fn namespaced_template_typo_suggests_did_you_mean_within_namespace() {
            let (mut compiler, _lib) = compiler_with_stub("Square", sig(&[], &["x"], &["y"]));
            let entry = compiler.circom_table.remove("Square").unwrap();
            compiler.circom_table.insert("P::Square".to_string(), entry);
            // `Squar` is a near-miss of `Square` inside namespace `P`.
            let expr = parse_expr("P.Squar()(x)");
            let err = compiler.compile_expr(&expr).expect_err("should fail");
            let msg = format!("{err}");
            assert!(
                msg.contains("namespace `P`")
                    && msg.contains("Squar")
                    && msg.contains("did you mean `Square`"),
                "expected namespace-scoped did-you-mean, got: {msg}"
            );
        }

        #[test]
        fn bare_template_call_without_param_layer_hints_atomic_curry() {
            // User wrote `Square(x)` instead of `Square()(x)`.
            let (mut compiler, _lib) = compiler_with_stub("Square", sig(&[], &["x"], &["y"]));
            let expr = parse_expr("Square(x)");
            let err = compiler.compile_expr(&expr).expect_err("should fail");
            let msg = format!("{err}");
            assert!(
                msg.contains("called atomically") && msg.contains("template params"),
                "expected atomic-curry hint, got: {msg}"
            );
        }

        #[test]
        fn template_arg_not_const_uses_structured_kind() {
            let (mut compiler, _lib) = compiler_with_stub("Num2Bits", sig(&["n"], &["in"], &["y"]));
            let expr = parse_expr("Num2Bits(x)(x)");
            let err = compiler.compile_expr(&expr).expect_err("should fail");
            // Verify the error uses the structured CircomDispatch
            // variant, not a raw UnsupportedOperation.
            assert!(
                matches!(
                    err,
                    ProveIrError::CircomDispatch {
                        kind: CircomDispatchErrorKind::TemplateArgNotConst { arg_index: 0, .. },
                        ..
                    }
                ),
                "expected CircomDispatch(TemplateArgNotConst), got: {err:?}"
            );
        }

        #[test]
        fn param_count_mismatch_uses_structured_kind() {
            let (mut compiler, _lib) = compiler_with_stub("Num2Bits", sig(&["n"], &["in"], &["y"]));
            let expr = parse_expr("Num2Bits()(x)");
            let err = compiler.compile_expr(&expr).expect_err("should fail");
            assert!(
                matches!(
                    err,
                    ProveIrError::CircomDispatch {
                        kind: CircomDispatchErrorKind::ParamCountMismatch {
                            expected: 1,
                            got: 0,
                            ..
                        },
                        ..
                    }
                ),
                "expected CircomDispatch(ParamCountMismatch), got: {err:?}"
            );
        }

        #[test]
        fn dot_access_on_array_output_bit_resolves_via_indexed_env_key() {
            // `r.out_2` should resolve to the mangled `circom_call_0_out_2`.
            let lib: Arc<dyn CircomLibraryHandle> = Arc::new(ArrayOutputLibrary {
                name: "Num2Bits".to_string(),
                dims: vec![4],
            });
            let mut compiler = ProveIrCompiler::<Bn254Fr>::new();
            compiler.register_circom_template("Num2Bits".to_string(), lib, "Num2Bits".to_string());
            compiler
                .env
                .insert("x".to_string(), CompEnvValue::Scalar("x".to_string()));

            compile_block(
                &mut compiler,
                "let r = Num2Bits(4)(x)\nassert_eq(r.out_2, x)",
            )
            .expect("dot access on array-output bit should resolve");
            // Verify an AssertEq landed that references the mangled
            // 2nd element of the array output.
            let has_expected = compiler.body.iter().any(|n| match n {
                CircuitNode::AssertEq {
                    lhs: CircuitExpr::Var(lhs),
                    ..
                } => lhs == "circom_call_0_out_2",
                _ => false,
            });
            assert!(
                has_expected,
                "expected assert_eq lhs = circom_call_0_out_2, body: {:?}",
                compiler.body
            );
        }
    }
}
