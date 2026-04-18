//! ProveIR compiler: AST Block → ProveIR template.

mod api;
mod calls;
mod helpers;
mod state;
mod stmts;

use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;

use achronyme_parser::ast::*;
use diagnostics::SpanRange;
use memory::{Bn254Fr, FieldBackend, FieldElement};

use super::circom_interop::CircomCallable;
use super::error::ProveIrError;
use super::types::*;
use helpers::to_span;

use resolve::{
    AnnotationKey, Availability, ModuleId, ResolvedProgram, ResolverState, SymbolId, SymbolTable,
};

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
///
/// `resolver_state` (Movimiento 2 Phase 3E) forwards the VM compiler's
/// already-built [`ResolvedProgram`] + [`SymbolTable`] + root
/// [`ModuleId`]. When present, the ProveIR compiler uses it to record
/// shadow resolver hits alongside its own dispatch. The legacy
/// `fn_table`/`env` lookup remains authoritative in 3E.1; Phase
/// 3E.2/3 is where dispatch actually reads from annotations.
#[derive(Clone, Debug, Default)]
pub struct OuterScope {
    /// Captured values (scalars / arrays) from the VM scope.
    pub values: HashMap<String, OuterScopeEntry>,
    /// Function declarations to register in fn_table before compilation.
    pub functions: Vec<Stmt>,
    /// Circom templates importable into this block. Keys are the
    /// names the ProveIR dispatcher will look up at Call time.
    pub circom_imports: HashMap<String, CircomCallable>,
    /// Optional resolver state forwarded from the caller. None
    /// means "standalone compile" — the ProveIR compiler will
    /// either run without resolver observation, or (future work)
    /// build its own state.
    pub resolver_state: Option<OuterResolverState>,
}

/// Borrow-free bundle of resolver state for prove-block outer scope.
///
/// The VM compiler stores these three pieces in separate `Option`
/// fields; for the prove-block hand-off we repackage them into a
/// single [`Arc`]-shared struct so cloning `OuterScope` is free
/// regardless of how big the symbol table grows. The VM compiler
/// moves its own state into `Arc`s at the hand-off point (see
/// `compile_prove` in the `compiler` crate).
///
/// [`SymbolTable`] and [`ResolvedProgram`] are not `Clone`
/// themselves — the `Arc` indirection is therefore mandatory, not
/// a premature optimisation.
#[derive(Clone, Debug)]
pub struct OuterResolverState {
    /// Symbol table shared by the VM + ProveIR compilers.
    pub table: std::sync::Arc<SymbolTable>,
    /// Annotation map keyed by `(module_id, expr_id)`.
    pub resolved: std::sync::Arc<ResolvedProgram>,
    /// Root module id in the graph the annotations were built for.
    pub root_module: ModuleId,
    /// Phase 3F: precomputed map from [`SymbolId`] to the fn_table
    /// key the ProveIR compiler uses. Built once at auto-build
    /// time by walking the resolver's [`SymbolTable`] + module
    /// graph edges (see `compiler::build_dispatch_maps`).
    /// Consumed by [`resolve_dispatch_via_annotation`] to translate
    /// resolved user-fn annotations into fn_table lookups without
    /// parsing the resolver's name-mangling convention at dispatch
    /// time. Empty when the compile had no multi-module state —
    /// e.g. single-module programs whose only user fns are root
    /// and need no alias prefix.
    pub dispatch_key_by_symbol: std::sync::Arc<HashMap<SymbolId, String>>,
    /// Phase 3F inverse of [`dispatch_key_by_symbol`]: fn_table key
    /// to the owning [`ModuleId`]. Consumed by
    /// [`ProveIrCompiler::compile_user_fn_call`] to push the
    /// definer's module onto the resolver stack before inlining
    /// the body — the structural half of the gap 2.4 fix. Both
    /// the annotation path and the legacy StaticAccess path go
    /// through this, so every inlined body correctly resolves
    /// bare identifiers against the definer's scope.
    pub module_by_dispatch_key: std::sync::Arc<HashMap<String, ModuleId>>,
    /// Phase 4: fn_table key → [`Availability`] for every user function.
    /// `compile_user_fn_call` checks this to reject inlining of
    /// Vm-only functions inside prove blocks.
    pub availability_by_key: std::sync::Arc<HashMap<String, Availability>>,
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
    /// Owning module id — used for resolver module stack push in
    /// `compile_user_fn_call` so bare identifiers inside the inlined
    /// body resolve against the definer's scope. `None` for functions
    /// defined locally inside a prove/circuit block.
    owner_module: Option<ModuleId>,
    /// Availability of this function (Phase 4). `None` for locally
    /// defined functions or when resolver state is not installed.
    /// `compile_user_fn_call` checks this to reject Vm-only functions.
    availability: Option<Availability>,
}

/// The annotation-driven dispatch choice for a call site.
///
/// Returned by [`ProveIrCompiler::resolve_dispatch_via_annotation`].
/// `Builtin` dispatches via [`ProveIrLowerHandle`] into the lowering
/// table; `UserFn` carries the fn_table key for inlining. The legacy
/// name-based path in [`compile_named_call`] handles the
/// `NoAnnotation` fallback.
pub(super) enum DispatchDecision {
    Builtin {
        handle: resolve::builtins::ProveIrLowerHandle,
    },
    UserFn {
        qualified_name: String,
    },
    NoAnnotation,
}

/// Phase 3G: the full bundle of resolver state a standalone
/// [`ProveIrCompiler::compile_circuit`] invocation uses.
///
/// Built by [`ProveIrCompiler::try_build_circuit_resolver_state`]
/// from the parsed source + source directory. Short-circuits to
/// `None` on any build error so the caller can fall back to the
/// legacy path. The fields are consumed twice: once by
/// [`ProveIrCompiler::outer_functions_from_graph`] to derive
/// renamed [`Stmt::FnDecl`] entries for the fn_table population,
/// and once by the `OuterResolverState` constructor so the
/// ProveIR compiler's annotation-driven dispatch can flip.
pub(super) struct CircuitResolverBundle {
    state: ResolverState,
    dispatch_by_symbol: HashMap<SymbolId, String>,
    module_by_key: HashMap<String, ModuleId>,
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
    // ── Movimiento 2 Phase 3E ────────────────────────────────────
    /// Optional resolver state forwarded from the outer (VM)
    /// compiler via [`OuterScope::resolver_state`]. Installed at
    /// the start of `compile_with_source_dir`. When `None`, every
    /// resolver-shadow hook is a no-op (single-module prove blocks
    /// compiled without a pre-built resolver state).
    resolver_table: Option<std::sync::Arc<SymbolTable>>,
    /// Annotation map mirroring [`resolver_table`]; see the
    /// `compiler` crate's [`Compiler::resolved_program`] doc for
    /// the key semantics.
    resolver_resolved: Option<std::sync::Arc<ResolvedProgram>>,
    /// The [`ModuleId`] annotations are currently being resolved
    /// against when the stack is empty. Installed from
    /// `OuterScope::resolver_state.root_module` at compile-start.
    resolver_root_module: Option<ModuleId>,
    /// Stack of module ids that should override
    /// [`resolver_root_module`] while walking inlined user-fn
    /// bodies. Phase 3E.3 / 3F structural fix for gap 2.4: every
    /// [`compile_user_fn_call`] looks up its fn_table key in
    /// [`resolver_module_by_key`] and, if present, pushes the
    /// discovered [`ModuleId`] before compiling the inlined body
    /// and pops on exit. The stack top is consulted by every
    /// annotation lookup during the walk so that bare identifiers
    /// inside the inlined body resolve against the definer's
    /// scope, not the caller's.
    resolver_module_stack: Vec<ModuleId>,
    /// Reverse index from [`SymbolId`] to fn_table key, built during
    /// fn_table registration from the dispatch maps in
    /// [`OuterResolverState`]. Consumed by
    /// [`resolve_dispatch_via_annotation`] to translate a resolved
    /// user-fn annotation into the fn_table key.
    fn_symbol_index: HashMap<SymbolId, String>,
    /// Phase 3E shadow hit trace: every `(module_id, expr_id)` the
    /// annotation table resolved to a [`SymbolId`] during the walk.
    /// Populated by [`record_resolver_hit`]; consumed by tests
    /// under `ir/tests/prove_ir_resolver_dispatch.rs`. Clears per
    /// compile invocation.
    resolver_hits: Vec<(AnnotationKey, SymbolId)>,
    /// The id of the [`Expr`] currently being walked, set at the
    /// top of [`compile_expr`]. Pairs with
    /// [`resolver_root_module`] to form the annotation lookup key.
    /// `None` outside expression contexts.
    current_expr_id: Option<ExprId>,
    /// Phantom data for the field backend type parameter.
    _field: PhantomData<F>,
}

impl<F: FieldBackend> ProveIrCompiler<F> {

    // -----------------------------------------------------------------------
    // Statement compilation
    // -----------------------------------------------------------------------

    // -----------------------------------------------------------------------
    // Expression compilation
    // -----------------------------------------------------------------------

    /// Compile an AST expression into a `CircuitExpr`.
    pub(crate) fn compile_expr(&mut self, expr: &Expr) -> Result<CircuitExpr, ProveIrError> {
        // Phase 3E.1: thread the current ExprId so the shadow-dispatch
        // hooks in compile_ident / compile_named_call can read it off
        // the compiler. Mirrors the VM compiler's pattern in
        // `compiler/src/expressions/mod.rs::compile_expr`. We don't
        // need the previous id for scoping because compile_expr is
        // the only site that writes the field, and each recursive
        // call re-overrides it before any hook reads it.
        self.current_expr_id = Some(expr.id());
        match expr {
            Expr::Number { value, span, .. } => self.compile_number(value, span),
            Expr::FieldLit {
                value, radix, span, ..
            } => self.compile_field_lit(value, radix, span),
            Expr::Bool { value: true, .. } => Ok(CircuitExpr::Const(FieldConst::one())),
            Expr::Bool { value: false, .. } => Ok(CircuitExpr::Const(FieldConst::zero())),
            Expr::Ident { name, span, .. } => self.compile_ident(name, span),

            Expr::BinOp {
                op, lhs, rhs, span, ..
            } => self.compile_binop(op, lhs, rhs, span),
            Expr::UnaryOp {
                op, operand, span, ..
            } => self.compile_unary(op, operand, span),

            Expr::StaticAccess {
                type_name,
                member,
                span,
                ..
            } => self.compile_static_access(type_name, member, span),

            Expr::Call {
                callee, args, span, ..
            } => {
                let arg_vals: Vec<&Expr> = args.iter().map(|a| &a.value).collect();
                self.compile_call(callee, &arg_vals, span)
            }

            Expr::DotAccess {
                object,
                field,
                span,
                ..
            } => self.compile_dot_access(object, field, span),

            Expr::If {
                condition,
                then_block,
                else_branch,
                span,
                ..
            } => self.compile_if_expr(condition, then_block, else_branch.as_ref(), span),

            Expr::For {
                var,
                iterable,
                body,
                span,
                ..
            } => self.compile_for_expr(var, iterable, body, span),

            Expr::Block { block, .. } => self.compile_block_as_expr(block),

            Expr::Index {
                object,
                index,
                span,
                ..
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
            Expr::Nil { span, .. } => Err(ProveIrError::TypeNotConstrainable {
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
            Expr::Error { span, .. } => Err(ProveIrError::UnsupportedOperation {
                description: "cannot compile error placeholder (source has parse errors)".into(),
                span: to_span(span),
            }),
        }
    }

    // -----------------------------------------------------------------------
    // Literals
    // -----------------------------------------------------------------------

    pub(super) fn compile_number(&self, s: &str, span: &Span) -> Result<CircuitExpr, ProveIrError> {
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

    pub(super) fn compile_field_lit(
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

    pub(super) fn compile_ident(&mut self, name: &str, span: &Span) -> Result<CircuitExpr, ProveIrError> {
        // Phase 3E.1 shadow dispatch: observation only. Real
        // dispatch flip lands in Phase 3E.2/3. Records a hit only
        // when the resolver state is installed AND the annotation
        // map has an entry for the current `(root_module, expr_id)`
        // pair. No effect on the lookup that follows.
        self.record_resolver_hit();
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

    // -----------------------------------------------------------------------
    // Dot access (non-call)
    // -----------------------------------------------------------------------

    pub(super) fn compile_dot_access(
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

    pub(super) fn compile_method_call(
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
    pub(super) fn extract_array_ident(&mut self, expr: &Expr, span: &Span) -> Result<String, ProveIrError> {
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
    pub(super) fn compile_len_call(
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

    pub(super) fn check_arity(
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
    pub(super) fn check_assert_eq_arity(&self, got: usize, span: &Span) -> Result<(), ProveIrError> {
        if !(2..=3).contains(&got) {
            return Err(ProveIrError::UnsupportedOperation {
                description: format!("`assert_eq` expects 2 or 3 arguments, got {got}"),
                span: to_span(span),
            });
        }
        Ok(())
    }

    /// Validate assert arity: 1 or 2 arguments.
    pub(super) fn check_assert_arity(&self, got: usize, span: &Span) -> Result<(), ProveIrError> {
        if !(1..=2).contains(&got) {
            return Err(ProveIrError::UnsupportedOperation {
                description: format!("`assert` expects 1 or 2 arguments, got {got}"),
                span: to_span(span),
            });
        }
        Ok(())
    }

    /// Extract an optional string literal for assert_eq/assert messages.
    pub(super) fn extract_assert_message(
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

    pub(super) fn check_method_arity(
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

    pub(super) fn method_not_constrainable(&self, method: &str, reason: &str, span: &Span) -> ProveIrError {
        ProveIrError::MethodNotConstrainable {
            method: method.into(),
            reason: reason.into(),
            span: to_span(span),
        }
    }

    /// Check if a function name exists in the fn_table.
    pub(super) fn has_function(&self, name: &str) -> bool {
        self.fn_table.contains_key(name)
    }

    // -----------------------------------------------------------------------
    // Control flow
    // -----------------------------------------------------------------------

    pub(super) fn compile_if_expr(
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

    pub(super) fn compile_for_expr(
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

    pub(super) fn compile_index(
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

    pub(super) fn compile_user_fn_call(
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

        // Phase 4: reject Vm-only functions inside prove/circuit blocks.
        if let Some(avail) = fn_def.availability {
            if !avail.includes_prove_ir() {
                return Err(ProveIrError::VmOnlyFunction {
                    name: name.into(),
                    span: to_span(span),
                });
            }
        }

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

        // Phase 3F — gap 2.4 structural fix: push the definer's
        // module onto the resolver module stack before compiling the
        // inlined body. Both the annotation-driven dispatch path and
        // the legacy name-based path land here, so all inlined bodies
        // consistently resolve bare identifiers against their
        // definer's scope. `owner_module` is embedded in FnDef at
        // registration time from the dispatch maps.
        let module_pushed = fn_def
            .owner_module
            .map(|module| {
                self.resolver_module_stack.push(module);
                true
            })
            .unwrap_or(false);

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

        // Phase 3F: pop the definer's module we pushed above.
        // Paired with the push so the stack stays balanced across
        // nested inlinings. Only executes when we actually pushed —
        // see the `module_pushed` discussion above.
        if module_pushed {
            self.resolver_module_stack.pop();
        }

        self.call_stack.remove(name);
        Ok(result)
    }

    /// Bind an array parameter for function inlining.
    ///
    /// Resolves the argument as an array name in the environment, creates
    /// SSA-renamed copies of each element, and registers the parameter as
    /// `CompEnvValue::Array` in the env.
    pub(super) fn bind_array_fn_param(
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
    pub(super) fn compile_block_as_expr(&mut self, block: &Block) -> Result<CircuitExpr, ProveIrError> {
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

    pub(super) fn compile_binop(
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

    pub(super) fn compile_arith_binop(
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

    pub(super) fn compile_comparison(
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

    pub(super) fn compile_bool_binop(
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

    pub(super) fn compile_pow(
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
    pub(super) fn extract_const_u64(&self, expr: &Expr, span: &Span) -> Result<u64, ProveIrError> {
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

    pub(super) fn compile_unary(
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
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests;
