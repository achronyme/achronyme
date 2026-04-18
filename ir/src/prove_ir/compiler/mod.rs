//! ProveIR compiler: AST Block → ProveIR template.

mod api;
mod helpers;
mod state;
mod stmts;

use std::collections::{HashMap, HashSet};
use std::marker::PhantomData;

use achronyme_parser::ast::*;
use diagnostics::SpanRange;
use memory::{Bn254Fr, FieldBackend, FieldElement};

use super::circom_interop::CircomCallable;
use super::error::{CircomDispatchErrorKind, ProveIrError};
use super::types::*;
use helpers::{flat_index_suffix, to_span};

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

    pub(super) fn compile_static_access(
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
            _ => {
                // Namespace lookup for `alias::const` where `alias` is an
                // `import "./foo.ach" as alias`-style module alias. The
                // fn_table already carries entries keyed `alias::name` for
                // every exported function, and the outer scope's
                // `CompEnvValue` map carries the same for exported
                // constants. Resolving here at compile time is the prove-
                // block sibling of the VM compiler's static-access fast
                // path: no HashMap lookup at proof time, no runtime map
                // object, just a direct value reference.
                let qualified = format!("{type_name}::{member}");
                if let Some(CompEnvValue::Scalar(resolved)) = self.env.get(&qualified) {
                    return Ok(CircuitExpr::Var(resolved.clone()));
                }
                Err(ProveIrError::UnsupportedOperation {
                    description: format!("unknown static access `{type_name}::{member}`"),
                    span: to_span(span),
                })
            }
        }
    }

    // -----------------------------------------------------------------------
    // Call dispatch
    // -----------------------------------------------------------------------

    pub(super) fn compile_call(
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
            // Module function call via compile-time `::` path:
            //   `alias::func(args)` parses as
            //   `Call { callee: StaticAccess { type_name: alias, member: func }, args }`.
            // The alias's exported functions live in `fn_table` under the
            // `{alias}::{func}` key (seeded by the module loader at
            // OuterScope build time), so this is a direct qualified
            // lookup — no runtime map dispatch, no hashmap per call,
            // fully constexpr. This is the new preferred syntax; the
            // older `alias.func()` DotAccess form is still accepted
            // below for a transition period.
            Expr::StaticAccess {
                type_name,
                member,
                id: static_id,
                ..
            } => {
                // Phase 3F: try annotation-driven dispatch first so
                // cross-module calls via `alias::name` also push
                // the definer's module onto the resolver stack via
                // `compile_user_fn_call` — this is what kills gap
                // 2.4 for the `a → b::middle → helper` scenario
                // (helper is a bare identifier inside middle's
                // inlined body and resolves against mod_B, not
                // against a's root module).
                //
                // `compile_expr` set `current_expr_id` to the
                // Call's id when it dispatched here; we temporarily
                // override it with the StaticAccess's own id so
                // the annotation lookup keys correctly, then
                // restore it afterwards.
                let saved_expr_id = self.current_expr_id;
                self.current_expr_id = Some(*static_id);
                let annotation_result = self.try_annotation_dispatch(*static_id, args, span);
                self.current_expr_id = saved_expr_id;
                match annotation_result {
                    Ok(Some(expr)) => return Ok(expr),
                    Ok(None) => {}
                    Err(e) => return Err(e),
                }

                // Legacy name-based lookup. `compile_user_fn_call`
                // still maintains the resolver module stack via
                // `resolver_module_by_key`, so the stack discipline
                // holds even on this fallback path.
                let qualified = format!("{type_name}::{member}");
                if self.has_function(&qualified) {
                    return self.compile_user_fn_call(&qualified, args, span);
                }
                Err(ProveIrError::UnsupportedOperation {
                    description: format!(
                        "unknown function `{type_name}::{member}` — is the alias \
                         imported with `import \"./...\" as {type_name}` and the \
                         function exported?"
                    ),
                    span: to_span(span),
                })
            }

            // Method call: expr.method(args).
            //
            // `alias.func(...)` where `alias` is a module namespace
            // import is no longer the canonical syntax — use
            // `alias::func(...)` (handled by the `StaticAccess` arm
            // above). Emit a migration error instead of silently
            // falling through so the old syntax becomes a hard
            // compile-time failure with a clean "did you mean" hint.
            Expr::DotAccess {
                object,
                field,
                span: dot_span,
                ..
            } => {
                if let Expr::Ident { name: module, .. } = object.as_ref() {
                    let qualified = format!("{module}::{field}");
                    if self.has_function(&qualified) || self.circom_table.contains_key(&qualified) {
                        return Err(ProveIrError::UnsupportedOperation {
                            description: format!(
                                "use `{module}::{field}(...)` instead of \
                                 `{module}.{field}(...)` — module-qualified calls \
                                 are now compile-time paths, not dynamic method \
                                 dispatch"
                            ),
                            span: to_span(span),
                        });
                    }
                }
                self.compile_method_call(object, field, args, dot_span)
            }

            // Named function/builtin call: name(args)
            //
            // Phase 3E.1: the resolver's annotate_program walker
            // annotates the callee Ident (not the enclosing Call),
            // so we need the Ident's own ExprId to consult the
            // annotation table. `compile_expr` has stashed the Call's
            // id in `self.current_expr_id` by now — re-override it
            // with the Ident's id so the shadow hook in
            // `compile_named_call` reads the correct annotation key.
            // This is cheap and localized; the alternative of
            // threading the id through `compile_named_call`'s
            // signature would touch many test call sites.
            Expr::Ident { name, id, .. } => {
                self.current_expr_id = Some(*id);
                self.compile_named_call(name, args, span)
            }

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
    pub(super) fn diagnose_unresolved_circom_curry(
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
    pub(super) fn try_resolve_circom_key(&self, callee: &Expr) -> Option<String> {
        match callee {
            Expr::Ident { name, .. } => {
                if self.circom_table.contains_key(name) {
                    Some(name.clone())
                } else {
                    None
                }
            }
            // Namespaced circom template via the compile-time `::` path:
            // `P::Poseidon(2)([a, b])` parses as
            //   Call { Call { StaticAccess { P, Poseidon }, [2] }, [arr] }
            // so the inner callee is a `StaticAccess` whose `type_name`
            // is the import alias. Match the same `{alias}::{template}`
            // key format the circom dispatch table uses for namespace
            // imports.
            Expr::StaticAccess {
                type_name, member, ..
            } => {
                let key = format!("{type_name}::{member}");
                if self.circom_table.contains_key(&key) {
                    Some(key)
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
    pub(super) fn instantiate_circom_template(
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
    pub(super) fn compile_circom_template_call(
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
    pub(super) fn compile_let_for_circom_call(
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

    /// Attempt annotation-driven dispatch for a call site.
    ///
    /// Shared helper consumed by both [`compile_named_call`] (for
    /// bare-ident callees) and the `StaticAccess` arm of
    /// [`compile_call`] (for `alias::name` callees). Returns:
    ///
    /// - `Ok(Some(expr))` — the annotation path handled the call
    ///   fully and produced a [`CircuitExpr`]. The caller returns
    ///   this immediately.
    /// - `Ok(None)` — the annotation path declined (no annotation,
    ///   unresolved dispatch map, or the annotated fn_table key
    ///   isn't in `fn_table`). The caller falls through to the
    ///   legacy name-based dispatch.
    /// - `Err(e)` — the annotation path matched a dispatch site but
    ///   the downstream compile errored (builtin arity mismatch,
    ///   fn body compile failure, etc.).
    ///
    /// Module-stack push/pop for inlined user fn bodies lives in
    /// [`compile_user_fn_call`] itself — this helper only selects
    /// the dispatch arm.
    pub(super) fn try_annotation_dispatch(
        &mut self,
        callee_expr_id: ExprId,
        args: &[&Expr],
        span: &Span,
    ) -> Result<Option<CircuitExpr>, ProveIrError> {
        match self.resolve_dispatch_via_annotation(callee_expr_id) {
            DispatchDecision::Builtin { handle } => self
                .dispatch_builtin_by_handle(handle, args, span)
                .map(Some),
            DispatchDecision::UserFn { qualified_name } => {
                // Phase 3F: the dispatch map already translated the
                // SymbolId to the correct fn_table key. If the key
                // isn't in `fn_table` we fall through to legacy —
                // happens when a symbol is known to the resolver
                // but not registered in this specific prove block's
                // OuterScope (e.g. prove-block-local imports that
                // the auto-build never saw).
                if !self.has_function(&qualified_name) {
                    return Ok(None);
                }
                // Stack push/pop for the inlined body lives inside
                // `compile_user_fn_call` — it consults
                // `resolver_module_by_key` to discover the definer's
                // module, so both the annotation path and the
                // legacy path maintain the stack uniformly.
                self.compile_user_fn_call(&qualified_name, args, span)
                    .map(Some)
            }
            DispatchDecision::NoAnnotation => {
                // Record a shadow hit for symmetry with Phase 3E.1
                // — the annotation map may still have an entry
                // (Constant in call position, etc.) that the
                // dispatch helper rejected. The hit trace still
                // reflects what the resolver saw at this call site.
                self.record_resolver_hit_for(callee_expr_id);
                Ok(None)
            }
        }
    }

    /// Compile a named function or builtin call.
    ///
    /// Movimiento 2 Phase 3E.2 / 3F — annotation-driven dispatch
    /// delegates to [`try_annotation_dispatch`] and falls back to
    /// the legacy name-based path if the annotation path declines.
    pub(super) fn compile_named_call(
        &mut self,
        name: &str,
        args: &[&Expr],
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        // Phase 3E.2: consult the annotation table for the current
        // callee Ident. `current_expr_id` was overridden with the
        // Ident's ExprId by `compile_call`'s Ident arm.
        if let Some(expr_id) = self.current_expr_id {
            if let Some(expr) = self.try_annotation_dispatch(expr_id, args, span)? {
                return Ok(expr);
            }
        } else {
            // No current_expr_id — synthetic call or similar. The
            // shadow hook keys off current_expr_id internally, so
            // this is a no-op in practice; the call records
            // nothing for synthetic invocations.
            self.record_resolver_hit();
        }

        // Legacy dispatch path. `lower_builtin` returning `Ok(None)`
        // means the name isn't a recognised builtin; fall through
        // to user-fn inlining exactly as before.
        if let Some(expr) = self.lower_builtin(name, args, span)? {
            return Ok(expr);
        }
        self.compile_user_fn_call(name, args, span)
    }

    /// Dispatch a builtin by name. Returns:
    /// - `Ok(Some(expr))` — handled as a builtin, evaluation succeeded.
    /// - `Ok(None)` — `name` is not a recognised builtin; the caller
    ///   should fall through to user-function dispatch.
    /// - `Err(e)` — handled as a builtin but the arguments were malformed
    ///   (wrong arity, unsupported shape, etc.).
    ///
    /// Dispatch is driven by [`resolve::BuiltinRegistry`]: the name is
    /// looked up in the registry, and if a ProveIR-available entry
    /// exists, its [`ProveIrLowerHandle`] indexes into the lowering
    /// dispatch table. Names not in the registry return `Ok(None)`.
    pub(super) fn lower_builtin(
        &mut self,
        name: &str,
        args: &[&Expr],
        span: &Span,
    ) -> Result<Option<CircuitExpr>, ProveIrError> {
        use std::sync::OnceLock;
        static REGISTRY: OnceLock<resolve::BuiltinRegistry> = OnceLock::new();
        let registry = REGISTRY.get_or_init(resolve::BuiltinRegistry::default);

        let handle = match registry.lookup(name) {
            Some(entry) => match entry.prove_ir_lower {
                Some(h) => h,
                None => return Ok(None),
            },
            None => return Ok(None),
        };
        self.dispatch_builtin_by_handle(handle, args, span)
            .map(Some)
    }

    /// Dispatch a ProveIR builtin by its [`ProveIrLowerHandle`].
    ///
    /// The handle indexes into a function-pointer table whose slots
    /// correspond 1:1 with the `ProveIrLowerHandle` values declared in
    /// [`resolve::BuiltinRegistry::default()`]. Adding a new ProveIR
    /// builtin requires:
    /// 1. A new `ProveIrLowerHandle(N)` in the registry.
    /// 2. A new `lower_*` method below.
    /// 3. Slot `N` in the `LOWERINGS` table pointing to that method.
    pub(super) fn dispatch_builtin_by_handle(
        &mut self,
        handle: resolve::builtins::ProveIrLowerHandle,
        args: &[&Expr],
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        type LowerFn<F> =
            fn(&mut ProveIrCompiler<F>, &[&Expr], &Span) -> Result<CircuitExpr, ProveIrError>;

        const LOWERING_COUNT: usize = 10;
        let lowerings: [LowerFn<F>; LOWERING_COUNT] = [
            Self::lower_poseidon,      // 0
            Self::lower_poseidon_many, // 1
            Self::lower_mux,           // 2
            Self::lower_range_check,   // 3
            Self::lower_merkle_verify, // 4
            Self::lower_len,           // 5
            Self::lower_assert_eq,     // 6
            Self::lower_assert,        // 7
            Self::lower_int_div,       // 8
            Self::lower_int_mod,       // 9
        ];

        let idx = handle.as_u32() as usize;
        assert!(
            idx < LOWERING_COUNT,
            "ProveIrLowerHandle({idx}) out of range — \
             add the lowering function to dispatch_builtin_by_handle"
        );
        lowerings[idx](self, args, span)
    }

    // -- Individual builtin lowering functions --------------------------------

    pub(super) fn lower_poseidon(&mut self, args: &[&Expr], span: &Span) -> Result<CircuitExpr, ProveIrError> {
        self.check_arity("poseidon", 2, args.len(), span)?;
        let left = self.compile_expr(args[0])?;
        let right = self.compile_expr(args[1])?;
        Ok(CircuitExpr::PoseidonHash {
            left: Box::new(left),
            right: Box::new(right),
        })
    }

    pub(super) fn lower_poseidon_many(
        &mut self,
        args: &[&Expr],
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        if args.len() < 2 {
            return Err(ProveIrError::UnsupportedOperation {
                description: format!(
                    "`poseidon_many` requires at least 2 arguments, got {}",
                    args.len()
                ),
                span: to_span(span),
            });
        }
        let compiled: Result<Vec<_>, _> = args.iter().map(|a| self.compile_expr(a)).collect();
        Ok(CircuitExpr::PoseidonMany(compiled?))
    }

    pub(super) fn lower_mux(&mut self, args: &[&Expr], span: &Span) -> Result<CircuitExpr, ProveIrError> {
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

    pub(super) fn lower_range_check(
        &mut self,
        args: &[&Expr],
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
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

    pub(super) fn lower_merkle_verify(
        &mut self,
        args: &[&Expr],
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        self.check_arity("merkle_verify", 4, args.len(), span)?;
        let root = self.compile_expr(args[0])?;
        let leaf = self.compile_expr(args[1])?;
        let path = self.extract_array_ident(args[2], span)?;
        let indices = self.extract_array_ident(args[3], span)?;
        Ok(CircuitExpr::MerkleVerify {
            root: Box::new(root),
            leaf: Box::new(leaf),
            path,
            indices,
        })
    }

    pub(super) fn lower_len(&mut self, args: &[&Expr], span: &Span) -> Result<CircuitExpr, ProveIrError> {
        self.check_arity("len", 1, args.len(), span)?;
        self.compile_len_call(args[0], span)
    }

    pub(super) fn lower_assert_eq(
        &mut self,
        args: &[&Expr],
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
        self.check_assert_eq_arity(args.len(), span)?;
        let lhs = self.compile_expr(args[0])?;
        let rhs = self.compile_expr(args[1])?;
        let message = self.extract_assert_message(args.get(2), span)?;
        self.body.push(CircuitNode::AssertEq {
            lhs,
            rhs,
            message,
            span: Some(SpanRange::from(span)),
        });
        Ok(CircuitExpr::Const(FieldConst::zero()))
    }

    pub(super) fn lower_assert(&mut self, args: &[&Expr], span: &Span) -> Result<CircuitExpr, ProveIrError> {
        self.check_assert_arity(args.len(), span)?;
        let cond = self.compile_expr(args[0])?;
        let message = self.extract_assert_message(args.get(1), span)?;
        self.body.push(CircuitNode::Assert {
            expr: cond,
            message,
            span: Some(SpanRange::from(span)),
        });
        Ok(CircuitExpr::Const(FieldConst::zero()))
    }

    pub(super) fn lower_int_div(&mut self, args: &[&Expr], span: &Span) -> Result<CircuitExpr, ProveIrError> {
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

    pub(super) fn lower_int_mod(&mut self, args: &[&Expr], span: &Span) -> Result<CircuitExpr, ProveIrError> {
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
