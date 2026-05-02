//! Builtin lowering for prove-block calls.
//!
//! [`lower_builtin`](super::super::ProveIrCompiler::lower_builtin)
//! consults [`resolve::BuiltinRegistry`] for the active name and, on
//! a hit with a registered ProveIR lowering, forwards to
//! [`dispatch_builtin_by_handle`](super::super::ProveIrCompiler::dispatch_builtin_by_handle).
//! [`dispatch_builtin_by_handle`](super::super::ProveIrCompiler::dispatch_builtin_by_handle)
//! is a function-pointer table whose slots correspond 1:1 with the
//! `ProveIrLowerHandle` values declared in
//! [`resolve::BuiltinRegistry::default`].
//!
//! Adding a ProveIR builtin requires:
//! 1. A new `ProveIrLowerHandle(N)` in the registry.
//! 2. A new `lower_*` method in this file.
//! 3. Slot `N` in the `LOWERINGS` table pointing to that method.
//!
//! Per-builtin lowerings: `lower_poseidon`, `lower_poseidon_many`,
//! `lower_mux`, `lower_range_check`, `lower_merkle_verify`,
//! `lower_len`, `lower_assert_eq`, `lower_assert`, `lower_int_div`,
//! `lower_int_mod`.

use achronyme_parser::ast::*;
use diagnostics::SpanRange;
use memory::FieldBackend;

use super::super::helpers::to_span;
use super::super::ProveIrCompiler;
use crate::error::ProveIrError;
use crate::types::*;

impl<F: FieldBackend> ProveIrCompiler<F> {
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

    pub(super) fn lower_poseidon(
        &mut self,
        args: &[&Expr],
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
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

    pub(super) fn lower_mux(
        &mut self,
        args: &[&Expr],
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
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

    pub(super) fn lower_len(
        &mut self,
        args: &[&Expr],
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
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

    pub(super) fn lower_assert(
        &mut self,
        args: &[&Expr],
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
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

    pub(super) fn lower_int_div(
        &mut self,
        args: &[&Expr],
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
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

    pub(super) fn lower_int_mod(
        &mut self,
        args: &[&Expr],
        span: &Span,
    ) -> Result<CircuitExpr, ProveIrError> {
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
}
