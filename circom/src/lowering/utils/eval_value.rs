//! Compile-time value types for Circom function evaluation.

use crate::ast::Expr;

/// A value produced by compile-time evaluation of Circom functions.
///
/// Functions like `POSEIDON_C(t)` return arrays of field constants selected
/// by an if-else chain.  `EvalValue` lets the evaluator propagate both
/// scalar results (`return 42`) and array results (`return [a, b, c]`)
/// through control flow and up the call stack.
///
/// Array elements that are large field-element constants (e.g. 256-bit hex
/// values) cannot be represented as `i64`.  These are preserved as raw AST
/// [`Expr`] nodes and lowered to `CircuitExpr` when the array is expanded
/// into `Let` bindings.
#[derive(Clone, Debug)]
pub enum EvalValue {
    /// A single integer (fits in i64 — later promoted to a field element).
    Scalar(i64),
    /// An array of values (may nest for 2-D arrays like `POSEIDON_M`).
    Array(Vec<EvalValue>),
    /// An unevaluated expression preserved from the function body.
    /// Used for constants too large for i64 (256-bit field elements).
    Expr(Box<Expr>),
}

impl EvalValue {
    /// Extract as a scalar, returning `None` for arrays and raw expressions.
    pub fn as_scalar(&self) -> Option<i64> {
        match self {
            EvalValue::Scalar(v) => Some(*v),
            _ => None,
        }
    }

    /// Index into this value: only arrays support indexing.
    pub fn index(&self, idx: usize) -> Option<&EvalValue> {
        match self {
            EvalValue::Array(elems) => elems.get(idx),
            _ => None,
        }
    }

    /// Length for arrays, None for scalars/exprs.
    pub fn len(&self) -> Option<usize> {
        match self {
            EvalValue::Array(elems) => Some(elems.len()),
            _ => None,
        }
    }

    /// True if this is an array value.
    pub fn is_array(&self) -> bool {
        matches!(self, EvalValue::Array(_))
    }
}

/// Result of evaluating a single statement.
pub(super) enum StmtResult {
    /// Statement completed normally.
    Continue,
    /// A `return` statement was reached with the given value.
    Return(EvalValue),
}

/// Result of the unified compile-time precomputation pass.
pub struct PrecomputeResult {
    /// Scalar vars (e.g. `var nRoundsP = 56`).  Excludes original params.
    pub scalars: std::collections::HashMap<String, u64>,
    /// Array vars (e.g. `var C[n] = POSEIDON_C(t)`).
    pub arrays: std::collections::HashMap<String, EvalValue>,
}
