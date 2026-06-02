use std::fmt;

use memory::{FieldBackend, FieldElement};

use crate::types::{IrProgram, SsaVar};

/// Errors that can occur during IR evaluation.
#[derive(Debug)]
pub enum EvalError<F: FieldBackend = memory::Bn254Fr> {
    MissingInput(String),
    DivisionByZero {
        var: SsaVar,
        dividend_name: Option<String>,
        divisor_name: Option<String>,
    },
    AssertionFailed {
        var: SsaVar,
        name: Option<String>,
        value: Option<FieldElement<F>>,
        message: Option<String>,
    },
    AssertEqFailed {
        lhs: SsaVar,
        rhs: SsaVar,
        lhs_name: Option<String>,
        rhs_name: Option<String>,
        lhs_value: Option<FieldElement<F>>,
        rhs_value: Option<FieldElement<F>>,
        message: Option<String>,
    },
    RangeCheckFailed {
        var: SsaVar,
        bits: u32,
        name: Option<String>,
        value: Option<FieldElement<F>>,
    },
    NonBooleanMuxCondition {
        var: SsaVar,
        name: Option<String>,
        value: Option<FieldElement<F>>,
    },
    UndefinedVar(SsaVar),
    /// The embedded Artik witness program failed to decode, validate,
    /// or execute. `reason` is the stringified underlying error.
    WitnessCallFailed {
        primary_output: SsaVar,
        reason: String,
    },
}

/// Look up the source-level name for an SSA variable.
pub(super) fn resolve_name<F: FieldBackend>(program: &IrProgram<F>, var: SsaVar) -> Option<String> {
    program.get_name(var).map(|s| s.to_string())
}

impl<F: FieldBackend> fmt::Display for EvalError<F> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            EvalError::MissingInput(name) => write!(f, "missing input: `{name}`"),
            EvalError::DivisionByZero {
                dividend_name,
                divisor_name,
                ..
            } => match (dividend_name, divisor_name) {
                (Some(a), Some(b)) => {
                    write!(
                        f,
                        "division by zero when dividing '{a}' by '{b}' (which is 0)"
                    )
                }
                _ => write!(f, "division by zero"),
            },
            EvalError::AssertionFailed {
                name,
                value,
                message,
                ..
            } => {
                if let Some(msg) = message {
                    write!(f, "assertion failed: {msg}")
                } else {
                    match (name, value) {
                        (Some(n), Some(v)) => write!(
                            f,
                            "assertion failed at '{n}' (value is {}, expected non-zero)",
                            v.to_decimal_string()
                        ),
                        (Some(n), None) => {
                            write!(f, "assertion failed at '{n}' (expected non-zero)")
                        }
                        _ => write!(f, "assertion failed (expected non-zero)"),
                    }
                }
            }
            EvalError::AssertEqFailed {
                lhs_name,
                rhs_name,
                lhs_value,
                rhs_value,
                message,
                ..
            } => {
                if let Some(msg) = message {
                    write!(f, "assert_eq failed: {msg}")
                } else {
                    match (lhs_name, rhs_name, lhs_value, rhs_value) {
                        (Some(a), Some(b), Some(av), Some(bv)) => write!(
                            f,
                            "assert_eq failed: '{a}' (value {}) != '{b}' (value {})",
                            av.to_decimal_string(),
                            bv.to_decimal_string()
                        ),
                        _ => write!(f, "assert_eq failed: values are not equal"),
                    }
                }
            }
            EvalError::RangeCheckFailed {
                bits, name, value, ..
            } => match (name, value) {
                (Some(n), Some(v)) => {
                    let max_str = if *bits < 64 {
                        format!("{}", (1u64 << bits) - 1)
                    } else {
                        format!("2^{bits}-1")
                    };
                    write!(
                        f,
                        "range check failed: '{n}' (value {}) does not fit in {bits} bits (max {max_str})",
                        v.to_decimal_string()
                    )
                }
                _ => write!(f, "range check failed: value does not fit in {bits} bits"),
            },
            EvalError::NonBooleanMuxCondition { name, value, .. } => match (name, value) {
                (Some(n), Some(v)) => write!(
                    f,
                    "if/else condition must be boolean: '{n}' has value {} (expected 0 or 1)",
                    v.to_decimal_string()
                ),
                _ => write!(f, "if/else condition must be boolean (expected 0 or 1)"),
            },
            EvalError::UndefinedVar(var) => write!(f, "undefined variable #{}", var.0),
            EvalError::WitnessCallFailed {
                primary_output,
                reason,
            } => write!(
                f,
                "Artik witness call failed at primary output #{}: {reason}",
                primary_output.0
            ),
        }
    }
}

impl<F: FieldBackend> std::error::Error for EvalError<F> {}
