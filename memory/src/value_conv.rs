//! Conversion traits between `Value` and Rust types.
//!
//! Used by the `#[ach_native]` proc-macro to auto-generate argument
//! extraction and return-value wrapping. Only inline types (those that
//! don't need heap access) are supported here.

use crate::Value;

/// Error returned when a `Value` cannot be converted to the expected Rust type.
#[derive(Debug, Clone)]
pub struct ValueConvError {
    pub expected: &'static str,
    pub got_tag: u64,
}

impl std::fmt::Display for ValueConvError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "expected {}, got tag {}", self.expected, self.got_tag)
    }
}

/// Extract a Rust value from a VM `Value`.
pub trait FromValue: Sized {
    fn from_value(val: Value) -> Result<Self, ValueConvError>;
}

/// Convert a Rust value into a VM `Value`.
pub trait IntoValue {
    fn into_value(self) -> Value;
}

// ── i64 ──

impl FromValue for i64 {
    fn from_value(val: Value) -> Result<Self, ValueConvError> {
        val.as_int().ok_or(ValueConvError {
            expected: "Int",
            got_tag: val.tag(),
        })
    }
}

impl IntoValue for i64 {
    fn into_value(self) -> Value {
        Value::int(self)
    }
}

// ── bool ──

impl FromValue for bool {
    fn from_value(val: Value) -> Result<Self, ValueConvError> {
        val.as_bool().ok_or(ValueConvError {
            expected: "Bool",
            got_tag: val.tag(),
        })
    }
}

impl IntoValue for bool {
    fn into_value(self) -> Value {
        Value::bool(self)
    }
}

// ── Value (passthrough) ──

impl FromValue for Value {
    fn from_value(val: Value) -> Result<Self, ValueConvError> {
        Ok(val)
    }
}

impl IntoValue for Value {
    fn into_value(self) -> Value {
        self
    }
}

// ── () → nil ──

impl IntoValue for () {
    fn into_value(self) -> Value {
        Value::nil()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn i64_roundtrip() {
        let v = 42i64.into_value();
        assert_eq!(i64::from_value(v).unwrap(), 42);
    }

    #[test]
    fn bool_roundtrip() {
        let v = true.into_value();
        assert_eq!(bool::from_value(v).unwrap(), true);
    }

    #[test]
    fn value_passthrough() {
        let v = Value::int(99);
        assert_eq!(Value::from_value(v).unwrap().as_int(), Some(99));
    }

    #[test]
    fn unit_to_nil() {
        let v = ().into_value();
        assert!(v.is_nil());
    }

    #[test]
    fn type_mismatch_error() {
        let v = Value::nil();
        let err = i64::from_value(v).unwrap_err();
        assert_eq!(err.expected, "Int");
    }
}
