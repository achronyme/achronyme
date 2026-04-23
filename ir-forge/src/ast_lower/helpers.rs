//! Free helpers used across compiler submodules.
//!
//! - [`program_to_block`] — wrap a parsed [`Program`] in a [`Block`]
//!   so the prove-block compiler can treat it like any other body.
//! - [`flat_index_suffix`] — row-major suffix for a multi-dimensional
//!   element name (`arr[1][1]` in a `[2][2]` declaration → `"1_1"`).
//! - [`to_span`] — adapt a parser [`Span`] to an [`OptSpan`] for IR
//!   error reporting.
//! - [`annotation_to_ir_type`] — `TypeAnnotation::Field` → `IrType::Field`,
//!   etc. Panics on `Int`/`String` (VM-only types are caller-rejected).

use achronyme_parser::ast::{BaseType, Block, Program, Span, TypeAnnotation};
use diagnostics::SpanRange;

use ir_core::error::{span_box, OptSpan};
use ir_core::IrType;

/// Convert a parsed Program into a Block (Programs don't carry their own span).
pub(super) fn program_to_block(source: &str, program: Program) -> Block {
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

/// Build the row-major flattened suffix for a multi-dimensional
/// element index. For `dims = [3]` and `linear = 2` this returns
/// `"2"`; for `dims = [2, 2]` and `linear = 3` it returns `"1_1"`.
pub(super) fn flat_index_suffix(dims: &[u64], linear: usize) -> String {
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

/// Convert an AST Span to an OptSpan for error reporting.
pub(super) fn to_span(span: &Span) -> OptSpan {
    span_box(Some(SpanRange::from(span)))
}

/// Convert a TypeAnnotation to IrType.
/// Only circuit types (Field, Bool) are valid here — Int/String are VM-only
/// and surface as `TypeNotConstrainable` if a user writes them in a
/// circuit/prove context.
pub(super) fn annotation_to_ir_type(
    ann: &TypeAnnotation,
    span: &Span,
) -> Result<IrType, crate::error::ProveIrError> {
    match ann.base {
        BaseType::Field => Ok(IrType::Field),
        BaseType::Bool => Ok(IrType::Bool),
        BaseType::Int | BaseType::String => Err(crate::error::ProveIrError::TypeNotConstrainable {
            type_name: ann.base.to_string(),
            span: to_span(span),
        }),
    }
}
