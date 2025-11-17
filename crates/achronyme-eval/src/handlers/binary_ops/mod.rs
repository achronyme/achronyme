use achronyme_parser::ast::BinaryOp;
use achronyme_types::value::Value;

mod utils;
mod arithmetic;
mod comparison;
mod logical;

use arithmetic::{
    apply_add, apply_subtract, apply_multiply, apply_divide, apply_power, apply_modulo
};
use comparison::{apply_gt, apply_lt, apply_gte, apply_lte, apply_eq, apply_neq};
use logical::{apply_and, apply_or};

// Re-export is_truthy for use in short-circuit evaluation
pub use logical::is_truthy;

/// Apply a binary operation to two values
pub fn apply(op: &BinaryOp, left: Value, right: Value) -> Result<Value, String> {
    match op {
        BinaryOp::Add => apply_add(left, right),
        BinaryOp::Subtract => apply_subtract(left, right),
        BinaryOp::Multiply => apply_multiply(left, right),
        BinaryOp::Divide => apply_divide(left, right),
        BinaryOp::Power => apply_power(left, right),
        BinaryOp::Modulo => apply_modulo(left, right),
        BinaryOp::Gt => apply_gt(left, right),
        BinaryOp::Lt => apply_lt(left, right),
        BinaryOp::Gte => apply_gte(left, right),
        BinaryOp::Lte => apply_lte(left, right),
        BinaryOp::Eq => apply_eq(left, right),
        BinaryOp::Neq => apply_neq(left, right),
        BinaryOp::And => apply_and(left, right),
        BinaryOp::Or => apply_or(left, right),
    }
}
