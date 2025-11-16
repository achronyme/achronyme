/// Tail Call Optimization (TCO) Module
///
/// This module provides detection and optimization for tail-recursive function calls.
/// A tail call is a function call that is the last operation in a function body.
///
/// Examples:
/// - `if(n <= 1, 1, rec(n-1, acc*n))` - TAIL CALL (rec is last operation in branch)
/// - `n * rec(n-1)` - NOT A TAIL CALL (multiplication happens after rec returns)
///
/// TCO converts recursive calls into loops, eliminating stack frame creation
/// and allowing unlimited recursion depth for tail-recursive patterns.

use achronyme_parser::ast::{AstNode, ArrayElement, RecordFieldOrSpread, IndexArg, StringPart};

#[cfg(test)]
mod tests;

/// Check if an AST node is in tail position (can be a tail call)
///
/// A node is in tail position if its return value becomes the return value
/// of the function without any further computation.
///
/// # Arguments
/// * `node` - The AST node to check
///
/// # Returns
/// True if the node is in tail position
pub fn is_tail_position(node: &AstNode) -> bool {
    match node {
        // rec reference itself is in tail position
        AstNode::RecReference => true,

        // CallExpression with rec as callee is tail
        AstNode::CallExpression { callee, .. } => {
            matches!(**callee, AstNode::RecReference)
        }

        // If-expression: both branches must be in tail position
        AstNode::If { then_expr, else_expr, .. } => {
            is_tail_position(then_expr) && is_tail_position(else_expr)
        }

        // While loop: body is NOT in tail position (loop returns to top)
        AstNode::WhileLoop { .. } => false,

        // Piecewise: all result branches must be in tail position
        AstNode::Piecewise { cases, default } => {
            cases.iter().all(|(_, result)| is_tail_position(result))
                && default.as_ref().map(|d| is_tail_position(d)).unwrap_or(true)
        }

        // Do block: last statement must be in tail position
        AstNode::DoBlock { statements } => {
            statements.last().map(is_tail_position).unwrap_or(false)
        }

        // Sequence: last statement must be in tail position
        AstNode::Sequence { statements } => {
            statements.last().map(is_tail_position).unwrap_or(false)
        }

        // Binary/unary operations are NOT tail positions
        // (computation happens after the operands are evaluated)
        AstNode::BinaryOp { .. } => false,
        AstNode::UnaryOp { .. } => false,

        // Array/record construction is NOT tail position
        AstNode::ArrayLiteral(_) => false,
        AstNode::RecordLiteral(_) => false,

        // Indexing is NOT tail position
        AstNode::IndexAccess { .. } => false,

        // Field access is NOT tail position
        AstNode::FieldAccess { .. } => false,

        // Function/method calls (non-rec) are NOT tail if they contain rec in args
        AstNode::FunctionCall { .. } => false,

        // Literals are in tail position but not recursive
        AstNode::Number(_)
        | AstNode::Boolean(_)
        | AstNode::StringLiteral(_)
        | AstNode::ComplexLiteral { .. } => true,

        // Variable references are in tail position
        AstNode::VariableRef(_) => true,
        AstNode::SelfReference => true,

        // Lambda is in tail position
        AstNode::Lambda { .. } => true,

        // Edge is in tail position
        AstNode::Edge { .. } => true,

        // Variable declaration is NOT tail position (it's a statement)
        AstNode::VariableDecl { .. } => false,

        // Mutable declarations and assignments are NOT tail position
        AstNode::MutableDecl { .. } => false,
        AstNode::Assignment { .. } => false,
        AstNode::CompoundAssignment { .. } => false,

        // Destructuring declarations are NOT tail position (they're statements)
        AstNode::LetDestructuring { .. } => false,
        AstNode::MutableDestructuring { .. } => false,

        // Return statement: the value expression is in tail position
        AstNode::Return { value } => is_tail_position(value),

        // Import/Export are NOT tail positions (they're module declarations)
        AstNode::Import { .. } => false,
        AstNode::Export { .. } => false,

        // Null literal is in tail position
        AstNode::Null => true,

        // Type alias is NOT tail position (it's a type declaration)
        AstNode::TypeAlias { .. } => false,

        // Generator-related nodes are NOT tail positions
        // Yield suspends execution, it's not a regular tail call
        AstNode::Yield { .. } => false,
        // Generate block creates a generator, not tail recursive
        AstNode::GenerateBlock { .. } => false,
        // For-in loops are NOT tail position
        AstNode::ForInLoop { .. } => false,
        // Throw is NOT tail position (it throws an error)
        AstNode::Throw { .. } => false,
        // TryCatch: catch block could be tail position, but for simplicity mark as false
        AstNode::TryCatch { .. } => false,
        // Match: each arm body could be in tail position
        AstNode::Match { arms, .. } => {
            arms.iter().all(|arm| is_tail_position(&arm.body))
        }

        // Break and Continue are NOT tail positions (they're control flow statements)
        AstNode::Break { .. } => false,
        AstNode::Continue => false,

        // Interpolated string is in tail position (produces a value directly)
        AstNode::InterpolatedString { .. } => true,
    }
}

/// Check if the entire function body is tail-recursive
///
/// This determines if we can apply TCO to the entire function.
/// Returns true if all recursive calls are in tail position.
///
/// # Arguments
/// * `body` - The function body AST node
///
/// # Returns
/// True if the function can benefit from TCO
pub fn is_tail_recursive_function(body: &AstNode) -> bool {
    // Check if body contains rec and all rec calls are in tail position
    contains_rec(body) && all_rec_are_tail(body)
}

/// Check if an AST contains any 'rec' references
fn contains_rec(node: &AstNode) -> bool {
    match node {
        AstNode::RecReference => true,

        AstNode::FunctionCall { args, .. } => {
            args.iter().any(contains_rec)
        }

        AstNode::CallExpression { callee, args } => {
            // Check if callee is rec or if rec is in arguments
            matches!(**callee, AstNode::RecReference)
                || contains_rec(callee)
                || args.iter().any(contains_rec)
        }

        AstNode::BinaryOp { left, right, .. } => {
            contains_rec(left) || contains_rec(right)
        }

        AstNode::UnaryOp { operand, .. } => contains_rec(operand),

        AstNode::If { condition, then_expr, else_expr } => {
            contains_rec(condition) || contains_rec(then_expr) || contains_rec(else_expr)
        }

        AstNode::WhileLoop { condition, body } => {
            contains_rec(condition) || contains_rec(body)
        }

        AstNode::Piecewise { cases, default } => {
            cases.iter().any(|(cond, result)| contains_rec(cond) || contains_rec(result))
                || default.as_ref().map(|d| contains_rec(d)).unwrap_or(false)
        }

        AstNode::DoBlock { statements } | AstNode::Sequence { statements } => {
            statements.iter().any(contains_rec)
        }

        AstNode::ArrayLiteral(elements) => {
            elements.iter().any(|elem| match elem {
                ArrayElement::Single(node) => contains_rec(node),
                ArrayElement::Spread(node) => contains_rec(node),
            })
        }

        AstNode::RecordLiteral(fields) => {
            fields.iter().any(|field| match field {
                RecordFieldOrSpread::Field { value, .. } => contains_rec(value),
                RecordFieldOrSpread::MutableField { value, .. } => contains_rec(value),
                RecordFieldOrSpread::Spread(node) => contains_rec(node),
            })
        }

        AstNode::Lambda { .. } => {
            // Don't recurse into nested lambdas (they have their own rec)
            false
        }

        AstNode::IndexAccess { object, indices } => {
            contains_rec(object)
                || indices.iter().any(|idx| match idx {
                    IndexArg::Single(node) => contains_rec(node),
                    IndexArg::Range { start, end } => {
                        start.as_ref().map(|n| contains_rec(n)).unwrap_or(false)
                            || end.as_ref().map(|n| contains_rec(n)).unwrap_or(false)
                    }
                })
        }

        AstNode::FieldAccess { record, .. } => contains_rec(record),

        AstNode::VariableDecl { initializer, .. } => contains_rec(initializer),

        AstNode::MutableDecl { initializer, .. } => contains_rec(initializer.as_ref()),

        AstNode::Assignment { value, .. } => contains_rec(value),

        AstNode::CompoundAssignment { target, value, .. } => contains_rec(target) || contains_rec(value),

        AstNode::LetDestructuring { initializer, .. } => contains_rec(initializer.as_ref()),

        AstNode::MutableDestructuring { initializer, .. } => contains_rec(initializer.as_ref()),

        AstNode::Edge { metadata, .. } => {
            metadata.as_ref().map(|m| contains_rec(m)).unwrap_or(false)
        }

        AstNode::Match { value, arms } => {
            contains_rec(value) || arms.iter().any(|arm| {
                arm.guard.as_ref().map(|g| contains_rec(g)).unwrap_or(false)
                    || contains_rec(&arm.body)
            })
        }

        AstNode::InterpolatedString { parts } => {
            parts.iter().any(|part| match part {
                StringPart::Literal(_) => false,
                StringPart::Expression(expr) => contains_rec(expr),
            })
        }

        _ => false,
    }
}

/// Check if all 'rec' calls in the AST are in tail position
fn all_rec_are_tail(node: &AstNode) -> bool {
    all_rec_are_tail_helper(node, true)
}

/// Helper function that tracks whether we're in tail position
fn all_rec_are_tail_helper(node: &AstNode, in_tail_position: bool) -> bool {
    match node {
        // If we find rec, check if we're in tail position
        AstNode::RecReference => in_tail_position,

        // CallExpression with rec as callee
        AstNode::CallExpression { callee, args } => {
            if matches!(**callee, AstNode::RecReference) {
                // This is a rec call - must be in tail position
                if !in_tail_position {
                    return false;
                }
                // If we're in tail position, check that args don't contain rec
                // (they should be evaluated before the tail call)
                return args.iter().all(|arg| all_rec_are_tail_helper(arg, false));
            }

            // Not a rec call, check callee and arguments (NOT in tail position)
            all_rec_are_tail_helper(callee, false)
                && args.iter().all(|arg| all_rec_are_tail_helper(arg, false))
        }

        // Function call: arguments are NOT in tail position
        AstNode::FunctionCall { args, .. } => {
            args.iter().all(|arg| all_rec_are_tail_helper(arg, false))
        }

        // Binary/unary ops: children are NOT in tail position
        AstNode::BinaryOp { left, right, .. } => {
            all_rec_are_tail_helper(left, false) && all_rec_are_tail_helper(right, false)
        }

        AstNode::UnaryOp { operand, .. } => {
            all_rec_are_tail_helper(operand, false)
        }

        // If-expression: branches inherit tail position, condition doesn't
        AstNode::If { condition, then_expr, else_expr } => {
            all_rec_are_tail_helper(condition, false)
                && all_rec_are_tail_helper(then_expr, in_tail_position)
                && all_rec_are_tail_helper(else_expr, in_tail_position)
        }

        // While loop: neither condition nor body are in tail position
        // (the body loops back, so it's never the last operation)
        AstNode::WhileLoop { condition, body } => {
            all_rec_are_tail_helper(condition, false)
                && all_rec_are_tail_helper(body, false)
        }

        // Piecewise: result branches inherit tail position, conditions don't
        AstNode::Piecewise { cases, default } => {
            for (cond, result) in cases {
                if !all_rec_are_tail_helper(cond, false) {
                    return false;
                }
                if !all_rec_are_tail_helper(result, in_tail_position) {
                    return false;
                }
            }
            default
                .as_ref()
                .map(|d| all_rec_are_tail_helper(d, in_tail_position))
                .unwrap_or(true)
        }

        // Do block/Sequence: last statement inherits tail position, others don't
        AstNode::DoBlock { statements } | AstNode::Sequence { statements } => {
            for (i, stmt) in statements.iter().enumerate() {
                let stmt_in_tail = if i == statements.len() - 1 {
                    in_tail_position
                } else {
                    false
                };
                if !all_rec_are_tail_helper(stmt, stmt_in_tail) {
                    return false;
                }
            }
            true
        }

        // Array literals: elements are NOT in tail position
        AstNode::ArrayLiteral(elements) => {
            elements.iter().all(|elem| match elem {
                ArrayElement::Single(node) => all_rec_are_tail_helper(node, false),
                ArrayElement::Spread(node) => all_rec_are_tail_helper(node, false),
            })
        }

        // Record literals: values are NOT in tail position
        AstNode::RecordLiteral(fields) => {
            fields.iter().all(|field| match field {
                RecordFieldOrSpread::Field { value, .. } => all_rec_are_tail_helper(value, false),
                RecordFieldOrSpread::MutableField { value, .. } => all_rec_are_tail_helper(value, false),
                RecordFieldOrSpread::Spread(node) => all_rec_are_tail_helper(node, false),
            })
        }

        // Lambda: don't recurse (separate scope)
        AstNode::Lambda { .. } => true,

        // Indexing: children are NOT in tail position
        AstNode::IndexAccess { object, indices } => {
            all_rec_are_tail_helper(object, false)
                && indices.iter().all(|idx| match idx {
                    IndexArg::Single(node) => all_rec_are_tail_helper(node, false),
                    IndexArg::Range { start, end } => {
                        start.as_ref().map(|n| all_rec_are_tail_helper(n, false)).unwrap_or(true)
                            && end.as_ref().map(|n| all_rec_are_tail_helper(n, false)).unwrap_or(true)
                    }
                })
        }

        // Field access: record is NOT in tail position
        AstNode::FieldAccess { record, .. } => {
            all_rec_are_tail_helper(record, false)
        }

        // Variable declaration: initializer is NOT in tail position
        AstNode::VariableDecl { initializer, .. } => {
            all_rec_are_tail_helper(initializer, false)
        }

        // Mutable declaration: initializer is NOT in tail position
        AstNode::MutableDecl { initializer, .. } => {
            all_rec_are_tail_helper(initializer.as_ref(), false)
        }

        // Destructuring declarations: initializer is NOT in tail position
        AstNode::LetDestructuring { initializer, .. } => {
            all_rec_are_tail_helper(initializer.as_ref(), false)
        }

        AstNode::MutableDestructuring { initializer, .. } => {
            all_rec_are_tail_helper(initializer.as_ref(), false)
        }

        // Assignment: value is NOT in tail position
        AstNode::Assignment { value, .. } => {
            all_rec_are_tail_helper(value, false)
        }

        // Compound assignment: target and value are NOT in tail position
        AstNode::CompoundAssignment { target, value, .. } => {
            all_rec_are_tail_helper(target, false) && all_rec_are_tail_helper(value, false)
        }

        // Edge: metadata is NOT in tail position
        AstNode::Edge { metadata, .. } => {
            metadata.as_ref().map(|m| all_rec_are_tail_helper(m, false)).unwrap_or(true)
        }

        // Match: value is NOT in tail position, guard is NOT, but body inherits
        AstNode::Match { value, arms } => {
            all_rec_are_tail_helper(value, false)
                && arms.iter().all(|arm| {
                    let guard_ok = arm.guard.as_ref()
                        .map(|g| all_rec_are_tail_helper(g, false))
                        .unwrap_or(true);
                    guard_ok && all_rec_are_tail_helper(&arm.body, in_tail_position)
                })
        }

        // Interpolated string: expressions are NOT in tail position (they're evaluated first)
        AstNode::InterpolatedString { parts } => {
            parts.iter().all(|part| match part {
                StringPart::Literal(_) => true,
                StringPart::Expression(expr) => all_rec_are_tail_helper(expr, false),
            })
        }

        // Literals and references don't contain rec
        _ => true,
    }
}
