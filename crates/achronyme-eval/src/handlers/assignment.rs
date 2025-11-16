use achronyme_parser::ast::{AstNode, CompoundOp, BinaryOp};
use achronyme_types::value::Value;

use crate::evaluator::Evaluator;
use crate::type_checker;
use crate::handlers::binary_ops;

/// Evaluate an assignment statement
///
/// Supports:
/// - Simple variable assignment: `x = 20`
/// - Field assignment: `config.valor = 30`
/// - Nested field assignment: `app.config.debug = true`
/// - Array index assignment: `arr[0] = 100`
///
/// # Semantic Validation
/// - Target must be a valid lvalue (variable, field access, or index access)
/// - Cannot assign to literals, function calls, or arbitrary expressions
/// - Variables must be declared with `mut` to be assignable
/// - Type annotations are enforced on assignment (if variable was declared with a type)
pub fn evaluate_assignment(
    evaluator: &mut Evaluator,
    target: &AstNode,
    value_node: &AstNode,
) -> Result<Value, String> {
    // Evaluate the new value first
    let new_value = evaluator.evaluate(value_node)?;

    // Dispatch based on target type
    match target {
        // Simple variable: x = 20
        AstNode::VariableRef(name) => {
            // Check type annotation before assignment (if one exists)
            if let Some(expected_type) = evaluator.environment().get_type_annotation(name) {
                type_checker::check_type(&new_value, &expected_type).map_err(|_| {
                    format!(
                        "Type error: cannot assign {} to variable '{}' of type {}",
                        type_checker::infer_type(&new_value).to_string(),
                        name,
                        expected_type.to_string()
                    )
                })?;
            }

            evaluator.environment_mut().assign(name, new_value.clone())?;
            Ok(new_value)
        }

        // Field access: config.valor = 30
        AstNode::FieldAccess { record, field } => {
            assign_to_field(evaluator, record, field, new_value)
        }

        // Index access: arr[0] = 100
        AstNode::IndexAccess { object, indices } => {
            assign_to_index(evaluator, object, indices, new_value)
        }

        // Invalid assignment targets
        AstNode::Number(_) => {
            Err("Cannot assign to numeric literal".to_string())
        }
        AstNode::Boolean(_) => {
            Err("Cannot assign to boolean literal".to_string())
        }
        AstNode::StringLiteral(_) => {
            Err("Cannot assign to string literal".to_string())
        }
        AstNode::ArrayLiteral(_) => {
            Err("Cannot assign to array literal".to_string())
        }
        AstNode::RecordLiteral(_) => {
            Err("Cannot assign to record literal".to_string())
        }
        AstNode::Lambda { .. } => {
            Err("Cannot assign to lambda expression".to_string())
        }
        AstNode::CallExpression { .. } | AstNode::FunctionCall { .. } => {
            Err("Cannot assign to function call result".to_string())
        }
        AstNode::BinaryOp { .. } | AstNode::UnaryOp { .. } => {
            Err("Cannot assign to expression".to_string())
        }

        _ => Err(format!("Invalid assignment target: {:?}", target)),
    }
}

/// Assign to a record field: config.valor = 30
fn assign_to_field(
    evaluator: &mut Evaluator,
    record_node: &AstNode,
    field: &str,
    new_value: Value,
) -> Result<Value, String> {
    // Evaluate the record expression to get the record
    let record_value = evaluator.evaluate(record_node)?;

    // Perform field assignment
    assign_record_field(&record_value, field, new_value)
}

/// Internal: Assign to a field within a record value
fn assign_record_field(record: &Value, field: &str, value: Value) -> Result<Value, String> {
    match record {
        Value::Record(map) => {
            // Get the field value
            let field_value = map
                .get(field)
                .ok_or_else(|| format!("Field '{}' not found in record", field))?;

            // Try to assign (will fail if field is immutable)
            field_value.assign(value.clone())?;

            Ok(value)
        }
        _ => Err(format!(
            "Cannot access field '{}' on non-record value",
            field
        )),
    }
}

/// Assign to an array/tensor index: arr[0] = 100
fn assign_to_index(
    _evaluator: &mut Evaluator,
    _object_node: &AstNode,
    _indices: &[achronyme_parser::ast::IndexArg],
    _new_value: Value,
) -> Result<Value, String> {
    // For now, we don't support index assignment because:
    // 1. Tensors are immutable in the current architecture
    // 2. Vectors are immutable lists
    // 3. Would require complex mutation tracking

    // This could be implemented in the future by:
    // - Making Tensor/Vector use Rc<RefCell<>> internally
    // - Or only allowing assignment to mutable arrays declared with mut

    Err("Index assignment (arr[i] = value) is not yet supported. Use array reconstruction instead: arr = [...arr.slice(0, i), new_value, ...arr.slice(i+1)]".to_string())
}

/// Evaluate a compound assignment statement (+=, -=, *=, /=, %=, ^=)
///
/// Compound assignment is syntactic sugar:
/// - `x += expr` is equivalent to `x = x + expr`
/// - `x -= expr` is equivalent to `x = x - expr`
/// - etc.
///
/// # Semantic Validation
/// - Target must be a valid lvalue (variable, field access, or index access)
/// - Variables must be declared with `mut` to be assignable
/// - Type annotations are enforced on assignment (if variable was declared with a type)
pub fn evaluate_compound_assignment(
    evaluator: &mut Evaluator,
    target: &AstNode,
    operator: &CompoundOp,
    value_node: &AstNode,
) -> Result<Value, String> {
    // 1. Evaluate the current value of the target
    let current_value = evaluator.evaluate(target)?;

    // 2. Evaluate the right-hand side expression
    let rhs_value = evaluator.evaluate(value_node)?;

    // 3. Apply the corresponding binary operation
    let binary_op = match operator {
        CompoundOp::AddAssign => BinaryOp::Add,
        CompoundOp::SubAssign => BinaryOp::Subtract,
        CompoundOp::MulAssign => BinaryOp::Multiply,
        CompoundOp::DivAssign => BinaryOp::Divide,
        CompoundOp::ModAssign => BinaryOp::Modulo,
        CompoundOp::PowAssign => BinaryOp::Power,
    };

    let new_value = binary_ops::apply(&binary_op, current_value, rhs_value)?;

    // 4. Assign the new value to the target (reuse existing assignment logic)
    // Dispatch based on target type
    match target {
        // Simple variable: x += 5
        AstNode::VariableRef(name) => {
            // Check type annotation before assignment (if one exists)
            if let Some(expected_type) = evaluator.environment().get_type_annotation(name) {
                type_checker::check_type(&new_value, &expected_type).map_err(|_| {
                    format!(
                        "Type error: cannot assign {} to variable '{}' of type {}",
                        type_checker::infer_type(&new_value).to_string(),
                        name,
                        expected_type.to_string()
                    )
                })?;
            }

            evaluator.environment_mut().assign(name, new_value.clone())?;
            Ok(new_value)
        }

        // Field access: obj.field += 5
        AstNode::FieldAccess { record, field } => {
            assign_to_field(evaluator, record, field, new_value)
        }

        // Index access: arr[0] += 5
        AstNode::IndexAccess { object, indices } => {
            assign_to_index(evaluator, object, indices, new_value)
        }

        // Invalid compound assignment targets
        _ => Err(format!("Invalid compound assignment target: {:?}", target)),
    }
}
