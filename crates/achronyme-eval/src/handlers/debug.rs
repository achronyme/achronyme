use achronyme_parser::ast::AstNode;
use achronyme_types::value::Value;
use achronyme_types::function::Function;
use crate::evaluator::Evaluator;

/// Handle the describe() function - returns a detailed string description of a value
pub fn handle_describe(evaluator: &mut Evaluator, args: &[AstNode]) -> Result<Value, String> {
    if args.len() != 1 {
        return Err(format!("describe() expects 1 argument, got {}", args.len()));
    }

    let value = evaluator.evaluate(&args[0])?;
    let description = describe_value(&value, 0);

    Ok(Value::String(description))
}

fn describe_value(value: &Value, indent: usize) -> String {
    let indent_str = "  ".repeat(indent);

    match value {
        Value::Number(n) => format!("Number({})", n),
        Value::Boolean(b) => format!("Boolean({})", b),
        Value::String(s) => format!("String({:?})", s),
        Value::Complex(c) => format!("Complex(re: {}, im: {})", c.re, c.im),

        Value::Vector(vec) => {
            if vec.is_empty() {
                "Vector(empty)".to_string()
            } else {
                let items: Vec<String> = vec.iter()
                    .take(10)  // Limit to first 10 items
                    .map(|v| describe_value(v, 0))
                    .collect();

                let more = if vec.len() > 10 {
                    format!(" ... and {} more", vec.len() - 10)
                } else {
                    String::new()
                };

                format!("Vector(length: {}, items: [{}{}])", vec.len(), items.join(", "), more)
            }
        }

        Value::Tensor(tensor) => {
            format!("Tensor(shape: {:?}, elements: {})", tensor.shape(), tensor.data().len())
        }

        Value::ComplexTensor(tensor) => {
            format!("ComplexTensor(shape: {:?}, elements: {})", tensor.shape(), tensor.data().len())
        }

        Value::Function(func) => describe_function(func, indent),

        Value::Record(map) => {
            if map.is_empty() {
                "Record(empty)".to_string()
            } else {
                let mut fields: Vec<String> = Vec::new();
                for (key, val) in map.iter().take(10) {  // Limit to first 10 fields
                    let val_desc = describe_value(val, indent + 1);
                    fields.push(format!("\n{}  {}: {}", indent_str, key, val_desc));
                }

                let more = if map.len() > 10 {
                    format!("\n{}  ... and {} more fields", indent_str, map.len() - 10)
                } else {
                    String::new()
                };

                format!("Record(fields: {}{}{})", map.len(), fields.join(""), more)
            }
        }

        Value::Edge { from, to, directed, properties } => {
            let dir = if *directed { "directed" } else { "undirected" };
            if properties.is_empty() {
                format!("Edge({} -> {}, {})", from, to, dir)
            } else {
                format!("Edge({} -> {}, {}, properties: {})", from, to, dir, properties.len())
            }
        }

        Value::MutableRef(rc) => {
            let inner = rc.borrow();
            format!("MutableRef({})", describe_value(&inner, indent))
        }

        Value::TailCall(_) => {
            // TailCall should never be visible to user code - it's an internal marker
            "TailCall(internal marker - should not be visible)".to_string()
        }

        Value::EarlyReturn(_) => {
            // EarlyReturn should never be visible to user code - it's an internal marker
            "EarlyReturn(internal marker - should not be visible)".to_string()
        }

        Value::Null => "null".to_string(),

        Value::Generator(gen_rc) => {
            let state = gen_rc.borrow();
            format!("Generator(position: {}, done: {}, statements: {})",
                state.position, state.done, state.statements.len())
        }

        Value::GeneratorYield(inner) => {
            format!("GeneratorYield({})", describe_value(inner, indent))
        }

        Value::Error { message, kind, source } => {
            let kind_str = kind.as_deref().unwrap_or("Unknown");
            let source_str = match source {
                Some(src) => format!(" (source: {})", describe_value(src, indent + 1)),
                None => String::new(),
            };
            format!("Error({}: {}){}",  kind_str, message, source_str)
        }
    }
}

fn describe_function(func: &Function, indent: usize) -> String {
    let indent_str = "  ".repeat(indent);

    match func {
        Function::UserDefined { params, body, .. } => {
            let params_str = params.join(", ");
            let body_str = format_ast_node(body, indent + 1);

            // For closure environment, we just mention it's captured rather than
            // trying to iterate through all variables (which would require walking the chain)
            let captured_info = format!("\n{}  Closure: <environment>", indent_str);

            format!(
                "Function(UserDefined)\n{}  Parameters: ({})\n{}  Body: {}{}",
                indent_str, params_str, indent_str, body_str, captured_info
            )
        }
        Function::Builtin(name) => {
            format!("Function(Builtin: {})", name)
        }
    }
}

fn format_ast_node(node: &AstNode, indent: usize) -> String {
    let _indent_str = "  ".repeat(indent);

    match node {
        AstNode::Number(n) => format!("{}", n),
        AstNode::Boolean(b) => format!("{}", b),
        AstNode::StringLiteral(s) => format!("{:?}", s),
        AstNode::ComplexLiteral { re, im } => format!("{}+{}i", re, im),

        AstNode::VariableRef(name) => name.clone(),
        AstNode::SelfReference => "self".to_string(),
        AstNode::RecReference => "rec".to_string(),

        AstNode::BinaryOp { op, left, right } => {
            format!("({} {:?} {})",
                format_ast_node(left, indent),
                op,
                format_ast_node(right, indent))
        }

        AstNode::UnaryOp { op, operand } => {
            format!("{:?}({})", op, format_ast_node(operand, indent))
        }

        AstNode::If { condition, then_expr, else_expr } => {
            format!("if({}, {}, {})",
                format_ast_node(condition, indent),
                format_ast_node(then_expr, indent),
                format_ast_node(else_expr, indent))
        }

        AstNode::Lambda { params, body, .. } => {
            let params_str: String = params.iter()
                .map(|(name, type_ann)| {
                    match type_ann {
                        Some(ty) => format!("{}: {}", name, ty.to_string()),
                        None => name.clone(),
                    }
                })
                .collect::<Vec<String>>()
                .join(", ");
            format!("({}) => {}", params_str, format_ast_node(body, indent))
        }

        AstNode::FunctionCall { name, args } => {
            let args_str: Vec<String> = args.iter()
                .map(|arg| format_ast_node(arg, indent))
                .collect();
            format!("{}({})", name, args_str.join(", "))
        }

        AstNode::CallExpression { callee, args } => {
            let args_str: Vec<String> = args.iter()
                .map(|arg| format_ast_node(arg, indent))
                .collect();
            format!("{}({})", format_ast_node(callee, indent), args_str.join(", "))
        }

        AstNode::FieldAccess { record, field } => {
            format!("{}.{}", format_ast_node(record, indent), field)
        }

        AstNode::ArrayLiteral(elements) => {
            use achronyme_parser::ast::ArrayElement;

            if elements.len() > 3 {
                format!("[{} elements]", elements.len())
            } else {
                let items: Vec<String> = elements.iter()
                    .map(|e| match e {
                        ArrayElement::Single(node) => format_ast_node(node, indent),
                        ArrayElement::Spread(node) => format!("...{}", format_ast_node(node, indent)),
                    })
                    .collect();
                format!("[{}]", items.join(", "))
            }
        }

        AstNode::RecordLiteral(fields) => {
            use achronyme_parser::ast::RecordFieldOrSpread;

            if fields.len() > 3 {
                format!("{{ {} fields }}", fields.len())
            } else {
                let items: Vec<String> = fields.iter()
                    .map(|f| match f {
                        RecordFieldOrSpread::Field { name, value } => {
                            format!("{}: {}", name, format_ast_node(value, indent))
                        }
                        RecordFieldOrSpread::MutableField { name, value } => {
                            format!("mut {}: {}", name, format_ast_node(value, indent))
                        }
                        RecordFieldOrSpread::Spread(node) => {
                            format!("...{}", format_ast_node(node, indent))
                        }
                    })
                    .collect();
                format!("{{ {} }}", items.join(", "))
            }
        }

        _ => format!("<{:?}>", node),
    }
}
