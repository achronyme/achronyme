use tower_lsp::lsp_types::*;

use crate::document::Document;

/// Get hover information for a position in the document
pub fn get_hover(doc: &Document, position: Position) -> Option<Hover> {
    let word = doc.word_at_position(position.line, position.character)?;

    // Check if it's a builtin function
    if let Some(info) = get_builtin_info(&word) {
        return Some(Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: info,
            }),
            range: None,
        });
    }

    // Check if it's a keyword
    if let Some(info) = get_keyword_info(&word) {
        return Some(Hover {
            contents: HoverContents::Markup(MarkupContent {
                kind: MarkupKind::Markdown,
                value: info,
            }),
            range: None,
        });
    }

    // Check if it's a variable in the AST
    if let Some(ast) = doc.ast() {
        if let Some(info) = find_variable_info(ast, &word) {
            return Some(Hover {
                contents: HoverContents::Markup(MarkupContent {
                    kind: MarkupKind::Markdown,
                    value: info,
                }),
                range: None,
            });
        }
    }

    None
}

/// Get information about builtin functions
fn get_builtin_info(name: &str) -> Option<String> {
    match name {
        // Math functions
        "sin" => Some("```achronyme\nsin(x: Number) -> Number\n```\nReturns the sine of x (x in radians)".to_string()),
        "cos" => Some("```achronyme\ncos(x: Number) -> Number\n```\nReturns the cosine of x (x in radians)".to_string()),
        "tan" => Some("```achronyme\ntan(x: Number) -> Number\n```\nReturns the tangent of x (x in radians)".to_string()),
        "asin" => Some("```achronyme\nasin(x: Number) -> Number\n```\nReturns the arc sine of x".to_string()),
        "acos" => Some("```achronyme\nacos(x: Number) -> Number\n```\nReturns the arc cosine of x".to_string()),
        "atan" => Some("```achronyme\natan(x: Number) -> Number\n```\nReturns the arc tangent of x".to_string()),
        "atan2" => Some("```achronyme\natan2(y: Number, x: Number) -> Number\n```\nReturns the arc tangent of y/x".to_string()),
        "sinh" => Some("```achronyme\nsinh(x: Number) -> Number\n```\nReturns the hyperbolic sine of x".to_string()),
        "cosh" => Some("```achronyme\ncosh(x: Number) -> Number\n```\nReturns the hyperbolic cosine of x".to_string()),
        "tanh" => Some("```achronyme\ntanh(x: Number) -> Number\n```\nReturns the hyperbolic tangent of x".to_string()),
        "sqrt" => Some("```achronyme\nsqrt(x: Number) -> Number\n```\nReturns the square root of x".to_string()),
        "cbrt" => Some("```achronyme\ncbrt(x: Number) -> Number\n```\nReturns the cube root of x".to_string()),
        "exp" => Some("```achronyme\nexp(x: Number) -> Number\n```\nReturns e raised to the power x".to_string()),
        "ln" => Some("```achronyme\nln(x: Number) -> Number\n```\nReturns the natural logarithm of x".to_string()),
        "log" => Some("```achronyme\nlog(x: Number, base: Number) -> Number\n```\nReturns the logarithm of x with given base".to_string()),
        "log10" => Some("```achronyme\nlog10(x: Number) -> Number\n```\nReturns the base-10 logarithm of x".to_string()),
        "log2" => Some("```achronyme\nlog2(x: Number) -> Number\n```\nReturns the base-2 logarithm of x".to_string()),
        "abs" => Some("```achronyme\nabs(x: Number) -> Number\n```\nReturns the absolute value of x".to_string()),
        "floor" => Some("```achronyme\nfloor(x: Number) -> Number\n```\nReturns the largest integer less than or equal to x".to_string()),
        "ceil" => Some("```achronyme\nceil(x: Number) -> Number\n```\nReturns the smallest integer greater than or equal to x".to_string()),
        "round" => Some("```achronyme\nround(x: Number) -> Number\n```\nRounds x to the nearest integer".to_string()),
        "min" => Some("```achronyme\nmin(a: Number, b: Number) -> Number\n```\nReturns the minimum of two numbers".to_string()),
        "max" => Some("```achronyme\nmax(a: Number, b: Number) -> Number\n```\nReturns the maximum of two numbers".to_string()),

        // Array functions
        "len" => Some("```achronyme\nlen(arr: Array) -> Number\n```\nReturns the length of an array".to_string()),
        "push" => Some("```achronyme\npush(arr: Array, value: Any) -> Array\n```\nReturns a new array with value appended".to_string()),
        "pop" => Some("```achronyme\npop(arr: Array) -> Array\n```\nReturns a new array with the last element removed".to_string()),
        "head" => Some("```achronyme\nhead(arr: Array) -> Any\n```\nReturns the first element of the array".to_string()),
        "tail" => Some("```achronyme\ntail(arr: Array) -> Array\n```\nReturns all elements except the first".to_string()),
        "map" => Some("```achronyme\nmap(arr: Array, fn: Function) -> Array\n```\nApplies function to each element".to_string()),
        "filter" => Some("```achronyme\nfilter(arr: Array, predicate: Function) -> Array\n```\nFilters array by predicate".to_string()),
        "reduce" => Some("```achronyme\nreduce(arr: Array, initial: Any, fn: Function) -> Any\n```\nReduces array to single value".to_string()),
        "range" => Some("```achronyme\nrange(start: Number, end: Number) -> Array\n```\nCreates an array of numbers from start to end (exclusive)".to_string()),

        // Type functions
        "type" => Some("```achronyme\ntype(value: Any) -> String\n```\nReturns the type of the value as a string".to_string()),

        // I/O functions
        "print" => Some("```achronyme\nprint(value: Any) -> Null\n```\nPrints value to stdout".to_string()),

        _ => None,
    }
}

/// Get information about keywords
fn get_keyword_info(word: &str) -> Option<String> {
    match word {
        "let" => Some("**let** - Declare an immutable variable\n\n```achronyme\nlet name = value\nlet name: Type = value\n```".to_string()),
        "mut" => Some("**mut** - Declare a mutable variable\n\n```achronyme\nmut counter = 0\nmut counter: Number = 0\n```".to_string()),
        "if" => Some("**if** - Conditional expression\n\n```achronyme\nif condition { then_expr } else { else_expr }\n```".to_string()),
        "else" => Some("**else** - Alternative branch in conditional".to_string()),
        "while" => Some("**while** - Loop while condition is true\n\n```achronyme\nwhile(condition) { body }\n```".to_string()),
        "for" => Some("**for** - Iterate over a collection\n\n```achronyme\nfor(item in iterable) { body }\n```".to_string()),
        "in" => Some("**in** - Used in for loops to iterate".to_string()),
        "match" => Some("**match** - Pattern matching expression\n\n```achronyme\nmatch value {\n  pattern => result,\n  _ => default\n}\n```".to_string()),
        "return" => Some("**return** - Early return from function\n\n```achronyme\nreturn value\n```".to_string()),
        "do" => Some("**do** - Block expression\n\n```achronyme\ndo {\n  statement1;\n  statement2;\n  result\n}\n```".to_string()),
        "type" => Some("**type** - Define a type alias\n\n```achronyme\ntype Name = TypeAnnotation\n```".to_string()),
        "import" => Some("**import** - Import from module\n\n```achronyme\nimport { item1, item2 } from \"module\"\n```".to_string()),
        "from" => Some("**from** - Source module for import".to_string()),
        "export" => Some("**export** - Export items from module\n\n```achronyme\nexport { item1, item2 }\n```".to_string()),
        "try" => Some("**try** - Error handling block\n\n```achronyme\ntry { risky_code } catch(error) { handle_error }\n```".to_string()),
        "catch" => Some("**catch** - Handle errors from try block".to_string()),
        "throw" => Some("**throw** - Throw an error\n\n```achronyme\nthrow \"error message\"\n```".to_string()),
        "true" => Some("**true** - Boolean literal true".to_string()),
        "false" => Some("**false** - Boolean literal false".to_string()),
        "null" => Some("**null** - Null value (absence of value)".to_string()),
        "self" => Some("**self** - Reference to current record in record methods".to_string()),
        "rec" => Some("**rec** - Recursive function reference".to_string()),
        _ => None,
    }
}

/// Find information about a variable in the AST
fn find_variable_info(ast: &[achronyme_parser::ast::AstNode], name: &str) -> Option<String> {
    use achronyme_parser::ast::AstNode;

    for node in ast {
        match node {
            AstNode::VariableDecl {
                name: var_name,
                type_annotation,
                ..
            } if var_name == name => {
                let type_str = type_annotation
                    .as_ref()
                    .map(|t| format!("{:?}", t))
                    .unwrap_or_else(|| "inferred".to_string());
                return Some(format!("**Variable** `{}`\n\nType: {}", name, type_str));
            }
            AstNode::MutableDecl {
                name: var_name,
                type_annotation,
                ..
            } if var_name == name => {
                let type_str = type_annotation
                    .as_ref()
                    .map(|t| format!("{:?}", t))
                    .unwrap_or_else(|| "inferred".to_string());
                return Some(format!(
                    "**Mutable Variable** `{}`\n\nType: {}",
                    name, type_str
                ));
            }
            AstNode::Sequence { statements } => {
                if let Some(info) = find_variable_info(statements, name) {
                    return Some(info);
                }
            }
            AstNode::DoBlock { statements } => {
                if let Some(info) = find_variable_info(statements, name) {
                    return Some(info);
                }
            }
            _ => {}
        }
    }
    None
}
