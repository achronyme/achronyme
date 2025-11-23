use crate::ast::{AstNode, StringPart};
use crate::parser::AstParser;
use crate::pest_parser::Rule;
use pest::iterators::Pair;

impl AstParser {
    pub(super) fn build_primary(&mut self, pair: Pair<Rule>) -> Result<AstNode, String> {
        let inner = pair.into_inner().next().ok_or("Empty primary expression")?;

        match inner.as_rule() {
            Rule::boolean => {
                let value = inner.as_str() == "true";
                Ok(AstNode::Boolean(value))
            }
            Rule::string_literal => {
                // Parse string literal: "hello" -> hello
                let s = inner.as_str();
                // Remove surrounding quotes
                let content = &s[1..s.len() - 1];
                // Process escape sequences
                let processed = self.process_escape_sequences(content);
                Ok(AstNode::StringLiteral(processed))
            }
            Rule::interpolated_string => self.build_interpolated_string(inner),
            Rule::number => {
                let num = inner
                    .as_str()
                    .parse::<f64>()
                    .map_err(|e| format!("Failed to parse number: {}", e))?;
                Ok(AstNode::Number(num))
            }
            Rule::complex => {
                // Complex number: "3i" or "-2i"
                let s = inner.as_str();
                let num_part = &s[..s.len() - 1]; // Remove 'i'
                let im = num_part
                    .parse::<f64>()
                    .map_err(|e| format!("Failed to parse complex number: {}", e))?;
                Ok(AstNode::ComplexLiteral { re: 0.0, im })
            }
            Rule::identifier => Ok(AstNode::VariableRef(inner.as_str().to_string())),
            Rule::self_ref => Ok(AstNode::SelfReference),
            Rule::rec_ref => Ok(AstNode::RecReference),
            Rule::null_literal => Ok(AstNode::Null),
            Rule::infinity_literal => {
                // IEEE 754 Infinity literal
                Ok(AstNode::Number(f64::INFINITY))
            }
            Rule::nan_literal_value => {
                // IEEE 754 NaN literal
                Ok(AstNode::Number(f64::NAN))
            }
            Rule::array => self.build_array(inner),
            Rule::vector => self.build_array(inner), // Alias for array
            Rule::matrix => self.build_array(inner), // Alias for array
            Rule::record => self.build_record(inner),
            Rule::control_flow_expr => self.build_control_flow_expr(inner),
            Rule::do_block => self.build_do_block(inner),
            Rule::generate_block => self.build_generate_block(inner),
            Rule::lambda => self.build_lambda(inner),

            Rule::expr => self.build_ast_from_expr(inner),
            _ => Err(format!("Unexpected primary rule: {:?}", inner.as_rule())),
        }
    }

    /// Build an interpolated string AST node from parsed parts
    pub(super) fn build_interpolated_string(
        &mut self,
        pair: Pair<Rule>,
    ) -> Result<AstNode, String> {
        let mut parts = Vec::new();

        // Structure: interpolated_string = { "'" ~ interpolated_string_part* ~ "'" }
        for part in pair.into_inner() {
            match part.as_rule() {
                Rule::interpolated_string_part => {
                    let inner = part
                        .into_inner()
                        .next()
                        .ok_or("Empty interpolated string part")?;

                    match inner.as_rule() {
                        Rule::interpolation_expr => {
                            // ${expr} - parse the expression
                            let expr_pair = inner
                                .into_inner()
                                .next()
                                .ok_or("Empty interpolation expression")?;
                            let expr_ast = self.build_ast_from_expr(expr_pair)?;
                            parts.push(StringPart::Expression(Box::new(expr_ast)));
                        }
                        Rule::interpolated_text => {
                            // Plain text - process escape sequences
                            let text = inner.as_str();
                            let processed = self.process_interpolated_escapes(text);
                            parts.push(StringPart::Literal(processed));
                        }
                        _ => {
                            return Err(format!(
                                "Unexpected interpolated string part rule: {:?}",
                                inner.as_rule()
                            ))
                        }
                    }
                }
                _ => {
                    return Err(format!(
                        "Unexpected rule in interpolated string: {:?}",
                        part.as_rule()
                    ))
                }
            }
        }

        Ok(AstNode::InterpolatedString { parts })
    }

    /// Process escape sequences specific to interpolated strings
    /// Handles: \$, \', \\, \n, \t, \r
    pub(super) fn process_interpolated_escapes(&mut self, s: &str) -> String {
        let mut result = String::new();
        let mut chars = s.chars().peekable();

        while let Some(ch) = chars.next() {
            if ch == '\\' {
                if let Some(&next_ch) = chars.peek() {
                    match next_ch {
                        '$' => {
                            result.push('$');
                            chars.next();
                        }
                        '\'' => {
                            result.push('\'');
                            chars.next();
                        }
                        '\\' => {
                            result.push('\\');
                            chars.next();
                        }
                        'n' => {
                            result.push('\n');
                            chars.next();
                        }
                        't' => {
                            result.push('\t');
                            chars.next();
                        }
                        'r' => {
                            result.push('\r');
                            chars.next();
                        }
                        _ => {
                            // Unknown escape sequence, keep as is
                            result.push('\\');
                        }
                    }
                } else {
                    result.push('\\');
                }
            } else {
                result.push(ch);
            }
        }

        result
    }
}
