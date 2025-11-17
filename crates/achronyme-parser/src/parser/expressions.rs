use pest::iterators::Pair;
use crate::ast::{AstNode, BinaryOp, UnaryOp};
use crate::parser::AstParser;
use crate::pest_parser::Rule;

impl AstParser {
    pub(super) fn build_ast_from_expr(&mut self, pair: Pair<Rule>) -> Result<AstNode, String> {
        let rule = pair.as_rule();
        match rule {
            Rule::expr => {
                let inner = pair.into_inner().next()
                    .ok_or("Empty expression")?;
                self.build_ast_from_expr(inner)
            }
            Rule::standalone_range => self.build_standalone_range(pair),
            Rule::logical_or => self.build_binary_op(pair),
            Rule::logical_and => self.build_binary_op(pair),
            Rule::comparison => self.build_comparison(pair),
            Rule::edge => self.build_edge(pair),
            Rule::additive => self.build_binary_op(pair),
            Rule::multiplicative => self.build_binary_op(pair),
            Rule::unary => self.build_unary(pair),
            Rule::power => self.build_power(pair),
            Rule::postfix_expression => self.build_postfix_expression(pair),
            Rule::primary => self.build_primary(pair),
            _ => Err(format!("Unexpected expression rule: {:?} in {}", rule, pair.as_str()))
        }
    }

    pub(super) fn build_standalone_range(&mut self, pair: Pair<Rule>) -> Result<AstNode, String> {
        let pairs: Vec<_> = pair.into_inner().collect();

        if pairs.len() == 1 {
            // No range operator, just the logical_or expression
            return self.build_ast_from_expr(pairs[0].clone());
        }

        // Should have exactly 3 pairs: left, range_op, right
        if pairs.len() != 3 {
            return Err(format!("Expected 3 pairs for range, got {}", pairs.len()));
        }

        let start = self.build_ast_from_expr(pairs[0].clone())?;

        // Extract the range operator
        let inclusive = match pairs[1].as_rule() {
            Rule::range_op => {
                match pairs[1].as_str() {
                    "..=" => true,
                    ".." => false,
                    _ => return Err(format!("Unknown range operator: {}", pairs[1].as_str()))
                }
            }
            _ => return Err(format!("Expected range_op, got: {:?}", pairs[1].as_rule()))
        };

        let end = self.build_ast_from_expr(pairs[2].clone())?;

        Ok(AstNode::RangeExpr {
            start: Box::new(start),
            end: Box::new(end),
            inclusive,
        })
    }

    pub(super) fn build_edge(&mut self, pair: Pair<Rule>) -> Result<AstNode, String> {
        let pairs: Vec<_> = pair.into_inner().collect();

        if pairs.len() == 1 {
            // No edge, just the additive expression
            return self.build_ast_from_expr(pairs[0].clone());
        }

        // Edge syntax: additive edge_op additive [":" additive]
        // pairs can be: [left, edge_op, right] or [left, edge_op, right, metadata]

        if pairs.len() < 3 {
            return Err(format!("Edge requires at least 3 pairs (from, op, to), got {}", pairs.len()));
        }

        // Extract 'from' identifier - must be a single identifier
        let from = self.extract_identifier(&pairs[0])?;

        // Extract edge operator
        let directed = match pairs[1].as_rule() {
            Rule::edge_op => {
                match pairs[1].as_str() {
                    "->" => true,
                    "<>" => false,
                    _ => return Err(format!("Unknown edge operator: {}", pairs[1].as_str()))
                }
            }
            _ => return Err(format!("Expected edge_op, got: {:?}", pairs[1].as_rule()))
        };

        // Extract 'to' identifier - must be a single identifier
        let to = self.extract_identifier(&pairs[2])?;

        // Extract optional metadata
        let metadata = if pairs.len() >= 4 {
            Some(Box::new(self.build_ast_from_expr(pairs[3].clone())?))
        } else {
            None
        };

        Ok(AstNode::Edge {
            from,
            to,
            directed,
            metadata,
        })
    }

    pub(super) fn build_comparison(&mut self, pair: Pair<Rule>) -> Result<AstNode, String> {
        let pairs: Vec<_> = pair.into_inner().collect();

        if pairs.len() == 1 {
            // No comparison, just the edge expression
            return self.build_ast_from_expr(pairs[0].clone());
        }

        // Should have exactly 3 pairs: left, operator, right
        if pairs.len() != 3 {
            return Err(format!("Expected 3 pairs for comparison, got {}", pairs.len()));
        }

        let left = self.build_ast_from_expr(pairs[0].clone())?;

        // The operator should be a cmp_op rule
        let op = match pairs[1].as_rule() {
            Rule::cmp_op => {
                match pairs[1].as_str() {
                    ">" => BinaryOp::Gt,
                    "<" => BinaryOp::Lt,
                    ">=" => BinaryOp::Gte,
                    "<=" => BinaryOp::Lte,
                    "==" => BinaryOp::Eq,
                    "!=" => BinaryOp::Neq,
                    _ => return Err(format!("Unknown comparison operator: {}", pairs[1].as_str()))
                }
            }
            _ => return Err(format!("Expected cmp_op, got: {:?}", pairs[1].as_rule()))
        };

        let right = self.build_ast_from_expr(pairs[2].clone())?;

        Ok(AstNode::BinaryOp {
            op,
            left: Box::new(left),
            right: Box::new(right),
        })
    }

    pub(super) fn build_binary_op(&mut self, pair: Pair<Rule>) -> Result<AstNode, String> {
        let pairs: Vec<_> = pair.into_inner().collect();

        if pairs.len() == 1 {
            // Single operand, no operation
            return self.build_ast_from_expr(pairs[0].clone());
        }

        // Pest gives us: [operand, operator, operand, operator, operand, ...]
        // We need to separate them into operands and operators

        let mut operands = Vec::new();
        let mut operators = Vec::new();

        for p in pairs.iter() {
            // Check if this is an operator rule
            match p.as_rule() {
                Rule::add_op | Rule::mult_op | Rule::logical_and_op | Rule::logical_or_op => {
                    let s = p.as_str();
                    let op = match s {
                        "+" => BinaryOp::Add,
                        "-" => BinaryOp::Subtract,
                        "*" => BinaryOp::Multiply,
                        "/" => BinaryOp::Divide,
                        "%" => BinaryOp::Modulo,
                        "&&" => BinaryOp::And,
                        "||" => BinaryOp::Or,
                        _ => unreachable!()
                    };
                    operators.push(op);
                }
                _ => {
                    // It's an operand (a sub-rule)
                    operands.push(p.clone());
                }
            }
        }

        if operands.is_empty() {
            return Err("No operands found".to_string());
        }

        // Build left-associative tree
        let mut left = self.build_ast_from_expr(operands[0].clone())?;

        for (i, op) in operators.iter().enumerate() {
            let right = self.build_ast_from_expr(operands[i + 1].clone())?;
            left = AstNode::BinaryOp {
                op: op.clone(),
                left: Box::new(left),
                right: Box::new(right),
            };
        }

        Ok(left)
    }

    pub(super) fn build_unary(&mut self, pair: Pair<Rule>) -> Result<AstNode, String> {
        let pair_str = pair.as_str();
        let mut inner = pair.into_inner();
        let first = inner.next().ok_or("Empty unary expression")?;

        match first.as_rule() {
            Rule::unary => {
                // This is either - or ! operator
                // Check what operator we have by looking at the string
                let op = if pair_str.trim_start().starts_with('-') {
                    UnaryOp::Negate
                } else if pair_str.trim_start().starts_with('!') {
                    UnaryOp::Not
                } else {
                    return Err(format!("Unknown unary operator in: {}", pair_str));
                };

                Ok(AstNode::UnaryOp {
                    op,
                    operand: Box::new(self.build_unary(first)?),
                })
            }
            Rule::power => self.build_power(first),
            _ => Err(format!("Unexpected unary rule: {:?}", first.as_rule()))
        }
    }

    pub(super) fn build_power(&mut self, pair: Pair<Rule>) -> Result<AstNode, String> {
        let mut inner = pair.into_inner();
        let base = self.build_postfix_expression(inner.next().ok_or("Missing base in power")?)?;

        if let Some(exponent_pair) = inner.next() {
            // Right-associative: 2^3^4 = 2^(3^4)
            let exponent = self.build_power(exponent_pair)?;
            Ok(AstNode::BinaryOp {
                op: BinaryOp::Power,
                left: Box::new(base),
                right: Box::new(exponent),
            })
        } else {
            Ok(base)
        }
    }
}