use crate::ast::{AstNode, IndexArg};
use crate::parser::AstParser;
use crate::pest_parser::Rule;
use pest::iterators::Pair;

impl AstParser {
    pub(super) fn build_postfix_expression(&mut self, pair: Pair<Rule>) -> Result<AstNode, String> {
        let mut inner = pair.into_inner();
        let mut ast = self.build_primary(inner.next().ok_or("Expected a primary expression")?)?;

        for op_pair in inner {
            // These are postfix_op
            let op_inner = op_pair.into_inner().next().unwrap();
            match op_inner.as_rule() {
                Rule::field_op => {
                    let field_name = op_inner.into_inner().next().unwrap().as_str().to_string();
                    ast = AstNode::FieldAccess {
                        record: Box::new(ast),
                        field: field_name,
                    };
                }
                Rule::index_op => {
                    let indices: Vec<IndexArg> = op_inner
                        .into_inner()
                        .map(|p| self.build_access_arg(p))
                        .collect::<Result<_, _>>()?;
                    ast = AstNode::IndexAccess {
                        object: Box::new(ast),
                        indices,
                    };
                }
                Rule::call_op => {
                    let args: Vec<AstNode> = op_inner
                        .into_inner()
                        .map(|p| self.build_ast_from_expr(p))
                        .collect::<Result<_, _>>()?;

                    if let AstNode::VariableRef(ref name) = ast {
                        if name == "if" {
                            if args.len() != 3 {
                                return Err(format!(
                                    "if() requires 3 arguments, got {}",
                                    args.len()
                                ));
                            }
                            ast = AstNode::If {
                                condition: Box::new(args[0].clone()),
                                then_expr: Box::new(args[1].clone()),
                                else_expr: Box::new(args[2].clone()),
                            };
                            continue;
                        }
                        if name == "piecewise" {
                            ast = self.build_piecewise(args)?;
                            continue;
                        }
                    }

                    ast = AstNode::CallExpression {
                        callee: Box::new(ast),
                        args,
                    };
                }
                _ => unreachable!("Unexpected postfix operator: {:?}", op_inner.as_rule()),
            }
        }
        Ok(ast)
    }

    pub(super) fn build_lambda(&mut self, pair: Pair<Rule>) -> Result<AstNode, String> {
        let mut inner = pair.into_inner();

        // Grammar: typed_lambda_params ~ (":" ~ type_annotation)? ~ "=>" ~ lambda_body
        let params_pair = inner.next().ok_or("Missing lambda parameters")?;

        // Parse typed parameters
        let params = if params_pair.as_rule() == Rule::typed_lambda_params {
            self.parse_typed_lambda_params(params_pair)?
        } else {
            // Fallback to legacy lambda_params for backward compatibility
            self.extract_lambda_params(params_pair)?
                .into_iter()
                .map(|name| (name, None, None))
                .collect()
        };

        // Parse optional return type
        let mut return_type = None;
        let mut next_pair = inner.next().ok_or("Missing lambda body")?;

        if next_pair.as_rule() == Rule::type_annotation {
            return_type = Some(self.parse_type_annotation(next_pair)?);
            next_pair = inner
                .next()
                .ok_or("Missing lambda body after return type")?;
        }

        // Parse lambda body
        let body = match next_pair.as_rule() {
            Rule::lambda_body => {
                let inner_body = next_pair.into_inner().next().ok_or("Empty lambda body")?;
                match inner_body.as_rule() {
                    Rule::generate_block => self.build_generate_block(inner_body)?,
                    Rule::do_block => self.build_do_block(inner_body)?,
                    Rule::expr => self.build_ast_from_expr(inner_body)?,
                    _ => {
                        return Err(format!(
                            "Unexpected lambda body rule: {:?}",
                            inner_body.as_rule()
                        ))
                    }
                }
            }
            _ => {
                return Err(format!(
                    "Expected lambda_body, got {:?}",
                    next_pair.as_rule()
                ))
            }
        };

        Ok(AstNode::Lambda {
            params,
            return_type,
            body: Box::new(body),
        })
    }

    pub(super) fn build_generate_block(&mut self, pair: Pair<Rule>) -> Result<AstNode, String> {
        // Grammar: "generate" ~ block
        let block_pair = pair
            .into_inner()
            .next()
            .ok_or("Missing block in generate statement")?;

        // block contains sequence | statement
        let inner = block_pair
            .into_inner()
            .next()
            .ok_or("Empty generate block")?;

        let statements = match inner.as_rule() {
            Rule::sequence => {
                // Multiple statements
                inner
                    .into_inner()
                    .map(|stmt_pair| self.build_ast_from_statement(stmt_pair))
                    .collect::<Result<Vec<_>, _>>()?
            }
            Rule::statement => {
                // Single statement
                vec![self.build_ast_from_statement(inner)?]
            }
            _ => {
                return Err(format!(
                    "Unexpected rule in generate block: {:?}",
                    inner.as_rule()
                ))
            }
        };

        Ok(AstNode::GenerateBlock { statements })
    }

    pub(super) fn extract_lambda_params(
        &mut self,
        pair: Pair<Rule>,
    ) -> Result<Vec<String>, String> {
        let inner = pair.into_inner();
        let params: Vec<String> = inner.map(|p| p.as_str().to_string()).collect();

        // Allow empty parameter lists for lambdas like () => expr
        Ok(params)
    }

    pub(super) fn build_access_arg(&mut self, pair: Pair<Rule>) -> Result<IndexArg, String> {
        let inner = pair.into_inner().next().ok_or("Empty access_arg")?;

        match inner.as_rule() {
            Rule::range_expr => {
                // Range: start..end, start.., ..end, or ..
                // The grammar now has explicit alternatives, so we parse accordingly
                let inner_str = inner.as_str();
                let range_parts = inner.into_inner();

                // Count how many expressions we have
                let exprs: Vec<_> = range_parts.collect();

                let (start, end) = if inner_str.starts_with("..") && !inner_str.ends_with("..") {
                    // "..end" case
                    if exprs.len() == 1 {
                        (
                            None,
                            Some(Box::new(self.build_ast_from_expr(exprs[0].clone())?)),
                        )
                    } else {
                        return Err("Invalid range expression".to_string());
                    }
                } else if inner_str.ends_with("..") && !inner_str.starts_with("..") {
                    // "start.." case
                    if exprs.len() == 1 {
                        (
                            Some(Box::new(self.build_ast_from_expr(exprs[0].clone())?)),
                            None,
                        )
                    } else {
                        return Err("Invalid range expression".to_string());
                    }
                } else if inner_str == ".." {
                    // ".." case
                    (None, None)
                } else {
                    // "start..end" case
                    if exprs.len() == 2 {
                        (
                            Some(Box::new(self.build_ast_from_expr(exprs[0].clone())?)),
                            Some(Box::new(self.build_ast_from_expr(exprs[1].clone())?)),
                        )
                    } else {
                        return Err("Invalid range expression".to_string());
                    }
                };

                Ok(IndexArg::Range { start, end })
            }
            Rule::expr => {
                // Single index expression
                Ok(IndexArg::Single(Box::new(self.build_ast_from_expr(inner)?)))
            }
            _ => Err(format!("Unexpected access_arg rule: {:?}", inner.as_rule())),
        }
    }

    pub(super) fn build_piecewise(&mut self, args: Vec<AstNode>) -> Result<AstNode, String> {
        use crate::ast::ArrayElement;

        if args.is_empty() {
            return Err("piecewise() requires at least one argument".to_string());
        }

        let mut cases = Vec::new();
        let mut default = None;

        for (i, arg) in args.iter().enumerate() {
            match arg {
                AstNode::ArrayLiteral(elems) => {
                    if elems.len() != 2 {
                        return Err(format!(
                            "piecewise() case must have exactly 2 elements [condition, value], got {}",
                            elems.len()
                        ));
                    }

                    let first = match &elems[0] {
                        ArrayElement::Single(node) => node.clone(),
                        ArrayElement::Spread(_) => {
                            return Err(
                                "piecewise() does not support spread in case arrays".to_string()
                            );
                        }
                    };

                    let second = match &elems[1] {
                        ArrayElement::Single(node) => node.clone(),
                        ArrayElement::Spread(_) => {
                            return Err(
                                "piecewise() does not support spread in case arrays".to_string()
                            );
                        }
                    };

                    cases.push((Box::new(first), Box::new(second)));
                }
                _ => {
                    if i != args.len() - 1 {
                        return Err(format!(
                            "piecewise() default value must be the last argument (argument {} is not a case)",
                            i + 1
                        ));
                    }
                    default = Some(Box::new(arg.clone()));
                }
            }
        }

        Ok(AstNode::Piecewise { cases, default })
    }
}
