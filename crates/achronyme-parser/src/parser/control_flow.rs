use crate::ast::AstNode;
use crate::parser::AstParser;
use crate::pest_parser::Rule;
use pest::iterators::Pair;

impl AstParser {
    /// Build control flow expression (if, match, while, etc.)
    pub(super) fn build_control_flow_expr(&mut self, pair: Pair<Rule>) -> Result<AstNode, String> {
        let inner = pair
            .into_inner()
            .next()
            .ok_or("Empty control flow expression")?;

        match inner.as_rule() {
            Rule::if_expr => self.build_if_expr(inner),
            Rule::while_expr => self.build_while_expr(inner),
            Rule::for_in_loop => self.build_for_in_loop(inner),
            Rule::try_catch_expr => self.build_try_catch_expr(inner),
            Rule::match_expr => self.build_match_expr(inner),
            _ => Err(format!(
                "Unexpected control flow rule: {:?}",
                inner.as_rule()
            )),
        }
    }

    /// Build if expression: if(condition) { block } else { block }
    pub(super) fn build_if_expr(&mut self, pair: Pair<Rule>) -> Result<AstNode, String> {
        let mut inner = pair.into_inner();

        // Grammar: "if" ~ "(" ~ expr ~ ")" ~ &"{" ~ block ~ ("else" ~ (if_expr | block))?

        // Get condition
        let condition_pair = inner.next().ok_or("Missing condition in if expression")?;
        let condition = Box::new(self.build_ast_from_expr(condition_pair)?);

        // Get then block
        let then_block_pair = inner.next().ok_or("Missing then block in if expression")?;
        let then_expr = Box::new(self.build_block(then_block_pair)?);

        // Get optional else clause
        let else_expr = if let Some(else_pair) = inner.next() {
            // else_pair can be either if_expr or block
            match else_pair.as_rule() {
                Rule::if_expr => Box::new(self.build_if_expr(else_pair)?),
                Rule::block => Box::new(self.build_block(else_pair)?),
                _ => {
                    return Err(format!(
                        "Unexpected else clause rule: {:?}",
                        else_pair.as_rule()
                    ))
                }
            }
        } else {
            // No else clause - return 0 (could also be unit/null in the future)
            Box::new(AstNode::Number(0.0))
        };

        Ok(AstNode::If {
            condition,
            then_expr,
            else_expr,
        })
    }

    /// Build while expression: while(condition) { block }
    pub(super) fn build_while_expr(&mut self, pair: Pair<Rule>) -> Result<AstNode, String> {
        let mut inner = pair.into_inner();

        // Grammar: "while" ~ "(" ~ expr ~ ")" ~ &"{" ~ block

        // Get condition
        let condition_pair = inner
            .next()
            .ok_or("Missing condition in while expression")?;
        let condition = Box::new(self.build_ast_from_expr(condition_pair)?);

        // Get body block
        let body_pair = inner
            .next()
            .ok_or("Missing body block in while expression")?;
        let body = Box::new(self.build_block(body_pair)?);

        Ok(AstNode::WhileLoop { condition, body })
    }

    /// Build for-in loop: for(variable in iterable) { block }
    pub(super) fn build_for_in_loop(&mut self, pair: Pair<Rule>) -> Result<AstNode, String> {
        let mut inner = pair.into_inner();

        // Grammar: "for" ~ "(" ~ identifier ~ "in" ~ expr ~ ")" ~ &"{" ~ block

        // Get loop variable
        let variable_pair = inner.next().ok_or("Missing variable in for-in loop")?;
        let variable = variable_pair.as_str().to_string();

        // Get iterable expression
        let iterable_pair = inner.next().ok_or("Missing iterable in for-in loop")?;
        let iterable = Box::new(self.build_ast_from_expr(iterable_pair)?);

        // Get body block
        let body_pair = inner.next().ok_or("Missing body block in for-in loop")?;
        let body = Box::new(self.build_block(body_pair)?);

        Ok(AstNode::ForInLoop {
            variable,
            iterable,
            body,
        })
    }

    /// Build try-catch expression: try { block } catch(error) { block }
    pub(super) fn build_try_catch_expr(&mut self, pair: Pair<Rule>) -> Result<AstNode, String> {
        let mut inner = pair.into_inner();

        // Grammar: "try" ~ block ~ "catch" ~ "(" ~ identifier ~ ")" ~ block

        // Get try block
        let try_block_pair = inner
            .next()
            .ok_or("Missing try block in try-catch expression")?;
        let try_block = Box::new(self.build_block(try_block_pair)?);

        // Get error parameter name
        let error_param_pair = inner
            .next()
            .ok_or("Missing error parameter in catch clause")?;
        let error_param = error_param_pair.as_str().to_string();

        // Get catch block
        let catch_block_pair = inner
            .next()
            .ok_or("Missing catch block in try-catch expression")?;
        let catch_block = Box::new(self.build_block(catch_block_pair)?);

        Ok(AstNode::TryCatch {
            try_block,
            error_param,
            catch_block,
        })
    }

    /// Build do block: do { ... }
    /// Now uses the unified build_block and wraps the result in DoBlock
    pub(super) fn build_do_block(&mut self, pair: Pair<Rule>) -> Result<AstNode, String> {
        // do_block grammar: "do" ~ block
        let block_pair = pair
            .into_inner()
            .next()
            .ok_or("Missing block in do block")?;

        let block_content = self.build_block(block_pair)?;

        // Wrap the block content in DoBlock
        // Convert the result to a statements vec for DoBlock
        let statements = match block_content {
            AstNode::Sequence { statements } => statements,
            single_expr => vec![single_expr],
        };

        Ok(AstNode::DoBlock { statements })
    }

    /// Build generic block: { sequence or statement }
    /// Used by do blocks, if expressions, match expressions (future), etc.
    /// Returns either a Sequence or a single statement
    pub(super) fn build_block(&mut self, pair: Pair<Rule>) -> Result<AstNode, String> {
        let inner = pair.into_inner().next().ok_or("Empty block")?;

        match inner.as_rule() {
            Rule::sequence => {
                // Build sequence: multiple statements
                let mut statements = Vec::new();
                for stmt_pair in inner.into_inner() {
                    if stmt_pair.as_rule() == Rule::statement {
                        statements.push(self.build_ast_from_statement(stmt_pair)?);
                    }
                }
                if statements.is_empty() {
                    return Err("Empty sequence in block".to_string());
                }
                Ok(AstNode::Sequence { statements })
            }
            Rule::statement => {
                // Single statement (can be assignment, let, expr, etc.)
                self.build_ast_from_statement(inner)
            }
            _ => Err(format!("Unexpected block content: {:?}", inner.as_rule())),
        }
    }
}
