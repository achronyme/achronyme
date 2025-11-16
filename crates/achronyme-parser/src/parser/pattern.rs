use pest::iterators::Pair;
use crate::ast::{AstNode, Pattern, LiteralPattern, VectorPatternElement, MatchArm};
use crate::parser::AstParser;
use crate::pest_parser::Rule;

impl AstParser {
    /// Build a match expression: match value { pattern => expr, ... }
    pub(super) fn build_match_expr(&mut self, pair: Pair<Rule>) -> Result<AstNode, String> {
        let mut inner = pair.into_inner();

        // First element is the value to match
        let value_pair = inner.next()
            .ok_or("Missing value in match expression")?;
        let value = Box::new(self.build_ast_from_expr(value_pair)?);

        // Remaining elements are match arms
        let mut arms = Vec::new();
        for arm_pair in inner {
            if arm_pair.as_rule() == Rule::match_arm {
                arms.push(self.build_match_arm(arm_pair)?);
            }
        }

        if arms.is_empty() {
            return Err("Match expression must have at least one arm".to_string());
        }

        Ok(AstNode::Match { value, arms })
    }

    /// Build a single match arm: pattern [if guard] => expr
    fn build_match_arm(&mut self, pair: Pair<Rule>) -> Result<MatchArm, String> {
        let mut inner = pair.into_inner();

        // First is the pattern
        let pattern_pair = inner.next()
            .ok_or("Missing pattern in match arm")?;
        let pattern = self.build_pattern(pattern_pair)?;

        // Next could be guard_clause or expression
        let next_pair = inner.next()
            .ok_or("Missing body in match arm")?;

        let (guard, body) = if next_pair.as_rule() == Rule::guard_clause {
            // We have a guard clause
            let guard_expr = self.build_guard_clause(next_pair)?;
            let body_pair = inner.next()
                .ok_or("Missing body after guard in match arm")?;
            let body = Box::new(self.build_ast_from_expr(body_pair)?);
            (Some(guard_expr), body)
        } else {
            // No guard, this is the body
            let body = Box::new(self.build_ast_from_expr(next_pair)?);
            (None, body)
        };

        Ok(MatchArm { pattern, guard, body })
    }

    /// Build a guard clause: if condition
    fn build_guard_clause(&mut self, pair: Pair<Rule>) -> Result<Box<AstNode>, String> {
        let expr_pair = pair.into_inner().next()
            .ok_or("Missing expression in guard clause")?;
        Ok(Box::new(self.build_ast_from_expr(expr_pair)?))
    }

    /// Build a pattern
    pub(super) fn build_pattern(&mut self, pair: Pair<Rule>) -> Result<Pattern, String> {
        let inner = pair.into_inner().next()
            .ok_or("Empty pattern")?;

        match inner.as_rule() {
            Rule::literal_pattern => self.build_literal_pattern(inner),
            Rule::wildcard_pattern => Ok(Pattern::Wildcard),
            Rule::variable_pattern => self.build_variable_pattern(inner),
            Rule::type_pattern => Ok(Pattern::Type(inner.as_str().to_string())),
            Rule::record_pattern => self.build_record_pattern(inner),
            Rule::vector_pattern => self.build_vector_pattern(inner),
            _ => Err(format!("Unexpected pattern rule: {:?}", inner.as_rule()))
        }
    }

    /// Build a literal pattern (number, string, boolean, null)
    fn build_literal_pattern(&mut self, pair: Pair<Rule>) -> Result<Pattern, String> {
        let inner = pair.into_inner().next()
            .ok_or("Empty literal pattern")?;

        let literal = match inner.as_rule() {
            Rule::number => {
                let num = inner.as_str().parse::<f64>()
                    .map_err(|e| format!("Failed to parse number in pattern: {}", e))?;
                LiteralPattern::Number(num)
            }
            Rule::string_literal => {
                let s = inner.as_str();
                // Remove surrounding quotes
                let content = &s[1..s.len()-1];
                // Process escape sequences
                let processed = self.process_escape_sequences(content);
                LiteralPattern::String(processed)
            }
            Rule::boolean => {
                let value = inner.as_str() == "true";
                LiteralPattern::Boolean(value)
            }
            Rule::null_literal => {
                LiteralPattern::Null
            }
            _ => return Err(format!("Unexpected literal pattern rule: {:?}", inner.as_rule()))
        };

        Ok(Pattern::Literal(literal))
    }

    /// Build a variable pattern (identifier that binds the matched value)
    fn build_variable_pattern(&mut self, pair: Pair<Rule>) -> Result<Pattern, String> {
        let ident = pair.into_inner().next()
            .ok_or("Empty variable pattern")?;
        Ok(Pattern::Variable(ident.as_str().to_string()))
    }

    /// Build a record pattern: { field1: pattern1, field2: pattern2 }
    pub(super) fn build_record_pattern(&mut self, pair: Pair<Rule>) -> Result<Pattern, String> {
        let mut fields = Vec::new();

        for field_pair in pair.into_inner() {
            if field_pair.as_rule() == Rule::record_pattern_field {
                let (name, pattern) = self.build_record_pattern_field(field_pair)?;
                fields.push((name, pattern));
            }
        }

        Ok(Pattern::Record { fields })
    }

    /// Build a single record pattern field: name: pattern OR name (shorthand)
    fn build_record_pattern_field(&mut self, pair: Pair<Rule>) -> Result<(String, Pattern), String> {
        let mut inner = pair.into_inner();

        let name_pair = inner.next()
            .ok_or("Missing field name in record pattern")?;
        let name = name_pair.as_str().to_string();

        // Check if there's a pattern (name: pattern) or just name (shorthand)
        let pattern = if let Some(pattern_pair) = inner.next() {
            self.build_pattern(pattern_pair)?
        } else {
            // Shorthand: { name } means { name: name }
            Pattern::Variable(name.clone())
        };

        Ok((name, pattern))
    }

    /// Build a vector pattern: [x, y, ...rest]
    pub(super) fn build_vector_pattern(&mut self, pair: Pair<Rule>) -> Result<Pattern, String> {
        let mut elements = Vec::new();

        for elem_pair in pair.into_inner() {
            if elem_pair.as_rule() == Rule::vector_pattern_element {
                elements.push(self.build_vector_pattern_element(elem_pair)?);
            }
        }

        Ok(Pattern::Vector { elements })
    }

    /// Build a vector pattern element: pattern or ...rest
    fn build_vector_pattern_element(&mut self, pair: Pair<Rule>) -> Result<VectorPatternElement, String> {
        let inner = pair.into_inner().next()
            .ok_or("Empty vector pattern element")?;

        match inner.as_rule() {
            Rule::rest_pattern => {
                let ident = inner.into_inner().next()
                    .ok_or("Missing identifier in rest pattern")?;
                Ok(VectorPatternElement::Rest(ident.as_str().to_string()))
            }
            Rule::pattern => {
                let pattern = self.build_pattern(inner)?;
                Ok(VectorPatternElement::Pattern(pattern))
            }
            _ => Err(format!("Unexpected vector pattern element rule: {:?}", inner.as_rule()))
        }
    }
}
