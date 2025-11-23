use crate::ast::{ArrayElement, AstNode, RecordFieldOrSpread};
use crate::parser::AstParser;
use crate::pest_parser::Rule;
use pest::iterators::Pair;

impl AstParser {
    /// Build array from pest pair - handles vectors, matrices, and N-dimensional tensors
    /// Now returns unified ArrayLiteral for all dimensions
    /// Supports spread syntax: [1, ...vec, 2]
    pub(super) fn build_array(&mut self, pair: Pair<Rule>) -> Result<AstNode, String> {
        let elements: Vec<ArrayElement> = pair
            .into_inner()
            .map(|p| match p.as_rule() {
                Rule::array_element => {
                    let inner = p.into_inner().next().ok_or("Empty array_element")?;
                    match inner.as_rule() {
                        Rule::spread_expr => {
                            let spread_inner =
                                inner.into_inner().next().ok_or("Empty spread_expr")?;
                            Ok(ArrayElement::Spread(Box::new(
                                self.build_ast_from_expr(spread_inner)?,
                            )))
                        }
                        Rule::expr => Ok(ArrayElement::Single(self.build_ast_from_expr(inner)?)),
                        _ => Err(format!(
                            "Unexpected array_element inner rule: {:?}",
                            inner.as_rule()
                        )),
                    }
                }
                _ => Err(format!("Unexpected array rule child: {:?}", p.as_rule())),
            })
            .collect::<Result<Vec<_>, _>>()?;

        Ok(AstNode::ArrayLiteral(elements))
    }

    pub(super) fn build_record(&mut self, pair: Pair<Rule>) -> Result<AstNode, String> {
        let fields: Result<Vec<RecordFieldOrSpread>, String> = pair
            .into_inner()
            .map(|field_or_spread_pair| {
                match field_or_spread_pair.as_rule() {
                    Rule::record_field_or_spread => {
                        let inner = field_or_spread_pair
                            .into_inner()
                            .next()
                            .ok_or("Empty record_field_or_spread")?;
                        match inner.as_rule() {
                            Rule::spread_expr => {
                                let spread_inner =
                                    inner.into_inner().next().ok_or("Empty spread_expr")?;
                                Ok(RecordFieldOrSpread::Spread(Box::new(
                                    self.build_ast_from_expr(spread_inner)?,
                                )))
                            }
                            Rule::record_field => {
                                let mut field_inner = inner.into_inner();

                                // Grammar: (mut_keyword ~ identifier ~ ":" ~ expr) | (identifier ~ ":" ~ expr)
                                let first = field_inner.next().ok_or("Missing field key or mut")?;

                                // Check if first token is mut_keyword
                                if first.as_rule() == Rule::mut_keyword {
                                    // Mutable field: mut key: value
                                    let key = field_inner
                                        .next()
                                        .ok_or("Missing field key after mut")?
                                        .as_str()
                                        .to_string();
                                    let value = self.build_ast_from_expr(
                                        field_inner.next().ok_or("Missing field value")?,
                                    )?;
                                    Ok(RecordFieldOrSpread::MutableField { name: key, value })
                                } else {
                                    // Immutable field: key: value (first is the identifier)
                                    let key = first.as_str().to_string();
                                    let value = self.build_ast_from_expr(
                                        field_inner.next().ok_or("Missing field value")?,
                                    )?;
                                    Ok(RecordFieldOrSpread::Field { name: key, value })
                                }
                            }
                            _ => Err(format!(
                                "Unexpected record_field_or_spread inner rule: {:?}",
                                inner.as_rule()
                            )),
                        }
                    }
                    _ => Err(format!(
                        "Unexpected record rule child: {:?}",
                        field_or_spread_pair.as_rule()
                    )),
                }
            })
            .collect();

        Ok(AstNode::RecordLiteral(fields?))
    }
}
