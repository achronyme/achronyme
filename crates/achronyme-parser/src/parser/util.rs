use crate::parser::AstParser;
use crate::pest_parser::Rule;
use pest::iterators::Pair;

impl AstParser {
    /// Process escape sequences in string literals
    pub(super) fn process_escape_sequences(&mut self, s: &str) -> String {
        let mut result = String::new();
        let mut chars = s.chars();

        while let Some(ch) = chars.next() {
            if ch == '\\' {
                if let Some(next_ch) = chars.next() {
                    match next_ch {
                        'n' => result.push('\n'),
                        't' => result.push('\t'),
                        'r' => result.push('\r'),
                        '\\' => result.push('\\'),
                        '"' => result.push('"'),
                        _ => {
                            // Unknown escape sequence, keep as is
                            result.push('\\');
                            result.push(next_ch);
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

    /// Extract an identifier from a Pair, ensuring it's a single identifier
    /// This enforces that edge nodes are pure identifiers, not expressions
    pub(super) fn extract_identifier(&mut self, pair: &Pair<Rule>) -> Result<String, String> {
        // Navigate through the parsing tree to find the identifier
        // The structure is: additive -> multiplicative -> unary -> power -> field_access -> primary -> identifier

        fn find_identifier(p: &Pair<Rule>) -> Result<String, String> {
            match p.as_rule() {
                Rule::identifier => Ok(p.as_str().to_string()),
                Rule::additive
                | Rule::multiplicative
                | Rule::unary
                | Rule::power
                | Rule::postfix_expression
                | Rule::primary => {
                    let inner: Vec<_> = p.clone().into_inner().collect();
                    if inner.len() != 1 {
                        return Err(
                            "Edge nodes must be simple identifiers, not expressions".to_string()
                        );
                    }
                    find_identifier(&inner[0])
                }
                _ => Err(format!(
                    "Edge nodes must be identifiers, got: {:?}",
                    p.as_rule()
                )),
            }
        }

        find_identifier(pair)
    }
}
