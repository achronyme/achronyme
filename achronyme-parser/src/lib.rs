extern crate pest;
#[macro_use]
extern crate pest_derive;

use pest::Parser;

#[derive(Parser)]
#[grammar = "grammar.pest"]
pub struct AchronymeParser;

pub fn parse_expression(input: &str) -> std::result::Result<pest::iterators::Pairs<Rule>, pest::error::Error<Rule>> {
    AchronymeParser::parse(Rule::expr, input)
}
