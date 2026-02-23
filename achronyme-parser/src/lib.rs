extern crate pest;
#[macro_use]
extern crate pest_derive;

pub mod ast;
pub mod build_ast;
pub mod error;
pub mod lexer;
pub mod parser;
pub mod token;

use pest::Parser;

#[derive(Parser)]
#[grammar = "grammar.pest"]
pub struct AchronymeParser;

/// Re-export the new hand-written parser as the primary API.
pub use parser::{parse_block, parse_program};
pub use lexer::unescape;

pub fn parse_expression(
    input: &str,
) -> std::result::Result<pest::iterators::Pairs<'_, Rule>, pest::error::Error<Rule>> {
    let mut pairs = AchronymeParser::parse(Rule::program, input)?;
    let program_pair = pairs.next().unwrap();
    Ok(program_pair.into_inner())
}
