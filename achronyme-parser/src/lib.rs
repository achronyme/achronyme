extern crate pest;
#[macro_use]
extern crate pest_derive;

pub mod ast;
pub mod build_ast;

use pest::Parser;

#[derive(Parser)]
#[grammar = "grammar.pest"]
pub struct AchronymeParser;

pub fn parse_expression(
    input: &str,
) -> std::result::Result<pest::iterators::Pairs<'_, Rule>, pest::error::Error<Rule>> {
    let mut pairs = AchronymeParser::parse(Rule::program, input)?;
    // The program rule returns { SOI, expr, EOI } (plus implicit whitespace).
    // We want to return the inner `expr` pairs.
    // Actually, `pairs` is an iterator of `program`.
    // We should return `program`'s children if possible, or just return the pairs and let compiler handle it.
    // But `compiler` likely expects `expr` directly.
    // Let's modify the compiler to handle `program` or return the inner `expr` here.

    // If we return `pairs`, it will contain one element: `program`.
    // The compiler expects a stream of atom/primary/etc? No, it expects `expr`.
    // Ideally we return the inner `expr`.

    let program_pair = pairs.next().unwrap();
    // program_pair has children: expr, EOI.
    // We want the children of `expr`.
    // Wait, `expr = { additive }`.
    // If we return `program_pair.into_inner()`, we get `expr` and `EOI`.
    Ok(program_pair.into_inner())
}
