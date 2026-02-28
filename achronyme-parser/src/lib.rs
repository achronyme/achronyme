pub mod ast;
pub mod error;
pub mod lexer;
pub mod parser;
pub mod token;

pub use error::ParseError;
pub use lexer::unescape;
/// Re-export the hand-written parser as the primary API.
pub use parser::{parse_block, parse_program, parse_program_with_errors};
