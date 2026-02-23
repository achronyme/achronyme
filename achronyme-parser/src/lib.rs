pub mod ast;
pub mod error;
pub mod lexer;
pub mod parser;
pub mod token;

/// Re-export the hand-written parser as the primary API.
pub use parser::{parse_block, parse_program};
pub use lexer::unescape;
