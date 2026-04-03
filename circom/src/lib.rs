//! Circom frontend for Achronyme.
//!
//! Parses `.circom` files (Circom 2.x syntax) and lowers them through
//! Achronyme's ProveIR pipeline, producing R1CS or Plonkish constraints
//! with structural safety guarantees:
//!
//! - Every `<--` assignment must have a corresponding `===` constraint.
//! - Under-constrained signals are caught at compile time (hard error).
//!
//! # Pipeline
//!
//! `.circom` → Lexer → Parser → Circom AST → Analysis → Lowering → ProveIR

pub mod token;
pub mod lexer;
pub mod ast;
pub mod parser;
pub mod analysis;
mod lowering;
