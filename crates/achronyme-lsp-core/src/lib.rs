//! Core LSP functionality for Achronyme language
//!
//! This crate provides shared logic for code intelligence features
//! that can be used by both the LSP server and CLI tools.
//!
//! # Features
//!
//! - **Completion**: Provides completion items for functions, keywords, constants, and types
//! - **Signatures**: Function signature information for signature help
//!
//! # Example
//!
//! ```
//! use achronyme_lsp_core::{get_all_completions, get_signature};
//!
//! // Get all completion items
//! let completions = get_all_completions();
//! println!("Total completions: {}", completions.len());
//!
//! // Get signature for a specific function
//! if let Some(sig) = get_signature("sin") {
//!     println!("Signature: {}", sig.signature);
//! }
//! ```

pub mod completion;
pub mod signatures;

// Re-export main types for convenience
pub use completion::{
    get_all_completions, get_constant_completions, get_function_completions,
    get_keyword_completions, get_type_completions, CompletionEntry, CompletionKind,
};
pub use signatures::{get_all_signatures, get_signature, FunctionSignature, ParameterInfo};
