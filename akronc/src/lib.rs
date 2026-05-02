pub mod codegen;
pub mod control_flow;
pub mod error;
pub mod expressions;
pub mod function_compiler;
pub mod functions;
pub mod interner;
pub mod module_loader;
pub mod optimizer;
pub mod scopes;
pub mod statements;
pub mod suggest;
pub mod types;

pub use codegen::Compiler;
pub use error::CompilerError;
pub use interner::{FieldInterner, StringInterner};

/// Disambiguating alias for [`Compiler`]. `BytecodeCompiler` makes
/// the role explicit when [`Compiler`] would clash with
/// `ProveIrCompiler` (AST → ProveIR) or the `zkc` backend compilers
/// in the same scope. Prefer this name in new code.
pub type BytecodeCompiler = Compiler;

// declarations is inside statements.
use statements::declarations;
