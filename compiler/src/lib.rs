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

/// Forward-compat alias for [`Compiler`]. The bytecode compiler will
/// rename to `BytecodeCompiler` in the post-cleanup crate split (see
/// `.claude/plans/structural-cleanup.md` §10 D2) to disambiguate from
/// `ProveIrCompiler` (AST → ProveIR) and the post-cleanup `zkc`
/// backend compilers. Use this alias in new code to avoid a second
/// rename later.
pub type BytecodeCompiler = Compiler;

// declarations is inside statements.
use statements::declarations;
