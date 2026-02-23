pub mod codegen;
pub mod control_flow;
pub mod error;
pub mod expressions;
pub mod function_compiler;
pub mod functions;
pub mod interner;
pub mod plonkish_backend;
pub mod r1cs_backend;
pub mod r1cs_error;
pub mod scopes;
pub mod statements;
pub mod types;
pub mod witness_gen;

pub use codegen::Compiler;
pub use error::CompilerError;
pub use interner::StringInterner;

// Re-exports for convenience if needed, but Compiler has most traits implemented.
// Expose traits so they can be imported if necessary?
pub use declarations::DeclarationCompiler;
pub use expressions::ExpressionCompiler;
pub use statements::StatementCompiler;
// declarations is inside statements.
use statements::declarations;
