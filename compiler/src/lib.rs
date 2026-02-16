pub mod codegen;
pub mod error;
pub mod interner;
pub mod expressions;
pub mod statements;
pub mod functions;
pub mod control_flow;
pub mod scopes;
pub mod function_compiler;
pub mod types;
pub mod r1cs_backend;
pub mod r1cs_error;

pub use codegen::Compiler;
pub use error::CompilerError;
pub use interner::StringInterner;

// Re-exports for convenience if needed, but Compiler has most traits implemented.
// Expose traits so they can be imported if necessary?
pub use statements::StatementCompiler;
pub use expressions::ExpressionCompiler;
pub use declarations::DeclarationCompiler;
// declarations is inside statements.
use statements::declarations;
