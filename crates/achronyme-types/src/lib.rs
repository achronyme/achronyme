pub mod value;
pub mod complex;
pub mod tensor;
pub mod function;
pub mod lambda_evaluator;
pub mod environment;

// Re-exports
pub use lambda_evaluator::LambdaEvaluator;
pub use environment::Environment;