/// Handlers for different types of operations
///
/// This module organizes the evaluation logic into specialized handlers,
/// making the codebase more maintainable and easier to extend.

pub mod binary_ops;
pub mod unary_ops;
pub mod hof;
pub mod numerical;
pub mod optimization;
pub mod function_call;
pub mod debug;

// Node evaluation handlers
pub mod literals;
pub mod variables;
pub mod assignment;
pub mod control_flow;
pub mod functions;
pub mod indexing;
pub mod pattern_matching;
