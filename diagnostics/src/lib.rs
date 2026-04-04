//! Shared diagnostic infrastructure for Achronyme frontends.
//!
//! Provides source location tracking, structured error/warning diagnostics,
//! and a renderer with optional ANSI color output.
//!
//! This crate has **zero dependencies** and is consumed by all frontend
//! parsers (Achronyme, Circom, Noir, etc.) and the compiler pipeline.

pub mod diagnostic;
pub mod error;
pub mod render;
pub mod span;

pub use diagnostic::{Diagnostic, Label, Severity, SpanRange, Suggestion};
pub use error::ParseError;
pub use render::{atty_stderr, ColorMode, DiagnosticRenderer};
pub use span::Span;
