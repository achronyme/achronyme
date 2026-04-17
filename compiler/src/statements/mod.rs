//! Statement compilation — AST `Stmt` → VM bytecode.
//!
//! The public entry point is the [`StatementCompiler`] trait (implemented
//! for `Compiler`). Its body dispatches each `Stmt` variant to a
//! statement-category submodule:
//!
//! - [`circuit`] — `circuit { … }` and `import circuit`
//! - [`imports`] — `import "path"` / `import { … } from`
//! - [`declarations`] — `let` / `mut`
//! - [`circom_imports`] — `.circom` frontend dispatch
//! - [`import_kind`] — path-extension classifier
//! - [`dispatch`] — the trait + the big `compile_stmt` match

pub mod circom_imports;
pub(crate) mod circuit;
pub mod declarations;
pub(crate) mod dispatch;
pub(crate) mod import_kind;
pub(crate) mod imports;

#[cfg(test)]
mod tests;

pub use dispatch::StatementCompiler;

pub(crate) use dispatch::stmt_span;
