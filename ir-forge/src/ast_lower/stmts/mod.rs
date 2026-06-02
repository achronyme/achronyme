//! Statement-level compilation on [`ProveIrCompiler`].
//!
//! The methods that walk a `Block` and lower each `Stmt` into the ProveIR body.
//! Expression compilation lives in [`super::exprs`]; call dispatch + builtin
//! lowering in [`super::calls`]; method lookups in [`super::methods`].

mod block;
mod expr_stmt;
mod imports;
mod inputs;
mod lets;
mod mutation;
