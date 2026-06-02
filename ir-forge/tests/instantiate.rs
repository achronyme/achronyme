//! Tests for the ProveIR → IR instantiator.
//!
//! Loaded via `#[cfg(test)] mod tests;` in `instantiate/mod.rs`.

#[path = "instantiate/audit_control.rs"]
mod audit_control;
#[path = "instantiate/audit_inputs.rs"]
mod audit_inputs;
#[path = "instantiate/basic.rs"]
mod basic;
#[path = "instantiate/captures.rs"]
mod captures;
#[path = "instantiate/helpers.rs"]
mod helpers;
#[path = "instantiate/indexed.rs"]
mod indexed;
#[path = "instantiate/integration.rs"]
mod integration;
#[path = "instantiate/operators.rs"]
mod operators;
#[path = "instantiate/spans.rs"]
mod spans;
