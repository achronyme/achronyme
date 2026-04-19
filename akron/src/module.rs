//! NativeModule trait — modular registration of native functions.
//!
//! Each stdlib module (core, string, bigint, collections) implements
//! `NativeModule`, declaring its native functions in one place.
//! External modules (IO, zkML, etc.) will implement the same trait
//! in Phase 2 to extend the VM without modifying its internals.

use crate::native::NativeFn;

/// A single native function definition.
pub struct NativeDef {
    pub name: &'static str,
    pub func: NativeFn,
    pub arity: isize, // -1 = variadic
}

/// Trait implemented by each group of native functions.
///
/// # Contract
///
/// `natives()` must return definitions in a **stable order** — the
/// position within the returned `Vec` determines the global index
/// assigned to each function (after concatenating all modules).
pub trait NativeModule {
    /// Human-readable module name (e.g. `"core"`, `"string"`).
    fn name(&self) -> &'static str;

    /// The native functions provided by this module.
    fn natives(&self) -> Vec<NativeDef>;
}

/// Returns the built-in modules in registration order.
///
/// The order here **must** match the `VmFnHandle` ordering in
/// `resolve::BuiltinRegistry::default()` — `bootstrap_natives` verifies this.
pub fn builtin_modules() -> Vec<Box<dyn NativeModule>> {
    use crate::stdlib::{bigint::BigintModule, core::CoreModule};

    vec![Box::new(CoreModule), Box::new(BigintModule)]
}
