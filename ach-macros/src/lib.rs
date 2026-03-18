//! Proc-macros for Achronyme native function registration.
//!
//! - `#[ach_native]` — transforms a Rust fn into a `NativeFn` wrapper.
//! - `#[ach_module]` — transforms a mod into a `NativeModule` impl.

use proc_macro::TokenStream;

mod module;
mod native;

/// Attribute macro for native functions.
///
/// # Attributes
/// - `name = "..."` — the function name as seen from Achronyme code
/// - `arity = N` — argument count (-1 for variadic)
///
/// # Signature patterns
///
/// **Pure (no VM access):**
/// ```ignore
/// #[ach_native(name = "abs", arity = 1)]
/// pub fn native_abs(n: i64) -> i64 { n.abs() }
/// ```
///
/// **With VM access (first param `vm: &mut VM`):**
/// ```ignore
/// #[ach_native(name = "to_string", arity = 1)]
/// pub fn native_to_string(vm: &mut VM, val: Value) -> Result<Value, RuntimeError> { ... }
/// ```
///
/// **Variadic (`arity = -1`, last param `args: &[Value]`):**
/// ```ignore
/// #[ach_native(name = "print", arity = -1)]
/// pub fn native_print(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError> { ... }
/// ```
#[proc_macro_attribute]
pub fn ach_native(attr: TokenStream, item: TokenStream) -> TokenStream {
    native::ach_native_impl(attr.into(), item.into())
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}

/// Attribute macro for native modules.
///
/// Collects all `#[ach_native]` functions inside a `mod` and generates
/// a struct implementing `NativeModule`.
///
/// # Attributes
/// - `name = "..."` — the module name returned by `NativeModule::name()`
///
/// # Example
/// ```ignore
/// #[ach_module(name = "math")]
/// mod math_impl {
///     #[ach_native(name = "abs", arity = 1)]
///     pub fn native_abs(n: i64) -> i64 { n.abs() }
/// }
/// // Generates: pub struct MathModule; impl NativeModule for MathModule { ... }
/// ```
#[proc_macro_attribute]
pub fn ach_module(attr: TokenStream, item: TokenStream) -> TokenStream {
    module::ach_module_impl(attr.into(), item.into())
        .unwrap_or_else(|e| e.to_compile_error())
        .into()
}
