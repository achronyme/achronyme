use crate::error::RuntimeError;
use crate::machine::VM;
use memory::Value;

// The unified signature for ALL extensions (Internal or External)
// args: Slice of values from the stack.
// Return: Result<Value, RuntimeError> (RuntimeError for type mismatches, etc.)
pub type NativeFn = fn(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError>;

/// Signature for prototype methods.
/// `receiver` is the value the method is called on (already type-checked by tag).
/// `args` contains only the explicit arguments (receiver is NOT included).
pub type MethodFn = fn(vm: &mut VM, receiver: Value, args: &[Value]) -> Result<Value, RuntimeError>;

#[derive(Clone)]
pub struct NativeObj {
    pub name: String,
    pub func: NativeFn,
    pub arity: isize, // -1 for variadic
}
