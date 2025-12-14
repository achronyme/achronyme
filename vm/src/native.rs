use crate::machine::VM;
use memory::Value;
use crate::error::RuntimeError;

// The unified signature for ALL extensions (Internal or External)
// args: Slice of values from the stack.
// Return: Result<Value, RuntimeError> (RuntimeError for type mismatches, etc.)
pub type NativeFn = fn(vm: &mut VM, args: &[Value]) -> Result<Value, RuntimeError>;

#[derive(Clone)]
pub struct NativeObj {
    pub name: String,
    pub func: NativeFn,
    pub arity: isize, // -1 for variadic
}
