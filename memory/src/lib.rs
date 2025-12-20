pub mod heap;
pub mod value;

#[cfg(test)]
mod value_tests;

pub use heap::{Function, Heap, Upvalue, Closure};
pub use value::{Value, QNAN, TAG_NIL, TAG_TRUE, TAG_FALSE, TAG_STRING, TAG_LIST, TAG_MAP, TAG_FUNCTION, TAG_CLOSURE, TAG_NATIVE};
