pub mod value;
pub mod heap;

#[cfg(test)]
mod value_tests;

pub use value::Value;
pub use heap::{Heap, Function};
