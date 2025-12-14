pub mod heap;
pub mod value;

#[cfg(test)]
mod value_tests;

pub use heap::{Function, Heap};
pub use value::Value;
