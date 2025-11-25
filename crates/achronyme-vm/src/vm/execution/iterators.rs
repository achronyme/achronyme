//! Native iterator implementations for collections
//!
//! This module implements iterators for built-in collection types (vectors, strings, tensors)
//! that can be used in for-in loops. These iterators are wrapped as Generator values and
//! work seamlessly with the existing generator infrastructure.

use crate::value::Value;
use achronyme_types::sync::{shared, Shared};

/// Iterator for Vector values
/// Iterates over elements of a vector in order
#[derive(Debug)]
pub struct VectorIterator {
    /// The source vector (shared reference)
    source: Shared<Vec<Value>>,
    /// Current index
    current_index: usize,
}

impl VectorIterator {
    /// Create a new vector iterator
    pub fn new(vector: Shared<Vec<Value>>) -> Self {
        Self {
            source: vector,
            current_index: 0,
        }
    }

    /// Get the next value from the iterator
    /// Returns Some(value) if there are more elements, None if exhausted
    pub fn next(&mut self) -> Option<Value> {
        let vec = self.source.read();
        if self.current_index < vec.len() {
            let value = vec[self.current_index].clone();
            self.current_index += 1;
            Some(value)
        } else {
            None
        }
    }
}

/// Iterator for String values
/// Iterates over characters of a string
#[derive(Debug)]
pub struct StringIterator {
    /// The source string
    #[allow(dead_code)]
    source: String,
    /// Current character index (using char indices, not byte indices)
    current_index: usize,
    /// Cached character vector (to avoid re-collecting on each next() call)
    chars: Vec<char>,
}

impl StringIterator {
    /// Create a new string iterator
    pub fn new(string: String) -> Self {
        let chars: Vec<char> = string.chars().collect();
        Self {
            source: string,
            current_index: 0,
            chars,
        }
    }

    /// Get the next character from the iterator
    /// Returns Some(Value::String) if there are more characters, None if exhausted
    pub fn next(&mut self) -> Option<Value> {
        if self.current_index < self.chars.len() {
            let ch = self.chars[self.current_index];
            self.current_index += 1;
            Some(Value::String(ch.to_string()))
        } else {
            None
        }
    }
}

/// Enum to hold different types of native iterators
/// Uses type erasure pattern similar to Value::Generator
#[derive(Debug)]
pub enum NativeIterator {
    Vector(VectorIterator),
    String(StringIterator),
}

impl NativeIterator {
    /// Get the next value from any native iterator
    pub fn next(&mut self) -> Option<Value> {
        match self {
            NativeIterator::Vector(iter) => iter.next(),
            NativeIterator::String(iter) => iter.next(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_vector_iterator() {
        let vec = shared(vec![
            Value::Number(1.0),
            Value::Number(2.0),
            Value::Number(3.0),
        ]);

        let mut iter = VectorIterator::new(vec);

        assert_eq!(iter.next(), Some(Value::Number(1.0)));
        assert_eq!(iter.next(), Some(Value::Number(2.0)));
        assert_eq!(iter.next(), Some(Value::Number(3.0)));
        assert_eq!(iter.next(), None);
        assert_eq!(iter.next(), None); // Should stay exhausted
    }

    #[test]
    fn test_vector_iterator_empty() {
        let vec = shared(vec![]);
        let mut iter = VectorIterator::new(vec);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_string_iterator() {
        let mut iter = StringIterator::new("abc".to_string());

        assert_eq!(iter.next(), Some(Value::String("a".to_string())));
        assert_eq!(iter.next(), Some(Value::String("b".to_string())));
        assert_eq!(iter.next(), Some(Value::String("c".to_string())));
        assert_eq!(iter.next(), None);
        assert_eq!(iter.next(), None); // Should stay exhausted
    }

    #[test]
    fn test_string_iterator_empty() {
        let mut iter = StringIterator::new("".to_string());
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_string_iterator_unicode() {
        let mut iter = StringIterator::new("😀🎉".to_string());

        assert_eq!(iter.next(), Some(Value::String("😀".to_string())));
        assert_eq!(iter.next(), Some(Value::String("🎉".to_string())));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_native_iterator_vector() {
        let vec = shared(vec![Value::Number(42.0)]);
        let mut iter = NativeIterator::Vector(VectorIterator::new(vec));

        assert_eq!(iter.next(), Some(Value::Number(42.0)));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn test_native_iterator_string() {
        let mut iter = NativeIterator::String(StringIterator::new("hi".to_string()));

        assert_eq!(iter.next(), Some(Value::String("h".to_string())));
        assert_eq!(iter.next(), Some(Value::String("i".to_string())));
        assert_eq!(iter.next(), None);
    }
}
