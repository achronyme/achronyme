use achronyme_types::value::Value;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::errors::{EnvError, Result};

/// Serializable representation of Achronyme Value
///
/// This intermediate type is necessary because some Value variants
/// (like Function, MutableRef) cannot be directly serialized.
///
/// Note: We use tuple variants instead of struct variants for better
/// MessagePack compatibility.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum SerializedValue {
    Number(f64),
    Boolean(bool),
    String(String),
    Complex(f64, f64),  // (re, im)
    Vector(Vec<SerializedValue>),
    Tensor(Vec<usize>, Vec<f64>),  // (shape, data)
    ComplexTensor(Vec<usize>, Vec<(f64, f64)>),  // (shape, data as (re,im) pairs)
    Record(HashMap<String, SerializedValue>),
    Edge(String, String, bool, HashMap<String, SerializedValue>),  // (from, to, directed, props)
    BuiltinFunction(String),
    /// Null value for optional types
    Null,
    /// Placeholder for non-serializable values
    Unsupported(String),  // type_name
}

impl SerializedValue {
    /// Convert Achronyme Value to SerializedValue
    pub fn from_value(value: &Value) -> Self {
        match value {
            Value::Number(n) => SerializedValue::Number(*n),
            Value::Boolean(b) => SerializedValue::Boolean(*b),
            Value::String(s) => SerializedValue::String(s.clone()),

            Value::Complex(c) => SerializedValue::Complex(c.re, c.im),

            Value::Vector(vec) => {
                let serialized: Vec<SerializedValue> = vec
                    .iter()
                    .map(SerializedValue::from_value)
                    .collect();
                SerializedValue::Vector(serialized)
            }

            Value::Tensor(tensor) => SerializedValue::Tensor(
                tensor.shape().to_vec(),
                tensor.data().to_vec(),
            ),

            Value::ComplexTensor(tensor) => {
                let data: Vec<(f64, f64)> = tensor
                    .data()
                    .iter()
                    .map(|c| (c.re, c.im))
                    .collect();
                SerializedValue::ComplexTensor(
                    tensor.shape().to_vec(),
                    data,
                )
            },

            Value::Record(map) => {
                let serialized: HashMap<String, SerializedValue> = map
                    .iter()
                    .map(|(k, v)| (k.clone(), SerializedValue::from_value(v)))
                    .collect();
                SerializedValue::Record(serialized)
            },

            Value::Edge { from, to, directed, properties } => {
                let serialized_props: HashMap<String, SerializedValue> = properties
                    .iter()
                    .map(|(k, v)| (k.clone(), SerializedValue::from_value(v)))
                    .collect();
                SerializedValue::Edge(
                    from.clone(),
                    to.clone(),
                    *directed,
                    serialized_props,
                )
            },

            Value::Function(func) => {
                // Only serialize builtin functions
                if let Some(name) = func.builtin_name() {
                    SerializedValue::BuiltinFunction(name.to_string())
                } else {
                    SerializedValue::Unsupported("user-defined function".to_string())
                }
            },

            Value::MutableRef(rc) => {
                // Serialize the inner value
                match rc.try_borrow() {
                    Ok(inner) => SerializedValue::from_value(&inner),
                    Err(_) => SerializedValue::Unsupported("borrowed mutable reference".to_string()),
                }
            },

            Value::TailCall(_) => {
                // TailCall should never be persisted
                SerializedValue::Unsupported("tail call".to_string())
            },

            Value::EarlyReturn(_) => {
                // EarlyReturn should never be persisted
                SerializedValue::Unsupported("early return".to_string())
            },

            Value::Null => SerializedValue::Null,

            Value::Generator(_) => {
                // Generators cannot be serialized as they contain runtime state
                SerializedValue::Unsupported("generator".to_string())
            },

            Value::GeneratorYield(_) => {
                // GeneratorYield is an internal marker and should never be persisted
                SerializedValue::Unsupported("generator yield".to_string())
            },

            Value::Error { .. } => {
                // Errors should not be persisted across sessions
                SerializedValue::Unsupported("error".to_string())
            },

            Value::LoopBreak(_) => {
                // LoopBreak is an internal marker and should never be persisted
                SerializedValue::Unsupported("loop break".to_string())
            },

            Value::LoopContinue => {
                // LoopContinue is an internal marker and should never be persisted
                SerializedValue::Unsupported("loop continue".to_string())
            },
        }
    }

    /// Convert SerializedValue back to Achronyme Value
    pub fn to_value(&self) -> Result<Value> {
        match self {
            SerializedValue::Number(n) => Ok(Value::Number(*n)),
            SerializedValue::Boolean(b) => Ok(Value::Boolean(*b)),
            SerializedValue::String(s) => Ok(Value::String(s.clone())),

            SerializedValue::Complex(re, im) => {
                Ok(Value::Complex(achronyme_types::complex::Complex::new(*re, *im)))
            },

            SerializedValue::Vector(vec) => {
                let values: Result<Vec<Value>> = vec
                    .iter()
                    .map(|sv| sv.to_value())
                    .collect();
                Ok(Value::Vector(values?))
            },

            SerializedValue::Tensor(shape, data) => {
                use achronyme_types::tensor::RealTensor;
                let tensor = RealTensor::new(data.clone(), shape.clone())
                    .map_err(|e| EnvError::Deserialization(format!("Invalid tensor: {}", e)))?;
                Ok(Value::Tensor(tensor))
            },

            SerializedValue::ComplexTensor(shape, data) => {
                use achronyme_types::tensor::ComplexTensor;
                use achronyme_types::complex::Complex;

                let complex_data: Vec<Complex> = data
                    .iter()
                    .map(|(re, im)| Complex::new(*re, *im))
                    .collect();

                let tensor = ComplexTensor::new(complex_data, shape.clone())
                    .map_err(|e| EnvError::Deserialization(format!("Invalid complex tensor: {}", e)))?;
                Ok(Value::ComplexTensor(tensor))
            },

            SerializedValue::Record(map) => {
                let mut record = HashMap::new();
                for (k, v) in map {
                    record.insert(k.clone(), v.to_value()?);
                }
                Ok(Value::Record(record))
            },

            SerializedValue::Edge(from, to, directed, properties) => {
                let mut props = HashMap::new();
                for (k, v) in properties {
                    props.insert(k.clone(), v.to_value()?);
                }
                Ok(Value::Edge {
                    from: from.clone(),
                    to: to.clone(),
                    directed: *directed,
                    properties: props,
                })
            },

            SerializedValue::BuiltinFunction(_name) => {
                // For v1.0, we can't restore functions
                // In v2.0, we would look up the function in the registry
                Err(EnvError::Deserialization(
                    "Function restoration not yet supported".to_string()
                ))
            },

            SerializedValue::Null => Ok(Value::Null),

            SerializedValue::Unsupported(type_name) => {
                Err(EnvError::Deserialization(
                    format!("Cannot deserialize unsupported type: {}", type_name)
                ))
            },
        }
    }
}

/// Serialize a Value to MessagePack bytes
pub fn serialize_value(value: &Value) -> Result<Vec<u8>> {
    let serialized = SerializedValue::from_value(value);
    rmp_serde::to_vec(&serialized).map_err(EnvError::from)
}

/// Deserialize a Value from MessagePack bytes
pub fn deserialize_value(bytes: &[u8]) -> Result<Value> {
    let serialized: SerializedValue = rmp_serde::from_slice(bytes)?;
    serialized.to_value()
}

#[cfg(test)]
mod tests {
    use super::*;
    use achronyme_types::complex::Complex;
    use achronyme_types::tensor::RealTensor;

    #[test]
    fn test_serialize_number() {
        let value = Value::Number(42.0);
        let bytes = serialize_value(&value).unwrap();
        let restored = deserialize_value(&bytes).unwrap();
        assert_eq!(value, restored);
    }

    #[test]
    fn test_serialize_boolean() {
        let value = Value::Boolean(true);
        let bytes = serialize_value(&value).unwrap();
        let restored = deserialize_value(&bytes).unwrap();
        assert_eq!(value, restored);
    }

    #[test]
    fn test_serialize_string() {
        let value = Value::String("hello world".to_string());
        let bytes = serialize_value(&value).unwrap();
        let restored = deserialize_value(&bytes).unwrap();
        assert_eq!(value, restored);
    }

    #[test]
    fn test_serialize_complex() {
        let value = Value::Complex(Complex::new(3.0, 4.0));
        let bytes = serialize_value(&value).unwrap();
        let restored = deserialize_value(&bytes).unwrap();
        assert_eq!(value, restored);
    }

    #[test]
    fn test_serialize_vector() {
        let value = Value::Vector(vec![
            Value::Number(1.0),
            Value::Number(2.0),
            Value::Number(3.0),
        ]);
        let bytes = serialize_value(&value).unwrap();
        let restored = deserialize_value(&bytes).unwrap();
        assert_eq!(value, restored);
    }

    #[test]
    fn test_serialize_tensor() {
        let tensor = RealTensor::new(vec![1.0, 2.0, 3.0, 4.0], vec![2, 2]).unwrap();
        let value = Value::Tensor(tensor);
        let bytes = serialize_value(&value).unwrap();
        let restored = deserialize_value(&bytes).unwrap();
        assert_eq!(value, restored);
    }

    #[test]
    fn test_serialize_record() {
        let mut map = HashMap::new();
        map.insert("x".to_string(), Value::Number(10.0));
        map.insert("name".to_string(), Value::String("test".to_string()));

        let value = Value::Record(map);
        let bytes = serialize_value(&value).unwrap();
        let restored = deserialize_value(&bytes).unwrap();
        assert_eq!(value, restored);
    }

    #[test]
    fn test_serialize_nested() {
        let mut inner = HashMap::new();
        inner.insert("a".to_string(), Value::Number(1.0));

        let mut outer = HashMap::new();
        outer.insert("inner".to_string(), Value::Record(inner));
        outer.insert("value".to_string(), Value::Boolean(true));

        let value = Value::Record(outer);
        let bytes = serialize_value(&value).unwrap();
        let restored = deserialize_value(&bytes).unwrap();
        assert_eq!(value, restored);
    }
}
