use crate::complex::Complex;
use crate::tensor::{RealTensor, ComplexTensor};
use crate::function::Function;
use crate::environment::Environment;
use achronyme_parser::ast::AstNode;
use std::collections::HashMap;
use std::rc::Rc;
use std::cell::RefCell;
use std::any::Any;

#[derive(Debug)]
pub enum TypeError {
    IncompatibleTypes,
}

impl std::fmt::Display for TypeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TypeError::IncompatibleTypes => write!(f, "Incompatible types"),
        }
    }
}

#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    Number(f64),
    Boolean(bool),
    Complex(Complex),
    /// Vector with shared mutable ownership - allows mutation and sharing
    /// Uses Rc<RefCell<>> so that `let b = a` creates a reference, not a copy
    Vector(Rc<RefCell<Vec<Value>>>),
    Tensor(RealTensor),  // Optimized N-dimensional array of real numbers
    ComplexTensor(ComplexTensor),  // Optimized N-dimensional array of complex numbers
    Function(Function),  // Both user-defined lambdas and built-in functions
    String(String),
    /// Record (object/map) with shared mutable ownership
    /// Uses Rc<RefCell<>> so that `let b = a` creates a reference, not a copy
    Record(Rc<RefCell<HashMap<String, Value>>>),
    Edge {
        from: String,
        to: String,
        directed: bool,
        properties: HashMap<String, Value>,
    },
    /// Internal marker for tail call optimization
    /// Contains arguments for the next iteration of a tail-recursive function
    /// This variant should never be exposed to user code or returned from eval_str()
    TailCall(Vec<Value>),
    /// Internal marker for early return from functions
    /// Contains the value to return from the current function
    /// This variant should never be exposed to user code or returned from eval_str()
    EarlyReturn(Box<Value>),
    /// Mutable reference - allows mutation of values declared with `mut` keyword
    /// Uses Rc<RefCell<>> for shared mutable ownership
    MutableRef(Rc<RefCell<Value>>),
    /// Null value - represents absence of value (for optional types)
    /// Used in union types like `Number | null` for optional values
    Null,
    /// Generator: suspended function that can be resumed
    /// Uses Rc<dyn Any> for type erasure to avoid circular dependencies
    /// In the VM, this contains Rc<RefCell<VmGeneratorState>>
    /// In other backends, it can contain their own generator state
    Generator(Rc<dyn Any>),
    /// Internal marker for yield in generators
    /// Contains the value to yield and signals that generator should suspend
    /// This variant should never be exposed to user code
    GeneratorYield(Box<Value>),
    /// Error value for try/catch/throw error handling
    /// Contains message, optional kind (TypeError, ValueError, etc.), and optional source error
    Error {
        message: String,
        kind: Option<String>,
        source: Option<Box<Value>>,
    },
    /// Internal marker for break statement in loops
    /// Contains optional value to return from the loop
    /// This variant should never be exposed to user code
    LoopBreak(Option<Box<Value>>),
    /// Internal marker for continue statement in loops
    /// Signals that the loop should skip to the next iteration
    /// This variant should never be exposed to user code
    LoopContinue,
}


// Conversiones automáticas con From/Into
impl From<f64> for Value {
    fn from(n: f64) -> Self {
        Value::Number(n)
    }
}

// Helper functions for vector operations
impl Value {
    /// Check if a vector is numeric (contains only Number or Complex values)
    pub fn is_numeric_vector(vec: &Rc<RefCell<Vec<Value>>>) -> bool {
        vec.borrow().iter().all(|v| matches!(v, Value::Number(_) | Value::Complex(_)))
    }

    /// Convert a generic vector to a RealTensor (rank 1)
    pub fn to_real_tensor(vec: &Rc<RefCell<Vec<Value>>>) -> Result<RealTensor, TypeError> {
        let vec_borrowed = vec.borrow();
        let nums: Result<Vec<f64>, _> = vec_borrowed.iter().map(|v| match v {
            Value::Number(n) => Ok(*n),
            _ => Err(TypeError::IncompatibleTypes),
        }).collect();

        nums.and_then(|data| {
            let len = data.len();
            RealTensor::new(data, vec![len]).map_err(|_| TypeError::IncompatibleTypes)
        })
    }

    /// Convert a generic vector to a ComplexTensor (rank 1)
    pub fn to_complex_tensor(vec: &Rc<RefCell<Vec<Value>>>) -> Result<ComplexTensor, TypeError> {
        let vec_borrowed = vec.borrow();
        let complexes: Result<Vec<Complex>, _> = vec_borrowed.iter().map(|v| match v {
            Value::Number(n) => Ok(Complex::new(*n, 0.0)),
            Value::Complex(c) => Ok(*c),
            _ => Err(TypeError::IncompatibleTypes),
        }).collect();

        complexes.and_then(|data| {
            let len = data.len();
            ComplexTensor::new(data, vec![len]).map_err(|_| TypeError::IncompatibleTypes)
        })
    }

    /// Convert a RealTensor to a generic vector (if rank 1)
    pub fn from_real_tensor(tensor: RealTensor) -> Value {
        if tensor.is_vector() {
            let vec_data: Vec<Value> = tensor.data().iter().map(|&n| Value::Number(n)).collect();
            Value::Vector(Rc::new(RefCell::new(vec_data)))
        } else {
            Value::Tensor(tensor)
        }
    }

    /// Convert a ComplexTensor to a generic vector (if rank 1) or keep as ComplexTensor
    pub fn from_complex_tensor(tensor: ComplexTensor) -> Value {
        if tensor.is_vector() {
            let vec_data: Vec<Value> = tensor.data().iter().map(|&c| Value::Complex(c)).collect();
            Value::Vector(Rc::new(RefCell::new(vec_data)))
        } else {
            Value::ComplexTensor(tensor)
        }
    }

    pub fn as_complex(&self) -> Option<&Complex> {
        if let Value::Complex(c) = self {
            Some(c)
        } else {
            None
        }
    }

    /// Create a new mutable reference
    pub fn new_mutable(value: Value) -> Value {
        Value::MutableRef(Rc::new(RefCell::new(value)))
    }

    /// Dereferencia un valor mutable (para lectura)
    /// Si el valor es MutableRef, retorna una copia del valor interno
    /// Si no es mutable, retorna una copia del valor mismo
    pub fn deref(&self) -> Result<Value, String> {
        match self {
            Value::MutableRef(rc) => {
                Ok(rc.borrow().clone())
            }
            _ => Ok(self.clone()),
        }
    }

    /// Asigna un nuevo valor a una referencia mutable
    /// Retorna error si el valor no es mutable
    pub fn assign(&self, new_value: Value) -> Result<(), String> {
        match self {
            Value::MutableRef(rc) => {
                *rc.borrow_mut() = new_value;
                Ok(())
            }
            _ => Err("Cannot assign to immutable value".to_string()),
        }
    }

    /// Check if this value is a generator
    pub fn is_generator(&self) -> bool {
        matches!(self, Value::Generator(_))
    }

    /// Get the generator state if this value is a generator
    /// Returns the opaque Any reference - caller must downcast to their concrete type
    pub fn as_generator(&self) -> Option<&Rc<dyn Any>> {
        match self {
            Value::Generator(g) => Some(g),
            _ => None,
        }
    }
}


// Operadores sobrecargados de forma segura
impl std::ops::Add for Value {
    type Output = Result<Value, TypeError>;

    fn add(self, rhs: Value) -> Self::Output {
        match (self, rhs) {
            (Value::Number(a), Value::Number(b)) => Ok(Value::Number(a + b)),
            (Value::Vector(ref a), Value::Vector(ref b)) => {
                // Check if both vectors are numeric
                if Value::is_numeric_vector(a) && Value::is_numeric_vector(b) {
                    // Check if any element is complex
                    let has_complex_a = a.borrow().iter().any(|v| matches!(v, Value::Complex(_)));
                    let has_complex_b = b.borrow().iter().any(|v| matches!(v, Value::Complex(_)));

                    if has_complex_a || has_complex_b {
                        // Complex tensor addition
                        let tensor_a = Value::to_complex_tensor(a)?;
                        let tensor_b = Value::to_complex_tensor(b)?;
                        let result = tensor_a.add(&tensor_b).map_err(|_| TypeError::IncompatibleTypes)?;
                        Ok(Value::ComplexTensor(result))
                    } else {
                        // Real tensor addition
                        let tensor_a = Value::to_real_tensor(a)?;
                        let tensor_b = Value::to_real_tensor(b)?;
                        let result = tensor_a.add(&tensor_b).map_err(|_| TypeError::IncompatibleTypes)?;
                        Ok(Value::Tensor(result))
                    }
                } else {
                    Err(TypeError::IncompatibleTypes)
                }
            }
            // Type promotion
            (Value::Number(a), Value::Complex(b)) => {
                Ok(Value::Complex(Complex::new(a, 0.0) + b))
            }
            _ => Err(TypeError::IncompatibleTypes),
        }
    }
}