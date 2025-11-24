use crate::complex::Complex;
use crate::function::Function;
use crate::tensor::{ComplexTensor, RealTensor};
use futures::future::{FutureExt, Shared};
use std::any::Any;
use std::cell::RefCell;
use std::collections::HashMap;
use std::future::Future;
use std::pin::Pin;
use std::rc::Rc;

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

/// Wrapper for shared future to implement Clone and Debug
#[derive(Clone)]
pub struct VmFuture(pub Shared<Pin<Box<dyn Future<Output = Value> + Send>>>);

impl VmFuture {
    pub fn new<F>(future: F) -> Self
    where
        F: Future<Output = Value> + Send + 'static,
    {
        VmFuture(future.boxed().shared())
    }
}

impl std::fmt::Debug for VmFuture {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Future")
    }
}

#[derive(Debug, Clone)]
pub enum Value {
    Number(f64),
    Boolean(bool),
    Complex(Complex),
    /// Vector with shared mutable ownership - allows mutation and sharing
    /// Uses Rc<RefCell<>> so that `let b = a` creates a reference, not a copy
    Vector(Rc<RefCell<Vec<Value>>>),
    Tensor(RealTensor),           // Optimized N-dimensional array of real numbers
    ComplexTensor(ComplexTensor), // Optimized N-dimensional array of complex numbers
    Function(Function),           // Both user-defined lambdas and built-in functions
    String(String),
    /// Record (object/map) with shared mutable ownership
    /// Uses Rc<RefCell<>> so that `let b = a` creates a reference, not a copy
    Record(Rc<RefCell<HashMap<String, Value>>>),
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
    /// Future: asynchronous computation that produces a Value
    Future(VmFuture),
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
    /// Iterator (opaque handle for HOF operations)
    /// Uses Rc<dyn Any> for type erasure similar to Generator
    /// In the VM, this contains VmIterator
    Iterator(Rc<dyn Any>),
    /// Builder (opaque handle for HOF operations)
    /// Uses Rc<dyn Any> for type erasure similar to Generator
    /// In the VM, this contains VmBuilder
    Builder(Rc<dyn Any>),
    /// Range value: start..end (step is implicitly 1)
    /// Used for slicing and iteration
    Range {
        start: Box<Value>,
        end: Box<Value>,
        inclusive: bool,
    },
    /// Bound method (intrinsic method linked to a receiver)
    BoundMethod {
        receiver: Box<Value>,
        method_name: String,
    },
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
        vec.borrow()
            .iter()
            .all(|v| matches!(v, Value::Number(_) | Value::Complex(_)))
    }

    /// Convert a generic vector to a RealTensor (rank 1)
    pub fn to_real_tensor(vec: &Rc<RefCell<Vec<Value>>>) -> Result<RealTensor, TypeError> {
        let vec_borrowed = vec.borrow();
        let nums: Result<Vec<f64>, _> = vec_borrowed
            .iter()
            .map(|v| match v {
                Value::Number(n) => Ok(*n),
                _ => Err(TypeError::IncompatibleTypes),
            })
            .collect();

        nums.and_then(|data| {
            let len = data.len();
            RealTensor::new(data, vec![len]).map_err(|_| TypeError::IncompatibleTypes)
        })
    }

    /// Convert a generic vector to a ComplexTensor (rank 1)
    pub fn to_complex_tensor(vec: &Rc<RefCell<Vec<Value>>>) -> Result<ComplexTensor, TypeError> {
        let vec_borrowed = vec.borrow();
        let complexes: Result<Vec<Complex>, _> = vec_borrowed
            .iter()
            .map(|v| match v {
                Value::Number(n) => Ok(Complex::new(*n, 0.0)),
                Value::Complex(c) => Ok(*c),
                _ => Err(TypeError::IncompatibleTypes),
            })
            .collect();

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
            Value::MutableRef(rc) => Ok(rc.borrow().clone()),
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

    /// Attempt to convert a generic value (likely nested Vectors) into a Tensor or ComplexTensor
    pub fn try_to_tensor(&self) -> Option<Value> {
        // 1. Try to convert to RealTensor
        if let Ok((data, shape)) = Self::flatten_real(self) {
            // If it's a scalar (rank 0) or vector (rank 1), we might prefer to keep it as is?
            // But if this is called, it's likely we NEED a tensor (e.g. for multidim slicing).
            // So we convert.
            if let Ok(t) = RealTensor::new(data, shape) {
                return Some(Value::Tensor(t));
            }
        }

        // 2. Try to convert to ComplexTensor (promotes Numbers)
        if let Ok((data, shape)) = Self::flatten_complex(self) {
            if let Ok(t) = ComplexTensor::new(data, shape) {
                return Some(Value::ComplexTensor(t));
            }
        }

        None
    }

    fn flatten_real(v: &Value) -> Result<(Vec<f64>, Vec<usize>), ()> {
        match v {
            Value::Number(n) => Ok((vec![*n], vec![])),
            Value::Vector(vec_rc) => {
                let vec = vec_rc.borrow();
                if vec.is_empty() {
                    return Ok((vec![], vec![0]));
                }

                let (mut data, shape) = Self::flatten_real(&vec[0])?;
                for item in vec.iter().skip(1) {
                    let (sub_data, sub_shape) = Self::flatten_real(item)?;
                    if sub_shape != shape {
                        return Err(()); // Jagged array
                    }
                    data.extend(sub_data);
                }
                let mut new_shape = vec![vec.len()];
                new_shape.extend(shape);
                Ok((data, new_shape))
            }
            _ => Err(()),
        }
    }

    fn flatten_complex(v: &Value) -> Result<(Vec<Complex>, Vec<usize>), ()> {
        match v {
            Value::Number(n) => Ok((vec![Complex::new(*n, 0.0)], vec![])),
            Value::Complex(c) => Ok((vec![*c], vec![])),
            Value::Vector(vec_rc) => {
                let vec = vec_rc.borrow();
                if vec.is_empty() {
                    return Ok((vec![], vec![0]));
                }

                let (mut data, shape) = Self::flatten_complex(&vec[0])?;
                for item in vec.iter().skip(1) {
                    let (sub_data, sub_shape) = Self::flatten_complex(item)?;
                    if sub_shape != shape {
                        return Err(()); // Jagged array
                    }
                    data.extend(sub_data);
                }
                let mut new_shape = vec![vec.len()];
                new_shape.extend(shape);
                Ok((data, new_shape))
            }
            _ => Err(()),
        }
    }
}

// Manual PartialEq implementation (Generator uses Rc<dyn Any> which doesn't impl PartialEq)
impl PartialEq for Value {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (Value::Number(a), Value::Number(b)) => a == b,
            (Value::Boolean(a), Value::Boolean(b)) => a == b,
            (Value::Complex(a), Value::Complex(b)) => a == b,
            (Value::Vector(a), Value::Vector(b)) => Rc::ptr_eq(a, b), // Reference equality
            (Value::Tensor(a), Value::Tensor(b)) => a == b,
            (Value::ComplexTensor(a), Value::ComplexTensor(b)) => a == b,
            (Value::Function(a), Value::Function(b)) => a == b,
            (Value::String(a), Value::String(b)) => a == b,
            (Value::Record(a), Value::Record(b)) => Rc::ptr_eq(a, b), // Reference equality
            (Value::TailCall(a), Value::TailCall(b)) => a == b,
            (Value::EarlyReturn(a), Value::EarlyReturn(b)) => a == b,
            (Value::MutableRef(a), Value::MutableRef(b)) => Rc::ptr_eq(a, b), // Reference equality
            (Value::Null, Value::Null) => true,
            (Value::Generator(a), Value::Generator(b)) => {
                // Generators are compared by pointer equality (same instance)
                std::ptr::eq(a.as_ref() as *const dyn Any, b.as_ref() as *const dyn Any)
            }
            (Value::Future(_), Value::Future(_)) => false, // Futures are unique computations
            (Value::GeneratorYield(a), Value::GeneratorYield(b)) => a == b,
            (
                Value::Error {
                    message: m1,
                    kind: k1,
                    source: s1,
                },
                Value::Error {
                    message: m2,
                    kind: k2,
                    source: s2,
                },
            ) => m1 == m2 && k1 == k2 && s1 == s2,
            (Value::LoopBreak(a), Value::LoopBreak(b)) => a == b,
            (Value::LoopContinue, Value::LoopContinue) => true,
            (Value::Iterator(a), Value::Iterator(b)) => {
                // Iterators are compared by pointer equality (same instance)
                std::ptr::eq(a.as_ref() as *const dyn Any, b.as_ref() as *const dyn Any)
            }
            (Value::Builder(a), Value::Builder(b)) => {
                // Builders are compared by pointer equality (same instance)
                std::ptr::eq(a.as_ref() as *const dyn Any, b.as_ref() as *const dyn Any)
            }
            (
                Value::Range {
                    start: s1,
                    end: e1,
                    inclusive: i1,
                },
                Value::Range {
                    start: s2,
                    end: e2,
                    inclusive: i2,
                },
            ) => s1 == s2 && e1 == e2 && i1 == i2,
            (
                Value::BoundMethod {
                    receiver: r1,
                    method_name: m1,
                },
                Value::BoundMethod {
                    receiver: r2,
                    method_name: m2,
                },
            ) => r1 == r2 && m1 == m2,
            _ => false,
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
                        let result = tensor_a
                            .add(&tensor_b)
                            .map_err(|_| TypeError::IncompatibleTypes)?;
                        Ok(Value::ComplexTensor(result))
                    } else {
                        // Real tensor addition
                        let tensor_a = Value::to_real_tensor(a)?;
                        let tensor_b = Value::to_real_tensor(b)?;
                        let result = tensor_a
                            .add(&tensor_b)
                            .map_err(|_| TypeError::IncompatibleTypes)?;
                        Ok(Value::Tensor(result))
                    }
                } else {
                    Err(TypeError::IncompatibleTypes)
                }
            }
            // Type promotion
            (Value::Number(a), Value::Complex(b)) => Ok(Value::Complex(Complex::new(a, 0.0) + b)),
            _ => Err(TypeError::IncompatibleTypes),
        }
    }
}
