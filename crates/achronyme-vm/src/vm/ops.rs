//! Value operation helpers

use crate::error::VmError;
use crate::value::Value;

/// Implementation of value operations for the VM
pub(crate) struct ValueOperations;

impl ValueOperations {
    pub(crate) fn add_values(left: &Value, right: &Value) -> Result<Value, VmError> {
        use achronyme_types::complex::Complex;
        use std::cell::RefCell;
        use std::rc::Rc;

        match (left, right) {
            (Value::Number(a), Value::Number(b)) => Ok(Value::Number(a + b)),
            (Value::String(a), Value::String(b)) => Ok(Value::String(format!("{}{}", a, b))),
            (Value::Complex(a), Value::Complex(b)) => Ok(Value::Complex(*a + *b)),
            (Value::Number(a), Value::Complex(b)) => Ok(Value::Complex(Complex::new(*a, 0.0) + *b)),
            (Value::Complex(a), Value::Number(b)) => Ok(Value::Complex(*a + Complex::new(*b, 0.0))),

            // Vector + Vector
            (Value::Vector(ref a), Value::Vector(ref b)) => {
                if Value::is_numeric_vector(a) && Value::is_numeric_vector(b) {
                    let a_borrow = a.borrow();
                    let b_borrow = b.borrow();

                    if a_borrow.len() != b_borrow.len() {
                        return Err(VmError::TypeError {
                            operation: "addition".to_string(),
                            expected: "vectors of same length".to_string(),
                            got: format!(
                                "vectors of length {} and {}",
                                a_borrow.len(),
                                b_borrow.len()
                            ),
                        });
                    }

                    let result: Vec<Value> = a_borrow
                        .iter()
                        .zip(b_borrow.iter())
                        .map(|(av, bv)| match (av, bv) {
                            (Value::Number(an), Value::Number(bn)) => Value::Number(an + bn),
                            (Value::Number(an), Value::Complex(bc)) => {
                                Value::Complex(Complex::from_real(*an) + *bc)
                            }
                            (Value::Complex(ac), Value::Number(bn)) => {
                                Value::Complex(*ac + Complex::from_real(*bn))
                            }
                            (Value::Complex(ac), Value::Complex(bc)) => Value::Complex(*ac + *bc),
                            _ => unreachable!(),
                        })
                        .collect();
                    Ok(Value::Vector(Rc::new(RefCell::new(result))))
                } else {
                    Err(VmError::TypeError {
                        operation: "addition".to_string(),
                        expected: "numeric vectors".to_string(),
                        got: format!("{:?} + {:?}", left, right),
                    })
                }
            }

            // Broadcasting: Number + Vector
            (Value::Number(scalar), Value::Vector(ref vec)) => {
                if Value::is_numeric_vector(vec) {
                    let vec_borrow = vec.borrow();
                    let result: Vec<Value> = vec_borrow
                        .iter()
                        .map(|v| match v {
                            Value::Number(n) => Value::Number(n + scalar),
                            Value::Complex(c) => Value::Complex(*c + Complex::from_real(*scalar)),
                            _ => unreachable!(),
                        })
                        .collect();
                    Ok(Value::Vector(Rc::new(RefCell::new(result))))
                } else {
                    Err(VmError::TypeError {
                        operation: "addition".to_string(),
                        expected: "numeric vector for broadcasting".to_string(),
                        got: format!("{:?} + {:?}", left, right),
                    })
                }
            }
            (Value::Vector(ref vec), Value::Number(scalar)) => {
                if Value::is_numeric_vector(vec) {
                    let vec_borrow = vec.borrow();
                    let result: Vec<Value> = vec_borrow
                        .iter()
                        .map(|v| match v {
                            Value::Number(n) => Value::Number(n + scalar),
                            Value::Complex(c) => Value::Complex(*c + Complex::from_real(*scalar)),
                            _ => unreachable!(),
                        })
                        .collect();
                    Ok(Value::Vector(Rc::new(RefCell::new(result))))
                } else {
                    Err(VmError::TypeError {
                        operation: "addition".to_string(),
                        expected: "numeric vector for broadcasting".to_string(),
                        got: format!("{:?} + {:?}", left, right),
                    })
                }
            }

            // Broadcasting: Complex + Vector
            (Value::Complex(c), Value::Vector(ref vec)) => {
                if Value::is_numeric_vector(vec) {
                    let vec_borrow = vec.borrow();
                    let result: Vec<Value> = vec_borrow
                        .iter()
                        .map(|v| match v {
                            Value::Number(n) => Value::Complex(Complex::from_real(*n) + *c),
                            Value::Complex(cv) => Value::Complex(*cv + *c),
                            _ => unreachable!(),
                        })
                        .collect();
                    Ok(Value::Vector(Rc::new(RefCell::new(result))))
                } else {
                    Err(VmError::TypeError {
                        operation: "addition".to_string(),
                        expected: "numeric vector for broadcasting".to_string(),
                        got: format!("{:?} + {:?}", left, right),
                    })
                }
            }
            (Value::Vector(ref vec), Value::Complex(c)) => {
                if Value::is_numeric_vector(vec) {
                    let vec_borrow = vec.borrow();
                    let result: Vec<Value> = vec_borrow
                        .iter()
                        .map(|v| match v {
                            Value::Number(n) => Value::Complex(Complex::from_real(*n) + *c),
                            Value::Complex(cv) => Value::Complex(*cv + *c),
                            _ => unreachable!(),
                        })
                        .collect();
                    Ok(Value::Vector(Rc::new(RefCell::new(result))))
                } else {
                    Err(VmError::TypeError {
                        operation: "addition".to_string(),
                        expected: "numeric vector for broadcasting".to_string(),
                        got: format!("{:?} + {:?}", left, right),
                    })
                }
            }

            // String concatenation with automatic conversion
            (Value::String(s), other) => {
                let other_str = Self::value_to_string(other);
                Ok(Value::String(format!("{}{}", s, other_str)))
            }
            (other, Value::String(s)) => {
                let other_str = Self::value_to_string(other);
                Ok(Value::String(format!("{}{}", other_str, s)))
            }
            _ => Err(VmError::TypeError {
                operation: "addition".to_string(),
                expected: "Number, Complex, String, or Vector".to_string(),
                got: format!("{:?} + {:?}", left, right),
            }),
        }
    }

    pub(crate) fn sub_values(left: &Value, right: &Value) -> Result<Value, VmError> {
        use achronyme_types::complex::Complex;
        use std::cell::RefCell;
        use std::rc::Rc;

        match (left, right) {
            (Value::Number(a), Value::Number(b)) => Ok(Value::Number(a - b)),
            (Value::Complex(a), Value::Complex(b)) => Ok(Value::Complex(*a - *b)),
            (Value::Number(a), Value::Complex(b)) => Ok(Value::Complex(Complex::new(*a, 0.0) - *b)),
            (Value::Complex(a), Value::Number(b)) => Ok(Value::Complex(*a - Complex::new(*b, 0.0))),

            // Vector - Vector
            (Value::Vector(ref a), Value::Vector(ref b)) => {
                if Value::is_numeric_vector(a) && Value::is_numeric_vector(b) {
                    let a_borrow = a.borrow();
                    let b_borrow = b.borrow();

                    if a_borrow.len() != b_borrow.len() {
                        return Err(VmError::TypeError {
                            operation: "subtraction".to_string(),
                            expected: "vectors of same length".to_string(),
                            got: format!(
                                "vectors of length {} and {}",
                                a_borrow.len(),
                                b_borrow.len()
                            ),
                        });
                    }

                    let result: Vec<Value> = a_borrow
                        .iter()
                        .zip(b_borrow.iter())
                        .map(|(av, bv)| match (av, bv) {
                            (Value::Number(an), Value::Number(bn)) => Value::Number(an - bn),
                            (Value::Number(an), Value::Complex(bc)) => {
                                Value::Complex(Complex::from_real(*an) - *bc)
                            }
                            (Value::Complex(ac), Value::Number(bn)) => {
                                Value::Complex(*ac - Complex::from_real(*bn))
                            }
                            (Value::Complex(ac), Value::Complex(bc)) => Value::Complex(*ac - *bc),
                            _ => unreachable!(),
                        })
                        .collect();
                    Ok(Value::Vector(Rc::new(RefCell::new(result))))
                } else {
                    Err(VmError::TypeError {
                        operation: "subtraction".to_string(),
                        expected: "numeric vectors".to_string(),
                        got: format!("{:?} - {:?}", left, right),
                    })
                }
            }

            // Broadcasting: Number - Vector
            (Value::Number(scalar), Value::Vector(ref vec)) => {
                if Value::is_numeric_vector(vec) {
                    let vec_borrow = vec.borrow();
                    let result: Vec<Value> = vec_borrow
                        .iter()
                        .map(|v| match v {
                            Value::Number(n) => Value::Number(scalar - n),
                            Value::Complex(c) => Value::Complex(Complex::from_real(*scalar) - *c),
                            _ => unreachable!(),
                        })
                        .collect();
                    Ok(Value::Vector(Rc::new(RefCell::new(result))))
                } else {
                    Err(VmError::TypeError {
                        operation: "subtraction".to_string(),
                        expected: "numeric vector for broadcasting".to_string(),
                        got: format!("{:?} - {:?}", left, right),
                    })
                }
            }
            (Value::Vector(ref vec), Value::Number(scalar)) => {
                if Value::is_numeric_vector(vec) {
                    let vec_borrow = vec.borrow();
                    let result: Vec<Value> = vec_borrow
                        .iter()
                        .map(|v| match v {
                            Value::Number(n) => Value::Number(n - scalar),
                            Value::Complex(c) => Value::Complex(*c - Complex::from_real(*scalar)),
                            _ => unreachable!(),
                        })
                        .collect();
                    Ok(Value::Vector(Rc::new(RefCell::new(result))))
                } else {
                    Err(VmError::TypeError {
                        operation: "subtraction".to_string(),
                        expected: "numeric vector for broadcasting".to_string(),
                        got: format!("{:?} - {:?}", left, right),
                    })
                }
            }

            // Broadcasting: Complex - Vector
            (Value::Complex(c), Value::Vector(ref vec)) => {
                if Value::is_numeric_vector(vec) {
                    let vec_borrow = vec.borrow();
                    let result: Vec<Value> = vec_borrow
                        .iter()
                        .map(|v| match v {
                            Value::Number(n) => Value::Complex(*c - Complex::from_real(*n)),
                            Value::Complex(cv) => Value::Complex(*c - *cv),
                            _ => unreachable!(),
                        })
                        .collect();
                    Ok(Value::Vector(Rc::new(RefCell::new(result))))
                } else {
                    Err(VmError::TypeError {
                        operation: "subtraction".to_string(),
                        expected: "numeric vector for broadcasting".to_string(),
                        got: format!("{:?} - {:?}", left, right),
                    })
                }
            }
            (Value::Vector(ref vec), Value::Complex(c)) => {
                if Value::is_numeric_vector(vec) {
                    let vec_borrow = vec.borrow();
                    let result: Vec<Value> = vec_borrow
                        .iter()
                        .map(|v| match v {
                            Value::Number(n) => Value::Complex(Complex::from_real(*n) - *c),
                            Value::Complex(cv) => Value::Complex(*cv - *c),
                            _ => unreachable!(),
                        })
                        .collect();
                    Ok(Value::Vector(Rc::new(RefCell::new(result))))
                } else {
                    Err(VmError::TypeError {
                        operation: "subtraction".to_string(),
                        expected: "numeric vector for broadcasting".to_string(),
                        got: format!("{:?} - {:?}", left, right),
                    })
                }
            }

            _ => Err(VmError::TypeError {
                operation: "subtraction".to_string(),
                expected: "Number, Complex, or Vector".to_string(),
                got: format!("{:?} - {:?}", left, right),
            }),
        }
    }

    pub(crate) fn mul_values(left: &Value, right: &Value) -> Result<Value, VmError> {
        use achronyme_types::complex::Complex;
        use std::cell::RefCell;
        use std::rc::Rc;

        match (left, right) {
            (Value::Number(a), Value::Number(b)) => Ok(Value::Number(a * b)),
            (Value::Complex(a), Value::Complex(b)) => Ok(Value::Complex(*a * *b)),
            (Value::Number(a), Value::Complex(b)) => Ok(Value::Complex(Complex::new(*a, 0.0) * *b)),
            (Value::Complex(a), Value::Number(b)) => Ok(Value::Complex(*a * Complex::new(*b, 0.0))),

            // Vector * Vector (element-wise)
            (Value::Vector(ref a), Value::Vector(ref b)) => {
                if Value::is_numeric_vector(a) && Value::is_numeric_vector(b) {
                    let a_borrow = a.borrow();
                    let b_borrow = b.borrow();

                    if a_borrow.len() != b_borrow.len() {
                        return Err(VmError::TypeError {
                            operation: "multiplication".to_string(),
                            expected: "vectors of same length".to_string(),
                            got: format!(
                                "vectors of length {} and {}",
                                a_borrow.len(),
                                b_borrow.len()
                            ),
                        });
                    }

                    let result: Vec<Value> = a_borrow
                        .iter()
                        .zip(b_borrow.iter())
                        .map(|(av, bv)| match (av, bv) {
                            (Value::Number(an), Value::Number(bn)) => Value::Number(an * bn),
                            (Value::Number(an), Value::Complex(bc)) => {
                                Value::Complex(Complex::from_real(*an) * *bc)
                            }
                            (Value::Complex(ac), Value::Number(bn)) => {
                                Value::Complex(*ac * Complex::from_real(*bn))
                            }
                            (Value::Complex(ac), Value::Complex(bc)) => Value::Complex(*ac * *bc),
                            _ => unreachable!(),
                        })
                        .collect();
                    Ok(Value::Vector(Rc::new(RefCell::new(result))))
                } else {
                    Err(VmError::TypeError {
                        operation: "multiplication".to_string(),
                        expected: "numeric vectors".to_string(),
                        got: format!("{:?} * {:?}", left, right),
                    })
                }
            }

            // Broadcasting: Number * Vector
            (Value::Number(scalar), Value::Vector(ref vec)) => {
                if Value::is_numeric_vector(vec) {
                    let vec_borrow = vec.borrow();
                    let result: Vec<Value> = vec_borrow
                        .iter()
                        .map(|v| match v {
                            Value::Number(n) => Value::Number(n * scalar),
                            Value::Complex(c) => Value::Complex(*c * Complex::from_real(*scalar)),
                            _ => unreachable!(),
                        })
                        .collect();
                    Ok(Value::Vector(Rc::new(RefCell::new(result))))
                } else {
                    Err(VmError::TypeError {
                        operation: "multiplication".to_string(),
                        expected: "numeric vector for broadcasting".to_string(),
                        got: format!("{:?} * {:?}", left, right),
                    })
                }
            }
            (Value::Vector(ref vec), Value::Number(scalar)) => {
                if Value::is_numeric_vector(vec) {
                    let vec_borrow = vec.borrow();
                    let result: Vec<Value> = vec_borrow
                        .iter()
                        .map(|v| match v {
                            Value::Number(n) => Value::Number(n * scalar),
                            Value::Complex(c) => Value::Complex(*c * Complex::from_real(*scalar)),
                            _ => unreachable!(),
                        })
                        .collect();
                    Ok(Value::Vector(Rc::new(RefCell::new(result))))
                } else {
                    Err(VmError::TypeError {
                        operation: "multiplication".to_string(),
                        expected: "numeric vector for broadcasting".to_string(),
                        got: format!("{:?} * {:?}", left, right),
                    })
                }
            }

            // Broadcasting: Complex * Vector
            (Value::Complex(c), Value::Vector(ref vec)) => {
                if Value::is_numeric_vector(vec) {
                    let vec_borrow = vec.borrow();
                    let result: Vec<Value> = vec_borrow
                        .iter()
                        .map(|v| match v {
                            Value::Number(n) => Value::Complex(Complex::from_real(*n) * *c),
                            Value::Complex(cv) => Value::Complex(*cv * *c),
                            _ => unreachable!(),
                        })
                        .collect();
                    Ok(Value::Vector(Rc::new(RefCell::new(result))))
                } else {
                    Err(VmError::TypeError {
                        operation: "multiplication".to_string(),
                        expected: "numeric vector for broadcasting".to_string(),
                        got: format!("{:?} * {:?}", left, right),
                    })
                }
            }
            (Value::Vector(ref vec), Value::Complex(c)) => {
                if Value::is_numeric_vector(vec) {
                    let vec_borrow = vec.borrow();
                    let result: Vec<Value> = vec_borrow
                        .iter()
                        .map(|v| match v {
                            Value::Number(n) => Value::Complex(Complex::from_real(*n) * *c),
                            Value::Complex(cv) => Value::Complex(*cv * *c),
                            _ => unreachable!(),
                        })
                        .collect();
                    Ok(Value::Vector(Rc::new(RefCell::new(result))))
                } else {
                    Err(VmError::TypeError {
                        operation: "multiplication".to_string(),
                        expected: "numeric vector for broadcasting".to_string(),
                        got: format!("{:?} * {:?}", left, right),
                    })
                }
            }

            // String repetition: String * Number
            (Value::String(s), Value::Number(n)) => {
                if *n < 0.0 {
                    Err(VmError::TypeError {
                        operation: "string repetition".to_string(),
                        expected: "non-negative number".to_string(),
                        got: format!("negative count: {}", n),
                    })
                } else if !n.is_finite() {
                    Err(VmError::TypeError {
                        operation: "string repetition".to_string(),
                        expected: "finite number".to_string(),
                        got: "infinite count".to_string(),
                    })
                } else {
                    let count = *n as usize;
                    Ok(Value::String(s.repeat(count)))
                }
            }
            (Value::Number(n), Value::String(s)) => {
                if *n < 0.0 {
                    Err(VmError::TypeError {
                        operation: "string repetition".to_string(),
                        expected: "non-negative number".to_string(),
                        got: format!("negative count: {}", n),
                    })
                } else if !n.is_finite() {
                    Err(VmError::TypeError {
                        operation: "string repetition".to_string(),
                        expected: "finite number".to_string(),
                        got: "infinite count".to_string(),
                    })
                } else {
                    let count = *n as usize;
                    Ok(Value::String(s.repeat(count)))
                }
            }

            _ => Err(VmError::TypeError {
                operation: "multiplication".to_string(),
                expected: "Number, Complex, String, or Vector".to_string(),
                got: format!("{:?} * {:?}", left, right),
            }),
        }
    }

    pub(crate) fn div_values(left: &Value, right: &Value) -> Result<Value, VmError> {
        use achronyme_types::complex::Complex;
        use std::cell::RefCell;
        use std::rc::Rc;

        match (left, right) {
            (Value::Number(a), Value::Number(b)) => {
                // IEEE 754 semantics: division by zero produces Infinity or NaN
                // a / 0 = Infinity (if a > 0)
                // a / 0 = -Infinity (if a < 0)
                // 0 / 0 = NaN
                Ok(Value::Number(a / b))
            }
            (Value::Complex(a), Value::Complex(b)) => Ok(Value::Complex(*a / *b)),
            (Value::Number(a), Value::Complex(b)) => Ok(Value::Complex(Complex::new(*a, 0.0) / *b)),
            (Value::Complex(a), Value::Number(b)) => {
                // IEEE 754: division by zero is allowed, produces Infinity/NaN components
                Ok(Value::Complex(*a / Complex::new(*b, 0.0)))
            }

            // Vector / Vector (element-wise)
            (Value::Vector(ref a), Value::Vector(ref b)) => {
                if Value::is_numeric_vector(a) && Value::is_numeric_vector(b) {
                    let a_borrow = a.borrow();
                    let b_borrow = b.borrow();

                    if a_borrow.len() != b_borrow.len() {
                        return Err(VmError::TypeError {
                            operation: "division".to_string(),
                            expected: "vectors of same length".to_string(),
                            got: format!(
                                "vectors of length {} and {}",
                                a_borrow.len(),
                                b_borrow.len()
                            ),
                        });
                    }

                    let result: Vec<Value> = a_borrow
                        .iter()
                        .zip(b_borrow.iter())
                        .map(|(av, bv)| match (av, bv) {
                            (Value::Number(an), Value::Number(bn)) => Value::Number(an / bn),
                            (Value::Number(an), Value::Complex(bc)) => {
                                Value::Complex(Complex::from_real(*an) / *bc)
                            }
                            (Value::Complex(ac), Value::Number(bn)) => {
                                Value::Complex(*ac / Complex::from_real(*bn))
                            }
                            (Value::Complex(ac), Value::Complex(bc)) => Value::Complex(*ac / *bc),
                            _ => unreachable!(),
                        })
                        .collect();
                    Ok(Value::Vector(Rc::new(RefCell::new(result))))
                } else {
                    Err(VmError::TypeError {
                        operation: "division".to_string(),
                        expected: "numeric vectors".to_string(),
                        got: format!("{:?} / {:?}", left, right),
                    })
                }
            }

            // Broadcasting: Number / Vector
            (Value::Number(scalar), Value::Vector(ref vec)) => {
                if Value::is_numeric_vector(vec) {
                    let vec_borrow = vec.borrow();
                    let result: Vec<Value> = vec_borrow
                        .iter()
                        .map(|v| match v {
                            Value::Number(n) => Value::Number(scalar / n),
                            Value::Complex(c) => Value::Complex(Complex::from_real(*scalar) / *c),
                            _ => unreachable!(),
                        })
                        .collect();
                    Ok(Value::Vector(Rc::new(RefCell::new(result))))
                } else {
                    Err(VmError::TypeError {
                        operation: "division".to_string(),
                        expected: "numeric vector for broadcasting".to_string(),
                        got: format!("{:?} / {:?}", left, right),
                    })
                }
            }
            (Value::Vector(ref vec), Value::Number(scalar)) => {
                if Value::is_numeric_vector(vec) {
                    let vec_borrow = vec.borrow();
                    let result: Vec<Value> = vec_borrow
                        .iter()
                        .map(|v| match v {
                            Value::Number(n) => Value::Number(n / scalar),
                            Value::Complex(c) => Value::Complex(*c / Complex::from_real(*scalar)),
                            _ => unreachable!(),
                        })
                        .collect();
                    Ok(Value::Vector(Rc::new(RefCell::new(result))))
                } else {
                    Err(VmError::TypeError {
                        operation: "division".to_string(),
                        expected: "numeric vector for broadcasting".to_string(),
                        got: format!("{:?} / {:?}", left, right),
                    })
                }
            }

            // Broadcasting: Complex / Vector
            (Value::Complex(c), Value::Vector(ref vec)) => {
                if Value::is_numeric_vector(vec) {
                    let vec_borrow = vec.borrow();
                    let result: Vec<Value> = vec_borrow
                        .iter()
                        .map(|v| match v {
                            Value::Number(n) => Value::Complex(*c / Complex::from_real(*n)),
                            Value::Complex(cv) => Value::Complex(*c / *cv),
                            _ => unreachable!(),
                        })
                        .collect();
                    Ok(Value::Vector(Rc::new(RefCell::new(result))))
                } else {
                    Err(VmError::TypeError {
                        operation: "division".to_string(),
                        expected: "numeric vector for broadcasting".to_string(),
                        got: format!("{:?} / {:?}", left, right),
                    })
                }
            }
            (Value::Vector(ref vec), Value::Complex(c)) => {
                if Value::is_numeric_vector(vec) {
                    let vec_borrow = vec.borrow();
                    let result: Vec<Value> = vec_borrow
                        .iter()
                        .map(|v| match v {
                            Value::Number(n) => Value::Complex(Complex::from_real(*n) / *c),
                            Value::Complex(cv) => Value::Complex(*cv / *c),
                            _ => unreachable!(),
                        })
                        .collect();
                    Ok(Value::Vector(Rc::new(RefCell::new(result))))
                } else {
                    Err(VmError::TypeError {
                        operation: "division".to_string(),
                        expected: "numeric vector for broadcasting".to_string(),
                        got: format!("{:?} / {:?}", left, right),
                    })
                }
            }

            _ => Err(VmError::TypeError {
                operation: "division".to_string(),
                expected: "Number, Complex, or Vector".to_string(),
                got: format!("{:?} / {:?}", left, right),
            }),
        }
    }

    pub(crate) fn mod_values(left: &Value, right: &Value) -> Result<Value, VmError> {
        use std::cell::RefCell;
        use std::rc::Rc;

        match (left, right) {
            (Value::Number(a), Value::Number(b)) => Ok(Value::Number(a % b)),

            // Vector % Vector (element-wise)
            (Value::Vector(ref a), Value::Vector(ref b)) => {
                if Value::is_numeric_vector(a) && Value::is_numeric_vector(b) {
                    let a_borrow = a.borrow();
                    let b_borrow = b.borrow();

                    if a_borrow.len() != b_borrow.len() {
                        return Err(VmError::TypeError {
                            operation: "modulo".to_string(),
                            expected: "vectors of same length".to_string(),
                            got: format!(
                                "vectors of length {} and {}",
                                a_borrow.len(),
                                b_borrow.len()
                            ),
                        });
                    }

                    // Modulo only defined for real numbers
                    if a_borrow.iter().any(|v| matches!(v, Value::Complex(_)))
                        || b_borrow.iter().any(|v| matches!(v, Value::Complex(_)))
                    {
                        return Err(VmError::TypeError {
                            operation: "modulo".to_string(),
                            expected: "real numeric vectors".to_string(),
                            got: "complex numbers in vector".to_string(),
                        });
                    }

                    let result: Vec<Value> = a_borrow
                        .iter()
                        .zip(b_borrow.iter())
                        .map(|(av, bv)| match (av, bv) {
                            (Value::Number(an), Value::Number(bn)) => Value::Number(an % bn),
                            _ => unreachable!(),
                        })
                        .collect();
                    Ok(Value::Vector(Rc::new(RefCell::new(result))))
                } else {
                    Err(VmError::TypeError {
                        operation: "modulo".to_string(),
                        expected: "numeric vectors".to_string(),
                        got: format!("{:?} % {:?}", left, right),
                    })
                }
            }

            // Broadcasting: Number % Vector
            (Value::Number(scalar), Value::Vector(ref vec)) => {
                if Value::is_numeric_vector(vec) {
                    let vec_borrow = vec.borrow();

                    if vec_borrow.iter().any(|v| matches!(v, Value::Complex(_))) {
                        return Err(VmError::TypeError {
                            operation: "modulo".to_string(),
                            expected: "real numeric vector".to_string(),
                            got: "complex numbers in vector".to_string(),
                        });
                    }

                    let result: Vec<Value> = vec_borrow
                        .iter()
                        .map(|v| match v {
                            Value::Number(n) => Value::Number(scalar % n),
                            _ => unreachable!(),
                        })
                        .collect();
                    Ok(Value::Vector(Rc::new(RefCell::new(result))))
                } else {
                    Err(VmError::TypeError {
                        operation: "modulo".to_string(),
                        expected: "numeric vector for broadcasting".to_string(),
                        got: format!("{:?} % {:?}", left, right),
                    })
                }
            }
            (Value::Vector(ref vec), Value::Number(scalar)) => {
                if Value::is_numeric_vector(vec) {
                    let vec_borrow = vec.borrow();

                    if vec_borrow.iter().any(|v| matches!(v, Value::Complex(_))) {
                        return Err(VmError::TypeError {
                            operation: "modulo".to_string(),
                            expected: "real numeric vector".to_string(),
                            got: "complex numbers in vector".to_string(),
                        });
                    }

                    let result: Vec<Value> = vec_borrow
                        .iter()
                        .map(|v| match v {
                            Value::Number(n) => Value::Number(n % scalar),
                            _ => unreachable!(),
                        })
                        .collect();
                    Ok(Value::Vector(Rc::new(RefCell::new(result))))
                } else {
                    Err(VmError::TypeError {
                        operation: "modulo".to_string(),
                        expected: "numeric vector for broadcasting".to_string(),
                        got: format!("{:?} % {:?}", left, right),
                    })
                }
            }

            _ => Err(VmError::TypeError {
                operation: "modulo".to_string(),
                expected: "Number or Vector".to_string(),
                got: format!("{:?} % {:?}", left, right),
            }),
        }
    }

    pub(crate) fn pow_values(left: &Value, right: &Value) -> Result<Value, VmError> {
        use achronyme_types::complex::Complex;
        use std::cell::RefCell;
        use std::rc::Rc;

        match (left, right) {
            (Value::Number(a), Value::Number(b)) => Ok(Value::Number(a.powf(*b))),
            (Value::Complex(a), Value::Complex(b)) => Ok(Value::Complex(a.pow_complex(b))),
            (Value::Number(a), Value::Complex(b)) => {
                Ok(Value::Complex(Complex::new(*a, 0.0).pow_complex(b)))
            }
            (Value::Complex(a), Value::Number(b)) => Ok(Value::Complex(a.pow(*b))),

            // Vector ^ Vector (element-wise)
            (Value::Vector(ref a), Value::Vector(ref b)) => {
                if Value::is_numeric_vector(a) && Value::is_numeric_vector(b) {
                    let a_borrow = a.borrow();
                    let b_borrow = b.borrow();

                    if a_borrow.len() != b_borrow.len() {
                        return Err(VmError::TypeError {
                            operation: "exponentiation".to_string(),
                            expected: "vectors of same length".to_string(),
                            got: format!(
                                "vectors of length {} and {}",
                                a_borrow.len(),
                                b_borrow.len()
                            ),
                        });
                    }

                    let result: Vec<Value> = a_borrow
                        .iter()
                        .zip(b_borrow.iter())
                        .map(|(av, bv)| match (av, bv) {
                            (Value::Number(an), Value::Number(bn)) => Value::Number(an.powf(*bn)),
                            (Value::Number(an), Value::Complex(bc)) => {
                                Value::Complex(Complex::from_real(*an).pow_complex(bc))
                            }
                            (Value::Complex(ac), Value::Number(bn)) => Value::Complex(ac.pow(*bn)),
                            (Value::Complex(ac), Value::Complex(bc)) => {
                                Value::Complex(ac.pow_complex(bc))
                            }
                            _ => unreachable!(),
                        })
                        .collect();
                    Ok(Value::Vector(Rc::new(RefCell::new(result))))
                } else {
                    Err(VmError::TypeError {
                        operation: "exponentiation".to_string(),
                        expected: "numeric vectors".to_string(),
                        got: format!("{:?} ^ {:?}", left, right),
                    })
                }
            }

            // Broadcasting: Number ^ Vector
            (Value::Number(scalar), Value::Vector(ref vec)) => {
                if Value::is_numeric_vector(vec) {
                    let vec_borrow = vec.borrow();
                    let result: Vec<Value> = vec_borrow
                        .iter()
                        .map(|v| match v {
                            Value::Number(n) => Value::Number(scalar.powf(*n)),
                            Value::Complex(c) => {
                                Value::Complex(Complex::from_real(*scalar).pow_complex(c))
                            }
                            _ => unreachable!(),
                        })
                        .collect();
                    Ok(Value::Vector(Rc::new(RefCell::new(result))))
                } else {
                    Err(VmError::TypeError {
                        operation: "exponentiation".to_string(),
                        expected: "numeric vector for broadcasting".to_string(),
                        got: format!("{:?} ^ {:?}", left, right),
                    })
                }
            }
            (Value::Vector(ref vec), Value::Number(scalar)) => {
                if Value::is_numeric_vector(vec) {
                    let vec_borrow = vec.borrow();
                    let result: Vec<Value> = vec_borrow
                        .iter()
                        .map(|v| match v {
                            Value::Number(n) => Value::Number(n.powf(*scalar)),
                            Value::Complex(c) => Value::Complex(c.pow(*scalar)),
                            _ => unreachable!(),
                        })
                        .collect();
                    Ok(Value::Vector(Rc::new(RefCell::new(result))))
                } else {
                    Err(VmError::TypeError {
                        operation: "exponentiation".to_string(),
                        expected: "numeric vector for broadcasting".to_string(),
                        got: format!("{:?} ^ {:?}", left, right),
                    })
                }
            }

            // Broadcasting: Complex ^ Vector
            (Value::Complex(c), Value::Vector(ref vec)) => {
                if Value::is_numeric_vector(vec) {
                    let vec_borrow = vec.borrow();
                    let result: Vec<Value> = vec_borrow
                        .iter()
                        .map(|v| match v {
                            Value::Number(n) => Value::Complex(c.pow(*n)),
                            Value::Complex(cv) => Value::Complex(c.pow_complex(cv)),
                            _ => unreachable!(),
                        })
                        .collect();
                    Ok(Value::Vector(Rc::new(RefCell::new(result))))
                } else {
                    Err(VmError::TypeError {
                        operation: "exponentiation".to_string(),
                        expected: "numeric vector for broadcasting".to_string(),
                        got: format!("{:?} ^ {:?}", left, right),
                    })
                }
            }
            (Value::Vector(ref vec), Value::Complex(c)) => {
                if Value::is_numeric_vector(vec) {
                    let vec_borrow = vec.borrow();
                    let result: Vec<Value> = vec_borrow
                        .iter()
                        .map(|v| match v {
                            Value::Number(n) => {
                                Value::Complex(Complex::from_real(*n).pow_complex(c))
                            }
                            Value::Complex(cv) => Value::Complex(cv.pow_complex(c)),
                            _ => unreachable!(),
                        })
                        .collect();
                    Ok(Value::Vector(Rc::new(RefCell::new(result))))
                } else {
                    Err(VmError::TypeError {
                        operation: "exponentiation".to_string(),
                        expected: "numeric vector for broadcasting".to_string(),
                        got: format!("{:?} ^ {:?}", left, right),
                    })
                }
            }

            _ => Err(VmError::TypeError {
                operation: "exponentiation".to_string(),
                expected: "Number, Complex, or Vector".to_string(),
                got: format!("{:?} ^ {:?}", left, right),
            }),
        }
    }

    pub(crate) fn neg_value(value: &Value) -> Result<Value, VmError> {
        match value {
            Value::Number(n) => Ok(Value::Number(-n)),
            Value::Complex(c) => Ok(Value::Complex(-*c)),
            _ => Err(VmError::TypeError {
                operation: "negation".to_string(),
                expected: "Number or Complex".to_string(),
                got: format!("-{:?}", value),
            }),
        }
    }

    pub(crate) fn lt_values(left: &Value, right: &Value) -> Result<Value, VmError> {
        match (left, right) {
            (Value::Number(a), Value::Number(b)) => Ok(Value::Boolean(a < b)),
            _ => Err(VmError::TypeError {
                operation: "comparison".to_string(),
                expected: "Number".to_string(),
                got: format!("{:?} < {:?}", left, right),
            }),
        }
    }

    pub(crate) fn le_values(left: &Value, right: &Value) -> Result<Value, VmError> {
        match (left, right) {
            (Value::Number(a), Value::Number(b)) => Ok(Value::Boolean(a <= b)),
            _ => Err(VmError::TypeError {
                operation: "comparison".to_string(),
                expected: "Number".to_string(),
                got: format!("{:?} <= {:?}", left, right),
            }),
        }
    }

    pub(crate) fn gt_values(left: &Value, right: &Value) -> Result<Value, VmError> {
        match (left, right) {
            (Value::Number(a), Value::Number(b)) => Ok(Value::Boolean(a > b)),
            _ => Err(VmError::TypeError {
                operation: "comparison".to_string(),
                expected: "Number".to_string(),
                got: format!("{:?} > {:?}", left, right),
            }),
        }
    }

    pub(crate) fn ge_values(left: &Value, right: &Value) -> Result<Value, VmError> {
        match (left, right) {
            (Value::Number(a), Value::Number(b)) => Ok(Value::Boolean(a >= b)),
            _ => Err(VmError::TypeError {
                operation: "comparison".to_string(),
                expected: "Number".to_string(),
                got: format!("{:?} >= {:?}", left, right),
            }),
        }
    }

    pub(crate) fn is_truthy(value: &Value) -> bool {
        match value {
            Value::Boolean(b) => *b,
            Value::Null => false,
            Value::Number(n) => *n != 0.0,
            _ => true,
        }
    }

    pub(crate) fn not_value(value: &Value) -> Result<Value, VmError> {
        Ok(Value::Boolean(!Self::is_truthy(value)))
    }

    /// Convert a value to its string representation (for interpolated strings)
    pub(crate) fn value_to_string(value: &Value) -> String {
        match value {
            Value::Number(n) => {
                // Format number without unnecessary trailing zeros
                if n.fract() == 0.0 && n.is_finite() {
                    format!("{}", *n as i64)
                } else {
                    format!("{}", n)
                }
            }
            Value::Boolean(b) => b.to_string(),
            Value::String(s) => s.clone(),
            Value::Null => "null".to_string(),
            Value::Complex(c) => {
                let re = c.re;
                let im = c.im;
                if re == 0.0 {
                    format!("{}i", im)
                } else if im >= 0.0 {
                    format!("{}+{}i", re, im)
                } else {
                    format!("{}{}i", re, im)
                }
            }
            Value::Vector(vec) => {
                let vec_borrow = vec.borrow();
                let elements: Vec<String> = vec_borrow.iter().map(Self::value_to_string).collect();
                format!("[{}]", elements.join(", "))
            }
            Value::Record(map) => {
                let map_borrow = map.borrow();
                let fields: Vec<String> = map_borrow
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k, Self::value_to_string(v)))
                    .collect();
                format!("{{{}}}", fields.join(", "))
            }
            Value::Function(_) => "[Function]".to_string(),
            Value::Generator(_) => "[Generator]".to_string(),
            Value::Error { message, kind, .. } => {
                if let Some(k) = kind {
                    format!("Error({}): {}", k, message)
                } else {
                    format!("Error: {}", message)
                }
            }
            _ => format!("{:?}", value),
        }
    }
}
