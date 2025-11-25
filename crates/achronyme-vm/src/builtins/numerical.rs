//! Numerical Analysis Built-ins
//!
//! This module implements numerical analysis functions:
//!
//! ## Differentiation (4 functions):
//! - diff: First derivative using centered differences
//! - diff2: Second derivative
//! - diff3: Third derivative
//! - gradient: Multivariable gradient
//!
//! ## Integration (4 functions):
//! - integral: Trapezoidal rule
//! - simpson: Simpson's 1/3 rule
//! - romberg: Romberg integration
//! - quad: Adaptive quadrature
//!
//! ## Root Finding (3 functions):
//! - solve: Bisection method
//! - newton: Newton-Raphson method
//! - secant: Secant method

use crate::error::VmError;
use crate::value::Value;
use crate::vm::VM;
use achronyme_types::sync::shared;

// ============================================================================
// DIFFERENTIATION
// ============================================================================

/// diff(fn, x, h?) -> Number
///
/// Computes the first derivative of a function at point x using centered differences.
/// Formula: f'(x) ≈ [f(x+h) - f(x-h)] / (2h)
///
/// # Arguments
/// * `fn` - Function to differentiate (must be a lambda/closure)
/// * `x` - Point at which to evaluate the derivative
/// * `h` - Step size (optional, default = 1e-8)
///
/// # Examples
/// ```achronyme
/// let f = x => x^2
/// let df = diff(f, 3)  // Should be ≈ 6
/// ```
pub fn vm_diff(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    // Validate argument count
    if args.len() < 2 || args.len() > 3 {
        return Err(VmError::Runtime(format!(
            "diff() expects 2 or 3 arguments (fn, x, h?), got {}",
            args.len()
        )));
    }

    let func = &args[0];
    let x = match &args[1] {
        Value::Number(n) => *n,
        _ => {
            return Err(VmError::TypeError {
                operation: "diff".to_string(),
                expected: "Number for x".to_string(),
                got: format!("{:?}", args[1]),
            })
        }
    };

    // Default step size
    let h = if args.len() == 3 {
        match &args[2] {
            Value::Number(n) => *n,
            _ => {
                return Err(VmError::TypeError {
                    operation: "diff".to_string(),
                    expected: "Number for h".to_string(),
                    got: format!("{:?}", args[2]),
                })
            }
        }
    } else {
        1e-8
    };

    // Centered difference: f'(x) ≈ [f(x+h) - f(x-h)] / (2h)
    let f_plus = vm.call_value(func, &[Value::Number(x + h)])?;
    let f_minus = vm.call_value(func, &[Value::Number(x - h)])?;

    let f_plus_num = extract_number(f_plus, "diff")?;
    let f_minus_num = extract_number(f_minus, "diff")?;

    let derivative = (f_plus_num - f_minus_num) / (2.0 * h);
    Ok(Value::Number(derivative))
}

/// diff2(fn, x, h?) -> Number
///
/// Computes the second derivative of a function at point x.
/// Formula: f''(x) ≈ [f(x+h) - 2f(x) + f(x-h)] / h²
///
/// # Arguments
/// * `fn` - Function to differentiate
/// * `x` - Point at which to evaluate the second derivative
/// * `h` - Step size (optional, default = 1e-5)
///
/// # Examples
/// ```achronyme
/// let f = x => x^3
/// let d2f = diff2(f, 2)  // Should be ≈ 12
/// ```
pub fn vm_diff2(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() < 2 || args.len() > 3 {
        return Err(VmError::Runtime(format!(
            "diff2() expects 2 or 3 arguments (fn, x, h?), got {}",
            args.len()
        )));
    }

    let func = &args[0];
    let x = match &args[1] {
        Value::Number(n) => *n,
        _ => {
            return Err(VmError::TypeError {
                operation: "diff2".to_string(),
                expected: "Number for x".to_string(),
                got: format!("{:?}", args[1]),
            })
        }
    };

    let h = if args.len() == 3 {
        match &args[2] {
            Value::Number(n) => *n,
            _ => {
                return Err(VmError::TypeError {
                    operation: "diff2".to_string(),
                    expected: "Number for h".to_string(),
                    got: format!("{:?}", args[2]),
                })
            }
        }
    } else {
        1e-5
    };

    // Second derivative: f''(x) ≈ [f(x+h) - 2f(x) + f(x-h)] / h²
    let f_plus = vm.call_value(func, &[Value::Number(x + h)])?;
    let f_center = vm.call_value(func, &[Value::Number(x)])?;
    let f_minus = vm.call_value(func, &[Value::Number(x - h)])?;

    let f_plus_num = extract_number(f_plus, "diff2")?;
    let f_center_num = extract_number(f_center, "diff2")?;
    let f_minus_num = extract_number(f_minus, "diff2")?;

    let second_derivative = (f_plus_num - 2.0 * f_center_num + f_minus_num) / (h * h);
    Ok(Value::Number(second_derivative))
}

/// diff3(fn, x, h?) -> Number
///
/// Computes the third derivative of a function at point x using centered differences.
/// Formula: f'''(x) ≈ [f(x+2h) - 2f(x+h) + 2f(x-h) - f(x-2h)] / (2h³)
///
/// # Arguments
/// * `fn` - Function to differentiate
/// * `x` - Point at which to evaluate the third derivative
/// * `h` - Step size (optional, default = 1e-4)
///
/// # Examples
/// ```achronyme
/// let f = x => x^4
/// let d3f = diff3(f, 2)  // Should be ≈ 48
/// ```
pub fn vm_diff3(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() < 2 || args.len() > 3 {
        return Err(VmError::Runtime(format!(
            "diff3() expects 2 or 3 arguments (fn, x, h?), got {}",
            args.len()
        )));
    }

    let func = &args[0];
    let x = match &args[1] {
        Value::Number(n) => *n,
        _ => {
            return Err(VmError::TypeError {
                operation: "diff3".to_string(),
                expected: "Number for x".to_string(),
                got: format!("{:?}", args[1]),
            })
        }
    };

    let h = if args.len() == 3 {
        match &args[2] {
            Value::Number(n) => *n,
            _ => {
                return Err(VmError::TypeError {
                    operation: "diff3".to_string(),
                    expected: "Number for h".to_string(),
                    got: format!("{:?}", args[2]),
                })
            }
        }
    } else {
        1e-4
    };

    // Third derivative: f'''(x) ≈ [f(x+2h) - 2f(x+h) + 2f(x-h) - f(x-2h)] / (2h³)
    let f_plus2 = vm.call_value(func, &[Value::Number(x + 2.0 * h)])?;
    let f_plus1 = vm.call_value(func, &[Value::Number(x + h)])?;
    let f_minus1 = vm.call_value(func, &[Value::Number(x - h)])?;
    let f_minus2 = vm.call_value(func, &[Value::Number(x - 2.0 * h)])?;

    let f_plus2_num = extract_number(f_plus2, "diff3")?;
    let f_plus1_num = extract_number(f_plus1, "diff3")?;
    let f_minus1_num = extract_number(f_minus1, "diff3")?;
    let f_minus2_num = extract_number(f_minus2, "diff3")?;

    let third_derivative =
        (f_plus2_num - 2.0 * f_plus1_num + 2.0 * f_minus1_num - f_minus2_num) / (2.0 * h * h * h);
    Ok(Value::Number(third_derivative))
}

/// gradient(fn, point, h?) -> Vector
///
/// Computes the gradient (vector of partial derivatives) of a multivariable function.
/// The function should accept a Vector and return a Number.
///
/// # Arguments
/// * `fn` - Function f: Vector -> Number
/// * `point` - Point (as Vector) at which to evaluate the gradient
/// * `h` - Step size (optional, default = 1e-8)
///
/// # Examples
/// ```achronyme
/// let f = v => v[0]^2 + v[1]^2
/// let grad = gradient(f, [1, 2])  // Should be ≈ [2, 4]
/// ```
pub fn vm_gradient(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() < 2 || args.len() > 3 {
        return Err(VmError::Runtime(format!(
            "gradient() expects 2 or 3 arguments (fn, point, h?), got {}",
            args.len()
        )));
    }

    let func = &args[0];
    let point_vec = match &args[1] {
        Value::Vector(v) => v.clone(),
        _ => {
            return Err(VmError::TypeError {
                operation: "gradient".to_string(),
                expected: "Vector for point".to_string(),
                got: format!("{:?}", args[1]),
            })
        }
    };

    let h = if args.len() == 3 {
        match &args[2] {
            Value::Number(n) => *n,
            _ => {
                return Err(VmError::TypeError {
                    operation: "gradient".to_string(),
                    expected: "Number for h".to_string(),
                    got: format!("{:?}", args[2]),
                })
            }
        }
    } else {
        1e-8
    };

    let point = point_vec.read();
    let n = point.len();
    let mut gradient = Vec::with_capacity(n);

    // Compute partial derivative for each dimension
    for i in 0..n {
        let mut point_plus = point.clone();
        let mut point_minus = point.clone();

        // Modify i-th component
        if let Value::Number(val) = point[i] {
            point_plus[i] = Value::Number(val + h);
            point_minus[i] = Value::Number(val - h);
        } else {
            return Err(VmError::TypeError {
                operation: "gradient".to_string(),
                expected: "numeric vector".to_string(),
                got: format!("{:?}", point[i]),
            });
        }

        // Evaluate function at point + h and point - h
        let f_plus = vm.call_value(func, &[Value::Vector(shared(point_plus))])?;
        let f_minus = vm.call_value(func, &[Value::Vector(shared(point_minus))])?;

        let f_plus_num = extract_number(f_plus, "gradient")?;
        let f_minus_num = extract_number(f_minus, "gradient")?;

        // Centered difference for partial derivative
        let partial = (f_plus_num - f_minus_num) / (2.0 * h);
        gradient.push(Value::Number(partial));
    }

    Ok(Value::Vector(shared(gradient)))
}

// ============================================================================
// INTEGRATION
// ============================================================================

/// integral(fn, a, b, n?) -> Number
///
/// Computes the definite integral using the trapezoidal rule.
///
/// # Arguments
/// * `fn` - Function to integrate
/// * `a` - Lower bound
/// * `b` - Upper bound
/// * `n` - Number of subdivisions (optional, default = 1000)
///
/// # Examples
/// ```achronyme
/// let f = x => x^2
/// let area = integral(f, 0, 1)  // Should be ≈ 0.333...
/// ```
pub fn vm_integral(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() < 3 || args.len() > 4 {
        return Err(VmError::Runtime(format!(
            "integral() expects 3 or 4 arguments (fn, a, b, n?), got {}",
            args.len()
        )));
    }

    let func = &args[0];
    let a = extract_number(args[1].clone(), "integral (a)")?;
    let b = extract_number(args[2].clone(), "integral (b)")?;
    let n = if args.len() == 4 {
        extract_number(args[3].clone(), "integral (n)")? as usize
    } else {
        1000
    };

    if n == 0 {
        return Err(VmError::Runtime(
            "integral() requires n > 0 subdivisions".to_string(),
        ));
    }

    let h = (b - a) / (n as f64);
    let mut sum = 0.0;

    // Trapezoidal rule: ∫f(x)dx ≈ h/2 * [f(a) + 2*Σf(xi) + f(b)]
    let f_a = extract_number(vm.call_value(func, &[Value::Number(a)])?, "integral")?;
    let f_b = extract_number(vm.call_value(func, &[Value::Number(b)])?, "integral")?;

    sum += f_a + f_b;

    for i in 1..n {
        let x = a + i as f64 * h;
        let f_x = extract_number(vm.call_value(func, &[Value::Number(x)])?, "integral")?;
        sum += 2.0 * f_x;
    }

    Ok(Value::Number(sum * h / 2.0))
}

/// simpson(fn, a, b, n?) -> Number
///
/// Computes the definite integral using Simpson's 1/3 rule.
/// n must be even.
///
/// # Arguments
/// * `fn` - Function to integrate
/// * `a` - Lower bound
/// * `b` - Upper bound
/// * `n` - Number of subdivisions (optional, default = 1000, must be even)
///
/// # Examples
/// ```achronyme
/// let f = x => x^2
/// let area = simpson(f, 0, 1)  // Should be ≈ 0.333...
/// ```
pub fn vm_simpson(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() < 3 || args.len() > 4 {
        return Err(VmError::Runtime(format!(
            "simpson() expects 3 or 4 arguments (fn, a, b, n?), got {}",
            args.len()
        )));
    }

    let func = &args[0];
    let a = extract_number(args[1].clone(), "simpson (a)")?;
    let b = extract_number(args[2].clone(), "simpson (b)")?;
    let mut n = if args.len() == 4 {
        extract_number(args[3].clone(), "simpson (n)")? as usize
    } else {
        1000
    };

    // Ensure n is even
    if n % 2 != 0 {
        n += 1;
    }

    if n == 0 {
        return Err(VmError::Runtime(
            "simpson() requires n > 0 subdivisions".to_string(),
        ));
    }

    let h = (b - a) / (n as f64);

    // Simpson's 1/3 rule: ∫f(x)dx ≈ h/3 * [f(a) + 4*Σf(x_odd) + 2*Σf(x_even) + f(b)]
    let f_a = extract_number(vm.call_value(func, &[Value::Number(a)])?, "simpson")?;
    let f_b = extract_number(vm.call_value(func, &[Value::Number(b)])?, "simpson")?;

    let mut sum = f_a + f_b;

    for i in 1..n {
        let x = a + i as f64 * h;
        let f_x = extract_number(vm.call_value(func, &[Value::Number(x)])?, "simpson")?;

        if i % 2 == 1 {
            sum += 4.0 * f_x; // Odd indices
        } else {
            sum += 2.0 * f_x; // Even indices
        }
    }

    Ok(Value::Number(sum * h / 3.0))
}

/// romberg(fn, a, b, max_iter?) -> Number
///
/// Computes the definite integral using Romberg integration (Richardson extrapolation).
///
/// # Arguments
/// * `fn` - Function to integrate
/// * `a` - Lower bound
/// * `b` - Upper bound
/// * `max_iter` - Maximum number of iterations (optional, default = 10)
///
/// # Examples
/// ```achronyme
/// let f = x => x^2
/// let area = romberg(f, 0, 1)  // High-precision result ≈ 0.333...
/// ```
pub fn vm_romberg(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() < 3 || args.len() > 4 {
        return Err(VmError::Runtime(format!(
            "romberg() expects 3 or 4 arguments (fn, a, b, max_iter?), got {}",
            args.len()
        )));
    }

    let func = &args[0];
    let a = extract_number(args[1].clone(), "romberg (a)")?;
    let b = extract_number(args[2].clone(), "romberg (b)")?;
    let max_iter = if args.len() == 4 {
        extract_number(args[3].clone(), "romberg (max_iter)")? as usize
    } else {
        10
    };

    if max_iter == 0 {
        return Err(VmError::Runtime(
            "romberg() requires max_iter > 0".to_string(),
        ));
    }

    let mut r = vec![vec![0.0; max_iter]; max_iter];

    // First column: Trapezoidal rule with increasing subdivisions
    for i in 0..max_iter {
        let n = 1 << i; // 2^i subdivisions
        let h = (b - a) / (n as f64);

        if i == 0 {
            // First estimate with 1 subdivision
            let f_a = extract_number(vm.call_value(func, &[Value::Number(a)])?, "romberg")?;
            let f_b = extract_number(vm.call_value(func, &[Value::Number(b)])?, "romberg")?;
            r[0][0] = (f_a + f_b) * h / 2.0;
        } else {
            // Use previous estimate and add midpoints
            let mut sum = 0.0;
            let n_prev = 1 << (i - 1);
            for k in 0..n_prev {
                let x = a + (2 * k + 1) as f64 * h;
                let f_x = extract_number(vm.call_value(func, &[Value::Number(x)])?, "romberg")?;
                sum += f_x;
            }
            r[i][0] = r[i - 1][0] / 2.0 + sum * h;
        }

        // Richardson extrapolation
        for j in 1..=i {
            let factor = 4_f64.powi(j as i32);
            r[i][j] = (factor * r[i][j - 1] - r[i - 1][j - 1]) / (factor - 1.0);
        }

        // Check convergence
        if i > 0 {
            let diff = (r[i][i] - r[i - 1][i - 1]).abs();
            if diff < 1e-10 {
                return Ok(Value::Number(r[i][i]));
            }
        }
    }

    Ok(Value::Number(r[max_iter - 1][max_iter - 1]))
}

/// quad(fn, a, b, tol?) -> Number
///
/// Computes the definite integral using adaptive Simpson quadrature.
///
/// # Arguments
/// * `fn` - Function to integrate
/// * `a` - Lower bound
/// * `b` - Upper bound
/// * `tol` - Tolerance (optional, default = 1e-10)
///
/// # Examples
/// ```achronyme
/// let f = x => x^2
/// let area = quad(f, 0, 1)  // Adaptive high-precision result
/// ```
pub fn vm_quad(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() < 3 || args.len() > 4 {
        return Err(VmError::Runtime(format!(
            "quad() expects 3 or 4 arguments (fn, a, b, tol?), got {}",
            args.len()
        )));
    }

    let func = &args[0];
    let a = extract_number(args[1].clone(), "quad (a)")?;
    let b = extract_number(args[2].clone(), "quad (b)")?;
    let tol = if args.len() == 4 {
        extract_number(args[3].clone(), "quad (tol)")?
    } else {
        1e-10
    };

    // Helper function for recursive adaptive Simpson
    #[allow(clippy::too_many_arguments)]
    fn adaptive_simpson(
        vm: &mut VM,
        func: &Value,
        a: f64,
        b: f64,
        tol: f64,
        s: f64,
        fa: f64,
        fb: f64,
        fc: f64,
        depth: usize,
    ) -> Result<f64, VmError> {
        const MAX_DEPTH: usize = 50;

        if depth > MAX_DEPTH {
            return Err(VmError::Runtime(format!(
                "quad() maximum recursion depth {} exceeded",
                MAX_DEPTH
            )));
        }

        let c = (a + b) / 2.0;
        let h = b - a;

        let d = (a + c) / 2.0;
        let e = (c + b) / 2.0;

        let fd = extract_number(vm.call_value(func, &[Value::Number(d)])?, "quad")?;
        let fe = extract_number(vm.call_value(func, &[Value::Number(e)])?, "quad")?;

        let s_left = (h / 2.0) / 6.0 * (fa + 4.0 * fd + fc);
        let s_right = (h / 2.0) / 6.0 * (fc + 4.0 * fe + fb);
        let s2 = s_left + s_right;

        if (s2 - s).abs() <= 15.0 * tol {
            Ok(s2 + (s2 - s) / 15.0)
        } else {
            let left = adaptive_simpson(vm, func, a, c, tol / 2.0, s_left, fa, fc, fd, depth + 1)?;
            let right =
                adaptive_simpson(vm, func, c, b, tol / 2.0, s_right, fc, fb, fe, depth + 1)?;
            Ok(left + right)
        }
    }

    let c = (a + b) / 2.0;
    let h = b - a;

    let fa = extract_number(vm.call_value(func, &[Value::Number(a)])?, "quad")?;
    let fb = extract_number(vm.call_value(func, &[Value::Number(b)])?, "quad")?;
    let fc = extract_number(vm.call_value(func, &[Value::Number(c)])?, "quad")?;

    let s = h / 6.0 * (fa + 4.0 * fc + fb);

    let result = adaptive_simpson(vm, func, a, b, tol, s, fa, fb, fc, 0)?;
    Ok(Value::Number(result))
}

// ============================================================================
// ROOT FINDING
// ============================================================================

/// solve(fn, a, b, tol?) -> Number
///
/// Finds a root of the function in the interval [a, b] using the bisection method.
/// The function must have opposite signs at a and b.
///
/// # Arguments
/// * `fn` - Function for which to find a root
/// * `a` - Lower bound of search interval
/// * `b` - Upper bound of search interval
/// * `tol` - Tolerance (optional, default = 1e-10)
///
/// # Examples
/// ```achronyme
/// let f = x => x^2 - 4
/// let root = solve(f, 0, 3)  // Should be ≈ 2
/// ```
pub fn vm_solve(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() < 3 || args.len() > 4 {
        return Err(VmError::Runtime(format!(
            "solve() expects 3 or 4 arguments (fn, a, b, tol?), got {}",
            args.len()
        )));
    }

    let func = &args[0];
    let mut a = extract_number(args[1].clone(), "solve (a)")?;
    let mut b = extract_number(args[2].clone(), "solve (b)")?;
    let tol = if args.len() == 4 {
        extract_number(args[3].clone(), "solve (tol)")?
    } else {
        1e-10
    };

    // Evaluate at endpoints
    let mut fa = extract_number(vm.call_value(func, &[Value::Number(a)])?, "solve")?;
    let fb = extract_number(vm.call_value(func, &[Value::Number(b)])?, "solve")?;

    // Check that signs are opposite
    if fa * fb > 0.0 {
        return Err(VmError::Runtime(
            "solve() requires f(a) and f(b) to have opposite signs".to_string(),
        ));
    }

    const MAX_ITER: usize = 1000;
    let mut iter = 0;

    while (b - a).abs() > tol && iter < MAX_ITER {
        let c = (a + b) / 2.0;
        let fc = extract_number(vm.call_value(func, &[Value::Number(c)])?, "solve")?;

        if fc.abs() < tol {
            return Ok(Value::Number(c));
        }

        if fa * fc < 0.0 {
            b = c;
            // fb would be fc, but we don't need to track it
        } else {
            a = c;
            fa = fc;
        }

        iter += 1;
    }

    if iter >= MAX_ITER {
        return Err(VmError::Runtime(format!(
            "solve() failed to converge after {} iterations",
            MAX_ITER
        )));
    }

    Ok(Value::Number((a + b) / 2.0))
}

/// newton(fn, x0, tol?, max_iter?) -> Number
///
/// Finds a root using Newton-Raphson method with automatic numerical differentiation.
///
/// # Arguments
/// * `fn` - Function for which to find a root
/// * `x0` - Initial guess
/// * `tol` - Tolerance (optional, default = 1e-10)
/// * `max_iter` - Maximum iterations (optional, default = 100)
///
/// # Examples
/// ```achronyme
/// let f = x => x^2 - 4
/// let root = newton(f, 1)  // Should be ≈ 2
/// ```
pub fn vm_newton(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() < 2 || args.len() > 4 {
        return Err(VmError::Runtime(format!(
            "newton() expects 2-4 arguments (fn, x0, tol?, max_iter?), got {}",
            args.len()
        )));
    }

    let func = &args[0];
    let mut x = extract_number(args[1].clone(), "newton (x0)")?;
    let tol = if args.len() >= 3 {
        extract_number(args[2].clone(), "newton (tol)")?
    } else {
        1e-10
    };
    let max_iter = if args.len() >= 4 {
        extract_number(args[3].clone(), "newton (max_iter)")? as usize
    } else {
        100
    };

    const H: f64 = 1e-8; // Step size for numerical derivative

    for _ in 0..max_iter {
        let fx = extract_number(vm.call_value(func, &[Value::Number(x)])?, "newton")?;

        // Check if we've found the root
        if fx.abs() < tol {
            return Ok(Value::Number(x));
        }

        // Compute derivative using centered differences
        let f_plus = extract_number(vm.call_value(func, &[Value::Number(x + H)])?, "newton")?;
        let f_minus = extract_number(vm.call_value(func, &[Value::Number(x - H)])?, "newton")?;
        let fprime = (f_plus - f_minus) / (2.0 * H);

        // Check for zero derivative
        if fprime.abs() < 1e-15 {
            return Err(VmError::Runtime(format!(
                "newton() derivative is zero at x = {}",
                x
            )));
        }

        // Newton-Raphson update: x_new = x - f(x)/f'(x)
        x -= fx / fprime;

        // Check convergence
        if (fx / fprime).abs() < tol {
            return Ok(Value::Number(x));
        }
    }

    Err(VmError::Runtime(format!(
        "newton() failed to converge after {} iterations",
        max_iter
    )))
}

/// secant(fn, x0, x1, tol?) -> Number
///
/// Finds a root using the secant method.
///
/// # Arguments
/// * `fn` - Function for which to find a root
/// * `x0` - First initial guess
/// * `x1` - Second initial guess
/// * `tol` - Tolerance (optional, default = 1e-10)
///
/// # Examples
/// ```achronyme
/// let f = x => x^2 - 4
/// let root = secant(f, 1, 3)  // Should be ≈ 2
/// ```
pub fn vm_secant(vm: &mut VM, args: &[Value]) -> Result<Value, VmError> {
    if args.len() < 3 || args.len() > 4 {
        return Err(VmError::Runtime(format!(
            "secant() expects 3 or 4 arguments (fn, x0, x1, tol?), got {}",
            args.len()
        )));
    }

    let func = &args[0];
    let mut x0 = extract_number(args[1].clone(), "secant (x0)")?;
    let mut x1 = extract_number(args[2].clone(), "secant (x1)")?;
    let tol = if args.len() == 4 {
        extract_number(args[3].clone(), "secant (tol)")?
    } else {
        1e-10
    };

    const MAX_ITER: usize = 100;

    let mut f0 = extract_number(vm.call_value(func, &[Value::Number(x0)])?, "secant")?;

    for iter in 0..MAX_ITER {
        let f1 = extract_number(vm.call_value(func, &[Value::Number(x1)])?, "secant")?;

        // Check convergence
        if f1.abs() < tol {
            return Ok(Value::Number(x1));
        }

        // Check for zero denominator
        if (f1 - f0).abs() < 1e-15 {
            return Err(VmError::Runtime(format!(
                "secant() division by zero at iteration {}",
                iter
            )));
        }

        // Secant update: x_new = x1 - f1 * (x1 - x0) / (f1 - f0)
        let x2 = x1 - f1 * (x1 - x0) / (f1 - f0);

        // Update for next iteration
        x0 = x1;
        f0 = f1;
        x1 = x2;

        // Check convergence
        if (x1 - x0).abs() < tol {
            return Ok(Value::Number(x1));
        }
    }

    Err(VmError::Runtime(format!(
        "secant() failed to converge after {} iterations",
        MAX_ITER
    )))
}

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Helper to extract a number from a Value
fn extract_number(value: Value, context: &str) -> Result<f64, VmError> {
    match value {
        Value::Number(n) => Ok(n),
        _ => Err(VmError::TypeError {
            operation: context.to_string(),
            expected: "Number".to_string(),
            got: format!("{:?}", value),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_derivative_basic() {
        assert_eq!(extract_number(Value::Number(42.0), "test").unwrap(), 42.0);
        assert!(extract_number(Value::Null, "test").is_err());
    }
}
