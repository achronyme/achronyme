---
title: "Numerical Analysis"
description: "Differentiation, integration, and root finding in Achronyme"
section: "mathematical-computing"
order: 4
---


Achronyme provides comprehensive numerical analysis capabilities including differentiation, integration, root finding, and optimization for solving mathematical and engineering problems.

## Overview

| Category | Functions |
|----------|-----------|
| **Differentiation** | diff, diff2, diff3, gradient |
| **Integration** | integral/trapz, simpson, simpson38, romberg, quad |
| **Root Finding** | solve/bisect, newton, secant |
| **Optimization** | linprog, simplex, dual_simplex, two_phase, revised |
| **Sensitivity** | shadow_price, sensitivity_c, sensitivity_b |

All numerical functions use robust, well-tested algorithms with appropriate error handling and convergence criteria.

## Differentiation

### First Derivative - diff

Compute the first derivative using central finite differences:

```javascript
// f(x) = x², f'(2) = 4
let f = x => x^2
diff(f, 2, 1e-5)  // ~4.0

// f(x) = sin(x), f'(0) = cos(0) = 1
diff(x => sin(x), 0, 1e-5)  // ~1.0

// f(x) = e^x, f'(1) = e
diff(x => exp(x), 1, 1e-5)  // ~2.718
```

**Signature**: `diff(function, point, step_size)`

**Algorithm**: Central difference
```
f'(x) ≈ (f(x + h) - f(x - h)) / (2h)
```

**Parameters**:
- `function`: Function to differentiate
- `point`: Point at which to calculate derivative
- `step_size`: Step size h (typically 1e-5)

**Error**: O(h²) - quadratic error in step size

### Second Derivative - diff2

Compute the second derivative:

```javascript
// f(x) = x³, f''(2) = 12
diff2(x => x^3, 2, 1e-3)  // ~12.0

// f(x) = sin(x), f''(π/2) = -1
diff2(x => sin(x), pi/2, 1e-3)  // ~-1.0
```

**Signature**: `diff2(function, point, step_size)`

**Algorithm**: Central difference for second derivative
```
f''(x) ≈ (f(x + h) - 2f(x) + f(x - h)) / h²
```

**Parameters**:
- `step_size`: Typically 1e-3 (larger than for first derivative)

### Third Derivative - diff3

Compute the third derivative:

```javascript
// f(x) = x⁴, f'''(2) = 48
diff3(x => x^4, 2, 1e-2)  // ~48.0
```

**Signature**: `diff3(function, point, step_size)`

**Algorithm**: Five-point central difference
```
f'''(x) ≈ (f(x+2h) - 2f(x+h) + 2f(x-h) - f(x-2h)) / (2h³)
```

**Parameters**:
- `step_size`: Typically 1e-2 (larger for higher derivatives)

### Gradient - gradient

Compute the gradient (vector of partial derivatives):

```javascript
// f(x, y) = x² + y², ∇f = [2x, 2y]
let f = (x, y) => x^2 + y^2
gradient(f, [2, 3], 1e-5)  // ~[4, 6]

// f(x, y, z) = x*y + y*z
let g = (x, y, z) => x*y + y*z
gradient(g, [1, 2, 3], 1e-5)  // ~[2, 4, 2]
```

**Signature**: `gradient(function, point_vector, step_size)`

**Algorithm**: Central difference for each partial derivative
```
∂f/∂xᵢ ≈ (f(..., xᵢ + h, ...) - f(..., xᵢ - h, ...)) / (2h)
```

**Returns**: Vector of partial derivatives [∂f/∂x₁, ∂f/∂x₂, ..., ∂f/∂xₙ]

### Choosing Step Size

```javascript
// General guidelines:
// First derivative: h = 1e-5
let df = diff(f, x, 1e-5)

// Second derivative: h = 1e-3 (√ of first derivative)
let d2f = diff2(f, x, 1e-3)

// Third derivative: h = 1e-2 (∛ of first derivative)
let d3f = diff3(f, x, 1e-2)

// Balance: smaller h → smaller truncation error
//          larger h → smaller roundoff error
```

## Integration

### Trapezoidal Rule - integral / trapz

Composite trapezoidal rule for numerical integration:

```javascript
// ∫x dx from 0 to 1 = 0.5
integral(x => x, 0, 1, 1000)  // ~0.5

// ∫sin(x) dx from 0 to π = 2
integral(x => sin(x), 0, pi, 1000)  // ~2.0

// Area under parabola
integral(x => x^2, 0, 2, 1000)  // ~2.667
```

**Signature**: `integral(function, lower, upper, subdivisions)`
**Alias**: `trapz`

**Algorithm**: Composite trapezoidal rule
```
∫f(x)dx ≈ h/2 * (f(x₀) + 2f(x₁) + 2f(x₂) + ... + 2f(xₙ₋₁) + f(xₙ))
where h = (b - a) / n
```

**Parameters**:
- `function`: Function to integrate
- `lower`: Lower limit of integration
- `upper`: Upper limit of integration
- `subdivisions`: Number of subdivisions (higher = more accurate)

**Error**: O(h²) where h = (b-a)/n

### Simpson's Rule - simpson

More accurate integration using parabolic approximation:

```javascript
// ∫x² dx from 0 to 1 = 1/3
simpson(x => x^2, 0, 1, 100)  // ~0.333

// ∫exp(x) dx from 0 to 1 = e - 1
simpson(x => exp(x), 0, 1, 100)  // ~1.718
```

**Signature**: `simpson(function, lower, upper, subdivisions)`

**Algorithm**: Composite Simpson's 1/3 rule
```
∫f(x)dx ≈ h/3 * (f(x₀) + 4f(x₁) + 2f(x₂) + 4f(x₃) + ... + f(xₙ))
```

**Note**: Subdivisions automatically adjusted to be even

**Error**: O(h⁴) - more accurate than trapezoidal

### Simpson's 3/8 Rule - simpson38

Alternative Simpson's rule:

```javascript
simpson38(x => x^3, 0, 1, 99)  // ~0.25
```

**Signature**: `simpson38(function, lower, upper, subdivisions)`

**Note**: Subdivisions automatically adjusted to be divisible by 3

### Romberg Integration - romberg

High-accuracy adaptive integration:

```javascript
// ∫sin(x) dx from 0 to π = 2
romberg(x => sin(x), 0, pi, 1e-10)  // ~2.0 (very accurate)

// Difficult integrals
romberg(x => 1/(1 + x^2), 0, 1, 1e-10)  // π/4
```

**Signature**: `romberg(function, lower, upper, tolerance)`

**Algorithm**: Richardson extrapolation on trapezoidal rule
- Uses successive refinements: h, h/2, h/4, ...
- Extrapolates to h→0 limit
- Adapts until desired tolerance

**Parameters**:
- `tolerance`: Desired accuracy (e.g., 1e-8, 1e-10)

**Convergence**: Stops when |R[i][i] - R[i-1][i-1]| < tolerance

**Best for**: Smooth functions requiring high accuracy

### Adaptive Quadrature - quad

Automatic adaptive integration:

```javascript
// Automatically adapts for accuracy
quad(x => exp(x), 0, 1)  // ~1.718

// Works on difficult integrands
quad(x => 1/sqrt(x), 0.001, 1)  // Handles singularity
```

**Signature**: `quad(function, lower, upper)`

**Algorithm**: Adaptive Simpson's rule
- Starts with n=10 subdivisions
- Doubles n until convergence
- Stops when successive results agree to 1e-10

**Maximum subdivisions**: 100,000

**Best for**: General-purpose integration

### Comparison of Methods

```javascript
let f = x => x^2
let a = 0
let b = 1
let exact = 1/3

// Trapezoidal - O(h²)
integral(f, a, b, 100)    // ~0.33335

// Simpson's - O(h⁴)
simpson(f, a, b, 100)     // ~0.333333

// Romberg - adaptive
romberg(f, a, b, 1e-10)   // 0.333333333...

// Quad - automatic
quad(f, a, b)             // 0.333333333...
```

**Rule of thumb**:
- Use `simpson` for general problems
- Use `romberg` for high accuracy
- Use `quad` for automatic adaptation
- Use `integral/trapz` for simple/fast computation

## Root Finding

Find x where f(x) = 0.

### Bisection Method - solve / bisect

Robust bracketing method:

```javascript
// Find root of x² - 4 = 0 in [0, 5]
solve(x => x^2 - 4, 0, 5, 1e-6)  // ~2.0

// Find root of sin(x) = 0 in [3, 4]
solve(x => sin(x), 3, 4, 1e-6)  // ~π

// Find where two functions intersect
solve(x => x^2 - exp(x), 0, 1, 1e-6)
```

**Signature**: `solve(function, left, right, tolerance)`
**Alias**: `bisect`

**Algorithm**: Binary search
1. Check f(a) and f(b) have opposite signs
2. Compute midpoint c = (a + b) / 2
3. Replace a or b with c based on sign
4. Repeat until |b - a| < tolerance

**Requirements**: f(a) * f(b) < 0 (opposite signs)

**Convergence**: Linear, always converges

**Best for**:
- Guaranteed convergence
- Simple to use
- Finding initial bracket

### Newton's Method - newton

Fast iterative method using derivative:

```javascript
// f(x) = x² - 4, f'(x) = 2x
let f = x => x^2 - 4
let df = x => 2*x
newton(f, df, 1, 1e-10, 100)  // ~2.0

// f(x) = x³ - 2x - 5, f'(x) = 3x² - 2
let g = x => x^3 - 2*x - 5
let dg = x => 3*x^2 - 2
newton(g, dg, 2, 1e-10, 100)  // ~2.094
```

**Signature**: `newton(function, derivative, initial, tolerance, max_iterations)`

**Algorithm**: Tangent line iteration
```
xₙ₊₁ = xₙ - f(xₙ) / f'(xₙ)
```

**Parameters**:
- `function`: Function to find root of
- `derivative`: Derivative of function
- `initial`: Initial guess
- `tolerance`: Stop when |f(x)| < tolerance
- `max_iterations`: Typically 100

**Convergence**: Quadratic near root (very fast)

**Limitations**:
- Requires derivative
- May diverge with poor initial guess
- Fails if f'(x) = 0

**Best for**: Fast convergence when derivative available

### Secant Method - secant

Derivative-free alternative to Newton's method:

```javascript
// f(x) = x³ - x - 2
secant(x => x^3 - x - 2, 1, 2, 1e-10, 100)  // ~1.521

// No derivative needed
secant(x => sin(x) - 0.5, 0, 1, 1e-10, 100)  // ~0.524
```

**Signature**: `secant(function, x0, x1, tolerance, max_iterations)`

**Algorithm**: Approximates derivative using two points
```
xₙ₊₁ = xₙ - f(xₙ) * (xₙ - xₙ₋₁) / (f(xₙ) - f(xₙ₋₁))
```

**Parameters**:
- `x0`, `x1`: Two initial guesses

**Convergence**: Superlinear (φ ≈ 1.618, golden ratio)

**Best for**: When derivative unavailable or expensive

### Comparison of Root Finding Methods

```javascript
// Problem: find √2 (root of x² - 2 = 0)

// Bisection: slow but guaranteed
solve(x => x^2 - 2, 0, 2, 1e-6)
// ~15 iterations

// Newton: fast with derivative
newton(x => x^2 - 2, x => 2*x, 1, 1e-10, 100)
// ~5 iterations

// Secant: fast without derivative
secant(x => x^2 - 2, 1, 2, 1e-10, 100)
// ~7 iterations
```

## Practical Examples

### Find Intersection Points

```javascript
// Where does sin(x) = cos(x)?
let intersection = solve(
    x => sin(x) - cos(x),
    0,
    pi,
    1e-6
)
// ~π/4 = 0.785
```

### Approximate Derivative Numerically

```javascript
// When you don't know the derivative
let f = x => x^3 - 2*x - 5
let df_approx = x => diff(f, x, 1e-5)

newton(f, df_approx, 2, 1e-10, 100)
```

### Area Between Curves

```javascript
// Area between f(x) and g(x) from a to b
let f = x => x^2
let g = x => x^3

// Find intersection points first
let intersect1 = 0
let intersect2 = 1

// Area = ∫(f - g)dx
let area = integral(
    x => f(x) - g(x),
    intersect1,
    intersect2,
    1000
)
// 1/12 ≈ 0.083
```

### Arc Length

```javascript
// Arc length of f(x) from a to b
// L = ∫√(1 + (f'(x))²) dx

let f = x => x^2
let df = x => 2*x

let arc_length = (a, b) => integral(
    x => sqrt(1 + df(x)^2),
    a,
    b,
    1000
)

arc_length(0, 1)  // Arc length of parabola
```

### Numerical Optimization (1D)

```javascript
// Find maximum by finding where f'(x) = 0
let f = x => -(x - 2)^2 + 5  // Parabola
let df = x => -2*(x - 2)

let max_location = newton(df, x => -2, 1, 1e-10, 100)
// ~2.0

let max_value = f(max_location)
// ~5.0
```

### Center of Mass

```javascript
// Center of mass for region under f(x)
let f = x => x^2

// Total area
let A = integral(f, 0, 2, 1000)

// x-coordinate of centroid
let x_bar = integral(
    x => x * f(x),
    0,
    2,
    1000
) / A
// 1.5
```

## Optimization

See [Optimization](19-optimization.md) for linear programming and optimization details.

Quick overview:

```javascript
// Linear programming
let c = [40, 30]  // Objective: maximize 40x + 30y
let A = [[1, 0], [0, 1], [1, 1]]  // Constraints
let b = [40, 50, 70]

let solution = linprog(c, A, b, 1)  // 1 = maximize
// Optimal: x = 20, y = 50, profit = 2300
```

## Error Analysis

### Truncation Error

Error from approximating continuous with discrete:

```javascript
// Trapezoidal rule: O(h²)
// Smaller h → more accurate

let f = x => exp(x)
integral(f, 0, 1, 10)     // Less accurate
integral(f, 0, 1, 100)    // More accurate
integral(f, 0, 1, 1000)   // Even more accurate
```

### Roundoff Error

Error from finite precision arithmetic:

```javascript
// Very small h → roundoff dominates
diff(f, x, 1e-15)  // May be less accurate than 1e-5
```

### Optimal Step Size

For differentiation, optimal h balances truncation and roundoff:

```javascript
// Rule of thumb for diff:
// h ≈ √(machine_epsilon) ≈ 1e-8 for double precision
// In practice, 1e-5 works well

let optimal_h = 1e-5
diff(f, x, optimal_h)
```

## Best Practices

### 1. Choose Appropriate Method

```javascript
// Integration:
// - simpson: good balance of speed/accuracy
// - romberg: high accuracy needed
// - quad: automatic, general-purpose

// Root finding:
// - solve/bisect: guaranteed convergence
// - newton: fast if derivative available
// - secant: fast without derivative
```

### 2. Verify Results

```javascript
// Check against known values
let test_integral = simpson(x => x^2, 0, 1, 100)
// Should be 1/3 ≈ 0.333...

// Check convergence
let result1 = integral(f, a, b, 100)
let result2 = integral(f, a, b, 1000)
// If close, likely converged
```

### 3. Handle Edge Cases

```javascript
// Check for division by zero in Newton's method
let safe_newton = (f, df, x0, tol, max_iter) => {
    // Add check: if |df(x)| < small_value, switch method
}

// Check opposite signs for bisection
let safe_bisect = (f, a, b, tol) => {
    if(f(a) * f(b) > 0) {
        // Error: bracket doesn't contain root
    }
}
```

### 4. Use Adaptive Methods

```javascript
// Prefer adaptive methods for unknown functions
quad(mystery_function, 0, 1)  // Adapts automatically
romberg(mystery_function, 0, 1, 1e-10)  // Adapts to tolerance
```

## Limitations

### Recursion Depth

Due to recursion limits (~50 calls):

```javascript
// ❌ Can't use recursive integration for very fine grids
// ✅ Built-in functions handle large n internally
integral(f, 0, 1, 10000)  // Works fine
```

### Function Continuity

```javascript
// Discontinuous functions may fail
solve(x => if(x < 0, -1, 1), -1, 1, 1e-6)
// Bisection will fail (no sign change)

// Singularities
integral(x => 1/x, 0, 1, 1000)
// Fails at x=0 (division by zero)
```

### Oscillatory Functions

```javascript
// Highly oscillatory integrands need many points
integral(x => sin(100*x), 0, pi, 1000)  // May be inaccurate
integral(x => sin(100*x), 0, pi, 100000)  // Better
```

## Summary

**Differentiation**: diff, diff2, diff3, gradient (central differences)

**Integration**: integral/trapz, simpson, romberg, quad (various quadrature rules)

**Root Finding**: solve/bisect, newton, secant (bracketing and iterative methods)

**Key features**:
- Robust, well-tested algorithms
- Appropriate error handling
- Convergence criteria
- Suitable for engineering/scientific computing

**Best practices**:
- Choose appropriate method for problem
- Verify results and convergence
- Handle edge cases
- Use adaptive methods when appropriate

---

**Next**: [Statistics](16-statistics.md)

