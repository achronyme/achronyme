---
title: "Mathematical Functions"
description: "Trigonometric, exponential, logarithmic, and rounding functions in Achronyme"
section: "mathematical-computing"
order: 1
---


Achronyme provides a comprehensive library of mathematical functions for numerical computing, including trigonometric, exponential, logarithmic, and utility functions.

## Function Categories

| Category | Functions |
|----------|-----------|
| **Trigonometric** | sin, cos, tan, asin, acos, atan, atan2 |
| **Hyperbolic** | sinh, cosh, tanh |
| **Exponential** | exp, ln, log, log10, log2 |
| **Power & Root** | sqrt, cbrt, pow, ^ operator |
| **Rounding** | floor, ceil, round, trunc |
| **Utility** | abs, sign, min, max |
| **Conversion** | deg, rad |
| **Constants** | pi, e, phi, sqrt2, sqrt3, ln2, ln10 |

## Type Support

Most mathematical functions work with:
- **Numbers** (scalars)
- **Vectors** (element-wise operations)
- **Tensors** (element-wise operations)
- **Complex numbers** (where applicable)

```javascript
// Scalar
sin(3.14159)           // Single value

// Vector/Tensor - element-wise
sin([0, 1, 2, 3])      // [sin(0), sin(1), sin(2), sin(3)]

// Complex (where supported)
abs(3 + 4i)            // 5.0
```

## Trigonometric Functions

### Basic Trigonometry

```javascript
// Sine
sin(0)                 // 0
sin(pi/2)              // 1
sin(pi)                // ~0

// Cosine
cos(0)                 // 1
cos(pi/2)              // ~0
cos(pi)                // -1

// Tangent
tan(0)                 // 0
tan(pi/4)              // 1
tan(pi/2)              // Infinity (undefined)
```

### Inverse Trigonometric

```javascript
// Arcsine - range: [-π/2, π/2]
asin(0)                // 0
asin(1)                // π/2
asin(-1)               // -π/2

// Arccosine - range: [0, π]
acos(1)                // 0
acos(0)                // π/2
acos(-1)               // π

// Arctangent - range: (-π/2, π/2)
atan(0)                // 0
atan(1)                // π/4
atan(-1)               // -π/4
```

### Two-Argument Arctangent

```javascript
// atan2(y, x) - full circle range: (-π, π]
// Handles quadrants correctly

atan2(1, 1)            // π/4 (first quadrant)
atan2(1, -1)           // 3π/4 (second quadrant)
atan2(-1, -1)          // -3π/4 (third quadrant)
atan2(-1, 1)           // -π/4 (fourth quadrant)

// Special cases
atan2(0, 1)            // 0 (positive x-axis)
atan2(1, 0)            // π/2 (positive y-axis)
atan2(0, -1)           // π (negative x-axis)
atan2(-1, 0)           // -π/2 (negative y-axis)
```

### Hyperbolic Functions

```javascript
// Hyperbolic sine
sinh(0)                // 0
sinh(1)                // 1.175...

// Hyperbolic cosine
cosh(0)                // 1
cosh(1)                // 1.543...

// Hyperbolic tangent
tanh(0)                // 0
tanh(1)                // 0.761...
tanh(10)               // ~1 (asymptotically approaches 1)
```

### Working with Angles

```javascript
// Generate angles
let angles = linspace(0, 2*pi, 100)

// Apply trigonometric functions
let sin_values = map(sin, angles)
let cos_values = map(cos, angles)

// Parametric circle
let x = map(cos, angles)
let y = map(sin, angles)
```

## Exponential and Logarithmic

### Exponential Function

```javascript
// e^x
exp(0)                 // 1
exp(1)                 // e ≈ 2.718...
exp(2)                 // e^2 ≈ 7.389...
exp(-1)                // 1/e ≈ 0.368...

// Vector exponential
exp([0, 1, 2])         // [1, 2.718..., 7.389...]
```

### Natural Logarithm

```javascript
// ln(x) - base e
ln(1)                  // 0
ln(e)                  // 1
ln(10)                 // 2.302...

// Inverse of exp
ln(exp(5))             // 5
exp(ln(5))             // 5
```

### Other Logarithms

```javascript
// log is alias for ln
log(e)                 // 1

// Base 10 logarithm
log10(1)               // 0
log10(10)              // 1
log10(100)             // 2
log10(1000)            // 3

// Base 2 logarithm (useful in computer science)
log2(1)                // 0
log2(2)                // 1
log2(8)                // 3
log2(1024)             // 10
```

### Change of Base

```javascript
// Calculate log_b(x) using change of base formula
let log_base = (base, x) => ln(x) / ln(base)

log_base(5, 125)       // 3 (5^3 = 125)
log_base(3, 81)        // 4 (3^4 = 81)
```

## Power and Root Functions

### Square Root

```javascript
sqrt(4)                // 2
sqrt(9)                // 3
sqrt(2)                // 1.414...

// Vector
sqrt([1, 4, 9, 16])    // [1, 2, 3, 4]

// Negative numbers return NaN
sqrt(-1)               // NaN (use complex numbers: (-1)^0.5)
```

### Cube Root

```javascript
cbrt(8)                // 2
cbrt(27)               // 3
cbrt(-8)               // -2 (works with negatives)

// Vector
cbrt([1, 8, 27, 64])   // [1, 2, 3, 4]
```

### Power Function

```javascript
// pow(base, exponent)
pow(2, 3)              // 8
pow(5, 2)              // 25
pow(10, -1)            // 0.1

// Fractional exponents
pow(4, 0.5)            // 2 (square root)
pow(8, 1/3)            // 2 (cube root)

// Using ^ operator (preferred)
2^3                    // 8
5^2                    // 25
4^0.5                  // 2
```

### nth Root

```javascript
// Calculate nth root using fractional exponent
let nthroot = (n, x) => x^(1/n)

nthroot(2, 16)         // 4 (square root)
nthroot(3, 27)         // 3 (cube root)
nthroot(4, 81)         // 3 (fourth root)
```

## Rounding Functions

### Floor, Ceil, Round

```javascript
let x = 3.7

floor(x)               // 3 (round down)
ceil(x)                // 4 (round up)
round(x)               // 4 (round to nearest)

// Negative numbers
floor(-3.7)            // -4 (towards -∞)
ceil(-3.7)             // -3 (towards +∞)
round(-3.7)            // -4 (to nearest)
```

### Truncate

```javascript
// Remove decimal part (round towards zero)
trunc(3.7)             // 3
trunc(-3.7)            // -3

// Difference from floor
floor(3.7)             // 3
trunc(3.7)             // 3 (same for positive)

floor(-3.7)            // -4
trunc(-3.7)            // -3 (different for negative)
```

### Vector Rounding

```javascript
let data = [1.2, 2.5, 3.7, 4.9]

floor(data)            // [1, 2, 3, 4]
ceil(data)             // [2, 3, 4, 5]
round(data)            // [1, 2, 4, 5]
trunc(data)            // [1, 2, 3, 4]
```

## Utility Functions

### Absolute Value

```javascript
// Numbers
abs(5)                 // 5
abs(-5)                // 5
abs(0)                 // 0

// Vector
abs([-3, -1, 0, 2, 4]) // [3, 1, 0, 2, 4]

// Complex numbers (magnitude)
abs(3 + 4i)            // 5
abs(1 + 1i)            // √2 ≈ 1.414...
```

### Sign Function

```javascript
// Returns -1, 0, or 1
sign(5)                // 1
sign(-5)               // -1
sign(0)                // 0

// Vector
sign([-3, -1, 0, 2, 4])
// [-1, -1, 0, 1, 1]

// Useful for normalizing direction
let direction = x => sign(x)
```

### Minimum and Maximum

```javascript
// Variadic (multiple arguments)
min(5, 2, 8, 1)        // 1
max(5, 2, 8, 1)        // 8

// Single collection
min([5, 2, 8, 1])      // 1
max([5, 2, 8, 1])      // 8

// Two arguments
min(10, 20)            // 10
max(10, 20)            // 20

// Common pattern: clamp value to range
let clamp = (x, low, high) => max(low, min(high, x))
clamp(15, 0, 10)       // 10
clamp(-5, 0, 10)       // 0
clamp(5, 0, 10)        // 5
```

## Angle Conversion

### Degrees and Radians

```javascript
// Radians to degrees
deg(pi)                // 180
deg(pi/2)              // 90
deg(2*pi)              // 360

// Degrees to radians
rad(180)               // π
rad(90)                // π/2
rad(360)               // 2π

// Round trip
deg(rad(45))           // 45
rad(deg(pi/4))         // π/4
```

### Working with Degrees

```javascript
// Sine in degrees
let sind = x => sin(rad(x))
let cosd = x => cos(rad(x))

sind(0)                // 0
sind(90)               // 1
sind(180)              // ~0
cosd(0)                // 1
cosd(90)               // ~0
cosd(180)              // -1
```

## Mathematical Constants

### Available Constants

```javascript
// Pi (case-insensitive)
pi                     // 3.141592653589793
PI                     // 3.141592653589793

// Euler's number
e                      // 2.718281828459045
E                      // 2.718281828459045

// Golden ratio
phi                    // 1.618033988749895
PHI                    // 1.618033988749895
goldenratio            // 1.618033988749895

// Square roots
sqrt2                  // 1.4142135623730951
SQRT2                  // 1.4142135623730951
sqrt3                  // 1.7320508075688772
SQRT3                  // 1.7320508075688772

// Natural logarithms
ln2                    // 0.6931471805599453
LN2                    // 0.6931471805599453
ln10                   // 2.302585092994046
LN10                   // 2.302585092994046
```

### Using Constants

```javascript
// Circle area
let area = r => pi * r^2
area(5)                // 78.539...

// Compound interest
let compound = (p, r, t) => p * e^(r * t)
compound(1000, 0.05, 10)  // 1648.72...

// Golden rectangle
let golden_rect = w => {
    width: w,
    height: w * phi
}
```

## Practical Examples

### Signal Generation

```javascript
// Generate sine wave
let t = linspace(0, 1, 1000)
let freq = 50
let signal = map(x => sin(2 * pi * freq * x), t)

// Multiple frequencies
let f1 = 50
let f2 = 120
let mixed = map(
    x => sin(2*pi*f1*x) + 0.5*sin(2*pi*f2*x),
    t
)
```

### Exponential Decay

```javascript
// Decay function: A * e^(-λt)
let decay = (A, lambda, t) => A * exp(-lambda * t)

let half_life = ln(2) / lambda
```

### Gaussian (Normal) Distribution

```javascript
// PDF of normal distribution
let gaussian = (x, mu, sigma) =>
    (1 / (sigma * sqrt(2*pi))) * exp(-0.5 * ((x - mu) / sigma)^2)

let x = linspace(-5, 5, 100)
let pdf = map(t => gaussian(t, 0, 1), x)
```

### Polar to Cartesian

```javascript
// Convert (r, θ) to (x, y)
let polar_to_cart = (r, theta) => {
    x: r * cos(theta),
    y: r * sin(theta)
}

polar_to_cart(5, pi/4)
// {x: 3.535..., y: 3.535...}
```

### Distance and Magnitude

```javascript
// 2D distance
let distance_2d = (x1, y1, x2, y2) =>
    sqrt((x2 - x1)^2 + (y2 - y1)^2)

// 3D distance
let distance_3d = (p1, p2) =>
    sqrt((p2[0] - p1[0])^2 + (p2[1] - p1[1])^2 + (p2[2] - p1[2])^2)

// Vector magnitude
let magnitude = v => sqrt(reduce((acc, x) => acc + x^2, 0, v))
```

### Normalization

```javascript
// Normalize data to [0, 1]
let normalize_01 = data => (
    params => map(x => (x - params[0]) / (params[1] - params[2]), data)
)([min(data), max(data)])

// Z-score normalization (mean=0, std=1)
let normalize_z = data =>
    map(x => (x - mean(data)) / std(data), data)
```

### Clamping and Smoothing

```javascript
// Clamp to range
let clamp = (x, low, high) => max(low, min(high, x))

// Smooth step (0 to 1)
let smoothstep = x => 3*x^2 - 2*x^3

// Sigmoid function
let sigmoid = x => 1 / (1 + exp(-x))
```

## Complex Number Support

Some functions support complex numbers:

```javascript
// Magnitude
abs(3 + 4i)            // 5
abs(1 + 1i)            // √2

// Real and imaginary parts
real(3 + 4i)           // 3
imag(3 + 4i)           // 4

// Conjugate
conj(3 + 4i)           // 3 - 4i

// Argument (phase)
arg(1 + 1i)            // π/4
arg(-1)                // π
```

See [Complex Numbers](14-complex-numbers.md) for more details.

## Error Handling

### Domain Errors

```javascript
// sqrt of negative (real mode)
sqrt(-1)               // NaN or error

// ln of non-positive
ln(0)                  // -Infinity or error
ln(-1)                 // NaN or error

// asin/acos outside [-1, 1]
asin(2)                // NaN or error
acos(-2)               // NaN or error
```

### Division by Zero

```javascript
// Some functions may error on division by zero
tan(pi/2)              // Infinity or error
1 / 0                  // Error (see language limitations)
```

## Performance Tips

### Vector Operations

```javascript
// ✅ Efficient: single vectorized call
let result = sin(large_array)

// ❌ Less efficient: element-by-element with map
let result = map(sin, large_array)
// (Note: both work, but vectorized is faster internally)
```

### Prefer Constants

```javascript
// ✅ Use constant
let area = r => pi * r^2

// ❌ Calculate each time
let area = r => 3.14159265359 * r^2
```

### Combine Operations

```javascript
// ✅ Single pass
let result = map(x => sin(x) + cos(x), data)

// ❌ Two passes
let sins = map(sin, data)
let coss = map(cos, data)
let result = map((s, c) => s + c, sins, coss)
```

## Summary

**Trigonometric**: sin, cos, tan, asin, acos, atan, atan2, sinh, cosh, tanh

**Exponential/Log**: exp, ln, log, log10, log2

**Power/Root**: sqrt, cbrt, pow, ^

**Rounding**: floor, ceil, round, trunc

**Utility**: abs, sign, min, max, deg, rad

**Constants**: pi, e, phi, sqrt2, sqrt3, ln2, ln10

**Key features**:
- Vectorized operations
- Complex number support (where applicable)
- Standard mathematical conventions
- Case-insensitive constants

---

**Next**: [Linear Algebra](13-linear-algebra.md)

