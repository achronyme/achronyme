---
title: "Complex Numbers"
description: "Complex arithmetic, polar form, and complex analysis in Achronyme"
section: "mathematical-computing"
order: 3
---


Achronyme provides comprehensive support for complex numbers, including natural syntax, arithmetic operations, mathematical functions, and integration with tensors and signal processing.

## Overview

Complex numbers in Achronyme:
- Natural syntax: `i`, `2+3i`, `1-4i`
- Full arithmetic: `+`, `-`, `*`, `/`, `^`
- Built-in functions: `real`, `imag`, `conj`, `arg`, `abs`
- ComplexTensor support for N-dimensional arrays
- Integration with FFT and DSP operations

## Complex Number Literals

### Imaginary Unit

The imaginary unit `i` represents √(-1):

```javascript
i                  // 0+1i
i^2                // -1
i^3                // -i (or 0-1i)
i^4                // 1
```

### Pure Imaginary Numbers

```javascript
3i                 // 0+3i
-2i                // 0-2i
1.5i               // 0+1.5i
```

### Complex Numbers

Complex numbers are created using arithmetic:

```javascript
// a + bi form
2 + 3i             // 2+3i
1 - 4i             // 1-4i
3 + 4i             // 3+4i

// Expression evaluation
let z = 1 + 2*i    // 1+2i
```

### Explicit Construction

```javascript
// Using complex() function
complex(3, 4)      // 3+4i
complex(0, 1)      // i
complex(5, 0)      // 5+0i
```

## Arithmetic Operations

### Addition

```javascript
(3 + 4i) + (1 + 2i)     // 4+6i
2 + 3i                  // 2+3i (number + complex)
(1 + i) + 5             // 6+i (complex + number)
```

**Formula**: `(a+bi) + (c+di) = (a+c) + (b+d)i`

### Subtraction

```javascript
(3 + 4i) - (1 + 2i)     // 2+2i
5 - (1 + i)             // 4-i
(2 + 3i) - 1            // 1+3i
```

**Formula**: `(a+bi) - (c+di) = (a-c) + (b-d)i`

### Multiplication

```javascript
(3 + 4i) * (1 + 2i)     // -5+10i
i * i                   // -1
(1 + i) * (1 - i)       // 2 (real result)
2 * (3 + 4i)            // 6+8i
```

**Formula**: `(a+bi)(c+di) = (ac-bd) + (ad+bc)i`

**Special cases**:
```javascript
i * i                   // -1
i * (1 + i)             // -1+i
(a + bi) * (a - bi)     // a² + b² (magnitude squared)
```

### Division

```javascript
(1 + i) / (1 - i)       // i
10 / (3 + 4i)           // 1.2-1.6i
(4 + 2i) / 2            // 2+i
```

**Formula**: `(a+bi)/(c+di) = [(ac+bd) + (bc-ad)i] / (c²+d²)`

**Implementation**: Multiply numerator and denominator by conjugate of denominator.

### Power - Real Exponent

```javascript
(1 + i)^2               // 2i
i^2                     // -1
i^4                     // 1
(3 + 4i)^2              // -7+24i
```

**Formula**: Uses polar form:
- `z^n = r^n * (cos(nθ) + i*sin(nθ))`
- where `z = r(cos(θ) + i*sin(θ))`

### Power - Complex Exponent

```javascript
i^i                     // e^(-π/2) ≈ 0.2079
2^i                     // cos(ln2) + i*sin(ln2)
(1 + i)^(1 + i)         // Complex result
```

**Formula**: `a^b = e^(b*ln(a))`

**Note**: Uses principal branch of logarithm.

### Negation

```javascript
-(3 + 4i)               // -3-4i
-i                      // -i (or 0-1i)
```

## Complex Number Functions

### real - Extract Real Part

```javascript
real(3 + 4i)            // 3
real(i)                 // 0
real(5)                 // 5

// Works on vectors
real([1+i, 2+2i, 3+3i])
// [1, 2, 3]
```

### imag - Extract Imaginary Part

```javascript
imag(3 + 4i)            // 4
imag(i)                 // 1
imag(5)                 // 0

// Works on vectors
imag([1+i, 2+2i, 3+3i])
// [1, 2, 3]
```

### abs - Magnitude (Absolute Value)

```javascript
abs(3 + 4i)             // 5.0
abs(i)                  // 1.0
abs(5)                  // 5.0

// Pythagorean theorem
abs(3 + 4i) == sqrt(3^2 + 4^2)  // true
```

**Formula**: `|a+bi| = √(a²+b²)`

**Works on vectors**:
```javascript
abs([3+4i, 5+12i])      // [5, 13]
```

### arg - Argument (Phase Angle)

```javascript
arg(1 + i)              // π/4 ≈ 0.785
arg(i)                  // π/2 ≈ 1.571
arg(-1)                 // π ≈ 3.142
arg(1)                  // 0

// Using atan2
arg(3 + 4i)             // atan2(4, 3) ≈ 0.927
```

**Formula**: `arg(a+bi) = atan2(b, a)`

**Range**: (-π, π]

**Quadrant handling**:
```javascript
arg(1 + i)              // π/4 (Quadrant I)
arg(-1 + i)             // 3π/4 (Quadrant II)
arg(-1 - i)             // -3π/4 (Quadrant III)
arg(1 - i)              // -π/4 (Quadrant IV)
```

### conj - Complex Conjugate

```javascript
conj(3 + 4i)            // 3-4i
conj(i)                 // -i
conj(5)                 // 5

// Works on vectors
conj([1+i, 2+2i])       // [1-i, 2-2i]
```

**Formula**: `conj(a+bi) = a-bi`

**Properties**:
```javascript
// z * conj(z) = |z|²
let z = 3 + 4i
z * conj(z)             // 25 (= 5²)

// Conjugate of sum
conj(z1 + z2) == conj(z1) + conj(z2)

// Conjugate of product
conj(z1 * z2) == conj(z1) * conj(z2)
```

## Polar Form and Conversions

### Polar to Rectangular

```javascript
// z = r(cos(θ) + i*sin(θ))
// Euler's formula: z = r*e^(iθ)

let polar_to_rect = (r, theta) =>
    r * (cos(theta) + i * sin(theta))

polar_to_rect(1, pi/4)
// 0.707... + 0.707...i ≈ (1+i)/√2
```

### Rectangular to Polar

```javascript
let rect_to_polar = z => ({
    r: abs(z),
    theta: arg(z)
})

rect_to_polar(1 + i)
// {r: 1.414..., theta: 0.785...}
```

## Mathematical Identities

### Euler's Identity

```javascript
// e^(iπ) + 1 = 0
// Most beautiful equation in mathematics
```

### De Moivre's Theorem

```javascript
// (cos(θ) + i*sin(θ))^n = cos(nθ) + i*sin(nθ)

let z = cos(pi/4) + i * sin(pi/4)
z^4  // Approximately i (rotation by 4*π/4 = π)
```

### Powers of i

```javascript
i^0                     // 1
i^1                     // i
i^2                     // -1
i^3                     // -i
i^4                     // 1
// Pattern repeats every 4
```

### Roots of Unity

```javascript
// nth roots of unity: solutions to z^n = 1

// 3rd roots of unity
let omega = -0.5 + 0.866025403784i  // e^(2πi/3)
omega^0                 // 1
omega^1                 // -0.5 + 0.866i
omega^2                 // -0.5 - 0.866i
omega^3                 // 1 (back to start)
```

## Complex Vectors and Tensors

### ComplexTensor

Arrays containing complex numbers are automatically stored as ComplexTensor:

```javascript
// Vector of complex numbers
let z = [i, 2+3i, 4]
// ComplexTensor: [0+1i, 2+3i, 4+0i]

// Matrix of complex numbers
let M = [
    [1+i, 2],
    [3, 4+i]
]
// ComplexTensor (2D)
```

### Vector Arithmetic

```javascript
let v1 = [1+2i, 3+4i]
let v2 = [5+6i, 7+8i]

// Element-wise operations
v1 + v2                 // [6+8i, 10+12i]
v1 - v2                 // [-4-4i, -4-4i]
v1 * v2                 // [-7+16i, -11+52i]
```

### Scalar Broadcasting

```javascript
let v = [1+i, 2+2i, 3+3i]

// Scalar multiplication
v * 2                   // [2+2i, 4+4i, 6+6i]
v * i                   // [-1+i, -2+2i, -3+3i]

// Scalar addition
v + (1+i)               // [2+2i, 3+3i, 4+4i]
```

### Vector Functions

```javascript
let v = [3+4i, 5+12i, 0+1i]

// Extract parts
real(v)                 // [3, 5, 0]
imag(v)                 // [4, 12, 1]

// Magnitudes
abs(v)                  // [5, 13, 1]

// Conjugates
conj(v)                 // [3-4i, 5-12i, 0-1i]
```

## Integration with Signal Processing

### FFT Returns Complex

```javascript
let signal = [0, 1, 0, -1]
let spectrum = fft(signal)
// Returns ComplexTensor

// Extract information
let magnitudes = fft_mag(signal)
let phases = fft_phase(signal)
let real_parts = real(spectrum)
let imag_parts = imag(spectrum)
```

### Complex Frequency Analysis

```javascript
// Generate complex sinusoid
let t = linspace(0, 1, 100)
let freq = 10
let complex_signal = map(
    x => cos(2*pi*freq*x) + i*sin(2*pi*freq*x),
    t
)

// Analyze
let spectrum = fft(complex_signal)
```

### Filtering with Conjugate

```javascript
// Conjugate symmetry for real signals
let spectrum = fft(real_signal)
let filtered = conj(spectrum)  // Apply conjugate
let result = ifft(filtered)
```

## Type Promotion

Numbers are automatically promoted to complex when needed:

```javascript
// Number + Complex → Complex
2 + 3i                  // 2+3i

// Complex * Number → Complex
(1+i) * 5               // 5+5i

// Mixed operations
[1, 2, 3] + i           // [1+1i, 2+1i, 3+1i]
```

## Higher-Order Functions

### Map with Complex Functions

```javascript
let vec = [2+i, 3+i, 4+i]

// Square each element
map(z => z^2, vec)
// [-3+4i, 8+6i, 15+8i]

// Rotate by 90° (multiply by i)
map(z => z * i, vec)
// [-1+2i, -1+3i, -1+4i]

// Compute magnitudes
map(abs, vec)
// [2.236..., 3.162..., 4.123...]
```

### Filter Complex Values

```javascript
let vec = [1+i, 2, 3+i, 4, 5+i]

// Keep only complex (imaginary part ≠ 0)
filter(z => imag(z) != 0, vec)
// [1+i, 3+i, 5+i]

// Keep only real
filter(z => imag(z) == 0, vec)
// [2, 4]
```

### Reduce Complex Values

```javascript
let vec = [1+i, 2+2i, 3+3i]

// Sum
reduce((acc, z) => acc + z, 0, vec)
// 6+6i

// Product
reduce((acc, z) => acc * z, 1, vec)
// -16+16i
```

## Practical Examples

### Impedance Calculations

```javascript
// Electrical impedance: Z = R + jωL - j/(ωC)
let impedance = (R, L, C, omega) =>
    R + i*omega*L - i/(omega*C)

let Z = impedance(50, 0.001, 0.00001, 1000)
abs(Z)  // Magnitude
arg(Z)  // Phase
```

### Quantum State

```javascript
// Quantum state: |ψ⟩ = α|0⟩ + β|1⟩
// where |α|² + |β|² = 1

let state = [0.6+0.8i, 0]  // Normalized
let probability_0 = abs(state[0])^2  // 1.0
let probability_1 = abs(state[1])^2  // 0.0
```

### Complex Polynomial

```javascript
// Evaluate polynomial with complex coefficients
let eval_poly = (coeffs, z) =>
    reduce(
        (acc, c, i) => acc + c * z^i,
        0,
        coeffs
    )

// p(z) = 1 + 2z + (1+i)z²
let p = [1, 2, 1+i]
eval_poly(p, i)  // Evaluate at z = i
```

### Mandelbrot Set

```javascript
// Test if point c is in Mandelbrot set
let mandelbrot = (c, max_iter) => (
    (n, z) =>
        if(n >= max_iter, true,
           if(abs(z) > 2, false,
              rec(n+1, z^2 + c)))
)(0, 0)

// Note: Limited by recursion depth (~50)
mandelbrot(0, 100)      // true (origin is in set)
mandelbrot(2, 100)      // false (diverges)
```

### Complex Rotation

```javascript
// Rotate point by angle θ
let rotate = (z, theta) =>
    z * (cos(theta) + i*sin(theta))

// Or using exponential form
let rotate_exp = (z, theta) =>
    z * exp(i*theta)  // Would need exp() function

// Rotate by 90 degrees
let p = 1 + i
rotate(p, pi/2)  // Approximately -1+i
```

## Common Patterns

### Magnitude and Phase

```javascript
// Convert complex vector to magnitude and phase
let to_polar = vec => ({
    magnitude: abs(vec),
    phase: map(arg, vec)
})

let z_vec = [1+i, 3+4i]
to_polar(z_vec)
// {magnitude: [1.414, 5], phase: [0.785, 0.927]}
```

### Complex Mean

```javascript
// Average of complex numbers
let complex_mean = vec =>
    reduce((acc, z) => acc + z, 0, vec) / length(vec)

complex_mean([1+i, 2+2i, 3+3i])
// 2+2i
```

### Distance in Complex Plane

```javascript
// Distance between two complex numbers
let distance = (z1, z2) => abs(z1 - z2)

distance(3+4i, 0)       // 5.0 (distance from origin)
distance(1+i, 1-i)      // 2.0 (vertical distance)
```

## Error Handling

### Division by Zero

```javascript
// Division by zero with complex numbers
1 / (0+0i)              // Error or Infinity
```

### Branch Cuts

```javascript
// Logarithm and power have branch cuts
// Results depend on principal branch
ln(-1)                  // πi (principal value)
(-1)^(0.5)              // i (principal square root)
```

## Performance Tips

### Use Real Operations When Possible

```javascript
// ✅ Faster: keep as real
let real_vec = [1, 2, 3]
abs(real_vec)

// ⚠️ Slower: unnecessary complex promotion
let complex_vec = [1+0i, 2+0i, 3+0i]
abs(complex_vec)
```

### Vectorize Complex Operations

```javascript
// ✅ Efficient: vectorized
let result = map(z => z^2, complex_vector)

// ❌ Less efficient: element-by-element
let result = []
// ... manual iteration
```

## Summary

**Literals**: `i`, `3i`, `2+3i`

**Arithmetic**: `+`, `-`, `*`, `/`, `^` (including complex exponents)

**Functions**: `real`, `imag`, `abs`, `arg`, `conj`, `complex`

**ComplexTensor**: N-dimensional complex arrays

**Integration**: FFT, DSP, linear algebra

**Key features**:
- Natural mathematical syntax
- Automatic type promotion
- Element-wise operations
- Full arithmetic support
- Mathematical functions

**Best practices**:
- Use real numbers when imaginary part is zero
- Vectorize operations for performance
- Understand branch cuts for logarithm and power
- Use polar form for multiplication/division

---

**Next**: [Numerical Analysis](15-numerical-analysis.md)

