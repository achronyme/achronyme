---
title: "Statistics"
description: "Statistical functions including mean, standard deviation, and data analysis in Achronyme"
section: "mathematical-computing"
order: 5
---


Achronyme provides essential statistical functions for data analysis, including descriptive statistics, measures of central tendency and dispersion, and vector operations.

## Overview

| Category | Functions |
|----------|-----------|
| **Basic Statistics** | sum, mean, std, variance |
| **Extrema** | min, max |
| **Vector Operations** | dot, cross, norm, normalize |

All statistical functions work with vectors, tensors, and support both real and complex numbers.

## Basic Statistics

### Sum

Calculate the sum of all elements:

```javascript
let data = [1, 2, 3, 4, 5]
sum(data)  // 15

let prices = [10.50, 20.30, 15.75]
sum(prices)  // 46.55

// Works with complex numbers
sum([1+i, 2+2i, 3+3i])  // 6+6i
```

**Formula**: `sum = Σ xᵢ`

**Complexity**: O(n)

### Mean (Average)

Calculate the arithmetic mean:

```javascript
let data = [10, 20, 30, 40, 50]
mean(data)  // 30

let grades = [85, 92, 78, 90, 88]
mean(grades)  // 86.6

// Works with complex numbers
mean([1+i, 2+2i, 3+3i])  // 2+2i
```

**Formula**: `mean = (Σ xᵢ) / n`

**Error**: Returns error on empty vector

### Standard Deviation

Calculate sample standard deviation:

```javascript
let data = [2, 4, 4, 4, 5, 5, 7, 9]
std(data)  // ~2.138

let measurements = [10.2, 10.5, 10.1, 10.4]
std(measurements)  // ~0.171
```

**Formula**: `std = √(Σ(xᵢ - μ)² / (n - 1))`

**Note**: Uses Bessel's correction (n-1) for sample standard deviation

**Error**: Requires at least 2 data points

**Complex numbers**: Uses magnitude-based calculation

### Variance

Calculate sample variance:

```javascript
let data = [2, 4, 4, 4, 5, 5, 7, 9]
// variance = std^2
let v = std(data)^2  // ~4.571
```

**Formula**: `variance = Σ(xᵢ - μ)² / (n - 1)`

**Note**: Variance is the square of standard deviation

## Extrema Functions

### Minimum

Find the smallest value:

```javascript
let data = [3, 1, 4, 1, 5, 9, 2, 6]
min(data)  // 1

let temperatures = [-5, 0, 3, -2, 8]
min(temperatures)  // -5
```

**Complexity**: O(n)

### Maximum

Find the largest value:

```javascript
let data = [3, 1, 4, 1, 5, 9, 2, 6]
max(data)  // 9

let scores = [85, 92, 78, 95, 88]
max(scores)  // 95
```

**Complexity**: O(n)

### Range

Calculate the range (max - min):

```javascript
let data = [3, 1, 4, 1, 5, 9, 2, 6]
let range = max(data) - min(data)  // 9 - 1 = 8

let temps = [15, 20, 25, 18, 22]
let temp_range = max(temps) - min(temps)  // 10
```

## Vector Operations

### Dot Product

Calculate the inner product of two vectors:

```javascript
let v1 = [1, 2, 3]
let v2 = [4, 5, 6]
dot(v1, v2)  // 1*4 + 2*5 + 3*6 = 32

// Perpendicular vectors
dot([1, 0], [0, 1])  // 0

// Parallel vectors
dot([2, 0], [3, 0])  // 6
```

**Formula**: `dot(v₁, v₂) = Σ v₁ᵢ × v₂ᵢ`

**Complex vectors**: Uses Hermitian inner product
```javascript
// dot(v₁, v₂) = Σ conj(v₁ᵢ) × v₂ᵢ
let z1 = [1+i, 2+2i]
let z2 = [1-i, 2-2i]
dot(z1, z2)  // 10
```

**Requirements**: Both vectors must have same length

### Cross Product

Calculate the cross product (3D vectors only):

```javascript
// Unit vectors
let i = [1, 0, 0]
let j = [0, 1, 0]
let k = [0, 0, 1]

cross(i, j)  // [0, 0, 1] = k
cross(j, k)  // [1, 0, 0] = i
cross(k, i)  // [0, 1, 0] = j

// General case
let v1 = [2, 3, 4]
let v2 = [5, 6, 7]
cross(v1, v2)  // [-3, 6, -3]
```

**Formula**:
```
cross(v₁, v₂) = [v₁_y×v₂_z - v₁_z×v₂_y,
                  v₁_z×v₂_x - v₁_x×v₂_z,
                  v₁_x×v₂_y - v₁_y×v₂_x]
```

**Properties**:
- Anti-commutative: `cross(a, b) = -cross(b, a)`
- Result is perpendicular to both inputs
- Magnitude: `|a × b| = |a| |b| sin(θ)`

**Requirements**: Both vectors must be 3-dimensional

### Vector Norm (Length)

Calculate Euclidean norm (L2 norm):

```javascript
let v = [3, 4]
norm(v)  // 5.0

let v3d = [1, 2, 2]
norm(v3d)  // 3.0

// Complex vectors (magnitude)
norm([3+4i, 0])  // 5.0
```

**Formula**: `‖v‖ = √(Σ xᵢ²)`

**Aliases**: Also called magnitude or length

**Complex vectors**: Uses magnitude of each component

### Normalize Vector

Scale vector to unit length:

```javascript
let v = [3, 4]
let u = normalize(v)  // [0.6, 0.8]
norm(u)  // 1.0

let v3d = [1, 1, 1]
normalize(v3d)  // [0.577, 0.577, 0.577]
```

**Formula**: `û = v / ‖v‖`

**Error**: Returns error if vector has zero norm

**Use cases**:
- Direction vectors
- Unit normals
- Normalized inputs

## Practical Examples

### Descriptive Statistics

```javascript
// Analyze dataset
let data = [23, 45, 67, 12, 89, 34, 56, 78, 90, 23]

let analysis = {
    count: 10,
    sum: sum(data),           // 517
    mean: mean(data),         // 51.7
    std: std(data),           // ~27.8
    min: min(data),           // 12
    max: max(data),           // 90
    range: max(data) - min(data)  // 78
}
```

### Z-Score Normalization

```javascript
// Normalize data to mean=0, std=1
let normalize_z = data => {
    let mu = mean(data)
    let sigma = std(data)
    return map(x => (x - mu) / sigma, data)
}

let scores = [70, 85, 90, 65, 95]
let z_scores = normalize_z(scores)
// Normalized: mean ≈ 0, std ≈ 1
```

### Moving Average

```javascript
// Simple moving average with window size
let moving_avg = (data, window) => {
    let n = length(data)
    let result = []
    // Implementation would need slicing
    // This is conceptual
}
```

### Distance Calculations

```javascript
// Euclidean distance between points
let distance = (p1, p2) => {
    let diff = map((a, b) => a - b, p1, p2)
    return norm(diff)
}

distance([0, 0], [3, 4])  // 5.0
distance([1, 2, 3], [4, 5, 6])  // 5.196
```

### Angle Between Vectors

```javascript
// Calculate angle using dot product
let angle = (v1, v2) => {
    let cos_theta = dot(v1, v2) / (norm(v1) * norm(v2))
    return acos(cos_theta)
}

let v1 = [1, 0]
let v2 = [1, 1]
angle(v1, v2)  // π/4 ≈ 0.785 radians (45 degrees)
```

### Projection

```javascript
// Project vector v onto u
let project = (v, u) => {
    let scalar = dot(v, u) / dot(u, u)
    return map(x => x * scalar, u)
}

let v = [3, 4]
let u = [1, 0]
project(v, u)  // [3, 0]
```

### Variance Calculation

```javascript
// Manual variance calculation
let variance_manual = data => {
    let mu = mean(data)
    let squared_diffs = map(x => (x - mu)^2, data)
    return sum(squared_diffs) / (length(data) - 1)
}

let data = [2, 4, 4, 4, 5, 5, 7, 9]
variance_manual(data)  // ~4.571
```

### Coefficient of Variation

```javascript
// Relative variability (CV = std / mean)
let cv = data => {
    let sigma = std(data)
    let mu = mean(data)
    return sigma / mu
}

let measurements = [100, 102, 98, 101, 99]
cv(measurements)  // ~0.015 (1.5% variation)
```

### Standardize Data

```javascript
// Scale to range [0, 1]
let normalize_01 = data => {
    let min_val = min(data)
    let max_val = max(data)
    let range = max_val - min_val
    return map(x => (x - min_val) / range, data)
}

let raw = [10, 20, 30, 40, 50]
normalize_01(raw)  // [0, 0.25, 0.5, 0.75, 1]
```

### Weighted Average

```javascript
// Calculate weighted mean
let weighted_mean = (values, weights) => {
    let products = map((v, w) => v * w, values, weights)
    return sum(products) / sum(weights)
}

let grades = [85, 90, 78]
let credits = [3, 4, 3]
weighted_mean(grades, credits)  // 84.9
```

### Root Mean Square

```javascript
// RMS value
let rms = data => {
    let squared = map(x => x^2, data)
    return sqrt(mean(squared))
}

let signal = [1, -2, 3, -4, 5]
rms(signal)  // ~3.32
```

### Perpendicular Vector (2D)

```javascript
// Find perpendicular vector in 2D
let perpendicular = v => [-v[1], v[0]]

let v = [3, 4]
let perp = perpendicular(v)  // [-4, 3]
dot(v, perp)  // 0 (perpendicular)
```

## Advanced Statistical Calculations

### Population vs Sample Statistics

```javascript
// Sample statistics (Bessel's correction, n-1)
let sample_std = data => std(data)  // Built-in uses n-1

// Population statistics (n)
let population_std = data => {
    let n = length(data)
    let mu = mean(data)
    let sum_sq = sum(map(x => (x - mu)^2, data))
    return sqrt(sum_sq / n)  // Divide by n, not n-1
}
```

### Harmonic Mean

```javascript
// Harmonic mean (useful for rates)
let harmonic_mean = data => {
    let reciprocals = map(x => 1/x, data)
    return length(data) / sum(reciprocals)
}

let speeds = [60, 40, 30]  // km/h
harmonic_mean(speeds)  // 42.86 km/h
```

### Geometric Mean

```javascript
// Geometric mean (useful for growth rates)
let geometric_mean = data => {
    let product = reduce((acc, x) => acc * x, 1, data)
    return product^(1 / length(data))
}

let growth_rates = [1.10, 1.05, 1.08]
geometric_mean(growth_rates)  // 1.077
```

## Type Support

All statistical functions work with:

```javascript
// Regular arrays (vectors)
let v = [1, 2, 3, 4, 5]
mean(v)

// Tensors (multi-dimensional arrays)
let matrix = [[1, 2], [3, 4]]
// Apply functions element-wise or on flattened data

// Complex numbers (where applicable)
let z = [1+i, 2+2i, 3+3i]
sum(z)    // 6+6i
mean(z)   // 2+2i
abs(z)    // [1.414, 2.828, 4.243]
```

## Error Handling

Common errors and how to handle them:

```javascript
// Empty vector
mean([])  // Error: empty tensor

// Insufficient data for std
std([42])  // Error: requires at least 2 points

// Dimension mismatch
dot([1, 2], [1, 2, 3])  // Error: incompatible dimensions

// Cross product requires 3D
cross([1, 2], [3, 4])  // Error: must be 3D vectors

// Zero norm for normalize
normalize([0, 0, 0])  // Error: zero norm
```

## Performance Tips

### Vectorize Operations

```javascript
// ✅ Efficient: single pass
let total = sum(data)

// ❌ Less efficient: manual loop
let total = reduce((acc, x) => acc + x, 0, data)
```

### Reuse Calculations

```javascript
// ✅ Calculate once
let mu = mean(data)
let centered = map(x => x - mu, data)

// ❌ Recalculate each time
map(x => x - mean(data), data)  // Calls mean() n times
```

### Combine Operations

```javascript
// ✅ Single pass: sum and count together
let avg = sum(data) / length(data)

// ❌ Two passes
let s = sum(data)
let n = length(data)
let avg = s / n
```

## Summary

**Basic statistics**: sum, mean, std, variance

**Extrema**: min, max

**Vector operations**: dot, cross, norm, normalize

**Key features**:
- Works with vectors and tensors
- Supports real and complex numbers
- Bessel's correction for sample statistics
- Robust error handling

**Best practices**:
- Use built-in functions when available
- Vectorize operations for performance
- Reuse calculated values
- Handle edge cases (empty data, single point)

**Common patterns**:
- Descriptive statistics
- Normalization and standardization
- Distance calculations
- Vector projections
- Weighted averages

---

**Next**: [Digital Signal Processing](17-dsp.md)

