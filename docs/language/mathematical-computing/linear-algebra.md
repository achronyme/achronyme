---
title: "Linear Algebra"
description: "Matrix operations, decompositions, and vector algebra in Achronyme"
section: "mathematical-computing"
order: 2
---


Achronyme provides comprehensive linear algebra capabilities for vector and matrix operations, matrix decompositions, eigenvalue problems, and linear system solving.

## Overview

| Category | Operations |
|----------|------------|
| **Vector Operations** | dot, cross, norm, normalize |
| **Matrix Operations** | transpose, det, trace |
| **Matrix Decompositions** | LU, QR, Cholesky, SVD |
| **Eigenvalue Problems** | eigenvalues, eigenvectors, power iteration |
| **Linear Systems** | inverse, solve |
| **Utilities** | isSymmetric, isPositiveDefinite |

All operations use the high-performance **faer** library backend, which is 100% Rust and WASM-compatible.

## Vector Operations

### Dot Product

Compute the inner product of two vectors:

```javascript
let v1 = [1, 2, 3]
let v2 = [4, 5, 6]

dot(v1, v2)
// 1*4 + 2*5 + 3*6 = 32
```

**Formula**: `v₁ · v₂ = Σ(v₁ᵢ × v₂ᵢ)`

**Complex support**:
```javascript
let z1 = [1+2i, 3+4i]
let z2 = [5+6i, 7+8i]
dot(z1, z2)  // Complex result
```

### Cross Product

Compute the cross product of two 3D vectors:

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
cross(v1, v2)
// [3*7-4*6, 4*5-2*7, 2*6-3*5]
// = [-3, 6, -3]
```

**Properties**:
- Anti-commutative: `cross(a, b) = -cross(b, a)`
- Result is perpendicular to both inputs
- Magnitude: `|a × b| = |a| |b| sin(θ)`

**Requirements**: Both vectors must be 3-dimensional.

### Vector Norm

Compute the Euclidean (L2) norm:

```javascript
let v = [3, 4]
norm(v)  // 5.0

let v3d = [1, 2, 2]
norm(v3d)  // 3.0
```

**Formula**: `‖v‖ = √(v₁² + v₂² + ... + vₙ²)`

**Complex vectors**:
```javascript
let z = [3+4i, 0]
norm(z)  // 5.0 (magnitude of complex vector)
```

### Normalize Vector

Scale a vector to unit length:

```javascript
let v = [3, 4]
let u = normalize(v)
// [0.6, 0.8]

norm(u)  // 1.0
```

**Formula**: `û = v / ‖v‖`

**Error**: Returns error if vector has zero norm.

**Use cases**:
- Direction vectors
- Unit normals
- Normalized inputs for algorithms

## Matrix Operations

### Transpose

Swap rows and columns:

```javascript
let A = [
    [1, 2, 3],
    [4, 5, 6]
]

let AT = transpose(A)
// [[1, 4],
//  [2, 5],
//  [3, 6]]
```

**Properties**:
- `(Aᵀ)ᵀ = A`
- `(AB)ᵀ = BᵀAᵀ`
- Symmetric matrix: `A = Aᵀ`

### Determinant

Compute the determinant of a square matrix:

```javascript
// 2×2 matrix
let A = [
    [4, 7],
    [2, 6]
]
det(A)  // 4*6 - 7*2 = 10

// 3×3 matrix
let B = [
    [1, 2, 3],
    [0, 1, 4],
    [5, 6, 0]
]
det(B)  // -51
```

**Properties**:
- `det(I) = 1` (identity matrix)
- `det(AB) = det(A) × det(B)`
- `det(Aᵀ) = det(A)`
- Non-singular matrix: `det(A) ≠ 0`

**Implementation**: Uses efficient LU decomposition for large matrices, recursive cofactor expansion for small matrices.

### Trace

Sum of diagonal elements:

```javascript
let A = [
    [1, 2, 3],
    [4, 5, 6],
    [7, 8, 9]
]

trace(A)  // 1 + 5 + 9 = 15
```

**Formula**: `tr(A) = Σ aᵢᵢ`

**Properties**:
- `tr(A + B) = tr(A) + tr(B)`
- `tr(cA) = c × tr(A)`
- `tr(AB) = tr(BA)`
- `tr(Aᵀ) = tr(A)`

## Matrix Decompositions

### LU Decomposition

Decompose matrix into lower and upper triangular matrices:

```javascript
let A = [
    [4, 3],
    [6, 3]
]

// A = P × L × U (with partial pivoting)
// Where:
// - L is lower triangular with 1s on diagonal
// - U is upper triangular
// - P is permutation matrix
```

**Use cases**:
- Solve linear systems
- Compute determinant
- Compute inverse

**Algorithm**: Gaussian elimination with partial pivoting
**Complexity**: O(n³)

### QR Decomposition

Decompose matrix into orthogonal and upper triangular matrices:

```javascript
let A = [
    [12, -51, 4],
    [6, 167, -68],
    [-4, 24, -41]
]

// A = Q × R
// Where:
// - Q is orthogonal: Qᵀ × Q = I
// - R is upper triangular
```

**Properties of Q**:
- Orthogonal columns
- Preserves vector norms
- `Qᵀ = Q⁻¹`

**Use cases**:
- Least squares problems
- Eigenvalue algorithms
- Stable orthogonalization

**Algorithm**: Householder reflections (numerically stable)
**Complexity**: O(mn²) for m×n matrix

### Cholesky Decomposition

Decompose symmetric positive-definite matrix:

```javascript
let A = [
    [4, 2, 1],
    [2, 3, 1],
    [1, 1, 2]
]

// A = L × Lᵀ
// Where L is lower triangular
```

**Requirements**:
- Square matrix
- Symmetric: `A = Aᵀ`
- Positive definite: all eigenvalues > 0

**Use cases**:
- Solve symmetric systems (fastest)
- Monte Carlo simulation
- Covariance matrices
- Optimization

**Complexity**: O(n³/3) - Faster than LU

**Error**: Fails if matrix is not positive definite.

### SVD - Singular Value Decomposition

Decompose matrix into singular vectors and values:

```javascript
let A = [
    [1, 2],
    [3, 4],
    [5, 6]
]

// A = U × Σ × Vᵀ
// Where:
// - U: left singular vectors (m × min(m,n))
// - Σ: singular values (diagonal, min(m,n) values)
// - Vᵀ: right singular vectors transposed (min(m,n) × n)
```

**Properties**:
- Works for any matrix (not just square)
- Singular values ≥ 0
- U and V are orthogonal

**Use cases**:
- Principal Component Analysis (PCA)
- Data compression
- Pseudo-inverse
- Low-rank approximation
- Recommendation systems
- Image compression

**Complexity**: O(min(m,n)² × max(m,n))

**Example - Low-rank approximation**:
```javascript
// Keep only top k singular values for compression
// A_approx = U[:, :k] × Σ[:k, :k] × Vᵀ[:k, :]
```

## Eigenvalue Problems

### Eigenvalues

Find eigenvalues λ such that `Av = λv`:

```javascript
let A = [
    [4, 1],
    [2, 3]
]

// Returns complex eigenvalues (even if real)
let eigenvals = eigenvalues(A)
// [5.0, 2.0] (approximately)
```

**Properties**:
- Sum of eigenvalues = trace(A)
- Product of eigenvalues = det(A)
- Symmetric matrix has real eigenvalues

**Complexity**: O(n³)

### Eigenvectors

Find eigenvalues and corresponding eigenvectors:

```javascript
let A = [
    [4, 1],
    [2, 3]
]

// Returns (eigenvalues, eigenvector_matrix)
// Each column of eigenvector_matrix is an eigenvector
```

**Verification**:
```javascript
// For eigenvalue λ and eigenvector v:
// A × v = λ × v
```

**Use cases**:
- Principal Component Analysis
- Quantum mechanics
- Stability analysis
- Graph algorithms (PageRank)

### Power Iteration

Find dominant eigenvalue (largest magnitude):

```javascript
let A = [
    [2, 1],
    [1, 2]
]

// Iterative method
// Returns (dominant_eigenvalue, corresponding_eigenvector)
```

**Algorithm**: Repeatedly multiply by matrix and normalize

**Convergence**: Faster when dominant eigenvalue is well-separated

**Use cases**:
- PageRank algorithm
- Find largest eigenvalue only (faster than full decomposition)

**Parameters**:
- `max_iterations`: Maximum iterations (e.g., 1000)
- `tolerance`: Convergence threshold (e.g., 1e-10)

### Symmetric Eigendecomposition

Optimized for symmetric matrices:

```javascript
let A = [
    [4, 1],
    [1, 3]
]

// Guaranteed real eigenvalues and orthogonal eigenvectors
```

**Properties for symmetric matrices**:
- All eigenvalues are real
- Eigenvectors are orthogonal
- Can be diagonalized: `A = Q Λ Qᵀ`

## Linear System Solving

### Matrix Inverse

Compute A⁻¹ such that `A × A⁻¹ = I`:

```javascript
let A = [
    [4, 7],
    [2, 6]
]

let A_inv = inverse(A)
// [[0.6, -0.7],
//  [-0.2, 0.4]]

// Verify: A × A_inv ≈ I
```

**Requirements**:
- Square matrix
- Non-singular: `det(A) ≠ 0`

**Warning**: Direct inversion is numerically unstable and expensive. Prefer solving systems directly when possible.

**Complexity**: O(n³)

### Solve Linear System

Solve `Ax = b` for x:

```javascript
// System of equations:
// 3x + y = 9
// x + 2y = 8

let A = [
    [3, 1],
    [1, 2]
]
let b = [9, 8]

let x = solve(A, b)
// [2, 3]

// Verify: A × x ≈ b
```

**Method**: LU decomposition with pivoting

**Requirements**:
- A is a matrix (rank-2 tensor)
- b is a vector (rank-1 tensor)
- Dimension compatibility: `A.rows == b.length`
- A must be non-singular

**Preferred over inverse**:
```javascript
// ❌ Slower and less accurate
let x = dot(inverse(A), b)

// ✅ Faster and more accurate
let x = solve(A, b)
```

## Matrix Utilities

### Check Symmetry

Test if matrix is symmetric:

```javascript
let A = [
    [4, 2, 1],
    [2, 3, 1],
    [1, 1, 2]
]

isSymmetric(A, 1e-10)  // true
```

**Definition**: `A[i,j] ≈ A[j,i]` for all i, j (within tolerance)

**Parameters**:
- `matrix`: The matrix to test
- `tolerance`: Numerical tolerance (e.g., 1e-10)

### Check Positive Definite

Test if matrix is positive definite:

```javascript
let A = [
    [2, -1],
    [-1, 2]
]

isPositiveDefinite(A)  // true
```

**Method**: Attempts Cholesky decomposition

**Definition**: Matrix A is positive definite if:
- `xᵀAx > 0` for all non-zero vectors x
- Equivalently: all eigenvalues > 0
- Equivalently: has Cholesky decomposition

**Use case**: Verify preconditions before using Cholesky or optimization algorithms.

## Practical Examples

### Least Squares Regression

```javascript
// Fit y = mx + b to data points
let X = [
    [1, 1],  // [1, x₁]
    [1, 2],  // [1, x₂]
    [1, 3],  // [1, x₃]
    [1, 4]   // [1, x₄]
]
let y = [2, 4, 5, 7]

// Normal equation: (XᵀX)β = Xᵀy
let XtX = dot(transpose(X), X)
let Xty = dot(transpose(X), y)
let beta = solve(XtX, Xty)
// [0.3, 1.5] → y = 1.5x + 0.3
```

### Distance Between Points

```javascript
// Distance in n-dimensional space
let distance = (p1, p2) => {
    let diff = map((a, b) => a - b, p1, p2)
    return norm(diff)
}

distance([0, 0], [3, 4])  // 5.0
distance([1, 2, 3], [4, 5, 6])  // 5.196...
```

### Angle Between Vectors

```javascript
// Angle using dot product
let angle = (v1, v2) => {
    let cos_theta = dot(v1, v2) / (norm(v1) * norm(v2))
    return acos(cos_theta)
}

let v1 = [1, 0]
let v2 = [1, 1]
angle(v1, v2)  // π/4 = 45 degrees
```

### Project Vector onto Another

```javascript
// Project v onto u
let project = (v, u) => {
    let scalar = dot(v, u) / dot(u, u)
    return map(x => x * scalar, u)
}

let v = [3, 4]
let u = [1, 0]
project(v, u)  // [3, 0]
```

### Gram-Schmidt Orthogonalization

```javascript
// Orthogonalize two vectors
let v1 = [1, 2, 3]
let v2 = [4, 5, 6]

// u1 = v1
let u1 = v1

// u2 = v2 - proj(v2 onto u1)
let proj = project(v2, u1)
let u2 = map((a, b) => a - b, v2, proj)

// Now u1 and u2 are orthogonal
dot(u1, u2)  // ≈ 0
```

### Rotation Matrix

```javascript
// 2D rotation by angle θ
let rotation_2d = theta => [
    [cos(theta), -sin(theta)],
    [sin(theta), cos(theta)]
]

// Rotate vector by 90 degrees
let R = rotation_2d(pi/2)
let v = [1, 0]
// Apply: R × v = [0, 1]
```

### Matrix Condition Number

```javascript
// Estimate condition number (ratio of extreme singular values)
// Large condition number → ill-conditioned (numerical instability)
let condition_approx = A => {
    // TODO: Implement using SVD
    // κ(A) = σ_max / σ_min
}
```

## Performance Considerations

### Algorithm Complexity

| Operation | Complexity | Notes |
|-----------|------------|-------|
| dot | O(n) | Fast, vectorized |
| cross | O(1) | Only 3D vectors |
| norm | O(n) | Fast, vectorized |
| transpose | O(mn) | Element copy |
| det | O(n³) | Uses LU |
| trace | O(n) | Diagonal sum |
| LU | O(n³) | With pivoting |
| QR | O(mn²) | Householder |
| Cholesky | O(n³/3) | Fastest for SPD |
| SVD | O(min(m,n)²max(m,n)) | Most expensive |
| eigenvalues | O(n³) | Full decomposition |
| inverse | O(n³) | Uses LU |
| solve | O(n³) | Uses LU |

### Numerical Stability

```javascript
// ✅ Stable: Solve system directly
let x = solve(A, b)

// ⚠️ Less stable: Use inverse
let x = dot(inverse(A), b)

// ✅ Stable: QR for least squares
// ⚠️ Less stable: Normal equations with XᵀX

// ✅ Stable: Cholesky for SPD matrices
// ⚠️ Less stable: General LU for SPD
```

### Choose Appropriate Method

```javascript
// Symmetric positive-definite system
// ✅ Use Cholesky (fastest, most stable)
let x = solve_cholesky(A, b)

// General square system
// ✅ Use LU
let x = solve(A, b)

// Overdetermined system (more equations than unknowns)
// ✅ Use QR or normal equations
let x = solve_least_squares(A, b)

// Large sparse system
// ✅ Use iterative solvers (TODO: not yet implemented)
```

## Type Support

All linear algebra functions work with:

```javascript
// Regular arrays (inferred as tensors)
let v = [1, 2, 3]
let A = [[1, 2], [3, 4]]

// Explicit tensors
// (When working from Rust/WASM)

// Complex numbers
let z = [1+2i, 3+4i]
norm(z)  // Works with complex vectors
```

## Error Handling

Common errors and how to handle them:

```javascript
// Dimension mismatch
dot([1, 2], [1, 2, 3])  // Error: incompatible dimensions

// Non-square matrix for operations requiring it
det([[1, 2, 3], [4, 5, 6]])  // Error: must be square

// Singular matrix
inverse([[1, 2], [2, 4]])  // Error: determinant = 0

// Non-positive-definite for Cholesky
// cholesky([[1, 2], [2, 1]])  // Error: not positive definite

// Zero vector for normalize
normalize([0, 0, 0])  // Error: zero norm
```

## Summary

**Vector operations**: dot, cross, norm, normalize

**Matrix operations**: transpose, det, trace

**Decompositions**: LU, QR, Cholesky, SVD

**Eigenvalues**: eigenvalues, eigenvectors, power iteration

**Linear systems**: inverse, solve

**Utilities**: isSymmetric, isPositiveDefinite

**Key features**:
- High-performance faer backend
- Numerically stable algorithms
- WASM-compatible
- Support for real and complex numbers

**Best practices**:
- Prefer `solve()` over `inverse()`
- Use Cholesky for symmetric positive-definite systems
- Check matrix properties before expensive operations
- Consider numerical stability

---

**Next**: [Complex Numbers](14-complex-numbers.md)

