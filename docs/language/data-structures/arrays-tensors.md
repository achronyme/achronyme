---
title: "Arrays and Tensors"
description: "N-dimensional arrays and tensor operations for mathematical computing in Achronyme"
section: "data-structures"
order: 2
---


Achronyme provides powerful array and tensor capabilities for mathematical computing and data manipulation.

## Array Types

Achronyme automatically infers the appropriate array type based on the elements:

| Type | Elements | Use Case |
|------|----------|----------|
| **Tensor** | All numbers | Mathematical operations, linear algebra |
| **ComplexTensor** | Numbers and/or complex | Complex number computations |
| **Vector** | Mixed types or non-numeric | General-purpose collections |

### Type Inference

```javascript
// All numbers → Tensor
[1, 2, 3, 4, 5]

// Numbers with complex → ComplexTensor
[1, 2, 3 + 4i]

// Strings → Vector
["apple", "banana", "cherry"]

// Mixed types → Vector (heterogeneous)
[1, "hello", true, {x: 10}]
```

## Tensors (Numerical Arrays)

Tensors are N-dimensional arrays optimized for mathematical operations.

### 1D Tensors (Vectors)

```javascript
// Create a vector
let v = [1, 2, 3, 4, 5]

// Access elements (0-indexed)
v[0]        // 1
v[4]        // 5

// Negative indexing (from end)
v[-1]       // 5 (last element)
v[-2]       // 4 (second to last)
```

### 2D Tensors (Matrices)

```javascript
// Create a matrix
let matrix = [[1, 2, 3], [4, 5, 6]]

// Access elements [row, column]
matrix[0, 0]    // 1
matrix[1, 2]    // 6

// Or use nested indexing
matrix[0][1]    // 2
matrix[1][0]    // 4
```

### 3D and Higher-Dimensional Tensors

```javascript
// 3D tensor: 2×2×2
let tensor3d = [
    [[1, 2], [3, 4]],
    [[5, 6], [7, 8]]
]

// Access elements [dim1, dim2, dim3]
tensor3d[0, 0, 0]    // 1
tensor3d[1, 1, 1]    // 8

// Nested indexing also works
tensor3d[0][1][0]    // 3
```

## Tensor Operations

### Element-wise Arithmetic

```javascript
let a = [1, 2, 3]
let b = [4, 5, 6]

// Element-wise operations
a + b       // [5, 7, 9]
a - b       // [-3, -3, -3]
a * b       // [4, 10, 18]
a / b       // [0.25, 0.4, 0.5]
```

### Scalar Operations (Broadcasting)

```javascript
let v = [1, 2, 3, 4, 5]

// Scalar multiplication
v * 2       // [2, 4, 6, 8, 10]

// Scalar addition
v + 10      // [11, 12, 13, 14, 15]

// Scalar division
v / 2       // [0.5, 1, 1.5, 2, 2.5]

// Power
v^2         // [1, 4, 9, 16, 25]
```

### Matrix Operations

```javascript
let A = [[1, 2], [3, 4]]
let B = [[5, 6], [7, 8]]

// Element-wise operations
A + B       // [[6, 8], [10, 12]]
A * B       // [[5, 12], [21, 32]] (element-wise)

// Transpose
transpose(A)    // [[1, 3], [2, 4]]

// Determinant
det(A)          // -2

// Matrix multiplication would use dot()
// dot(A, B)
```

## Creating Tensors

### Literal Syntax

```javascript
// 1D
[1, 2, 3, 4, 5]

// 2D
[[1, 2, 3],
 [4, 5, 6]]

// 3D
[[[1, 2], [3, 4]],
 [[5, 6], [7, 8]]]
```

### Using Built-in Functions

```javascript
// Linear space (inclusive end)
linspace(0, 10, 11)     // [0, 1, 2, ..., 10]

// Range (exclusive end)
range(0, 10)            // [0, 1, 2, ..., 9]
range(1, 10, 2)         // [1, 3, 5, 7, 9] (with step)
range(10, 0, -1)        // [10, 9, 8, ..., 1] (descending)

// Zeros and ones (would need implementation)
// zeros(5)              // [0, 0, 0, 0, 0]
// ones(3, 3)            // [[1, 1, 1], [1, 1, 1], [1, 1, 1]]
```

## Indexing

### Basic Indexing

```javascript
let arr = [10, 20, 30, 40, 50]

// Positive indices (0-based)
arr[0]      // 10
arr[2]      // 30
arr[4]      // 50

// Negative indices (from end)
arr[-1]     // 50
arr[-2]     // 40
arr[-5]     // 10
```

### Multi-dimensional Indexing

```javascript
let matrix = [[1, 2, 3], [4, 5, 6], [7, 8, 9]]

// Single index
matrix[0]       // [1, 2, 3]
matrix[1]       // [4, 5, 6]

// Multi-index
matrix[0, 0]    // 1
matrix[1, 2]    // 6
matrix[2, 1]    // 8

// Nested indexing
matrix[0][1]    // 2
matrix[2][2]    // 9
```

## Slicing

### 1D Slicing

```javascript
let arr = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

// Range slice [start..end]
arr[2..5]       // [2, 3, 4, 5]
arr[0..3]       // [0, 1, 2, 3]

// From start [..end]
arr[..3]        // [0, 1, 2, 3]

// To end [start..]
arr[5..]        // [5, 6, 7, 8, 9]

// Full slice
arr[..]         // [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
```

### 2D Slicing

```javascript
let matrix = [
    [1, 2, 3, 4],
    [5, 6, 7, 8],
    [9, 10, 11, 12]
]

// Row slicing
matrix[0..1]    // First two rows

// Column slicing (if supported)
// matrix[:, 1..2]  // Columns 1-2

// Single row, range of columns
matrix[1][1..3] // [6, 7, 8]
```

## Vectors (Generic Arrays)

Vectors can hold any type of elements, including mixed types.

### Homogeneous Vectors

```javascript
// Strings
let names = ["Alice", "Bob", "Charlie"]

// Records
let users = [
    {name: "Alice", age: 30},
    {name: "Bob", age: 25}
]

// Functions
let operations = [
    x => x + 1,
    x => x * 2,
    x => x^2
]
```

### Heterogeneous Vectors

```javascript
// Mixed types
let mixed = [1, "hello", true, {x: 10}, x => x + 1]

// Access different types
mixed[0]        // 1 (Number)
mixed[1]        // "hello" (String)
mixed[2]        // true (Boolean)
mixed[3].x      // 10 (Record field)
mixed[4](5)     // 6 (Function call)

// Nested structures
let complex = [
    [1, 2, 3],              // Tensor
    "metadata",             // String
    {x: 10, y: 20},        // Record
    x => x * 2              // Function
]
```

## Array Construction

### Spread Operator

```javascript
// Concatenate arrays
let a = [1, 2, 3]
let b = [4, 5, 6]
let combined = [...a, ...b]     // [1, 2, 3, 4, 5, 6]

// Add elements
let extended = [...a, 7, 8]     // [1, 2, 3, 7, 8]

// Prepend elements
let prepended = [0, ...a]       // [0, 1, 2, 3]
```

### From Functions

```javascript
// Using map
let squares = map(x => x^2, [1, 2, 3, 4, 5])
// [1, 4, 9, 16, 25]

// Using filter
let evens = filter(x => x % 2 == 0, [1, 2, 3, 4, 5, 6])
// [2, 4, 6]

// Using reduce
let sum = reduce((acc, x) => acc + x, 0, [1, 2, 3, 4, 5])
// 15
```

## Array Properties

### Length

```javascript
let arr = [1, 2, 3, 4, 5]
len(arr)        // 5

let matrix = [[1, 2], [3, 4], [5, 6]]
len(matrix)     // 6 (total tensor elements for numeric arrays)

let strings = ["a", "b", "c"]
len(strings)    // 3
```

**Note:** For numeric arrays that become tensors, `len()` returns the total number of elements. Use `length()` for string length.

### Shape (for Tensors)

```javascript
// 1D: shape = [n]
let v = [1, 2, 3, 4, 5]         // shape: [5]

// 2D: shape = [rows, cols]
let m = [[1, 2, 3], [4, 5, 6]]  // shape: [2, 3]

// 3D: shape = [d1, d2, d3]
let t = [[[1, 2], [3, 4]], [[5, 6], [7, 8]]]  // shape: [2, 2, 2]
```

## Array Utility Functions

### Tier 1: Essential Operations

#### product(array)

Multiplies all elements in an array.

```javascript
product([1, 2, 3, 4])     // 24
product([2, 3, 4])        // 24
product([])               // 1 (empty product identity)
product([5])              // 5
```

#### range(start, end, step?)

Generates an integer sequence from start to end (exclusive) with optional step.

```javascript
range(0, 5)               // [0, 1, 2, 3, 4]
range(1, 10, 2)           // [1, 3, 5, 7, 9]
range(10, 0, -1)          // [10, 9, 8, 7, 6, 5, 4, 3, 2, 1]
range(0, 0)               // []
```

**Differences from linspace:**
- `range` generates integers, `linspace` generates floats
- `range` excludes end, `linspace` includes end
- `range` uses step, `linspace` uses count

#### len(array)

Returns the length of an array, vector, or tensor.

```javascript
len([1, 2, 3])            // 3
len([])                   // 0
len([[1, 2], [3, 4]])     // 4 (total elements for tensors)
len("hello")              // 5 (also works with strings)
```

#### reverse(array)

Reverses the order of elements in an array.

```javascript
reverse([1, 2, 3])        // [3, 2, 1]
reverse([])               // []
reverse(["a", "b", "c"])  // ["c", "b", "a"]
reverse("hello")          // "olleh" (also works with strings)
```

### Tier 2: Predicates and Search

#### any(array, predicate)

Returns true if any element satisfies the predicate. Short-circuits on first match.

```javascript
any([1, 2, 3, 4], x => x > 3)     // true
any([1, 2, 3], x => x > 10)       // false
any([], x => x > 0)               // false
```

#### all(array, predicate)

Returns true if all elements satisfy the predicate. Short-circuits on first failure.

```javascript
all([2, 4, 6, 8], x => x % 2 == 0)  // true
all([1, 2, 3], x => x > 0)          // true
all([1, 2, 3], x => x > 2)          // false
all([], x => x > 0)                 // true (vacuous truth)
```

#### find(array, predicate)

Finds and returns the first element that satisfies the predicate. Errors if not found.

```javascript
find([1, 2, 3, 4, 5], x => x > 3)   // 4 (first element > 3)
find([1, 2, 3], x => x > 10)        // Error: "Element not found"
```

#### findIndex(array, predicate)

Returns the index of the first element that satisfies the predicate. Returns -1 if not found.

```javascript
findIndex([1, 2, 3, 4, 5], x => x > 3)  // 3 (index of 4)
findIndex([1, 2, 3], x => x > 10)       // -1
findIndex([5, 4, 3, 2, 1], x => x == 5) // 0
```

#### count(array, predicate)

Counts how many elements satisfy the predicate.

```javascript
count([1, 2, 3, 4, 5], x => x > 2)     // 3 (3, 4, 5)
count([1, 2, 3], x => x > 10)          // 0
count(range(1, 11), x => x % 2 == 0)   // 5 (2, 4, 6, 8, 10)
```

#### contains(array, value)

Checks if an array contains a specific value. Also works with strings.

```javascript
contains([1, 2, 3, 4, 5], 3)           // true
contains([1, 2, 3], 10)                // false
contains([], 1)                        // false
contains("hello world", "world")       // true (string variant)
```

## Common Patterns

### Creating Ranges

```javascript
// Using linspace
let x = linspace(0, 10, 11)     // [0, 1, 2, ..., 10]
let y = linspace(0, 1, 5)       // [0, 0.25, 0.5, 0.75, 1]
```

### Matrix Construction

```javascript
// Row vectors
let row = [1, 2, 3, 4]

// Column vectors (1D tensor)
let col = [1, 2, 3, 4]

// Matrix from rows
let matrix = [
    [1, 2, 3],
    [4, 5, 6],
    [7, 8, 9]
]
```

### Nested Arrays

```javascript
// Array of arrays
let data = [
    [1, 2, 3],
    [4, 5, 6],
    [7, 8, 9]
]

// Access nested elements
data[1][2]      // 6
data[0][0]      // 1

// Modify with spread (immutable)
let updated = [
    [...data[0]],
    [...data[1], 10],  // Add element to row 1
    [...data[2]]
]
```

## Working with Multi-dimensional Data

### Flattening

```javascript
// Manual flattening (2D to 1D)
let matrix = [[1, 2], [3, 4], [5, 6]]
let flat = reduce(
    (acc, row) => [...acc, ...row],
    [],
    matrix
)
// [1, 2, 3, 4, 5, 6]
```

### Reshaping (Conceptual)

```javascript
// Create data
let data = [1, 2, 3, 4, 5, 6]

// "Reshape" to 2×3 manually
let reshaped = [
    [data[0], data[1], data[2]],
    [data[3], data[4], data[5]]
]
// [[1, 2, 3], [4, 5, 6]]
```

## Type Promotion

### Number to Complex

When mixing numbers and complex numbers, automatic promotion occurs:

```javascript
// Numbers promoted to complex
let mixed = [1, 2, 3 + 4i]
// Becomes: [1+0i, 2+0i, 3+4i] (ComplexTensor)
```

### Tensor to Vector

Mixed types force Vector type:

```javascript
// All numbers → Tensor
[1, 2, 3]

// Mixed → Vector
[1, "hello", 3]
```

## Best Practices

### 1. Use Tensors for Math

```javascript
// Good: homogeneous numeric data
let data = [1.2, 3.4, 2.1, 4.5]
let normalized = (data - mean(data)) / std(data)
```

### 2. Use Vectors for Heterogeneous Data

```javascript
// Good: mixed-type data
let record = [1, "Alice", 30, true]
```

### 3. Prefer Immutable Operations

```javascript
// Good: create new array
let original = [1, 2, 3]
let extended = [...original, 4, 5]

// Avoid: trying to mutate (won't work)
// original[0] = 99  // Error: immutable
```

### 4. Use Descriptive Names

```javascript
// Good
let pixel_values = [[255, 0, 0], [0, 255, 0]]
let coordinates = [[0, 0], [1, 1], [2, 2]]

// Avoid
let data = [[255, 0, 0], [0, 255, 0]]
let vals = [[0, 0], [1, 1], [2, 2]]
```

## Common Operations

### Sum and Statistics

```javascript
let data = [1, 2, 3, 4, 5]

sum(data)       // 15
mean(data)      // 3
std(data)       // Standard deviation
min(data)       // 1
max(data)       // 5
```

### Element-wise Functions

```javascript
let angles = [0, 3.14159/4, 3.14159/2]

// Apply function to each element
map(sin, angles)
map(cos, angles)
map(x => x^2, angles)
```

### Filtering and Selection

```javascript
let numbers = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

// Select even numbers
filter(x => x % 2 == 0, numbers)  // [2, 4, 6, 8, 10]

// Select values > 5
filter(x => x > 5, numbers)       // [6, 7, 8, 9, 10]
```

## Summary

- **Tensors**: Homogeneous numerical arrays (1D, 2D, 3D, ...)
- **Vectors**: Generic arrays (can be heterogeneous)
- **Type Inference**: Automatic based on elements
- **Indexing**: 0-based, supports negative indices
- **Slicing**: Range syntax `[start..end]`
- **Operations**: Element-wise arithmetic, broadcasting
- **Immutable**: All operations create new arrays
- **Spread**: Use `...` to combine/extend arrays

---

**Next**: [Indexing and Slicing](10-indexing-slicing.md)
