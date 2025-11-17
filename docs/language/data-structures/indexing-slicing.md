---
title: "Indexing and Slicing"
description: "Array indexing, slicing, and data extraction in Achronyme"
section: "data-structures"
order: 3
---


Achronyme provides powerful indexing and slicing capabilities for accessing and extracting data from arrays, tensors, and strings.

## Basic Indexing

### Single Index Access

Access individual elements using square brackets `[index]`:

```javascript
let data = [10, 20, 30, 40, 50]

data[0]    // 10 (first element)
data[2]    // 30 (third element)
data[4]    // 50 (fifth element)
```

### Negative Indexing

Use negative indices to count from the end (Python-style):

```javascript
let data = [10, 20, 30, 40, 50]

data[-1]   // 50 (last element)
data[-2]   // 40 (second to last)
data[-5]   // 10 (fifth from end = first)
```

### Multi-dimensional Indexing

Access elements in multi-dimensional arrays with comma-separated indices:

```javascript
let matrix = [
    [1, 2, 3],
    [4, 5, 6],
    [7, 8, 9]
]

// Syntax: matrix[row, column]
matrix[0, 0]    // 1
matrix[1, 2]    // 6
matrix[2, 1]    // 8

// Negative indices work too
matrix[-1, -1]  // 9 (bottom-right)
matrix[-1, 0]   // 7 (bottom-left)
```

### 3D and Higher Dimensions

```javascript
let tensor3d = [
    [[1, 2], [3, 4]],
    [[5, 6], [7, 8]]
]

// Syntax: tensor[dim1, dim2, dim3]
tensor3d[0, 0, 0]    // 1
tensor3d[1, 1, 1]    // 8
tensor3d[0, 1, 0]    // 3
```

## Chained Indexing

You can chain index operations using nested brackets:

```javascript
let matrix = [[1, 2, 3], [4, 5, 6]]

// These are equivalent:
matrix[0, 1]    // 2
matrix[0][1]    // 2

// Chaining is useful for irregular structures
let data = [[1, 2], [3, 4, 5], [6]]
data[1][2]      // 5
```

## Slicing

### Range Syntax

Extract subsequences using the range operator `..`:

```javascript
let data = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

// Syntax: array[start..end]
// Note: start is inclusive, end is exclusive
data[2..5]      // [2, 3, 4]
data[0..3]      // [0, 1, 2]
data[7..10]     // [7, 8, 9]
```

### Open-ended Slicing

Omit start or end to slice from beginning or to end:

```javascript
let data = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

// From start to index (exclusive)
data[..5]       // [0, 1, 2, 3, 4]
data[..3]       // [0, 1, 2]

// From index to end
data[5..]       // [5, 6, 7, 8, 9]
data[7..]       // [7, 8, 9]

// Full copy
data[..]        // [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
```

### Negative Indices in Slices

Use negative indices in range expressions:

```javascript
let data = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

// Last 3 elements
data[-3..]      // [7, 8, 9]

// All except last 2
data[..-2]      // [0, 1, 2, 3, 4, 5, 6, 7]

// Middle portion
data[2..-2]     // [2, 3, 4, 5, 6, 7]
```

## Multi-dimensional Slicing

### 2D Slicing (Matrices)

Extract sub-matrices using ranges:

```javascript
let matrix = [
    [1,  2,  3,  4],
    [5,  6,  7,  8],
    [9,  10, 11, 12],
    [13, 14, 15, 16]
]

// Top-left 2×2 submatrix
matrix[0..2, 0..2]
// [[1, 2], [5, 6]]

// Center 2×2 submatrix
matrix[1..3, 1..3]
// [[6, 7], [10, 11]]

// Bottom-right 2×2 submatrix
matrix[2..4, 2..4]
// [[11, 12], [15, 16]]
```

### Extract Rows and Columns

```javascript
let matrix = [
    [1, 2, 3, 4],
    [5, 6, 7, 8],
    [9, 10, 11, 12]
]

// Extract single row (using one index)
matrix[0]           // [1, 2, 3, 4]
matrix[1]           // [5, 6, 7, 8]
matrix[-1]          // [9, 10, 11, 12] (last row)

// Extract multiple rows
matrix[0..2]        // [[1,2,3,4], [5,6,7,8]]

// Extract column (using full range for rows, single index for column)
matrix[.., 0]       // [1, 5, 9] (first column)
matrix[.., 2]       // [3, 7, 11] (third column)
matrix[.., -1]      // [4, 8, 12] (last column)

// Extract column range
matrix[.., 1..3]    // [[2,3], [6,7], [10,11]]
```

### 3D Tensor Slicing

```javascript
let tensor3d = [
    [[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12]],
    [[13, 14, 15, 16], [17, 18, 19, 20], [21, 22, 23, 24]]
]

// Extract 2D slice (first layer)
tensor3d[0]
// [[1, 2, 3, 4], [5, 6, 7, 8], [9, 10, 11, 12]]

// Extract 1D slice (first layer, first row)
tensor3d[0, 0]
// [1, 2, 3, 4]

// Extract single element
tensor3d[0, 1, 2]
// 7

// Extract sub-tensor
tensor3d[0..1, 0..2, 1..3]
// [[[2, 3], [6, 7]]]
```

## String Slicing

Strings support the same indexing and slicing operations:

```javascript
let text = "Achronyme Language"

// Single character
text[0]         // "A"
text[1]         // "c"
text[-1]        // "e"

// Substrings
text[0..9]      // "Achronyme"
text[10..]      // "Language"
text[..9]       // "Achronyme"

// Last 8 characters
text[-8..]      // "Language"
```

## Sub-tensor Extraction

When you provide fewer indices than dimensions, you get a sub-tensor:

```javascript
let tensor3d = [
    [[1, 2], [3, 4]],
    [[5, 6], [7, 8]]
]

// One index: returns 2D tensor
tensor3d[0]         // [[1, 2], [3, 4]]
tensor3d[1]         // [[5, 6], [7, 8]]

// Two indices: returns 1D tensor
tensor3d[0, 0]      // [1, 2]
tensor3d[1, 1]      // [7, 8]

// Three indices: returns scalar
tensor3d[0, 0, 0]   // 1
```

## Practical Examples

### Extract First N Elements

```javascript
let data = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

let first_3 = data[..3]       // [0, 1, 2]
let first_5 = data[..5]       // [0, 1, 2, 3, 4]
```

### Extract Last N Elements

```javascript
let data = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

let last_3 = data[-3..]       // [7, 8, 9]
let last_5 = data[-5..]       // [5, 6, 7, 8, 9]
```

### Skip First N Elements

```javascript
let data = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

let skip_2 = data[2..]        // [2, 3, 4, 5, 6, 7, 8, 9]
let skip_5 = data[5..]        // [5, 6, 7, 8, 9]
```

### Remove First and Last

```javascript
let data = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

let middle = data[1..-1]      // [1, 2, 3, 4, 5, 6, 7, 8]
```

### Window Extraction

```javascript
let data = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

// Extract windows of size 3
let window1 = data[0..3]      // [0, 1, 2]
let window2 = data[1..4]      // [1, 2, 3]
let window3 = data[2..5]      // [2, 3, 4]
```

### Matrix Row and Column Operations

```javascript
let matrix = [
    [1, 2, 3],
    [4, 5, 6],
    [7, 8, 9]
]

// Get diagonal (manually)
let diagonal = [matrix[0, 0], matrix[1, 1], matrix[2, 2]]
// [1, 5, 9]

// Get first row
let row1 = matrix[0]
// [1, 2, 3]

// Get first column
let col1 = matrix[.., 0]
// [1, 4, 7]

// Get submatrix (top-left 2×2)
let submatrix = matrix[0..2, 0..2]
// [[1, 2], [4, 5]]
```

### Data Processing with Slicing

```javascript
// Helper functions using slicing
let take = (n, arr) => arr[..n]
let drop = (n, arr) => arr[n..]
let head = arr => arr[0]
let tail = arr => arr[1..]
let last = arr => arr[-1]
let init = arr => arr[..-1]

// Example usage
let data = [1, 2, 3, 4, 5]

take(3, data)       // [1, 2, 3]
drop(2, data)       // [3, 4, 5]
head(data)          // 1
tail(data)          // [2, 3, 4, 5]
last(data)          // 5
init(data)          // [1, 2, 3, 4]
```

## Type Behavior

### Vectors

- Single index: Returns the element
- Range slice: Returns new vector or tensor
- Requires exactly 1 index/range

```javascript
let vec = [1, 2, 3, 4, 5]

vec[2]          // 3 (Number)
vec[1..4]       // [2, 3, 4] (Tensor/Vector)
```

### Tensors

- Support multi-dimensional indexing
- Support multi-dimensional slicing
- Fewer indices than dimensions returns sub-tensor

```javascript
let matrix = [[1, 2], [3, 4]]

matrix[0]       // [1, 2] (1D Tensor)
matrix[0, 1]    // 2 (Number)
```

### Strings

- Single index: Returns single-character string
- Range slice: Returns substring
- Requires exactly 1 index/range

```javascript
let s = "hello"

s[0]            // "h" (String)
s[1..4]         // "ell" (String)
```

## Edge Cases and Limitations

### Out of Bounds

```javascript
let data = [1, 2, 3, 4, 5]

// Single index out of bounds: ERROR
// data[10]       // Error: Index out of bounds

// Negative index too large: ERROR
// data[-10]      // Error: Index out of bounds

// Range clamping: end is clamped to length
data[2..100]    // [3, 4, 5] (clamped to length)
```

### Empty Ranges

```javascript
let data = [1, 2, 3, 4, 5]

// Empty range is allowed
data[2..2]      // []
data[5..3]      // [] (start >= end)
```

### Dimension Mismatch

```javascript
let matrix = [[1, 2], [3, 4]]

// Too many indices: ERROR
// matrix[0, 0, 0]    // Error: Too many indices

// Vectors require exactly 1 index
let vec = [1, 2, 3]
// vec[0, 1]          // Error: Vector requires 1 index
```

### Non-indexable Types

Cannot index these types:
- Numbers
- Booleans
- Functions
- Edges
- Networks

```javascript
let num = 42
// num[0]         // Error: Cannot index into Number
```

## Best Practices

### 1. Use Slicing for Subsequences

```javascript
// Good: clear and concise
let first_half = data[..5]
let second_half = data[5..]

// Avoid: manual element extraction
let first_half = [data[0], data[1], data[2], data[3], data[4]]
```

### 2. Negative Indices for End Access

```javascript
// Good: robust to length changes
let last = data[-1]
let second_last = data[-2]

// Avoid: brittle if length changes
let last = data[9]  // Only works for length 10
```

### 3. Use Full Range for Column Extraction

```javascript
let matrix = [[1, 2, 3], [4, 5, 6], [7, 8, 9]]

// Good: extract column
let col = matrix[.., 1]    // [2, 5, 8]

// Avoid: manual extraction
let col = [matrix[0][1], matrix[1][1], matrix[2][1]]
```

### 4. Bounds Checking

```javascript
// Good: check bounds first
let safe_access = arr =>
    if(length(arr) > 5, arr[5], undefined)

// Risky: direct access without check
let risky = arr => arr[5]  // Might error
```

## Common Patterns

### Split at Index

```javascript
let split_at = (n, arr) => [arr[..n], arr[n..]]

split_at(3, [1, 2, 3, 4, 5])
// [[1, 2, 3], [4, 5]]
```

### Sliding Window

```javascript
let window = (size, arr) => (
    (i, windows) =>
        if(i + size > length(arr),
           windows,
           rec(i + 1, [...windows, arr[i..i+size]]))
)(0, [])

// Note: Limited by recursion depth (~40)
window(3, [1, 2, 3, 4, 5])
// [[1, 2, 3], [2, 3, 4], [3, 4, 5]]
```

### Reverse (using slices)

```javascript
// For small arrays, build reversed manually
let reverse = arr => (
    (i, result) =>
        if(i < 0, result, rec(i - 1, [...result, arr[i]]))
)(length(arr) - 1, [])

// Limited to ~40 elements due to recursion depth
```

## Summary

- **Single index**: `arr[i]` - access element
- **Negative index**: `arr[-i]` - count from end
- **Range slice**: `arr[start..end]` - extract subsequence (start inclusive, end exclusive)
- **Open-ended**: `arr[..n]`, `arr[n..]`, `arr[..]`
- **Multi-dimensional**: `matrix[i, j]`, `tensor[i, j, k]`
- **Multi-dimensional slice**: `matrix[i1..i2, j1..j2]`
- **Column extraction**: `matrix[.., col_index]`
- **Sub-tensor**: Fewer indices than dimensions returns sub-tensor
- **String slicing**: Same syntax as arrays
- **Chained indexing**: `arr[i][j]` equivalent to `arr[i, j]` for regular tensors

---

**Next**: [Higher-Order Functions](11-higher-order-functions.md)

