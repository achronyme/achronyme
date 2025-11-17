---
title: "Data Types"
description: "Complete guide to Achronyme's type system including numbers, booleans, strings, complex numbers, tensors, and records"
section: "core-language"
order: 1
---

Achronyme has a rich type system designed for mathematical computing.

## Overview

| Type | Example | Description |
|------|---------|-------------|
| Number | `42`, `3.14` | 64-bit floating point |
| Boolean | `true`, `false` | Logical values |
| String | `"hello"` | Text |
| Complex | `2 + 3i` | Complex numbers |
| Tensor | `[1, 2, 3]` | N-dimensional numerical arrays (homogeneous) |
| Vector | `["a", "b"]` or `[1, "hi", true]` | Generic arrays (can be heterogeneous) |
| Record | `{x: 10}` | Key-value structures |
| Function | `x => x^2` | Callable functions |
| Edge | `A -> B` | Graph edges |
| Null | `null` | Absence of value (for optional types) |
| Error | `{message: "...", kind: "..."}` | Error values for try/catch |
| Generator | `generate { yield 1 }` | Lazy sequences |

## Numbers

All numbers are 64-bit floating point (IEEE 754 compliant).

```javascript
42            // Integer (stored as float)
3.14159       // Decimal
1.5e-10       // Scientific notation
-17           // Negative
```

### Special Values

```javascript
// Available constants
PI            // 3.14159...
E             // 2.71828...

// IEEE 754 special values
Infinity      // Positive infinity
1/0           // Infinity
-Infinity     // Negative infinity
-1/0          // -Infinity
NaN           // Not a Number
0/0           // NaN
```

### Special Floating-Point Values

Achronyme supports IEEE 754 special values: `Infinity`, `-Infinity`, and `NaN`.

```javascript
// Infinity values
1 / 0         // Infinity
-1 / 0        // -Infinity
Infinity + 1  // Infinity
Infinity - Infinity  // NaN

// NaN (Not a Number)
0 / 0         // NaN
sqrt(-1) in real numbers  // NaN (complex returns 0+1i instead)
NaN == NaN    // false (NaN is not equal to anything, including itself)
NaN != NaN    // true

// NaN from invalid operations
Infinity / Infinity  // NaN
Infinity - Infinity  // NaN
```

### Testing for Special Values

Use built-in functions to test for these special values:

```javascript
// Check for NaN
isnan(0/0)      // true
isnan(5)        // false

// Check for infinity
isinf(1/0)      // true
isinf(-1/0)     // true
isinf(42)       // false

// Check if value is finite
isfinite(42)    // true
isfinite(1/0)   // false
isfinite(NaN)   // false
```

### Important Notes

- **Complex numbers preserve mathematical meaning**: `sqrt(-1)` returns `0+1i` (complex) rather than `NaN`
- **Propagation**: Operations with `NaN` and `Infinity` follow IEEE 754 standard behavior
- **Falsy value**: `NaN` is a falsy value in boolean contexts: `if(!NaN)` is true
- **Equality**: `NaN` is the only value that is not equal to itself: `NaN == NaN` is `false`

## Booleans

```javascript
true
false

// From comparisons
5 > 3         // true
10 == 20      // false

// Logical operations
true && false // false
true || false // true
!true         // false
```

## Strings

Strings are immutable sequences of characters.

```javascript
"Hello, World!"
"The answer is 42"
""               // Empty string

// Escape sequences
"Line 1\nLine 2"
"He said \"Hi\""
```

### String Operations

```javascript
concat("Hello", " World")     // "Hello World"
length("hello")               // 5
```

## Complex Numbers

Complex numbers have real and imaginary parts.

```javascript
3i              // 0 + 3i
2 + 3i          // 2 + 3i
-5i             // 0 - 5i

// Operations
(2 + 3i) + (1 + 4i)    // 3 + 7i
(2 + 3i) * (1 - 2i)    // 8 - i

// Functions
let z = 3 + 4i
real(z)         // 3
imag(z)         // 4
conj(z)         // 3 - 4i
arg(z)          // Phase angle
```

### Imaginary Unit

The constant `i` represents sqrt(-1):

```javascript
i * i           // -1
let z = 2 + i * 3     // 2 + 3i
```

## Tensors

Tensors are N-dimensional arrays of numbers, optimized for mathematical operations.

### Vectors (1D Tensors)

```javascript
[1, 2, 3, 4, 5]        // 1D tensor (vector)

// Operations
[1, 2, 3] + [4, 5, 6]  // Element-wise: [5, 7, 9]
[1, 2, 3] * 2          // Broadcast: [2, 4, 6]
```

### Matrices (2D Tensors)

```javascript
[[1, 2], [3, 4]]       // 2x2 matrix

// Matrix operations
transpose([[1, 2], [3, 4]])
det([[1, 2], [3, 4]])
```

### Higher-Dimensional Tensors

```javascript
// 3D tensor: 2x2x2
[
    [[1, 2], [3, 4]],
    [[5, 6], [7, 8]]
]
```

### Shape and Dimensions

```javascript
let t = [[1, 2, 3], [4, 5, 6]]  // 2x3 tensor
// Shape: [2, 3]
// Dimensions: 2
```

## Vectors (Generic)

Vectors can hold elements of any type, including mixed types.

```javascript
// String vector
["apple", "banana", "cherry"]

// Vector of records
[
    {name: "Alice", age: 30},
    {name: "Bob", age: 25}
]

// Vector of functions
[
    x => x^2,
    x => x^3,
    x => x^4
]

// Heterogeneous vector (mixed types)
[1, "hello", true, {x: 10}, x => x + 1]

// Nested mixed types
[
    [1, 2, 3],
    "Alice",
    {name: "Bob", age: 30},
    false,
    x => x * 2
]
```

## Records

Records are key-value structures (like objects).

```javascript
// Simple record
{
    name: "Alice",
    age: 30,
    email: "alice@example.com"
}

// Nested records
{
    person: {
        name: "Bob",
        age: 25
    },
    address: {
        city: "Madrid",
        country: "Spain"
    }
}

// Records with methods
{
    x: 10,
    y: 20,
    distance: () => sqrt(self.x^2 + self.y^2)
}
```

### Accessing Fields

```javascript
let point = {x: 10, y: 20}
point.x         // 10
point.y         // 20
```

## Functions

Functions are first-class values.

```javascript
// Lambda function
let square = x => x^2

// Multi-parameter
let add = (a, b) => a + b

// Built-in function
sin
cos
map
```

### Function Types

1. **User-Defined** (lambdas)
```javascript
x => x^2
(a, b) => a + b
```

2. **Built-in**
```javascript
sin
cos
fft
```

3. **Closures** (capture environment)
```javascript
let makeAdder = n => x => x + n
let add5 = makeAdder(5)
add5(10)  // 15
```

## Edges (Graphs)

Edges represent graph relationships.

```javascript
// Directed edge
A -> B

// Undirected edge
A <> B

// Edge with metadata
A -> B : {weight: 5, label: "road"}
```

### Creating Networks

```javascript
let edges = [
    A -> B,
    B -> C,
    C -> A
]

let graph = network(edges)
```

## Type Conversion

### Automatic Conversions

Numbers to tensors:
```javascript
[1, 2, 3]  // Automatically becomes Tensor
```

Type promotion in arrays:
```javascript
[1, 2.5, 3]      // All floats
[1, 2, 3 + 4i]   // All complex
```

### Explicit Construction

```javascript
// Complex number
complex(2, 3)    // 2 + 3i

// Record
{x: 1, y: 2}

// Tensor operations
linspace(0, 10, 11)  // [0, 1, 2, ..., 10]
```

## Type Checking

Use `describe` to inspect types:

```javascript
describe(42)            // Number: 42
describe("hello")       // String: "hello"
describe([1, 2, 3])     // Tensor(1D): [1, 2, 3]
describe({x: 10})       // Record
describe(x => x^2)      // Function(UserDefined)
```

## Type Compatibility

### In Arrays

Arrays automatically infer their type based on elements:

```javascript
// All numbers -> Tensor (optimized for math)
[1, 2, 3]

// All strings -> Vector
["a", "b", "c"]

// Numbers with complex -> Complex Tensor (promoted)
[1, 2, 3 + 4i]

// All records -> Vector
[{x: 1}, {x: 2}]

// Mixed types -> Heterogeneous Vector
[1, "hello", true]

// Complex nested structures
[
    [1, 2],           // Tensor
    "text",           // String
    {x: 10},          // Record
    x => x + 1        // Function
]
```

**Type Promotion**: When mixing numbers and complex numbers, all numbers are promoted to complex for consistency.

### In Operations

```javascript
// OK: Number + Number
10 + 20            // 30

// OK: Tensor + Tensor (same shape)
[1, 2] + [3, 4]    // [4, 6]

// OK: Number + Complex
2 + 3i             // 2 + 3i

// Error: String + Number
"hello" + 42       // Type error
```

## Empty Values

```javascript
[]             // Empty array
{}             // Empty record
""             // Empty string
```

## Immutability

All values are immutable. Operations create new values:

```javascript
let v1 = [1, 2, 3]
let v2 = [...v1, 4]  // [1, 2, 3, 4]
// v1 is unchanged: [1, 2, 3]
```

## Heterogeneous Collections

Achronyme supports truly heterogeneous vectors, allowing you to mix any types:

### Practical Examples

```javascript
// Mixed data collection
let user_data = [
    1,                  // ID
    "Alice",            // Name
    30,                 // Age
    true,               // Active status
    {role: "admin"}     // Metadata
]

// Access by index
user_data[0]        // 1
user_data[1]        // "Alice"
user_data[4].role   // "admin"

// Collection of operations
let operations = [
    x => x + 1,
    x => x * 2,
    x => x^2
]
operations[0](5)    // 6
operations[1](5)    // 10
operations[2](5)    // 25

// Nested heterogeneous structures
let data = [
    [1, 2, 3],                    // Tensor
    "metadata",                   // String
    {x: 10, y: 20},              // Record
    [x => x^2, x => x^3],        // Vector of functions
    true                          // Boolean
]

data[0][1]          // 2
data[2].x           // 10
data[3][0](5)       // 25
```

### Use Cases

**1. Flexible Data Structures**
```javascript
// Row-based data (like CSV)
let row = ["Alice", 30, true, 75000.50]

// Mixed type tuples
let result = [true, "Success", {code: 200}]
```

**2. Function Collections**
```javascript
// Pipeline of transformations
let pipeline = [
    x => x * 2,
    x => x + 10,
    x => x^2
]

// Apply all transformations
let apply_all = (funcs, value) =>
    reduce((acc, f) => f(acc), value, funcs)

apply_all(pipeline, 5)  // ((5*2)+10)^2 = 400
```

**3. Configuration and Metadata**
```javascript
// Mixed configuration
let config = [
    "production",           // Environment
    8080,                   // Port
    true,                   // SSL enabled
    {timeout: 30000},      // Options
    x => log(x)            // Logger function
]
```

## Null

The `null` value represents the absence of a value, useful for optional types.

```javascript
// Null literal
null

// Optional record fields
type User = {name: String, email?: String}
let user: User = {name: "Alice"}  // email is null

// Pattern matching with null
match maybeValue {
    null => "no value",
    v => "got: " + str(v)
}

// Union types with null
let result: Number | null = null
```

## Error

Error values are used with the try/catch/throw system for structured error handling.

```javascript
// Error structure
{
    message: "Error description",
    kind: "TypeError",
    source: null  // Optional: chain errors
}

// Throw an error
throw "Simple error"
throw { message: "Detailed error", kind: "ValidationError" }

// Catch and inspect
try {
    riskyOperation()
} catch (e) {
    print(e.message)  // Access error message
    print(e.kind)     // Access error kind
}

// Type checking
let err: Error = try { throw "test" } catch (e) { e }
typeof(err)  // "Error"
```

See [Error Handling](../advanced-topics/error-handling.md) for complete documentation.

## Generator

Generators are lazy sequences that can be iterated over. They are created with `generate` blocks and can yield values with `yield`.

```javascript
// Create a generator
let gen = generate {
    yield 1
    yield 2
    yield 3
}

// Iterate over generator
for(x in gen) {
    print(x)  // 1, 2, 3
}

// Generator with logic
let range = (n) => generate {
    mut i = 0
    while(i < n) {
        yield i
        i += 1
    }
}

// Type annotation
let myGen: Generator = range(5)
typeof(myGen)  // "Generator"
```

See [Generators](../advanced-topics/generators.md) for complete documentation.

## Summary

- **Numbers**: 64-bit floating point
- **Booleans**: `true`/`false`
- **Strings**: Immutable text
- **Complex**: Real + imaginary
- **Tensors**: N-D numerical arrays (homogeneous)
- **Vectors**: Generic arrays (can be heterogeneous)
- **Records**: Key-value structures
- **Functions**: First-class callables
- **Edges**: Graph relationships
- **Null**: Absence of value (for optional types)
- **Error**: Structured error values for try/catch
- **Generator**: Lazy sequences with yield
- All values are **immutable** (except mut variables)
- Types are **inferred** automatically (with optional annotations)
- **Heterogeneous vectors** supported: mix any types freely

---

**Next**: [Operators](operators.md)
