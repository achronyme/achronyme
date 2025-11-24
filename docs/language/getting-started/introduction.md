---
title: "Achronyme Language Reference"
description: "Welcome to the Achronyme programming language - a functional, expression-oriented language for mathematical computing"
section: "getting-started"
order: 1
---

Welcome to the Achronyme programming language documentation. Achronyme is a functional, expression-oriented language designed for mathematical computations, numerical analysis, and scientific computing.

## What is Achronyme?

Achronyme (also known as SOC - Scientific Operations Calculator) is a domain-specific language that combines:
- **Functional programming** with first-class functions and closures
- **Mathematical notation** familiar to scientists and engineers
- **Comprehensive built-in functions** for numerical analysis, DSP, linear algebra, and graph theory (available globally)
- **Tensor operations** with support for multi-dimensional arrays
- **Interactive REPL** for rapid prototyping and exploration

## File Extension

Achronyme source files use the `.soc` extension (Scientific Operations Calculator).

## Quick Example

```javascript
// Built-in functions are available globally (no imports needed)
// math: sin, cos, exp, log...
// stats: mean, std, var...

// Functions with default and optional parameters
let greet = (name, greeting = "Hello") => '${greeting}, ${name}!'
greet("Alice")  // "Hello, Alice!"

// String interpolation
let user = {name: "Bob", age: 30}
'User ${user.name} is ${user.age} years old'

// For-in loops with break/continue
mut sum = 0
for(x in [1, 2, 3, 4, 5]) {
    if(x % 2 == 0) { continue }
    sum += x
}

// Range operator for sequences
let numbers = 1..=10        // [1, 2, 3, ..., 10] (inclusive)
for(i in 1..10) {           // 1 to 9 (exclusive)
    print(i)
}

// Records with optional fields
type User = {name: String, email?: String}
let user: User = {name: "Alice"}  // email is optional

// Pattern matching
let describe = x => match x {
    0 => "zero"
    n if (n < 0) => "negative"
    _ => "positive"
}

// Short-circuit operators with default values
let name = userInput || "Anonymous"
let profile = user && user.profile    // Safe navigation

// IEEE 754 special values
Infinity                    // Positive infinity
1 / 0                       // Also Infinity
0 / 0                       // NaN (Not a Number)
isnan(0/0)                  // true
isinf(1/0)                  // true
isfinite(42)                // true

// Statistical analysis
let data = [10, 20, 30, 40, 50]
let average = mean(data)
let stdDev = std(data)
```

## Language Philosophy

### Expression-Oriented with Statements
Achronyme is primarily expression-oriented, where most constructs return values. However, it also supports imperative-style statements for better control flow.

```javascript
// Functional form: if() as a function
let result = if(x > 0, 1, -1)

// Statement form: if-else blocks
let classify = x => if (x < 0) {
    "negative"
} else if (x > 0) {
    "positive"
} else {
    "zero"
}

// While loops and for-in loops
mut sum = 0
for(x in [1, 2, 3]) { sum += x }
```

### Immutable by Default, Mutable When Needed
Variables are immutable by default but can be declared mutable with `mut`:

```javascript
// Immutable (default)
let x = 10
let x = x + 5  // New binding, shadows the old one

// Mutable (explicit)
mut counter = 0
counter = counter + 1  // Reassignment allowed
```

### First-Class Functions
Functions are values that can be passed around, stored in variables, and returned from other functions:

```javascript
let operation = if(mode == "add", (a, b) => a + b, (a, b) => a * b)
operation(3, 4)
```

### Type Inference
The language automatically infers types based on usage. Arrays of numbers become tensors, supporting efficient mathematical operations.

## Feature Highlights

### Mathematical Computing
- Built-in support for complex numbers: `2 + 3i`
- Tensor operations with broadcasting
- Comprehensive math library (trig, exp, log, etc.)

### Numerical Analysis
- Automatic differentiation
- Numerical integration (trapezoid, Simpson, Romberg)
- Root finding (bisection, Newton-Raphson, secant)

### Signal Processing
- Fast Fourier Transform (FFT)
- Convolution (direct and FFT-based)
- Window functions (Hanning, Hamming, Blackman)

### Graph Algorithms
- BFS, DFS, Dijkstra
- Minimum Spanning Trees (Kruskal, Prim)
- Topological sort
- PERT/CPM for project management

### Modern Syntax
- Lambda functions: `x => x^2`
- Default parameters: `(x = 10) => x^2`
- Optional parameters: `(x?: Number) => x`
- String interpolation: `'Hello, ${name}!'`
- Higher-order functions: `map`, `filter`, `reduce`
- Spread operator: `[...array1, ...array2]`
- Records with methods and `self` reference
- Optional record fields: `{field?: Type}`

### Concurrency and Reactivity
- **Async/Await**: Non-blocking execution with `async` functions and `await`.
- **Concurrency**: Spawn lightweight tasks (`spawn`) and communicate via `channel`s.
- **Reactivity**: Fine-grained reactivity system with `signal` and `effect` for building responsive UIs.

### Native GUI System
- **Immediate Mode**: High-performance UI rendering with `egui`.
- **Declarative Styling**: Tailwind-like syntax for rapid design.
- **Scientific Plotting**: Hardware-accelerated plotting for massive datasets.
- **Reactive Integration**: Bidirectional binding with Signals.

### System & Networking
- **File I/O**: Asynchronous file reading, writing, and management.
- **Networking**: Async HTTP client (`fetch`, `post`) for API integration.
- **Data Encoding**: Native support for JSON and CSV parsing/generation.

### Control Flow
- Pattern matching with `match` expressions
- Break and continue in loops
- For-in loops for collections
- Generators with `yield` and `generate`
- Compound assignment: `+=`, `-=`, `*=`, `/=`, `%=`, `^=`

## Community and Support

- **GitHub**: [Achronyme Repository](https://github.com/achronyme/achronyme-core)
- **Issues**: Report bugs or request features
- **Examples**: See the `examples/soc/` directory

## Next Steps

1. Start with [Installation](installation.md) to set up your environment
2. Learn the [Syntax Basics](syntax-basics.md)
3. Explore [Data Types](../core-language/data-types.md)
4. Try the [Examples](../advanced-topics/examples.md)
5. Dive into [Concurrency and Reactivity](../concurrency/async-await.md)
6. Explore the [Native GUI System](../ui/overview.md)

---

**Note**: This is an evolving language. Some features may be experimental or subject to change.