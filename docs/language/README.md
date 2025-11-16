# Achronyme Language Documentation

Quick reference and complete documentation for the Achronyme programming language.

## Quick Start

```javascript
// Variables
let x = 42

// Functions
let square = x => x^2

// Arrays
let numbers = [1, 2, 3, 4, 5]

// Higher-order functions
let doubled = map(x => x * 2, numbers)

// Records
let point = {
    x: 10,
    y: 20,
    distance: () => sqrt(self.x^2 + self.y^2)
}
```

## Documentation Index

### Core Language
1. **[Index](00-index.md)** - Overview and navigation
2. **[Getting Started](01-getting-started.md)** - Installation and first steps
3. **[Syntax Basics](02-syntax-basics.md)** - Fundamental syntax rules
4. **[Data Types](03-data-types.md)** - Numbers, strings, arrays, records
5. **[Operators](04-operators.md)** - Arithmetic, logical, comparison
6. **[Variables](05-variables.md)** - Declaration and scope
7. **[Functions](06-functions.md)** - Lambdas, closures, recursion
8. **[Records](07-records.md)** - Objects and OOP patterns
9. **[Control Flow](08-control-flow.md)** - Conditionals and piecewise

### Advanced Features
10. **[Arrays and Tensors](09-arrays-tensors.md)** - Multi-dimensional arrays
11. **[Indexing and Slicing](10-indexing-slicing.md)** - Array access patterns
12. **[Higher-Order Functions](11-higher-order-functions.md)** - map, filter, reduce
13. **[Do Blocks](21-do-blocks.md)** - Multi-statement blocks
14. **[Recursion](22-recursion.md)** - Recursive patterns

### Mathematical Computing
15. **[Mathematical Functions](12-mathematical-functions.md)** - Trig, exp, log
16. **[Linear Algebra](13-linear-algebra.md)** - Vectors and matrices
17. **[Complex Numbers](14-complex-numbers.md)** - Complex arithmetic
18. **[Numerical Analysis](15-numerical-analysis.md)** - Calculus and solvers
19. **[Statistics](16-statistics.md)** - Statistical functions

### Specialized Modules
20. **[Digital Signal Processing](17-dsp.md)** - FFT, convolution, windows
21. **[Graph Theory](18-graph-theory.md)** - Networks and algorithms
22. **[Optimization](19-optimization.md)** - Linear programming
23. **[Strings](20-strings.md)** - String operations

### Additional Resources
24. **[Best Practices](23-best-practices.md)** - Code style and patterns
25. **[Examples](24-examples.md)** - Complete programs
26. **[Performance Limitations](25-performance-limitations.md)** - Stack limits and workarounds
27. **[Mutability](26-mutability.md)** - Mutable variables and record fields
28. **[I/O and Persistence](27-io-persistence.md)** - File I/O, environment save/restore
29. **[Modules](28-modules.md)** - Import/export system, code organization

### Pattern Matching and Destructuring
30. **[Pattern Matching](36-pattern-matching.md)** - Match expressions, guards, type patterns
31. **[Destructuring](37-destructuring.md)** - Extract values from records and vectors

### Iteration and Control Flow
32. **[Generators](38-generators.md)** - Lazy iterators with yield, infinite sequences
33. **[Loop Control](39-loop-control.md)** - break, continue, and for-in loops

## Quick Reference Card

### Literals
```javascript
42              // Number
3.14            // Float
true, false     // Boolean
"hello"         // String
2 + 3i          // Complex
[1, 2, 3]       // Array/Tensor
{x: 10, y: 20}  // Record
```

### Operators
```javascript
+, -, *, /, %   // Arithmetic
^               // Power
==, !=, <, >    // Comparison
&&, ||, !       // Logical
+=, -=, *=, /=  // Compound assignment
%=, ^=          // Compound assignment
```

### Variables
```javascript
// Immutable (default)
let x = 10
let y = x + 5

// Mutable (explicit)
mut counter = 0
counter = counter + 1
```

### Functions
```javascript
// Lambda
let f = x => x^2

// Multiple parameters
let add = (a, b) => a + b

// Default parameters
let greet = (name, greeting = "Hello") => '${greeting}, ${name}!'

// Optional parameters
let format = (value: Number, decimals?: Number) => value

// IIFE (complex expressions)
let process = x => (doubled => doubled + 10)(x * 2)

// Recursion with rec
let fact = n =>
    if(n <= 1, 1, n * rec(n - 1))
```

### Control Flow
```javascript
// if() function (functional form)
if(x > 0, 1, -1)

// if-else statement (block form)
if (x < 0) {
    -1
} else {
    1
}

// Early return
let validate = (x) => do {
    if (x < 0) {
        return false
    };
    if (x > 100) {
        return false
    };
    true
}

// break and continue in loops
mut i = 0
while(i < 100) {
    if(i == 10) { break }
    i += 1
}

// for-in iteration
for(x in [1, 2, 3, 4, 5]) {
    if(x % 2 == 0) { continue }
    sum += x
}

// piecewise() for multiple conditions
piecewise(
    [x < 0, -1],
    [x > 0, 1],
    0
)
```

### Arrays
```javascript
// Homogeneous (Tensor)
[1, 2, 3]
[[1, 2], [3, 4]]

// Heterogeneous (Vector)
[1, "hello", true, {x: 10}]

// Indexing
arr[0]
matrix[1, 2]

// Slicing
arr[1..3]
arr[..5]

// Spread
[...arr1, ...arr2]
```

### Records
```javascript
{x: 10, y: 20}
point.x
point.method()

// Optional fields
type User = {name: String, email?: String}
let user: User = {name: "Alice"}  // OK, email is optional

// Self-reference with mutable fields
{
    mut value: 10,
    double: () => do { self.value = self.value * 2 }
}

// Spread
{...base, extra: value}
```

### Higher-Order Functions
```javascript
map(f, array)
filter(pred, array)
reduce(fn, init, array)
pipe(value, f, g, h)  // Apply functions left-to-right
```

### Modules
```javascript
// Import from built-in modules
import { mean, std } from "stats"
import { sin, cos } from "math"
import { dot, norm } from "linalg"

// Import with alias
import { mean as average } from "stats"

// Import from user modules (relative paths)
import { helper } from "src/utils"

// Export from module
let myFunction = x => x * 2
export { myFunction }
```

### Common Functions
```javascript
// Math
sin(x), cos(x), sqrt(x)
exp(x), ln(x), pow(a, b)

// Array
sum(arr), mean(arr), std(arr)

// Linear Algebra
dot(v1, v2), cross(v1, v2)
transpose(M), det(M)

// DSP
fft(signal), ifft(spectrum)
linspace(start, end, n)

// Numerical
diff(f), integral(f, a, b)
solve(f, a, b)
```

## File Extension

Achronyme files use the `.soc` extension (Scientific Operations Calculator).

## Comments

```javascript
// Single-line comment
let x = 10  // End-of-line comment
```

## REPL Commands

```
help    - Show help
exit    - Exit REPL
quit    - Exit REPL
clear   - Clear screen
```

## Language Features

✅ **Functional Programming**
- First-class functions
- Closures
- Higher-order functions
- Recursion with `rec`

✅ **Mathematical Computing**
- Tensors (N-dimensional numerical arrays)
- Complex numbers
- Rich math library
- Numerical analysis

✅ **Flexible Data Structures**
- Heterogeneous vectors (mix any types)
- Homogeneous tensors (optimized for math)
- Records with methods
- First-class functions

✅ **Modern Syntax**
- Lambda functions: `x => expr`
- Spread operator: `...`
- IIFE pattern: `(x => expr)(value)`
- Records with methods

✅ **Immutability by Default**
- Variables immutable by default
- Optional mutability with `mut` keyword
- Functional updates
- Controlled state management

## Reserved Keywords

```
let      // Immutable variable declaration
mut      // Mutable variable declaration
true     // Boolean literal
false    // Boolean literal
self     // Record self-reference
rec      // Recursive function reference
import   // Import from modules
export   // Export from current module
from     // Used with import
as       // Alias in imports
return   // Early return from functions
break    // Exit loop early
continue // Skip to next iteration
yield    // Generator yield value
generate // Create generator
for      // For-in loop
in       // Used with for loops
match    // Pattern matching
type     // Type alias declaration
```

**Note**: `if` and `piecewise` are **built-in functions**, not keywords.

## Getting Help

- 📖 Read the [Getting Started Guide](01-getting-started.md)
- 💡 Check [Examples](24-examples.md)
- 🐛 Report issues on GitHub
- 📚 Explore the `examples/soc/` directory

## Contributing

The language is under active development. Contributions welcome!

---

**Start Learning**: [Getting Started](01-getting-started.md)
