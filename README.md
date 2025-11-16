# Achronyme

**A modern functional programming language for mathematical computing**

[![CI](https://github.com/achronyme/achronyme-core/actions/workflows/ci.yml/badge.svg)](https://github.com/achronyme/achronyme-core/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/achronyme/achronyme-core?include_prereleases)](https://github.com/achronyme/achronyme-core/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-1.70%2B-orange.svg)](https://www.rust-lang.org/)

Achronyme is a high-performance functional programming language designed for mathematical computing, data science, and digital signal processing. Built in Rust with a focus on expressiveness and performance, it combines the elegance of functional programming with the power of numerical computation.

```javascript
// Variables and functions with defaults
let greet = (name, greeting = "Hello") => '${greeting}, ${name}!'
greet("Alice")  // "Hello, Alice!"

// String interpolation
let user = {name: "Bob", age: 25}
'User ${user.name} is ${user.age} years old'

// Higher-order functions
let numbers = [1, 2, 3, 4, 5]
let doubled = map(x => x * 2, numbers)

// For-in loops with break/continue
mut sum = 0
for(x in numbers) {
    if(x % 2 == 0) { continue }
    sum += x
}

// Generators for lazy sequences
let range = (n) => generate {
    mut i = 0
    while(i < n) { yield i; i += 1 }
}

// Records with optional fields
type User = {name: String, email?: String}
let user: User = {name: "Alice"}  // email is optional
```

---

## ✨ Key Features

### 🎯 Functional Programming
- **First-class functions**: Lambdas, closures, and higher-order functions
- **Default and optional parameters**: `(x = 10)` and `(x?: Type)` syntax
- **Immutability by default**: Variables are immutable unless marked with `mut`
- **Pattern matching**: Powerful control flow with `match`, `if-else` and `piecewise()`
- **Recursion**: Native support with `rec` keyword for recursive functions
- **Generators**: Lazy sequences with `yield` and `generate`

### 🔢 Rich Type System
- **Number**: 64-bit floating point
- **Complex**: Native complex number support (`2+3i`)
- **Tensor**: N-dimensional homogeneous arrays (optimized for math)
- **Vector**: Heterogeneous arrays (can mix types)
- **Record**: Objects with methods and self-reference
- **Function**: First-class function values

### 📐 Mathematical Computing
- **Linear Algebra**: Vectors, matrices, decompositions (LU, QR, SVD, Eigenvalues)
- **DSP**: FFT, convolution, windowing functions
- **Numerical Analysis**: Differentiation, integration, equation solving
- **Statistics**: Mean, standard deviation, distributions
- **Complex Numbers**: Full arithmetic support

### 🏗️ Modern Language Features
- **Modules**: Import/export system for code organization
- **String interpolation**: Template strings with `'Hello, ${name}!'`
- **Compound assignment**: `+=`, `-=`, `*=`, `/=`, `%=`, `^=` operators
- **Loop control**: `break`, `continue`, and `for-in` loops
- **Optional record fields**: `{field?: Type}` syntax
- **Do Blocks**: Multi-statement blocks with early returns
- **Mutable Variables**: Controlled mutability with `mut` keyword
- **I/O and Persistence**: File operations and environment management
- **REPL**: Interactive development environment

---

## 🚀 Getting Started

### Installation

#### Option 1: Download Pre-built Binary (Recommended)

Download the latest release for your platform from [GitHub Releases](https://github.com/achronyme/achronyme-core/releases):

**Linux:**
```bash
wget https://github.com/achronyme/achronyme-core/releases/latest/download/achronyme-VERSION-linux-x64.tar.gz
tar -xzf achronyme-VERSION-linux-x64.tar.gz
chmod +x achronyme
./achronyme --version
```

**macOS:**
```bash
curl -LO https://github.com/achronyme/achronyme-core/releases/latest/download/achronyme-VERSION-macos-x64.tar.gz
tar -xzf achronyme-VERSION-macos-x64.tar.gz
chmod +x achronyme
./achronyme --version
```

**Windows:**
Download `achronyme-VERSION-windows-x64.zip`, extract, and run `achronyme.exe`.

> **Note:** Windows SmartScreen may show a warning for unsigned executables. Click "More info" → "Run anyway" to proceed. This is normal for open-source software without code signing certificates.

#### Option 2: Build from Source

Requires Rust 1.70+ and system dependencies (OpenBLAS, LAPACK).

```bash
git clone https://github.com/achronyme/achronyme-core.git
cd achronyme-core
cargo build --release
./target/release/achronyme --version
```

### Your First Program

Create a file `hello.soc`:

```javascript
// hello.soc - Using string interpolation and default parameters
let greet = (name, greeting = "Hello") => '${greeting}, ${name}!'

// Call the function
greet("Achronyme")       // "Hello, Achronyme!"
greet("World", "Hi")     // "Hi, World!"
```

Run it:

```bash
achronyme hello.soc
# or with the run subcommand
achronyme run hello.soc
```

### CLI Usage

```bash
# Start interactive REPL
achronyme

# Run a script
achronyme script.soc

# Evaluate an expression
achronyme "2 + 3 * 4"
achronyme --eval "map(x => x^2, [1,2,3,4])"

# Check syntax without running
achronyme check script.soc

# Show version and help
achronyme --version
achronyme --help
```

### REPL

Start the interactive REPL:

```bash
achronyme repl
# or just
achronyme
```

Try some examples:

```javascript
> let x = 42
> let double = x => x * 2
> double(x)
84

> let numbers = [1, 2, 3, 4, 5]
> map(x => x^2, numbers)
[1, 4, 9, 16, 25]

> let signal = [1, 0, -1, 0]
> fft(signal)
[0+0i, 1+1i, 0+0i, 1-1i]
```

---

## 📖 Language Examples

### Variables and Functions

```javascript
// Immutable by default
let x = 10
let y = x + 5

// Mutable with compound assignment
mut counter = 0
counter += 1    // counter = 1
counter *= 2    // counter = 2

// Lambda functions with defaults
let square = x => x^2
let add = (a, b = 0) => a + b
add(5)     // 5 (uses default)
add(5, 3)  // 8

// Optional parameters
let greet = (name: String, title?: String) =>
    match title { null => name, t => '${t} ${name}' }

greet("Alice")         // "Alice"
greet("Smith", "Dr.")  // "Dr. Smith"

// Recursion with rec
let factorial = (n, acc = 1) =>
    if(n <= 1) { acc } else { rec(n - 1, acc * n) }

factorial(5)  // → 120
```

### Arrays and Tensors

```javascript
// Homogeneous tensors (optimized for math)
let tensor = [1, 2, 3, 4, 5]
let matrix = [[1, 2], [3, 4]]

// Heterogeneous vectors (mixed types)
let mixed = [1, "hello", true, {x: 10}]

// Indexing and slicing
tensor[0]        // → 1
tensor[1..3]     // → [2, 3]
matrix[0, 1]     // → 2

// Spread operator
let combined = [...tensor, 6, 7, 8]
```

### Higher-Order Functions

```javascript
let numbers = [1, 2, 3, 4, 5, 6]

// Map: transform each element
map(x => x^2, numbers)
// → [1, 4, 9, 16, 25, 36]

// Filter: select elements
filter(x => x % 2 == 0, numbers)
// → [2, 4, 6]

// Reduce: aggregate values
reduce((a, b) => a + b, 0, numbers)
// → 21

// Pipe: chain functions
pipe(numbers,
    x => filter(n => n > 2, x),
    x => map(n => n^2, x),
    x => reduce((a,b) => a+b, 0, x))
// → 77
```

### Records and Methods

```javascript
// Simple record
let point = {x: 10, y: 20}
point.x  // → 10

// Record with methods
let counter = {
    mut value: 0,
    increment: () => do { self.value = self.value + 1 },
    get: () => self.value
}

counter.increment()
counter.get()  // → 1

// Record with computed properties
let circle = {
    radius: 5,
    area: () => pi() * self.radius^2,
    circumference: () => 2 * pi() * self.radius
}

circle.area()  // → 78.539...
```

### Control Flow

```javascript
// if() function (functional style)
let sign = x => if(x > 0, 1, if(x < 0, -1, 0))

// if-else statement (block style)
let classify = x => {
    if (x < 0) {
        "negative"
    } else if (x > 0) {
        "positive"
    } else {
        "zero"
    }
}

// For-in loops with break/continue
mut sum = 0
for(x in [1, 2, 3, 4, 5]) {
    if(x % 2 == 0) { continue }  // Skip evens
    sum += x
}
sum  // 9 (1 + 3 + 5)

// Break with value
let found = while(true) {
    let result = search()
    if(result > 100) { break result }
}

// Pattern matching
let describe = x => match x {
    0 => "zero"
    n if n < 0 => "negative"
    _ => "positive"
}

// piecewise for multiple conditions
let abs = x => piecewise(
    [x < 0, -x],
    [x >= 0, x]
)
```

### Digital Signal Processing

```javascript
// Generate a signal
let n = 1024
let t = linspace(0, 1, n)
let signal = map(x => sin(2 * pi() * 50 * x), t)

// Apply windowing
let window = hanning(n)
let windowed = map((s, w) => s * w, signal, window)

// FFT analysis
let spectrum = fft(windowed)
let magnitude = fft_mag(windowed)

// Convolution
let impulse = [1, 0.5, 0.25]
let filtered = conv(signal, impulse)
```

### Modules

```javascript
// Import from built-in modules
import { mean, std } from "stats"
import { sin, cos, exp } from "math"
import { dot, cross } from "linalg"

// Import from user modules
import { myHelper } from "src/utils"

// Export from current module
let myFunction = x => x * 2
export { myFunction }
```

---

## 📚 Documentation

### Language Documentation

Complete language reference available in `/docs/language/`:

- **[Overview](./docs/language/README.md)** - Quick reference and feature overview
- **[Getting Started](./docs/language/01-getting-started.md)** - Installation and first steps
- **[Syntax Basics](./docs/language/02-syntax-basics.md)** - Core syntax rules
- **[Data Types](./docs/language/03-data-types.md)** - Numbers, strings, arrays, records
- **[Functions](./docs/language/06-functions.md)** - Lambdas, closures, default/optional parameters
- **[Strings](./docs/language/20-strings.md)** - String interpolation and manipulation
- **[Records](./docs/language/07-records.md)** - Object-oriented patterns, optional fields
- **[Pattern Matching](./docs/language/36-pattern-matching.md)** - Match expressions and guards
- **[Loop Control](./docs/language/39-loop-control.md)** - break, continue, and for-in loops
- **[Generators](./docs/language/38-generators.md)** - Lazy sequences with yield
- **[Higher-Order Functions](./docs/language/11-higher-order-functions.md)** - map, filter, reduce
- **[Modules](./docs/language/28-modules.md)** - Import/export system
- **[Mutability](./docs/language/26-mutability.md)** - Mutable variables and fields

### Examples

Explore complete programs in `examples/soc/`:

```bash
# Run examples
cargo run -- examples/soc/fibonacci.soc
cargo run -- examples/soc/dsp_pipeline.soc
cargo run -- examples/soc/linear_algebra.soc
```

### Tests

Run the comprehensive test suite:

```bash
cargo test
```

---

## 🛠️ Building from Source

### Prerequisites

- **Rust 1.70+** (install from [rustup.rs](https://rustup.rs))
- **Cargo** (included with Rust)

### Build

```bash
# Clone the repository
git clone https://github.com/achronyme/achronyme-core.git
cd achronyme-core

# Build in release mode
cargo build --release

# Run tests
cargo test

# Run the REPL
cargo run --bin repl

# Run a script
cargo run -- path/to/script.soc
```

### Project Structure

```
achronyme-core/
├── crates/
│   ├── achronyme-eval/      # Evaluator and runtime
│   ├── achronyme-parser/    # Lexer and parser
│   └── achronyme-types/     # Core type system
├── docs/
│   └── language/            # Language documentation
├── examples/
│   └── soc/                 # Example programs
└── src/
    ├── bin/                 # CLI and REPL binaries
    └── lib.rs               # Library entry point
```

---

## 🎯 Language Philosophy

Achronyme is designed around these core principles:

1. **Functional First**: Immutability by default, functions as first-class values
2. **Mathematical Expressiveness**: Syntax optimized for mathematical notation
3. **Performance**: Native compilation with Rust for high-performance computing
4. **Simplicity**: Clear, concise syntax without unnecessary complexity
5. **Practical**: Designed for real-world mathematical and scientific computing

### Design Decisions

- **No null/undefined**: All values are concrete types
- **Expression-oriented**: Everything is an expression that returns a value
- **Type inference**: Types are inferred where possible
- **Lexical scoping**: Closures capture their environment
- **Tensors vs Vectors**: Homogeneous tensors for math, heterogeneous vectors for data structures

---

## 🗺️ Roadmap

### ✅ Completed

- ✅ Core language (variables, functions, control flow)
- ✅ Type system (Number, Complex, Tensor, Vector, Record, Function)
- ✅ Parser and evaluator
- ✅ Higher-order functions (map, filter, reduce, pipe)
- ✅ DSP module (FFT, convolution, windows)
- ✅ Linear algebra (matrix operations, decompositions)
- ✅ Recursion with `rec` keyword
- ✅ Modules and import/export system
- ✅ Mutability with `mut` keyword
- ✅ Do blocks and early returns
- ✅ I/O and persistence
- ✅ Pattern matching with `match` expressions
- ✅ String interpolation (`'Hello, ${name}!'`)
- ✅ Default parameter values (`(x = 10) => ...`)
- ✅ Optional parameters (`(x?: Type) => ...`)
- ✅ Optional record fields (`{field?: Type}`)
- ✅ Compound assignment operators (`+=`, `-=`, `*=`, `/=`, `%=`, `^=`)
- ✅ Loop control (`break`, `continue`)
- ✅ For-in loops (`for(x in collection)`)
- ✅ Generators with `yield` and `generate`
- ✅ Destructuring assignments

### 🚧 In Progress

- 🚧 Numerical analysis (derivatives, integrals, ODE solvers)
- 🚧 Advanced statistics
- 🚧 Optimization algorithms
- 🚧 Documentation improvements
- 🚧 LSP server for IDE support

### 🔮 Planned

- 🔮 Algebraic data types (enums, tagged unions)
- 🔮 Trait system (type classes)
- 🔮 Effect system (purity tracking)
- 🔮 Parallel computing primitives
- 🔮 GPU acceleration
- 🔮 Package manager
- 🔮 Standard library expansion

---

## 🤝 Contributing

Achronyme is open source and we welcome contributions!

### Areas We Need Help

- **Language Design**: Syntax improvements, new features
- **Core Implementation**: Parser, evaluator, optimizations
- **Standard Library**: New modules and functions
- **Documentation**: Tutorials, examples, translations
- **Testing**: Edge cases, performance benchmarks
- **Tooling**: IDE support, syntax highlighting, linters

### How to Contribute

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Submit a pull request

**Repository**: https://github.com/achronyme/achronyme-core
**Discussions**: https://github.com/achronyme/achronyme-core/discussions
**Issues**: https://github.com/achronyme/achronyme-core/issues

---

## 📝 License

MIT License - Copyright (c) 2025 Eduardo Alonso

See [LICENSE](./LICENSE) for details.

---

## 🔗 Links

- **[Documentation](./docs/language/)** - Complete language reference
- **[Examples](./examples/soc/)** - Sample programs
- **[GitHub](https://github.com/achronyme/achronyme-core)** - Source code
- **Website**: https://achrony.me

---

## 🌟 Why Achronyme?

**For Data Scientists**: Expressive syntax for data manipulation and analysis
**For Engineers**: High-performance DSP and numerical computing
**For Mathematicians**: Natural mathematical notation and operations
**For Programmers**: Modern functional programming with practical features

---

**Current Version**: 0.6.3

**Questions?** Open an issue on GitHub or join the discussions.

---

<p align="center">
  <strong>Built with ❤️ by the Achronyme community</strong>
  <br>
  Making mathematical computing accessible and elegant
</p>
