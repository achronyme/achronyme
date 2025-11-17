---
title: "Getting Started with Achronyme"
description: "Installation guide and first steps with the Achronyme programming language"
section: "getting-started"
order: 2
---

This guide will help you get started with the Achronyme programming language.

## What You'll Learn

- How to run Achronyme programs
- Using the interactive REPL
- Your first Achronyme program
- Basic workflow

## Prerequisites

- Basic understanding of programming concepts
- Familiarity with mathematical notation is helpful but not required

## Installation

### Option 1: Download Pre-built Binary (Recommended)

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

> **Note:** Windows SmartScreen may show a warning for unsigned executables. Click "More info" then "Run anyway" to proceed.

### Option 2: Build from Source

Requires Rust 1.70+ toolchain.

```bash
# Clone the repository
git clone https://github.com/achronyme/achronyme-core.git
cd achronyme-core

# Build the project
cargo build --release

# The binary will be available in target/release/
```

## Running Achronyme

### Interactive REPL

The easiest way to get started is with the interactive REPL (Read-Eval-Print Loop):

```bash
# Using pre-built binary
achronyme

# Or from source
cargo run --release
```

You'll see a prompt like this:

```
Achronyme REPL v0.6.3
Type 'exit' or 'quit' to exit, 'help' for help, 'clear' to clear screen

>
```

### Running .soc Files

To run a `.soc` file:

```bash
# Using pre-built binary
achronyme myprogram.soc

# Or with explicit run subcommand
achronyme run myprogram.soc

# From source
cargo run --release -- myprogram.soc
```

### CLI Commands

```bash
# Start REPL
achronyme

# Run a script
achronyme script.soc

# Evaluate an expression directly
achronyme --eval "map(x => x^2, [1,2,3])"

# Check syntax without execution
achronyme check script.soc

# Show version
achronyme --version
```

## Your First Program

### Hello, World! (The Mathematical Way)

In the REPL, type:

```javascript
"Hello, World!"
```

Output:
```
"Hello, World!"
```

### Basic Arithmetic

```javascript
ach[1]> 2 + 2
4

ach[2]> 3.14 * 2
6.28

ach[3]> 2^10
1024
```

### Using Variables

```javascript
ach[4]> let x = 42
42

ach[5]> x * 2
84

ach[6]> let y = x + 8
50
```

### Defining Functions

```javascript
ach[7]> let square = x => x^2
Function(UserDefined)

ach[8]> square(5)
25

ach[9]> let add = (a, b) => a + b
Function(UserDefined)

ach[10]> add(10, 20)
30
```

### Working with Arrays

```javascript
ach[11]> let numbers = [1, 2, 3, 4, 5]
[1, 2, 3, 4, 5]

ach[12]> let doubled = map(x => x * 2, numbers)
[2, 4, 6, 8, 10]

ach[13]> sum(numbers)
15
```

## REPL Commands

The REPL supports several special commands:

| Command | Description |
|---------|-------------|
| `help` | Show help message |
| `exit` or `quit` | Exit the REPL |
| `clear` | Clear the screen |

## Creating Your First .soc File

Create a file called `first.soc`:

```javascript
// first.soc - My first Achronyme program

// Define a factorial function using rec
let factorial = n =>
    if(n <= 1, 1, n * rec(n - 1))

// Calculate some factorials
let f5 = factorial(5)
let f10 = factorial(10)

// Display results
f5
f10
```

Run it:

```bash
cargo run --bin achronyme-repl < first.soc
```

## Comments

Achronyme supports single-line comments:

```javascript
// This is a comment
let x = 42  // Comments can go at the end of lines

// Multi-line comments are done with multiple // lines
// like this
let y = 10
```

## Basic Workflow

### 1. Experiment in the REPL

Use the REPL for quick calculations and testing:

```javascript
ach[1]> sin(3.14159 / 2)
0.9999999999991198

ach[2]> let data = [1, 2, 3, 4, 5]
[1, 2, 3, 4, 5]

ach[3]> mean(data)
3
```

### 2. Write .soc Files for Larger Programs

For more complex programs, write `.soc` files:

```javascript
// analysis.soc

let data = [23, 45, 67, 12, 89, 34, 56]

let stats = {
    count: length(data),
    total: sum(data),
    average: mean(data),
    spread: std(data)
}

stats
```

### 3. Load and Test Functions

```javascript
// functions.soc

let fibonacci = n =>
    if(n <= 1, n, rec(n - 1) + rec(n - 2))

// Test the function
fibonacci(10)
```

## Common Patterns

### Mathematical Computations

```javascript
// Calculate area under curve
let f = x => x^2
let area = integral(f, 0, 10)

// Find derivative
let df = diff(f)
let slope_at_5 = df(5)
```

### Data Processing

```javascript
// Load and process data
let raw_data = [1.2, 3.4, 2.1, 4.5, 3.2]

// Normalize (z-score)
let mu = mean(raw_data)
let sigma = std(raw_data)
let normalized = map(x => (x - mu) / sigma, raw_data)
```

### Signal Processing

```javascript
// Generate a signal
let t = linspace(0, 1, 100)
let signal = map(x => sin(2 * 3.14159 * 5 * x), t)

// Apply FFT
let spectrum = fft(signal)
let magnitude = fft_mag(signal)
```

## Tips for Beginners

### 1. Use the REPL for Learning

The REPL provides immediate feedback. Try things out!

```javascript
ach[1]> let x = 10
10

ach[2]> describe(x)
Number: 10
```

### 2. Functions are Values

Don't forget that functions are first-class values:

```javascript
ach[3]> let operations = [
    (a, b) => a + b,
    (a, b) => a * b,
    (a, b) => a^b
]

ach[4]> operations[0](2, 3)
5
```

### 3. Explore Built-in Functions

Use `describe` to learn about values:

```javascript
ach[4]> describe(sin)
Function(Builtin): sin

ach[5]> describe([1, 2, 3])
Tensor(1D)
  Shape: [3]
  Data: [1, 2, 3]
```

## Next Steps

Now that you can run Achronyme programs, continue to:

- [Syntax Basics](syntax-basics.md) - Learn the fundamental syntax
- [Data Types](../core-language/data-types.md) - Understand Achronyme's type system
- [Functions](../core-language/functions.md) - Deep dive into functions and lambdas
- [Examples](../advanced-topics/examples.md) - See complete example programs

## Troubleshooting

### "Undefined variable or constant"

Make sure the function or variable is defined:

```javascript
ach[1]> myFunction(10)
Error: Undefined variable or constant: myFunction

// Define it first:
ach[2]> let myFunction = x => x * 2
Function(UserDefined)

ach[3]> myFunction(10)
20
```

### "Parse error"

Check your syntax. Common issues:
- Missing parentheses in function calls
- Incorrect lambda syntax (should be `=>` not `->`)
- Mismatched brackets/braces

```javascript
// Wrong:
let f = x -> x^2

// Correct:
let f = x => x^2
```

### Performance Issues

If recursion is slow, make sure you're using proper tail recursion or iterative approaches. See [Recursion Patterns](../functional-programming/recursion.md).

---

**Next**: [Syntax Basics](syntax-basics.md)
