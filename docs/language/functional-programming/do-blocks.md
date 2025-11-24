---
title: "Do Blocks"
description: "Multi-statement blocks for imperative-style code in Achronyme"
section: "functional-programming"
order: 2
---


Do blocks provide a way to group multiple statements together, creating a local scope for intermediate computations and variable declarations. They are essential for writing complex, multi-step algorithms in Achronyme.

## Overview

**Syntax**: `do { statements }`

**IMPORTANT - Braces Are NOT Blocks**: In Achronyme, `{ }` alone creates a **record literal**, NOT a code block. To create a block of statements, you MUST use a keyword like `do`, `if`, `while`, `for`, or `generate` before the braces.

```javascript
// ❌ ERROR: This creates a record, not a block
let a = {
    if (x > 0) { 1 } else { -1 }
}
// Parse error: expected record_field_or_spread

// ✅ CORRECT: Use do { } for statement blocks
let a = do {
    if (x > 0) { 1 } else { -1 }
}

// ✅ CORRECT: Direct if-else expression (no outer block needed)
let a = if (x > 0) { 1 } else { -1 }
```

**IMPORTANT - Statement Separators**: All statements inside do blocks **must be separated by semicolons** (`;`). The last expression can optionally omit the semicolon.

```javascript
// ✅ Correct: statements separated by semicolons
let result = do {
    let x = 5;
    let y = 10;
    x + y
}

// ❌ Incorrect: missing semicolons
let result = do {
    let x = 5
    let y = 10
    x + y
}
```

**Note**: Newline-only separation is not currently supported in do blocks. This is a known limitation in the CLI/parser.

**Purpose**:
- Group multiple statements into a single expression
- Create local scope for intermediate variables
- Enable multi-step computations with readable names
- Support complex lambda bodies

**Key Features**:
- Creates new local scope
- Variables declared with `let` are local to the block
- Last statement's value is returned
- Can be used anywhere an expression is expected

## Basic Syntax

### Simple Do Block

```javascript
let result = do {
    let x = 5;
    let y = 10;
    x + y
}
// result = 15
```

**Characteristics**:
- Each statement must be separated by `;`
- Variables `x` and `y` are local
- Last expression (`x + y`) is returned (no semicolon needed)
- Variables not accessible outside block

**Important**: Statements inside do blocks must be separated by semicolons (`;`). The last expression can optionally omit the semicolon.

### Single Statement

```javascript
let value = do {
    42
}
// value = 42
```

### Multi-Step Computation

```javascript
let compute = x => do {
    let doubled = x * 2;
    let squared = doubled * doubled;
    squared + 10
}

compute(5)  // (5*2)^2 + 10 = 110
```

## Scope and Variables

### Local Scope

Do blocks create a new local scope:

```javascript
let outer = 10

let result = do {
    let inner = 20;
    outer + inner
}
// result = 30

// inner is NOT accessible here
// outer is still 10
```

**Scoping Rules**:
- Variables from outer scope are accessible
- Variables declared inside are local
- Local variables are destroyed when block exits
- No pollution of outer scope

### Variable Shadowing

Local variables can shadow outer ones:

```javascript
let x = 10

let f = () => do {
    let x = 20;  // Shadows outer x
    x * 2
}

f()  // 40 (uses inner x)
x    // Still 10 (outer x unchanged)
```

**Shadowing Behavior**:
- Inner declaration hides outer variable
- Outer variable remains unchanged
- Shadowing is temporary (scope-local)
- Supports immutability principle

### Closure Capture

Do blocks can capture variables from outer scope:

```javascript
let makeMultiplier = factor => do {
    let multiply = x => x * factor;  // Captures factor
    multiply
}

let double = makeMultiplier(2)
let triple = makeMultiplier(3)

double(5)  // 10
triple(5)  // 15
```

## Use Cases

### Multi-Step Computations

Break complex calculations into readable steps:

```javascript
let analyzeData = data => do {
    let cleaned = filter(x => x > 0, data)
    let normalized = map(x => x / 100, cleaned)
    let mean_val = sum(normalized) / length(normalized)
    let variance = sum(map(x => (x - mean_val)^2, normalized)) / length(normalized)

    {
        mean: mean_val,
        variance: variance,
        std: sqrt(variance),
        count: length(cleaned)
    }
}
```

### Pipeline Processing

Transform data through series of operations:

```javascript
let processSignal = signal => do {
    let windowed = signal * hanning(length(signal))
    let spectrum = fft(windowed)
    let magnitudes = fft_mag(spectrum)
    let normalized = map(x => x / max(magnitudes), magnitudes)
    normalized
}
```

### Complex Record Construction

Build records with computed fields:

```javascript
let createUser = (name, birthYear) => do {
    let currentYear = 2024
    let age = currentYear - birthYear
    let isAdult = age >= 18

    {
        name: name,
        age: age,
        adult: isAdult,
        category: if(age < 13, "child",
                   if(age < 18, "teen", "adult"))
    }
}
```

### Recursive Functions

Enable recursion with `rec`:

```javascript
let factorial = n => do {
    if(n <= 1, 1, n * rec(n - 1))
}

let fibonacci = n => do {
    if(n <= 1, n, rec(n - 1) + rec(n - 2))
}
```

**Note**: Recursion limited to ~50 calls (see [Performance Limitations](../advanced-topics/performance.md))

### Helper Functions

Define local helpers inside do blocks:

```javascript
let quicksort = arr => do {
    if(length(arr) <= 1,
        arr,
        do {
            let pivot = arr[0]
            let rest = arr[1..]
            let less = filter(x => x < pivot, rest)
            let greater = filter(x => x >= pivot, rest)
            [...rec(less), pivot, ...rec(greater)]
        }
    )
}
```

### Data Validation

Validate and transform data with checks:

```javascript
let validateAge = input => do {
    let parsed = if(input < 0, 0, input)
    let capped = if(parsed > 150, 150, parsed)
    let valid = capped > 0

    {
        value: capped,
        valid: valid,
        category: if(capped < 18, "minor", "adult")
    }
}
```

### Nested Do Blocks

Stack multiple scopes for complex logic:

```javascript
let process = data => do {
    let step1 = do {
        let filtered = filter(x => x > 0, data)
        let scaled = map(x => x * 2, filtered)
        scaled
    }

    let step2 = do {
        let mean = sum(step1) / length(step1)
        let centered = map(x => x - mean, step1)
        centered
    }

    {
        original: data,
        step1: step1,
        step2: step2
    }
}
```

## Lambda Bodies

Do blocks are particularly useful in lambda functions:

### Without Do Block (Single Expression)

```javascript
let simple = x => x * 2
```

### With Do Block (Multi-Step)

```javascript
let complex = x => do {
    let doubled = x * 2
    let squared = doubled * doubled
    let adjusted = squared + 10
    adjusted
}
```

### Function Parameters

```javascript
let operation = (x, y) => do {
    let sum = x + y
    let product = x * y
    let average = sum / 2

    {
        sum: sum,
        product: product,
        average: average
    }
}

operation(5, 10)
// {sum: 15, product: 50, average: 7.5}
```

## Return Values

### Implicit Return

Last statement's value is returned automatically:

```javascript
let compute = x => do {
    let a = x * 2
    let b = a + 5
    b  // This value is returned
}
```

### Any Type Can Be Returned

```javascript
// Return number
let num = do { 42 }

// Return string
let str = do { "hello" }

// Return vector
let vec = do {
    let a = [1, 2, 3]
    let b = [4, 5, 6]
    [...a, ...b]
}

// Return record
let rec = do {
    {x: 10, y: 20}
}

// Return function
let fn = do {
    x => x * 2
}
```

## Comparison with IIFE

### IIFE Pattern

Immediately Invoked Function Expression:

```javascript
// Simple IIFE
let result = (x => x * 2)(5)

// IIFE with multiple params
let sum = ((x, y) => x + y)(3, 7)

// IIFE for scope isolation
let value = (() => {
    let temp = 42
    temp * 2
})()
```

### Do Block Pattern

```javascript
// Simple do block
let result = do {
    let x = 5
    x * 2
}

// Do block with parameters (needs lambda)
let sum = ((x, y) => do {
    x + y
})(3, 7)

// Do block for scope isolation
let value = do {
    let temp = 42
    temp * 2
}
```

### Comparison

| Aspect | IIFE | Do Block |
|--------|------|----------|
| **Syntax** | `(() => expr)()` | `do { statements }` |
| **Clarity** | Less obvious intent | Explicit scoping |
| **Parameters** | Easy: `(x => ...)(val)` | Requires lambda wrapper |
| **Multi-line** | Requires function body | Natural syntax |
| **Use case** | Inline computations | Multi-step logic |

**Recommendation**:
- Use IIFE for simple inline computations with parameters
- Use do blocks for multi-step computations and readability
- Use do blocks in lambda bodies for complex functions

## Practical Examples

### Statistical Analysis

```javascript
let analyze = data => do {
    let n = length(data)
    let mean_val = sum(data) / n
    let deviations = map(x => x - mean_val, data)
    let squared_devs = map(x => x^2, deviations)
    let variance = sum(squared_devs) / (n - 1)
    let std_dev = sqrt(variance)

    {
        count: n,
        mean: mean_val,
        variance: variance,
        std: std_dev,
        min: min(data),
        max: max(data)
    }
}
```

### Signal Processing Pipeline

```javascript
let processAudio = signal => do {
    let sample_rate = 44100
    let duration = length(signal) / sample_rate

    // Apply window
    let window = hanning(length(signal))
    let windowed = signal * window

    // FFT analysis
    let spectrum = fft(windowed)
    let magnitudes = fft_mag(windowed)
    let phases = fft_phase(windowed)

    // Find dominant frequency
    let max_magnitude = max(magnitudes)
    let peak_bin = 0  // Would need argmax
    let dominant_freq = peak_bin * sample_rate / length(signal)

    {
        duration: duration,
        sample_rate: sample_rate,
        peak_frequency: dominant_freq,
        spectrum: spectrum,
        magnitudes: magnitudes
    }
}
```

### Matrix Computation

```javascript
let solveLinearSystem = (A, b) => do {
    // Check if square matrix
    let n = A.rows
    let m = A.cols

    if(n != m,
        error("Matrix must be square"),
        do {
            // LU decomposition
            let lu = lu_decompose(A)
            let L = lu.L
            let U = lu.U

            // Forward substitution: L*y = b
            let y = forward_substitute(L, b)

            // Backward substitution: U*x = y
            let x = backward_substitute(U, y)

            // Verify solution
            let residual = A * x - b
            let error = norm(residual)

            {
                solution: x,
                error: error,
                L: L,
                U: U
            }
        }
    )
}
```

### Tree Traversal

```javascript
let traverseTree = (tree, operation) => do {
    let process_node = node => do {
        let value = operation(node.value)
        let left_result = if(node.left != null,
            rec(node.left),
            null)
        let right_result = if(node.right != null,
            rec(node.right),
            null)

        {
            value: value,
            left: left_result,
            right: right_result
        }
    }

    process_node(tree)
}
```

### Data Transformation

```javascript
let transformDataset = data => do {
    // Clean data
    let cleaned = filter(x => x != null, data)

    // Remove outliers (simple method)
    let mean = sum(cleaned) / length(cleaned)
    let std = std(cleaned)
    let lower = mean - 2 * std
    let upper = mean + 2 * std
    let filtered = filter(x => x >= lower && x <= upper, cleaned)

    // Normalize to [0, 1]
    let min_val = min(filtered)
    let max_val = max(filtered)
    let range = max_val - min_val
    let normalized = map(x => (x - min_val) / range, filtered)

    {
        original_count: length(data),
        cleaned_count: length(cleaned),
        filtered_count: length(filtered),
        data: normalized,
        stats: {
            mean: mean,
            std: std,
            min: min_val,
            max: max_val
        }
    }
}
```

## Advanced Patterns

### Accumulator Pattern

```javascript
let makeCounter = start => do {
    let state = start

    {
        increment: () => state + 1,
        decrement: () => state - 1,
        reset: () => start,
        get: () => state
    }
}
```

**Note**: This creates closures but state is immutable (read-only).

### Builder Pattern

```javascript
let buildQuery = table => do {
    let base = {table: table}

    {
        select: fields => do {
            {...base, fields: fields}
        },
        where: condition => do {
            {...base, condition: condition}
        },
        limit: n => do {
            {...base, limit: n}
        }
    }
}

// Usage (conceptual)
let query = buildQuery("users")
    .select(["name", "age"])
    .where("age > 18")
    .limit(10)
```

### Composition with Do Blocks

```javascript
let compose = (f, g) => do {
    let composed = x => f(g(x))
    composed
}

let pipeline = (value, ...functions) => do {
    let apply_all = (v, fns) =>
        if(length(fns) == 0,
            v,
            rec(fns[0](v), fns[1..]))

    apply_all(value, functions)
}
```

## Error Handling

### Validation in Do Blocks

```javascript
let safeDivide = (a, b) => do {
    if(b == 0,
        error("Division by zero"),
        a / b)
}

let validateInput = input => do {
    let is_number = true  // Would need type check
    let is_positive = input > 0
    let is_finite = true  // Would need isFinite check

    if(!is_number, error("Not a number"),
    if(!is_positive, error("Not positive"),
    if(!is_finite, error("Not finite"),
        input)))
}
```

## Limitations

### Semicolon Requirement

Statements must be separated by semicolons:

```javascript
// ❌ Error: missing semicolons
let bad = do {
    let x = 5
    let y = 10
    x + y
}

// ✅ Correct: semicolons between statements
let good = do {
    let x = 5;
    let y = 10;
    x + y
}
```

**Current Status**: Newline-only separation is not supported in do blocks. This is a parser/CLI limitation that may be addressed in future versions.

### No Early Return

Cannot exit block early; no `return` statement:

```javascript
// ❌ No way to exit early
let process = x => do {
    let result = compute(x)
    if(result < 0, /* want to return here */, true)
    // Must continue evaluation
    doMoreWork(result)
}

// ✅ Use if() to control flow
let process = x => do {
    let result = compute(x)
    if(result < 0,
        result,  // Early path
        doMoreWork(result))  // Normal path
}
```

### Statement Order

Variables must be declared before use:

```javascript
// ❌ Error: y not defined
let bad = do {
    let x = y + 1
    let y = 10
    x
}

// ✅ Correct order
let good = do {
    let y = 10
    let x = y + 1
    x
}
```

### Non-Empty Blocks

Do blocks must contain at least one statement:

```javascript
// ❌ Error: empty do block
let empty = do { }

// ✅ Minimum: one expression
let valid = do { 0 }
```

### Recursion Depth

Limited to approximately 50 recursive calls:

```javascript
// ❌ Stack overflow at ~50
let deep = n => do {
    if(n <= 0, 0, rec(n - 1))
}
deep(100)  // Error

// ✅ Use iterative approach or built-ins
```

See [Performance Limitations](25-performance-limitations.md) for details.

## Best Practices

### Use Descriptive Names

```javascript
// ✅ Clear intent
let calculateBMI = (weight_kg, height_m) => do {
    let height_squared = height_m * height_m
    let bmi = weight_kg / height_squared
    let category = if(bmi < 18.5, "underweight",
                   if(bmi < 25, "normal",
                   if(bmi < 30, "overweight", "obese")))

    {bmi: bmi, category: category}
}

// ❌ Unclear
let calc = (w, h) => do {
    let x = h * h
    let y = w / x
    {r: y, c: if(y < 18.5, "u", "n")}
}
```

### Keep Blocks Focused

```javascript
// ✅ Small, focused blocks
let process = data => do {
    let cleaned = cleanData(data)
    let transformed = transformData(cleaned)
    let analyzed = analyzeData(transformed)
    analyzed
}

// ❌ Too much in one block
let process = data => do {
    // 50 lines of complex logic...
}
```

### Leverage Immutability

```javascript
// ✅ Create new values
let update = record => do {
    let updated = {...record, status: "active"}
    let timestamped = {...updated, timestamp: now()}
    timestamped
}

// ✅ Transformation chain
let transform = x => do {
    let step1 = x * 2
    let step2 = step1 + 5
    let step3 = step2 / 3
    step3
}
```

## Summary

**Syntax**: `do { statements }`

**Key features**:
- Local scope creation
- Multi-statement grouping
- Implicit return (last statement)
- Variable shadowing support
- Closure capture

**Use cases**:
- Multi-step computations
- Complex lambda bodies
- Pipeline processing
- Local helper functions
- Readable intermediate steps

**Limitations**:
- No early return
- Variables must be declared before use
- Non-empty blocks required
- Recursion depth ~50 calls

**Best practices**:
- Use descriptive variable names
- Keep blocks focused and small
- Leverage immutability
- Prefer do blocks for readability
- Use IIFE for simple inline computations

**Integration**:
- Works with `rec` for recursion
- Can be nested
- Supports all value types
- Compatible with closures

---

**Next**: [Recursion Patterns](recursion.md)
