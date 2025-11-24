---
title: "Control Flow"
description: "Control flow in Achronyme including if-else statements, if() function, piecewise functions, and return statements"
section: "core-language"
order: 5
---

Achronyme provides robust control flow mechanisms, primarily centered around conditional expressions.

## If-Else Expressions (Block Form)

The standard way to handle conditionals in Achronyme is using `if-else` blocks. Since Achronyme is expression-oriented, `if-else` blocks return a value.

### Basic Syntax

```javascript
if (condition) {
    // Code executed if condition is true
} else {
    // Code executed if condition is false
}
```

### Simple Examples

```javascript
// Basic if-else returning a value
let result = if (x > 0) {
    "Positive"
} else {
    "Non-positive"
}

// With multiple statements
let classify = (x) => if (x < 0) {
    print("Found negative")
    -1
} else {
    print("Found positive or zero")
    1
}
```

### Else-If Chains

You can chain multiple conditions:

```javascript
let grade = (score) => if (score >= 90) {
    "A"
} else if (score >= 80) {
    "B"
} else if (score >= 70) {
    "C"
} else {
    "F"
}
```

### Key Features

- **Returns a value**: The last expression in the executed block becomes the result.
- **Multi-statement blocks**: Blocks can contain multiple statements separated by semicolons or newlines.
- **No `do` required**: Unlike lambda bodies, `if` blocks implicitly handle multiple statements.

## The if() Function (Functional Form)

For simple, single-line conditional expressions, Achronyme provides a functional form `if()`. This is similar to the ternary operator (`?:`) in other languages.

### Basic Syntax

```javascript
if(condition, then_value, else_value)
```

The `if()` function takes **three arguments**:
1. **condition**: Boolean expression to evaluate
2. **then_value**: Value returned if condition is true
3. **else_value**: Value returned if condition is false

### Examples

```javascript
// Absolute value
let abs = x => if(x < 0, -x, x)

// Maximum of two numbers
let max = (a, b) => if(a > b, a, b)

// ReLU activation function
let relu = x => if(x > 0, x, 0)
```

### Nested if() Functions

While possible, nesting `if()` functions can become hard to read. For multiple conditions, prefer `if-else` blocks or `piecewise()`.

```javascript
// Harder to read
let sign = x => if(x < 0, -1, if(x > 0, 1, 0))

// Better: if-else block
let sign = x => if (x < 0) { -1 } else if (x > 0) { 1 } else { 0 }
```

## The piecewise() Function

For decision logic with **3 or more branches**, `piecewise()` offers a clean, mathematical syntax.

### Basic Syntax

```javascript
piecewise(
    [condition1, value1],
    [condition2, value2],
    [condition3, value3],
    default_value
)
```

- Each condition is a `[boolean_expr, value]` pair
- Conditions are evaluated **sequentially** (first match wins)
- The last argument (without brackets) is the **default** value (optional but recommended)

### Examples

```javascript
// Sign function
let sign = x => piecewise(
    [x < 0, -1],
    [x > 0, 1],
    0
)

// Grading system
let grade = score => piecewise(
    [score >= 90, 5],
    [score >= 80, 4],
    [score >= 70, 3],
    [score >= 60, 2],
    1
)
```

### Piecewise Functions (Mathematics)

Perfect for defining mathematical functions defined by parts:

```javascript
// f(x) = { x^2      if x < -1
//        { 2x + 1   if -1 <= x < 1
//        { x^3      if x >= 1

let f = x => piecewise(
    [x < -1, x^2],
    [x < 1, 2*x + 1],
    x^3
)
```

## Early Return with `return`

The `return` statement allows early exit from a function.

### Basic Syntax

```javascript
return value
```

### Guard Clauses Pattern

Use `return` to handle edge cases early and avoid deep nesting:

```javascript
let processData = (data) => do {
    // Guard clause 1: Handle empty data
    if (len(data) == 0) {
        return 0
    }

    // Guard clause 2: Handle invalid data
    if (mean(data) < 0) {
        return null
    }

    // Main logic (no else needed)
    sum(data) / len(data)
}
```

## Choosing the Right Control Flow

| Construct | Best Use Case | Example |
|-----------|---------------|---------|
| **If-Else Block** | General purpose, multi-statement logic | `if (x > 0) { ... } else { ... }` |
| **if() Function** | Simple, single-line expressions | `let y = if(x > 0, x, 0)` |
| **piecewise()** | Multi-branch conditions (3+), math functions | `piecewise([x<0, -1], [x>0, 1], 0)` |
| **return** | Early exit, guard clauses | `if (err) { return null }` |

## Common Patterns

### Indicator/Characteristic Function

```javascript
// Using if() function
let indicator = (x, a, b) => if(x >= a && x <= b, 1, 0)
```

### Clipping/Clamping

```javascript
// Using nested if()
let clip = (x, min, max) => if(x < min, min, if(x > max, max, x))

// Using if-else block
let clip = (x, min, max) => if (x < min) {
    min
} else if (x > max) {
    max
} else {
    x
}
```

### Conditional Map

```javascript
// Apply ReLU to vector
let relu_vec = v => map(x => if(x > 0, x, 0), v)
```

## Summary

- **If-Else Blocks**: The standard for control flow. Return values and support multiple statements.
- **if() Function**: Functional shorthand for simple binary choices.
- **piecewise()**: Clean syntax for multi-branch logic.
- **return**: Use for early exits to keep code flat and readable.

---

**Next**: [Records](../data-structures/records.md)