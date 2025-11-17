---
title: "Control Flow"
description: "Control flow in Achronyme including if() function, if-else statements, piecewise functions, and return statements"
section: "core-language"
order: 5
---

Achronyme provides two forms of conditional expressions:
1. **Functional form**: `if(condition, then_value, else_value)` - Expression-based
2. **Statement form**: `if (condition) { ... } else { ... }` - Block-based

Both forms are expressions that return values.

## The if() Function (Functional Form)

### Basic Syntax

```javascript
if(condition, then_value, else_value)
```

The `if()` function takes **three arguments**:
1. **condition**: Boolean expression to evaluate
2. **then_value**: Value returned if condition is true
3. **else_value**: Value returned if condition is false

### Simple Examples

```javascript
// Basic if
let result = if(5 > 3, 100, 200)    // 100

// With variables
let x = 10
let category = if(x > 5, 1, 0)      // 1

// Negative numbers
let value = if(-5 < 0, true, false)  // true
```

### if() Returns a Value

Since `if()` is a function, it always returns a value:

```javascript
// Assign result directly
let status = if(score >= 60, "pass", "fail")

// Use in expressions
let total = 10 + if(bonus, 5, 0)

// Return from lambda
let classify = x => if(x < 0, "negative", "positive")
```

### Mathematical Functions with if()

```javascript
// Absolute value
let abs = x => if(x < 0, -x, x)
abs(-5)   // 5
abs(3)    // 3

// Maximum of two numbers
let max = (a, b) => if(a > b, a, b)
max(10, 5)   // 10

// Minimum of two numbers
let min = (a, b) => if(a < b, a, b)
min(10, 5)   // 5
```

### Activation Functions (ML)

```javascript
// ReLU (Rectified Linear Unit)
let relu = x => if(x > 0, x, 0)
relu(5)    // 5
relu(-3)   // 0

// Leaky ReLU
let leaky_relu = x => if(x > 0, x, 0.01 * x)
leaky_relu(5)    // 5
leaky_relu(-10)  // -0.1

// Heaviside step function
let heaviside = x => if(x >= 0, 1, 0)
heaviside(5)   // 1
heaviside(-2)  // 0
```

### Nested if() Functions

For multiple conditions, nest `if()` calls:

```javascript
// Sign function (-1, 0, or 1)
let sign = x => if(x < 0, -1, if(x > 0, 1, 0))
sign(-10)  // -1
sign(10)   // 1
sign(0)    // 0

// Grading system (4=A, 3=B, 2=C, 1=D, 0=F)
let grade = score => if(score >= 90,
                        4,
                        if(score >= 80,
                           3,
                           if(score >= 70,
                              2,
                              if(score >= 60, 1, 0))))
grade(95)  // 4 (A)
grade(75)  // 2 (C)
grade(50)  // 0 (F)
```

### Complex Conditions

Use logical operators (`&&`, `||`, `!`) for complex conditions:

```javascript
// Check if value is in range [min, max]
let in_range = (x, min, max) => if(x >= min && x <= max, true, false)
in_range(5, 0, 10)    // true
in_range(15, 0, 10)   // false

// XOR (exclusive or)
let xor = (a, b) => if((a || b) && !(a && b), true, false)
xor(true, false)   // true
xor(true, true)    // false
```

## if-else Statements (Block Form)

Achronyme supports traditional `if-else` statement syntax with blocks.

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
// Basic if-else
let f = (x) => if (x < 0) { -1 } else { 1 }
f(-5)  // -1
f(10)  // 1

// With multiple statements
let classify = (x) => if (x < 0) {
    print("Negative")
    -1
} else {
    print("Positive or zero")
    1
}

// Assigning result
let sign = if (value < 0) {
    -1
} else if (value > 0) {
    1
} else {
    0
}
```

### Key Features

- **Returns a value**: The last expression in each block becomes the return value
- **Multi-statement blocks**: Can contain multiple statements separated by semicolons (`;`)
- **Else-if chains**: Support `else if` for multiple conditions
- **No `do` required**: Unlike lambdas, if-else blocks directly support multiple statements

## Early Return with `return`

The `return` statement allows early function exit.

### Basic Syntax

```javascript
return value
```

The `return` statement:
- **Immediately exits** the current function with the given value
- **Can be used in** if-else blocks, do blocks, and anywhere inside a function
- **Stops execution** - code after `return` is not evaluated
- **Only valid** inside lambda functions (not at top level)

### Guard Clauses Pattern

Use `return` for guard clauses to handle edge cases early:

```javascript
// With return (guard clauses - cleaner)
let processDataClean = (data) => do {
    if (len(data) == 0) {
        return 0
    };
    if (mean(data) <= 0) {
        return 0
    };
    // Main logic here (less nesting)
    sum(data) / len(data)
}
```

### Return in if-else Blocks

```javascript
// Return in both branches
let abs = (x) => if (x < 0) {
    return -x
} else {
    return x
}

// Return in else-if chain
let grade = (score) => do {
    if (score >= 90) {
        return "A"
    } else if (score >= 80) {
        return "B"
    } else if (score >= 70) {
        return "C"
    } else if (score >= 60) {
        return "D"
    };
    "F"
}
```

### Best Practices for Return

**1. Use return for guard clauses**
```javascript
let process = (data) => do {
    if (!data) {
        return "error"
    };
    if (len(data) == 0) {
        return "empty"
    };
    // Main logic here
    "success"
}
```

**2. Use return to avoid deep nesting**
```javascript
let checkClean = (x) => do {
    if (x <= 0) {
        return "negative"
    };
    if (x >= 100) {
        return "too large"
    };
    if (x % 2 != 0) {
        return "odd"
    };
    "valid"
}
```

## The piecewise() Function

For **3 or more conditions**, `piecewise()` is cleaner than nested `if()` calls.

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
- The last argument (without brackets) is the **default** value
- Default is **optional** - error if no match and no default

### Simple Examples

```javascript
// Sign function
let sign = x => piecewise(
    [x < 0, -1],
    [x > 0, 1],
    0
)
sign(-10)  // -1
sign(5)    // 1
sign(0)    // 0

// Absolute value
let abs = x => piecewise([x < 0, -x], x)
abs(-5)  // 5
abs(3)   // 3
```

### Multi-Branch Examples

```javascript
// Progressive tax brackets
let tax = income => piecewise(
    [income <= 10000, income * 0.1],
    [income <= 50000, income * 0.2],
    income * 0.3
)
tax(5000)    // 500 (10%)
tax(30000)   // 6000 (20%)
tax(100000)  // 30000 (30%)

// Grading system
let grade = score => piecewise(
    [score >= 90, 5],
    [score >= 80, 4],
    [score >= 70, 3],
    [score >= 60, 2],
    1
)
grade(95)  // 5
grade(75)  // 3
grade(50)  // 1
```

### Piecewise Functions (Mathematics)

```javascript
// f(x) = { x^2      if x < -1
//        { 2x + 1   if -1 <= x < 1
//        { x^3      if x >= 1

let f = x => piecewise(
    [x < -1, x^2],
    [x < 1, 2*x + 1],
    x^3
)
f(-2)   // 4 (from x^2)
f(0)    // 1 (from 2x+1)
f(2)    // 8 (from x^3)
```

## if() vs piecewise()

### When to Use if()

- **2 branches** (condition + else)
- Simple true/false decisions
- More concise for binary choices

```javascript
// Good use of if()
let abs = x => if(x < 0, -x, x)
let max = (a, b) => if(a > b, a, b)
```

### When to Use piecewise()

- **3+ branches**
- Sequential condition checking
- More readable than nested `if()`

```javascript
// Bad: nested if() for multiple conditions
let grade = score => if(score >= 90, 5,
                       if(score >= 80, 4,
                          if(score >= 70, 3,
                             if(score >= 60, 2, 1))))

// Good: piecewise() for multiple conditions
let grade = score => piecewise(
    [score >= 90, 5],
    [score >= 80, 4],
    [score >= 70, 3],
    [score >= 60, 2],
    1
)
```

## Common Patterns

### Indicator/Characteristic Function

```javascript
let indicator = (x, a, b) => if(x >= a && x <= b, 1, 0)
indicator(5, 0, 10)   // 1
indicator(15, 0, 10)  // 0
```

### Clipping/Clamping

```javascript
let clip = (x, min, max) => if(x < min, min, if(x > max, max, x))
clip(5, 0, 10)    // 5
clip(-5, 0, 10)   // 0
clip(15, 0, 10)   // 10
```

### if() with Higher-Order Functions

```javascript
// Filter positive numbers
let positives = v => filter(x => x > 0, v)
positives([1, -2, 3, -4, 5])  // [1, 3, 5]

// Clamp values to range
let clamp = (v, min_val, max_val) =>
    map(x => if(x < min_val,
                min_val,
                if(x > max_val, max_val, x)), v)
clamp([1, 5, 10, 15, 20], 5, 15)  // [5, 5, 10, 15, 15]

// Apply ReLU to vector
let relu_vec = v => map(x => if(x > 0, x, 0), v)
relu_vec([1, -2, 3, -4, 5])  // [1, 0, 3, 0, 5]
```

## Best Practices

### 1. Use Appropriate Function

```javascript
// Good: if() for 2 branches
let sign_bit = x => if(x >= 0, 0, 1)

// Good: piecewise() for 3+ branches
let grade = score => piecewise(
    [score >= 90, "A"],
    [score >= 80, "B"],
    [score >= 70, "C"],
    "F"
)
```

### 2. Order Conditions Correctly

```javascript
// Correct: most restrictive first
piecewise(
    [x >= 90, "A"],  // Must be first
    [x >= 80, "B"],
    [x >= 70, "C"],
    "F"
)

// Wrong: will always return "F" for x < 70
piecewise(
    [x >= 70, "C"],
    [x >= 80, "B"],  // Never reached!
    [x >= 90, "A"],  // Never reached!
    "F"
)
```

### 3. Always Provide Default (When Possible)

```javascript
// Good: has default
piecewise([x > 0, 1], [x < 0, -1], 0)

// Risky: no default (error if conditions don't cover all cases)
piecewise([x > 0, 1], [x < 0, -1])  // Error when x == 0!
```

### 4. Keep Conditions Simple

```javascript
// Good: clear conditions
let category = x => piecewise(
    [x < 0, "negative"],
    [x > 0, "positive"],
    "zero"
)

// Avoid: overly complex conditions
let category = x => piecewise(
    [x < 0 && x > -100 && (x % 2 == 0 || x % 3 == 0), "complex"],
    [x > 0, "positive"],
    "other"
)
```

## Summary

| Feature | `if()` | `piecewise()` |
|---------|--------|---------------|
| Arguments | 3 (condition, then, else) | Variable ([cond, val], ..., default) |
| Best for | 2 branches | 3+ branches |
| Syntax | `if(cond, then, else)` | `piecewise([c1, v1], [c2, v2], default)` |
| Nesting | Gets messy with 3+ conditions | Clean for many conditions |
| Default | Always has else | Optional (error if missing) |
| Evaluation | Short-circuit | Sequential, first match wins |

**Key Points**:
- `if()` and `piecewise()` are **functions**, not statements
- They **return values** (can be used in expressions)
- Use `if()` for **2-way** decisions
- Use `piecewise()` for **3+ way** decisions
- Both support **short-circuit evaluation**
- Always provide a **default** in `piecewise()` when possible

---

**Next**: [Records](../data-structures/records.md)
