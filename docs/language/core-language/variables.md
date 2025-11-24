---
title: "Variables"
description: "Guide to variable declaration, scope, immutability, and compound assignment operators in Achronyme"
section: "core-language"
order: 3
---

Variables in Achronyme are **immutable** bindings that associate names with values.

## Variable Declaration

### Basic Syntax

Variables are declared with the `let` keyword:

```javascript
let x = 42
let name = "Alice"
let active = true
```

### Type Inference

Achronyme automatically infers types:

```javascript
let n = 42              // Number
let s = "hello"         // String
let b = true            // Boolean
let arr = [1, 2, 3]     // Tensor
let rec = {x: 10}       // Record
let f = x => x^2        // Function
```

## Immutability

Variables declared with `let` are **immutable** - their values cannot be changed after assignment:

```javascript
let x = 10
// x = 20  // ERROR: Cannot reassign x

let arr = [1, 2, 3]
// arr[0] = 99  // ERROR: Cannot mutate array
```

> **Note**: For mutable variables, use the `mut` keyword. See **[Mutability](../advanced-topics/mutability.md)** for details.

### Creating New Values

Instead of mutation, create new values:

```javascript
// Numbers
let x = 10
let y = x + 5      // y = 15, x is still 10

// Arrays - use spread or functions
let arr1 = [1, 2, 3]
let arr2 = [...arr1, 4]           // [1, 2, 3, 4]
let arr3 = map(x => x * 2, arr1)  // [2, 4, 6]

// Records - use spread
let person1 = {name: "Alice", age: 30}
let person2 = {...person1, age: 31}  // Updated age
```

## Naming Rules

### Valid Identifiers

Variable names must:
- Start with a letter or underscore: `x`, `_temp`, `myVar`
- Contain only letters, numbers, and underscores: `x1`, `my_var`, `temp_2`
- Be case-sensitive: `var` and `Var` are different
- Not be reserved keywords

```javascript
// Valid names
let x = 1
let myVariable = 2
let _private = 3
let value_1 = 4
let calculateArea = 5
```

### Invalid Identifiers

```javascript
// Invalid - starts with number
// let 1x = 10  // ERROR

// Invalid - contains hyphen
// let my-var = 10  // ERROR

// Invalid - reserved keyword
// let let = 10  // ERROR
```

### Naming Conventions

```javascript
// camelCase (recommended for functions)
let calculateTotal = (a, b) => a + b
let getUserName = () => "Alice"

// snake_case (common for data)
let user_count = 100
let max_value = 1000

// UPPER_CASE (for constants)
let PI = 3.14159
let MAX_ITERATIONS = 1000
```

## Variable Scope

### Top-Level Scope

Variables declared at the top level are available globally:

```javascript
let x = 10

let f = () => x * 2    // Can access x
f()  // 20
```

### Function Scope

Variables inside functions are local to that function:

```javascript
let outer = 10

let f = () => do {
    let inner = 20;
    outer + inner
}

f()      // 30
// inner is not accessible here
```

### Shadowing

Inner scopes can shadow outer variables:

```javascript
let x = 10

let f = () => do {
    let x = 20;    // Shadows outer x
    x              // 20
}

f()    // 20
x      // Still 10
```

## Closures

Functions capture variables from their enclosing scope:

```javascript
let makeAdder = n => x => x + n

let add5 = makeAdder(5)
let add10 = makeAdder(10)

add5(3)    // 8
add10(3)   // 13
```

### Capturing Variables

```javascript
let multiplier = factor => data => map(x => x * factor, data)

let double = multiplier(2)
let triple = multiplier(3)

double([1, 2, 3])   // [2, 4, 6]
triple([1, 2, 3])   // [3, 6, 9]
```

## Compound Assignment Operators

Achronyme supports compound assignment operators for concise mutation of variables:

### Available Operators

```javascript
mut x = 10
x += 5    // x = 15 (equivalent to x = x + 5)
x -= 3    // x = 12 (equivalent to x = x - 3)
x *= 2    // x = 24 (equivalent to x = x * 2)
x /= 4    // x = 6  (equivalent to x = x / 4)
x %= 4    // x = 2  (equivalent to x = x % 4)
x ^= 3    // x = 8  (equivalent to x = x ^ 3, power)
```

### With Record Fields

Compound assignment also works with mutable record fields:

```javascript
mut obj = {mut value: 10}
obj.value += 5    // obj.value = 15
obj.value *= 2    // obj.value = 30

mut counter = {
    mut count: 0,
    increment: () => do { self.count += 1 }
}
counter.increment()
counter.count  // 1
```

### Common Use Cases

**Loop Counters:**
```javascript
mut i = 0
while(i < 10) {
    i += 1  // More concise than i = i + 1
}
```

**Accumulators:**
```javascript
mut sum = 0
for(x in [1, 2, 3, 4, 5]) {
    sum += x
}
sum  // 15
```

**Mathematical Computations:**
```javascript
mut result = 2
result ^= 10  // result = 1024 (2^10)

mut angle = 0
angle += PI / 4  // Increment by 45 degrees
```

### Important Notes

- Compound assignment requires `mut` variables
- The operators are right-associative
- They return the new value (like regular assignment)

```javascript
// ERROR: Cannot use compound assignment on immutable variable
let x = 10
// x += 5  // ERROR

// CORRECT: Use mut for mutable variables
mut y = 10
y += 5    // OK
```

## Constants

Achronyme has built-in mathematical constants:

```javascript
PI           // 3.14159265358979...
E            // 2.71828182845905...

// Use in calculations
let circle_area = r => PI * r^2
let exponential = x => E^x
```

## Multiple Declarations

Use semicolons to declare multiple variables:

```javascript
let a = 1; let b = 2; let c = 3

// Or on separate lines
let x = 10
let y = 20
let z = 30
```

## Variable Usage Patterns

### Configuration Values

```javascript
let config = {
    timeout: 5000,
    retries: 3,
    debug: false
}
```

### Intermediate Results

```javascript
// Calculate distance
let dx = x2 - x1
let dy = y2 - y1
let distance = sqrt(dx^2 + dy^2)
```

### Data Transformation

```javascript
let raw_data = [1.2, 3.4, 2.1, 4.5]
let mean_value = mean(raw_data)
let std_dev = std(raw_data)
let normalized = map(x => (x - mean_value) / std_dev, raw_data)
```

### Function Definitions

```javascript
let square = x => x^2
let cube = x => x^3
let sum_of_squares = arr => sum(map(square, arr))
```

## Working with Records

### Record Variables

```javascript
let point = {
    x: 10,
    y: 20,
    distance: () => sqrt(self.x^2 + self.y^2)
}

point.x            // 10
point.distance()   // 22.36...
```

### Updating Records

Since records are immutable, use spread to "update":

```javascript
let person = {name: "Alice", age: 30}

// Create new record with updated age
let updated = {...person, age: 31}

person.age     // Still 30
updated.age    // 31
```

## Working with Arrays

### Array Variables

```javascript
let numbers = [1, 2, 3, 4, 5]
let strings = ["apple", "banana", "cherry"]
let matrix = [[1, 2], [3, 4]]
```

### Array Transformations

```javascript
let data = [1, 2, 3, 4, 5]

// Map - transform each element
let doubled = map(x => x * 2, data)

// Filter - select elements
let evens = filter(x => x % 2 == 0, data)

// Reduce - aggregate
let sum = reduce((acc, x) => acc + x, 0, data)
```

## Best Practices

### 1. Use Descriptive Names

```javascript
// Good
let user_count = 100
let total_price = calculate_price(items)

// Avoid
let n = 100
let x = calculate_price(items)
```

### 2. Keep Scope Small

```javascript
// Good - minimal scope
let result = do {
    let temp = compute();
    transform(temp)
}

// Avoid - unnecessary global
let temp = compute()
let result = transform(temp)
```

### 3. Group Related Variables

```javascript
// Good - use records
let config = {
    width: 800,
    height: 600,
    title: "My App"
}

// Avoid - scattered variables
let config_width = 800
let config_height = 600
let config_title = "My App"
```

### 4. Constants in UPPER_CASE

```javascript
// Good
let PI = 3.14159
let MAX_RETRIES = 3

// Avoid
let pi = 3.14159
let maxRetries = 3
```

### 5. Avoid Single-Letter Names (Except in Math)

```javascript
// OK in mathematical context
let f = x => x^2
let distance = (x, y) => sqrt(x^2 + y^2)

// Avoid in general code
let d = get_data()  // What is 'd'?

// Better
let user_data = get_data()
```

## Common Patterns

### Builder Pattern

```javascript
let query = {
    table: "",
    columns: [],
    from: t => {...self, table: t},
    select: cols => {...self, columns: cols}
}

let q = query.from("users").select(["id", "name"])
```

### Pipeline Pattern

```javascript
let data = [1, 2, 3, 4, 5]

let result = pipe(
    x => filter(n => n % 2 == 0, x),
    x => map(n => n^2, x),
    x => sum(x)
)(data)
```

### Factory Pattern

```javascript
let createPoint = (x, y) => {
    x: x,
    y: y,
    distance: () => sqrt(self.x^2 + self.y^2)
}

let p1 = createPoint(3, 4)
let p2 = createPoint(5, 12)
```

## Reserved Keywords

These cannot be used as variable names:

- `let` - Variable declaration
- `mut` - Mutable variable declaration
- `true`, `false` - Boolean literals
- `null` - Null literal
- `self` - Record self-reference
- `rec` - Recursive function reference
- `if`, `else` - Conditional statements
- `while` - While loops
- `for`, `in` - For-in loops
- `break`, `continue` - Loop control
- `return` - Early return
- `match` - Pattern matching
- `try`, `catch`, `throw` - Error handling
- `generate`, `yield` - Generators
- `type` - Type aliases

**Note**: `if()` and `piecewise()` can also be used as built-in **functions** for functional-style conditionals.

## Error Cases

### Using Undefined Variables

```javascript
// Error: x is not defined
let y = x + 10

// Correct: define x first
let x = 5
let y = x + 10
```

### Reserved Keywords

```javascript
// Error: 'let' is a keyword
// let let = 10

// Error: 'true' is a keyword
// let true = 10
```

### Invalid Names

```javascript
// Error: starts with number
// let 1x = 10

// Error: contains special characters
// let my-var = 10
// let my@var = 10
```

## Summary

- Variables declared with `let`
- All variables are **immutable** (use `mut` for mutable)
- Type inference - no type annotations needed (optional type annotations supported)
- Scope: top-level, function-local, closures
- Create new values instead of mutating
- Compound assignment: `+=`, `-=`, `*=`, `/=`, `%=`, `^=`
- Use descriptive names
- Built-in constants: `PI`, `E`
- Reserved keywords: `let`, `mut`, `true`, `false`, `null`, `self`, `rec`, `if`, `else`, `while`, `for`, `match`, `try`, `catch`, `throw`, `break`, `continue`, `return`, `generate`, `yield`, `type`

---

**Next**: [Functions and Lambdas](functions.md)
