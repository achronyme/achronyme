---
title: "Functions and Lambdas"
description: "Complete guide to functions in Achronyme including lambdas, default parameters, optional parameters, recursion, and closures"
section: "core-language"
order: 4
---

Functions are first-class values in Achronyme, meaning they can be assigned to variables, passed as arguments, and returned from other functions.

## Function Calls

### Built-in Functions

```javascript
sin(3.14159 / 2)     // 1.0
sqrt(16)             // 4.0
sum([1, 2, 3, 4])    // 10
```

### Multiple Arguments

```javascript
pow(2, 10)           // 1024
atan2(1, 1)          // 0.785...
concat("Hello", " World")  // "Hello World"
```

## Lambda Functions

Lambda functions are anonymous functions defined with `=>`.

### Single Parameter

```javascript
x => x^2

// Usage
let square = x => x^2
square(5)  // 25
```

### Multiple Parameters

```javascript
(x, y) => x + y

// Usage
let add = (x, y) => x + y
add(3, 4)  // 7
```

### No Parameters

```javascript
() => 42

// Usage
let getAnswer = () => 42
getAnswer()  // 42
```

## Default Parameter Values

Parameters can have default values that are used when arguments are not provided:

### Basic Syntax

```achronyme
let greet = (name, greeting = "Hello") => '${greeting}, ${name}!'

greet("Alice")           // "Hello, Alice!"
greet("Bob", "Hi")       // "Hi, Bob!"
```

### With Type Annotations

```achronyme
let fetch = (url: String, timeout: Number = 5000): Number => timeout

fetch("api.com")         // 5000
fetch("api.com", 10000)  // 10000
```

### Multiple Defaults

```achronyme
let createPoint = (x = 0, y = 0, z = 0) => {x: x, y: y, z: z}

createPoint()            // {x: 0, y: 0, z: 0}
createPoint(1)           // {x: 1, y: 0, z: 0}
createPoint(1, 2)        // {x: 1, y: 2, z: 0}
createPoint(1, 2, 3)     // {x: 1, y: 2, z: 3}
```

### Practical Examples

**Recursion with Accumulators:**
```achronyme
let factorial = (n, acc = 1) =>
    if(n <= 1) { acc } else { rec(n - 1, acc * n) }

factorial(5)      // 120
factorial(5, 2)   // 240 (custom initial accumulator)
```

**Configuration Functions:**
```achronyme
let configureApi = (baseUrl, timeout = 3000, retries = 3) => {
    url: baseUrl,
    timeout: timeout,
    retries: retries
}

configureApi("https://api.com")  // Uses defaults
configureApi("https://api.com", 5000, 5)  // Custom values
```

**Mathematical Functions:**
```achronyme
let power = (base, exp = 2) => base ^ exp

power(5)       // 25 (5^2)
power(2, 10)   // 1024 (2^10)
```

## Optional Parameters

Parameters marked with `?` are optional and receive `null` if not provided:

### Basic Syntax

```achronyme
let greet = (name: String, title?: String) =>
    match title {
        null => name
        _ => '${title} ${name}'
    }

greet("Alice")           // "Alice"
greet("Bob", "Dr.")      // "Dr. Bob"
```

### Difference from Default Values

- **Optional parameter (`?`)**: Value is `null` if not provided
- **Default parameter (`=`)**: Uses specified default value if not provided

```achronyme
// Optional: value is null if not passed
let formatOptional = (value: Number, decimals?: Number) =>
    match decimals {
        null => value
        d => round(value, d)
    }

formatOptional(3.14159)      // 3.14159 (null passed)
formatOptional(3.14159, 2)   // 3.14

// Default: uses default value if not passed
let formatDefault = (value: Number, decimals: Number = 2) =>
    round(value, decimals)

formatDefault(3.14159)       // 3.14 (uses default 2)
formatDefault(3.14159, 4)    // 3.1416
```

### Use Cases

**API Functions:**
```achronyme
let request = (url: String, method?: String, body?: String) => {
    let actualMethod = match method { null => "GET", m => m }
    // ... perform request
    {url: url, method: actualMethod}
}

request("api.com")                    // GET request
request("api.com", "POST", "{}")      // POST with body
```

**Formatting Functions:**
```achronyme
let formatDate = (date: String, format?: String) =>
    match format {
        null => date  // Return as-is
        f => applyFormat(date, f)
    }
```

## Lambda Bodies

### Single Expression

```javascript
x => x^2
(a, b) => a * b + a + b
```

### IIFE (Immediately Invoked Function Expression)

For complex expressions needing intermediate calculations, use IIFE pattern:

```javascript
// IIFE pattern with intermediate calculation
let process = x => (
    doubled => doubled^2 + 10
)(x * 2)

// More complex: multiple intermediates
let complex = x => (
    params => params[0]^2 + params[1]
)([x * 2, 10])
```

## Recursion

### Using `rec` Keyword

The `rec` keyword refers to the current function:

```javascript
let factorial = n =>
    if(n <= 1, 1, n * rec(n - 1))

factorial(5)  // 120
```

### Anonymous Recursion

```javascript
let fib = n =>
    if(n <= 1, n, rec(n - 1) + rec(n - 2))
```

### Recursion Depth Limit

**IMPORTANT**: Achronyme currently has a strict limit of approximately **50 recursive calls** before encountering stack overflow.

```javascript
let factorial = n =>
    if(n <= 1, 1, n * rec(n - 1))

factorial(10)   // Works: 3628800
factorial(40)   // Works (near limit)
factorial(50)   // Stack overflow!
```

This limitation affects all recursive patterns. For large iterations:

```javascript
// Don't use recursion for large n
let range = n => (
    (left, current, vector) =>
        if(left == 0, vector, rec(left - 1, current + 1, [...vector, current]))
)(n, 0, [])

// Use built-in functions instead
let range = n => linspace(0, n - 1, n)
```

See [Performance](../advanced-topics/performance.md) for details and workarounds.

## Closures

Lambdas can capture variables from their enclosing scope:

```javascript
let makeAdder = n => x => x + n

let add5 = makeAdder(5)
add5(10)   // 15
add5(20)   // 25

let add10 = makeAdder(10)
add10(10)  // 20
```

### Captured Variables

```javascript
let makeAdder = n => x => x + n

let add5 = makeAdder(5)
add5(10)  // 15
add5(20)  // 25

// Closures capture from outer scope
let multiplier = factor => data => map(x => x * factor, data)
let double = multiplier(2)
double([1, 2, 3])  // [2, 4, 6]
```

## First-Class Functions

Functions are values and can be stored, passed, and returned.

### Storing in Variables

```javascript
let f = sin
let g = x => x^2

f(3.14)    // ~0
g(5)       // 25
```

### Passing as Arguments

```javascript
let apply = (f, x) => f(x)

apply(sin, 3.14)           // ~0
apply(x => x^2, 5)         // 25
```

### Returning Functions

```javascript
let makeMultiplier = n => x => n * x

let triple = makeMultiplier(3)
triple(5)  // 15
```

### Storing in Arrays

```javascript
let operations = [
    (a, b) => a + b,
    (a, b) => a - b,
    (a, b) => a * b
]

operations[0](5, 3)  // 8
operations[1](5, 3)  // 2
operations[2](5, 3)  // 15
```

### Storing in Records

```javascript
let math = {
    add: (a, b) => a + b,
    multiply: (a, b) => a * b,
    square: x => x^2
}

math.add(3, 4)      // 7
math.square(5)      // 25
```

## Function Composition

### Manual Composition

```javascript
let f = x => x + 1
let g = x => x * 2

let composed = x => g(f(x))
composed(3)  // 8  (3+1)*2
```

### Using Pipe

```javascript
pipe(
    3,              // Initial value
    x => x + 1,     // 4
    x => x * 2,     // 8
    x => x^2        // 64
)  // Result: 64
```

## Partial Application

```javascript
// Create specialized versions
let multiply = (a, b) => a * b

let double = x => multiply(2, x)
let triple = x => multiply(3, x)

double(5)  // 10
triple(5)  // 15
```

## Conditional Patterns

Using if() and piecewise():

```javascript
// Simple conditional with if()
let abs = x => if(x < 0, -x, x)

// Multiple patterns with piecewise
let sign = x => piecewise(
    [x > 0, 1],
    [x < 0, -1],
    0
)
```

## Common Patterns

### Map-Reduce

```javascript
let numbers = [1, 2, 3, 4, 5]

// Sum of squares
let sumSquares = reduce(
    (acc, x) => acc + x,
    0,
    map(x => x^2, numbers)
)
```

### Function Factory

```javascript
let makePower = n => x => x^n

let square = makePower(2)
let cube = makePower(3)

square(5)  // 25
cube(5)    // 125
```

### Recursive Functions

```javascript
// Simple recursion with rec
let fibonacci = n =>
    if(n <= 1, n, rec(n-1) + rec(n-2))

fibonacci(10)  // 55

// Factorial
let factorial = n =>
    if(n <= 1, 1, n * rec(n-1))

factorial(5)  // 120
```

## Best Practices

### 1. Prefer Expression Bodies

```javascript
// Good - simple expression
let square = x => x^2

// Also good - IIFE when needed
let complex = x => (doubled => doubled^2)(x * 2)
```

### 2. Use Descriptive Names

```javascript
// Good
let calculateArea = (width, height) => width * height

// Avoid
let f = (a, b) => a * b
```

### 3. Keep Functions Small

```javascript
// Good - single responsibility
let double = x => x * 2
let square = x => x^2
let process = x => square(double(x))

// Also good - pipe for composition
let process2 = x => pipe(x, double, square)
process2(5)  // 100
```

### 4. Use Higher-Order Functions

```javascript
// Good
map(x => x * 2, numbers)

// Avoid
let doubled = [];
// ... manual iteration
```

## Common Mistakes

### 1. Wrong Lambda Syntax

```javascript
// Wrong
let f = x -> x^2

// Correct
let f = x => x^2
```

### 2. Missing Parentheses for Multiple Parameters

```javascript
// Wrong
let add = x, y => x + y

// Correct
let add = (x, y) => x + y
```

### 3. Forgetting rec in Recursion

```javascript
// Wrong - 'factorial' not in scope inside lambda
let factorial = n =>
    if(n <= 1, 1, n * factorial(n - 1))  // ERROR

// Correct - use 'rec' for self-reference
let factorial = n =>
    if(n <= 1, 1, n * rec(n - 1))
```

## Summary

- Functions are first-class values
- Lambdas: `x => expr` or `(x, y) => expr`
- Default parameters: `(x = 10) => expr`
- Optional parameters: `(x?: Type) => expr`
- IIFE pattern for complex expressions: `(x => expr)(value)`
- `rec` for recursion (self-reference)
- Closures capture variables from outer scope
- Functions can be stored, passed, returned
- Prefer small, focused functions
- Use `if()` and `piecewise()` for conditionals

---

**Next**: [Control Flow](control-flow.md)
