# Pattern Matching

Achronyme provides comprehensive pattern matching with the `match` expression, enabling expressive and type-safe control flow based on value structure.

## Overview

Pattern matching in Achronyme:
- Is **expression-based** - always returns a value
- Supports **multiple pattern types** - literals, variables, records, vectors, types
- Provides **destructuring** - extract values from complex data structures
- Includes **guard clauses** - add conditional logic to patterns
- Uses **first-match semantics** - first matching pattern wins
- Creates **scoped bindings** - variables bound in patterns are local to the arm

## Basic Syntax

```javascript
match value {
    pattern1 => expression1,
    pattern2 => expression2,
    _ => defaultExpression
}
```

The match expression evaluates `value`, then tries each pattern in order until one matches. The corresponding expression is evaluated and its result is returned.

## Pattern Types

### Literal Patterns

Match exact values - numbers, strings, or booleans:

```javascript
match status {
    0 => "pending",
    1 => "active",
    2 => "completed",
    _ => "unknown"
}

match response {
    "yes" => true,
    "no" => false,
    _ => null
}

match flag {
    true => "enabled",
    false => "disabled"
}
```

### Variable Binding Patterns

Capture the matched value in a named variable:

```javascript
match x {
    n => n * 2  // binds x to n, returns x * 2
}

// Multiple arms with variable binding
match score {
    s if (s >= 90) => "A: " + str(s),
    s if (s >= 80) => "B: " + str(s),
    s if (s >= 70) => "C: " + str(s),
    s => "Below C: " + str(s)
}
```

Variable bindings are scoped to the arm's body expression.

### Wildcard Pattern

Match anything without binding:

```javascript
match value {
    0 => "zero",
    1 => "one",
    _ => "other"  // catches everything else
}
```

The wildcard `_` is commonly used as the last pattern to ensure exhaustive matching.

### Record Destructuring Patterns

Extract fields from records:

```javascript
match person {
    { name: n, age: a } => n + " is " + str(a) + " years old",
    { name: n } => n,  // partial match - only need name
    _ => "unknown person"
}
```

#### Nested Record Patterns

```javascript
match data {
    { user: { name: n, role: "admin" } } => "Admin: " + n,
    { user: { name: n, role: "user" } } => "User: " + n,
    { user: { name: n } } => "Unknown role: " + n,
    _ => "No user data"
}
```

#### Shorthand Field Binding

When the field name matches the variable name:

```javascript
match config {
    { host, port } => host + ":" + str(port),
    _ => "default:8080"
}
// Equivalent to: { host: host, port: port }
```

### Vector/Array Patterns

Match arrays by structure:

```javascript
// Empty array
match list {
    [] => "empty list"
}

// Single element
match list {
    [x] => "single: " + str(x)
}

// Fixed size
match list {
    [x, y] => "pair: " + str(x) + ", " + str(y),
    [a, b, c] => "triple"
}

// With rest pattern
match list {
    [] => "empty",
    [head, ...tail] => "head: " + str(head) + ", rest length: " + str(len(tail))
}
```

#### Rest Pattern Details

The `...name` syntax captures remaining elements:

```javascript
let sumList = (list) => match list {
    [] => 0,
    [x, ...rest] => x + sumList(rest)
};

sumList([1, 2, 3, 4, 5])  // => 15
```

Rest patterns must be the last element:

```javascript
// Valid
[first, ...rest]
[a, b, ...remaining]

// Not supported (rest must be last)
// [...start, last]
// [first, ...middle, last]
```

### Type Patterns

Match by runtime type:

```javascript
match value {
    Number => "it's a number",
    String => "it's a string",
    Boolean => "it's a boolean",
    Vector => "it's a vector",
    Record => "it's a record",
    Error => "it's an error",
    Function => "it's a function",
    Generator => "it's a generator",
    Complex => "it's complex",
    null => "it's null",
    _ => "unknown type"
}
```

#### Combining Type and Destructuring

```javascript
match result {
    Error => "got an error",
    { success: true, value: v } => v,
    { success: false } => "operation failed",
    _ => "unexpected result"
}
```

## Guard Clauses

Add conditions to patterns with `if`:

```javascript
match n {
    x if (x > 0) => "positive",
    x if (x < 0) => "negative",
    _ => "zero"
}
```

Guards are evaluated after the pattern matches but before the body executes. Variables bound in the pattern are available in the guard:

```javascript
match person {
    { name: n, age: a } if (a >= 21) => n + " can drink",
    { name: n, age: a } if (a >= 18) => n + " is adult",
    { name: n, age: a } => n + " is minor (" + str(a) + ")"
}
```

### Complex Guards

```javascript
match point {
    { x, y } if (x == 0 && y == 0) => "origin",
    { x, y } if (x == 0) => "on Y-axis",
    { x, y } if (y == 0) => "on X-axis",
    { x, y } if (x == y) => "on diagonal",
    { x, y } => "point at (" + str(x) + ", " + str(y) + ")"
}
```

## Practical Examples

### Result Handling

```javascript
let handleResult = (result) => match result {
    { success: true, data: d } => d,
    { success: false, error: e } => throw e,
    Error => throw "unexpected error",
    _ => throw "invalid result format"
};
```

### Option/Maybe Pattern

```javascript
let getOrDefault = (maybeValue, default) => match maybeValue {
    null => default,
    v => v
};

let safeHead = (list) => match list {
    [] => null,
    [x, ...rest] => x
};
```

### Command Processing

```javascript
let processCommand = (cmd) => match cmd {
    { type: "add", x, y } => x + y,
    { type: "sub", x, y } => x - y,
    { type: "mul", x, y } => x * y,
    { type: "div", x, y } if (y != 0) => x / y,
    { type: "div" } => throw "division by zero",
    _ => throw "unknown command"
};

processCommand({ type: "add", x: 10, y: 5 })  // => 15
```

### Tree Traversal

```javascript
let countNodes = (node) => match node {
    null => 0,
    { value, left, right } => 1 + countNodes(left) + countNodes(right),
    { value } => 1,
    _ => 0
};

let tree = {
    value: 1,
    left: { value: 2, left: null, right: null },
    right: { value: 3, left: null, right: null }
};

countNodes(tree)  // => 3
```

### State Machine

```javascript
let transition = (state, event) => match [state, event] {
    ["idle", "start"] => "running",
    ["running", "pause"] => "paused",
    ["running", "stop"] => "idle",
    ["paused", "resume"] => "running",
    ["paused", "stop"] => "idle",
    [s, e] => throw "invalid transition: " + s + " + " + e
};
```

### Error Classification

```javascript
let classifyError = (err) => match err {
    { kind: "NetworkError" } => "check your connection",
    { kind: "ValidationError", message: m } => "invalid input: " + m,
    { kind: "AuthError" } => "please login again",
    Error => "unknown error occurred",
    _ => "not an error"
};
```

### List Operations

Using `rec` for self-recursion:

```javascript
// Sum with pattern matching
let sumList = (list) => match list {
    [] => 0,
    [x, ...rest] => x + rec(rest)
};

sumList([1, 2, 3, 4, 5])  // => 15

// Map implementation
let map = (list, f) => match list {
    [] => [],
    [x, ...rest] => push([f(x)], rec(rest, f))
};

// Filter implementation
let filter = (list, pred) => match list {
    [] => [],
    [x, ...rest] if pred(x) => push([x], rec(rest, pred)),
    [x, ...rest] => rec(rest, pred)
};

// Reduce implementation
let reduce = (list, acc, f) => match list {
    [] => acc,
    [x, ...rest] => rec(rest, f(acc, x), f)
};
```

## Integration with Error Handling

Pattern matching integrates naturally with try/catch:

```javascript
let safeDivide = (a, b) => try {
    if (b == 0) { throw { message: "div by zero", kind: "MathError" } };
    { success: true, value: a / b }
} catch (e) {
    { success: false, error: e }
};

let result = safeDivide(10, 0);

match result {
    { success: true, value: v } => print("Result: " + str(v)),
    { success: false, error: { kind: k, message: m } } => print(k + ": " + m),
    _ => print("unexpected")
}
```

## Best Practices

### 1. Always Include a Catch-All

```javascript
// Good - handles all cases
match x {
    0 => "zero",
    1 => "one",
    _ => "other"
}

// Risky - might fail at runtime
match x {
    0 => "zero",
    1 => "one"
    // No catch-all, will error if x is not 0 or 1
}
```

### 2. Order Patterns from Specific to General

```javascript
// Good - specific patterns first
match n {
    0 => "zero",
    x if (x < 0) => "negative",
    x => "positive"
}

// Bad - general pattern first (unreachable code)
match n {
    x => "any number",  // Always matches!
    0 => "zero"         // Never reached
}
```

### 3. Use Destructuring for Clarity

```javascript
// Clear - shows expected structure
let processUser = (user) => match user {
    { name: n, email: e, verified: true } => sendTo(e, n),
    { name: n, verified: false } => requestVerification(n),
    _ => throw "invalid user"
};

// Less clear - manual field access
let processUser = (user) => do {
    if (user.verified) {
        sendTo(user.email, user.name)
    } else {
        requestVerification(user.name)
    }
};
```

### 4. Combine with Guards for Complex Conditions

```javascript
match transaction {
    { amount: a, type: "withdrawal" } if (a > balance) =>
        throw "insufficient funds",
    { amount: a, type: "withdrawal" } =>
        updateBalance(balance - a),
    { amount: a, type: "deposit" } =>
        updateBalance(balance + a)
}
```

### 5. Use Type Patterns for Runtime Dispatch

```javascript
let serialize = (value) => match value {
    Number => str(value),
    String => "\"" + value + "\"",
    Boolean => if(value, "true", "false"),
    Vector => "[" + join(map(value, serialize), ", ") + "]",
    null => "null",
    _ => "<unknown>"
};
```

## Limitations

Current implementation limitations:

1. **No Exhaustiveness Checking** - No compile-time warning for incomplete patterns
2. **No Or-Patterns** - Cannot match alternatives in one arm (e.g., `1 | 2 | 3 => ...`)
3. **No As-Patterns** - Cannot bind and destructure simultaneously
4. **No Constant Patterns** - Cannot match against named constants
5. **Rest Must Be Last** - Vector rest pattern only at end position
6. **Guard Parentheses Required** - Guard conditions must be wrapped in parentheses:
   ```javascript
   // Required syntax:
   { x: a, y: b } if (a == b) => "same"

   // This is consistent with if statements: if (condition) { ... }
   ```

## Future Enhancements

Planned improvements:

- Exhaustiveness checking and warnings
- Or-patterns: `match x { 1 | 2 | 3 => "small" }`
- As-patterns: `match x { list @ [_, _, _] => len(list) }`
- Pattern matching in let bindings: `let { x, y } = point`
- Range patterns: `match n { 1..10 => "small" }`
