---
title: "Destructuring"
description: "Extract values from records and vectors using patterns in Achronyme"
section: "advanced-topics"
order: 11
---


Achronyme v0.6.2 introduces **destructuring assignment** in `let` and `mut` bindings, allowing you to extract values from records and vectors directly into variables. This feature reuses the pattern matching infrastructure to provide consistent and powerful value extraction.

## Overview

Destructuring assignment:
- **Extracts values** from complex data structures into individual variables
- **Supports records and vectors** with full pattern matching syntax
- **Enables renaming** during extraction for clearer variable names
- **Allows partial matching** to extract only needed fields
- **Works with mutability** via `mut` keyword for mutable bindings
- **Handles nesting** for deeply nested structures

## Record Destructuring

### Basic Record Destructuring

Extract fields from a record into variables with matching names:

```javascript
let person = { name: "Alice", age: 30, city: "Boston" }

// Extract name and age into variables
let { name, age } = person

name  // "Alice"
age   // 30
```

The variable names must match the field names in the record.

### Renaming During Extraction

Use `:` to rename fields as you extract them:

```javascript
let person = { name: "Alice", age: 30 }

// Extract with different variable names
let { name: personName, age: personAge } = person

personName  // "Alice"
personAge   // 30
```

This is useful when field names conflict with existing variables or when you want more descriptive names.

### Partial Record Destructuring

Extract only the fields you need - other fields are ignored:

```javascript
let data = { x: 1, y: 2, z: 3, w: 4 }

// Extract only x and z
let { x, z } = data

x  // 1
z  // 3
// y and w are not bound
```

### Nested Record Destructuring

Destructure deeply nested structures:

```javascript
let response = {
    status: 200,
    user: {
        name: "Bob",
        profile: {
            email: "bob@example.com",
            verified: true
        }
    }
}

// Extract nested fields
let { user: { name, profile: { email } } } = response

name   // "Bob"
email  // "bob@example.com"
```

You can also rename nested fields:

```javascript
let data = {
    user: {
        name: "Charlie",
        role: "admin"
    }
}

let { user: { name: userName, role: userRole } } = data

userName  // "Charlie"
userRole  // "admin"
```

## Vector/Array Destructuring

### Basic Vector Destructuring

Extract elements by position:

```javascript
let coords = [10, 20, 30]

let [x, y, z] = coords

x  // 10
y  // 20
z  // 30
```

### Vector with Rest Pattern

Use `...` to capture remaining elements:

```javascript
let numbers = [1, 2, 3, 4, 5]

let [first, second, ...rest] = numbers

first   // 1
second  // 2
rest    // [3, 4, 5]
```

The rest pattern captures all remaining elements as a new array:

```javascript
let [head, ...tail] = [1, 2, 3, 4, 5]

head  // 1
tail  // [2, 3, 4, 5]
```

**Note**: The rest pattern must be the last element in the destructuring pattern.

### Vector with Wildcard

Use `_` to skip elements you don't need:

```javascript
let values = ["a", "b", "c", "d"]

let [first, _, third, _] = values

first  // "a"
third  // "c"
// second and fourth elements are ignored
```

This is useful when you only care about specific positions:

```javascript
let [_, middle, _] = [1, 2, 3]

middle  // 2
```

### Empty and Single Element

Handle edge cases:

```javascript
// Empty destructuring
let [] = []

// Single element
let [only] = [42]
only  // 42

// Pair
let [a, b] = [true, false]
a  // true
b  // false
```

## Mutable Destructuring

Use `mut` to create mutable bindings from destructured values:

```javascript
let point = { x: 10, y: 20 }

// Mutable destructuring
mut { x, y } = point

// Now x and y are mutable
x = x + 5   // 15
y = y * 2   // 40
```

This works with vectors too:

```javascript
let coords = [100, 200, 300]

mut [a, b, c] = coords

a = a * 2  // 200
b = b * 2  // 400
c = c * 2  // 600
```

Mutable destructuring is useful for:
- Updating extracted values
- Building modified results
- Accumulating changes

## Practical Examples

### Processing Configuration

```javascript
let config = {
    server: {
        host: "localhost",
        port: 8080
    },
    database: {
        url: "postgres://localhost/db",
        pool_size: 10
    },
    debug: true
}

// Extract only what you need
let { server: { host, port }, debug } = config

let connection_string = host + ":" + str(port)
// "localhost:8080"
```

### Function Parameter Processing

```javascript
let processPoint = (point) => do {
    let { x, y } = point;
    sqrt(x^2 + y^2)
}

processPoint({ x: 3, y: 4 })  // 5
```

### API Response Handling

```javascript
let response = {
    success: true,
    data: {
        items: [1, 2, 3, 4, 5],
        total: 100
    },
    metadata: {
        timestamp: "2024-01-01"
    }
}

let { success, data: { items, total } } = response

if (success) {
    let average = sum(items) / total
}
```

### Working with Coordinates

```javascript
let line = {
    start: { x: 0, y: 0 },
    end: { x: 10, y: 10 }
}

let { start: { x: x1, y: y1 }, end: { x: x2, y: y2 } } = line

let dx = x2 - x1  // 10
let dy = y2 - y1  // 10
let length = sqrt(dx^2 + dy^2)  // 14.142...
```

### List Processing

```javascript
let splitList = (list) => do {
    let [head, ...tail] = list;
    { first: head, rest: tail }
}

splitList([1, 2, 3, 4, 5])
// { first: 1, rest: [2, 3, 4, 5] }
```

### Swapping Values

```javascript
let pair = [10, 20]

let [a, b] = pair
let swapped = [b, a]  // [20, 10]
```

### Accumulator Pattern

```javascript
let data = [1, 2, 3, 4, 5]

mut { total, count } = { total: 0, count: 0 }

map((x) => do {
    total = total + x;
    count = count + 1
}, data)

let average = total / count  // 3
```

## Error Cases

### Pattern Mismatch - Missing Fields

If the record doesn't have the required fields, an error occurs:

```javascript
let person = { name: "Alice" }

// ERROR: Field 'age' not found
let { name, age } = person
```

### Pattern Mismatch - Not Enough Elements

If the vector doesn't have enough elements:

```javascript
let short = [1, 2]

// ERROR: Not enough elements (expected 3, got 2)
let [a, b, c] = short
```

### Type Mismatch

Destructuring expects the correct value type:

```javascript
let num = 42

// ERROR: Cannot destructure number as record
let { x } = num

// ERROR: Cannot destructure number as vector
let [a] = num
```

### Wrong Structure

Attempting to use record pattern on vector or vice versa:

```javascript
let arr = [1, 2, 3]

// ERROR: Cannot destructure vector as record
let { x } = arr

let rec = { x: 1, y: 2 }

// ERROR: Cannot destructure record as vector
let [a, b] = rec
```

## Comparison with Pattern Matching

Destructuring assignment in `let`/`mut` bindings is built on the same pattern matching infrastructure used by `match` expressions:

### Pattern Matching (conditional)

```javascript
match value {
    { name: n, age: a } if (a >= 18) => "Adult: " + n,
    { name: n } => "Minor: " + n,
    _ => "Unknown"
}
```

### Destructuring Assignment (unconditional)

```javascript
let { name, age } = person
// Assumes pattern will match; errors if not
```

Key differences:
- **Destructuring assumes success** - no fallback patterns
- **Pattern matching is conditional** - provides alternatives
- **Destructuring creates bindings** - in current scope
- **Pattern matching is an expression** - returns values

Use destructuring when you're confident about the structure. Use pattern matching when you need to handle multiple possible structures.

## Best Practices

### 1. Use Destructuring to Reduce Boilerplate

```javascript
// Without destructuring
let name = user.name
let email = user.email
let age = user.age

// With destructuring - cleaner
let { name, email, age } = user
```

### 2. Prefer Partial Matching for Flexibility

Extract only what you need - additional fields are ignored:

```javascript
// Flexible - works even if config has more fields
let { timeout, retries } = config

// Rather than accessing everything
let timeout = config.timeout
let retries = config.retries
```

### 3. Rename for Clarity

```javascript
// Rename to avoid conflicts or improve readability
let { data: responseData, error: responseError } = result
```

### 4. Combine with Pattern Matching for Complex Logic

```javascript
let processData = (input) => match input {
    { type: "array", data: d } => do {
        let [first, ...rest] = d;
        process(first, rest)
    },
    { type: "object", data: d } => do {
        let { value, metadata } = d;
        processObject(value, metadata)
    },
    _ => throw "unsupported type"
}
```

### 5. Use Rest Pattern for Variable-Length Data

```javascript
let [required1, required2, ...optional] = args
// Handle required arguments first
// Then process optional ones
```

### 6. Document Expected Structure

```javascript
// Expects: { user: { id: Number, name: String }, timestamp: String }
let processEvent = (event) => do {
    let { user: { id, name }, timestamp } = event;
    log(timestamp + ": User " + str(id) + " (" + name + ")")
}
```

### 7. Handle Errors Gracefully

When you're unsure about structure, use pattern matching instead:

```javascript
// Safe - handles missing fields
let getName = (obj) => match obj {
    { name: n } => n,
    _ => "unknown"
}

// Risky - errors if name is missing
let getName = (obj) => do {
    let { name } = obj;
    name
}
```

### 8. Use Mutable Destructuring Sparingly

Only use `mut` when you genuinely need to modify the values:

```javascript
// Good - need to accumulate
mut { sum, count } = { sum: 0, count: 0 }

// Prefer immutable when possible
let { x, y } = point
let newPoint = { x: x + 1, y: y + 1 }
```

## Integration with Other Features

### With Do Blocks

```javascript
let compute = (data) => do {
    let { values, factor } = data;
    let scaled = map(v => v * factor, values);
    sum(scaled)
}
```

### With Recursion

```javascript
let sumList = (list) => match list {
    [] => 0,
    _ => do {
        let [head, ...tail] = list;
        head + sumList(tail)
    }
}

sumList([1, 2, 3, 4, 5])  // 15
```

### With Higher-Order Functions

```javascript
let people = [
    { name: "Alice", age: 30 },
    { name: "Bob", age: 25 },
    { name: "Charlie", age: 35 }
]

let names = map((person) => do {
    let { name } = person;
    name
}, people)

// ["Alice", "Bob", "Charlie"]
```

### With Try-Catch

```javascript
let safeDestructure = (obj) => try {
    let { required_field } = obj;
    required_field
} catch (e) {
    "default_value"
}
```

## Limitations

Current implementation limitations:

1. **No Default Values** - Cannot provide defaults for missing fields
   ```javascript
   // Not supported:
   // let { x = 0, y = 0 } = point
   ```

2. **No Computed Property Names** - Field names must be known at parse time
   ```javascript
   // Not supported:
   // let { [key]: value } = obj
   ```

3. **No Type Annotations** - Cannot specify expected types
   ```javascript
   // Not supported:
   // let { x: Number, y: Number } = point
   ```

4. **Rest Must Be Last in Vectors** - Cannot have rest pattern in middle
   ```javascript
   // Not supported:
   // let [...start, last] = array
   // let [first, ...middle, last] = array
   ```

5. **No Record Rest Pattern** - Cannot capture remaining record fields
   ```javascript
   // Not supported:
   // let { x, ...rest } = { x: 1, y: 2, z: 3 }
   ```

## Summary

Destructuring assignment in Achronyme provides:

- **Record destructuring**: `let { field1, field2 } = record`
- **Field renaming**: `let { field: newName } = record`
- **Partial matching**: Extract subset of fields
- **Nested destructuring**: `let { outer: { inner } } = data`
- **Vector destructuring**: `let [a, b, c] = array`
- **Rest patterns**: `let [head, ...tail] = array`
- **Wildcards**: `let [first, _, third] = array`
- **Mutable bindings**: `mut { x, y } = point`

Use destructuring to write cleaner, more expressive code when working with complex data structures. For conditional structure matching, combine with the `match` expression for comprehensive pattern matching capabilities.

---

**Related**: [Pattern Matching](36-pattern-matching.md) | [Variables](05-variables.md) | [Mutability](26-mutability.md) | [Records](07-records.md)
