---
title: "Best Practices"
description: "Code style, patterns, and performance guidelines for Achronyme"
section: "advanced-topics"
order: 1
---


This guide provides conventions, patterns, and recommendations for writing clean, maintainable, and performant Achronyme code.

## Table of Contents

1. [Code Style](#code-style)
2. [Naming Conventions](#naming-conventions)
3. [Function Design](#function-design)
4. [Working with Data](#working-with-data)
5. [Performance Guidelines](#performance-guidelines)
6. [Error Handling](#error-handling)
7. [Code Organization](#code-organization)
8. [Common Patterns](#common-patterns)
9. [Anti-Patterns to Avoid](#anti-patterns-to-avoid)

## Code Style

### Indentation and Formatting

Use **consistent indentation** (2 or 4 spaces):

```javascript
// ✅ Good: Consistent indentation
let factorial = n =>
    if(n <= 1, 1, n * rec(n - 1))

let complex = x => do {
    let step1 = x * 2
    let step2 = step1 + 10
    step2
}

// ✅ Good: Multi-line for readability
let result = pipe(
    data,
    x => filter(n => n > 0, x),
    x => map(n => n * 2, x),
    x => reduce((acc, n) => acc + n, 0, x)
)
```

### Line Length

Keep lines under **80-100 characters** when possible:

```javascript
// ❌ Too long
let result = reallyLongFunctionName(parameter1, parameter2, parameter3, parameter4, parameter5)

// ✅ Better: Break into multiple lines
let result = reallyLongFunctionName(
    parameter1,
    parameter2,
    parameter3,
    parameter4,
    parameter5
)
```

### Whitespace

Use whitespace for readability:

```javascript
// ❌ Cramped
let f=x=>x*2+5

// ✅ Readable
let f = x => x * 2 + 5

// ✅ Group related operations
let analyze = data => do {
    let cleaned = filter(x => x > 0, data)
    let normalized = map(x => x / 100, cleaned)

    let mean_val = sum(normalized) / length(normalized)
    let variance = sum(map(x => (x - mean_val)^2, normalized)) / length(normalized)

    {mean: mean_val, variance: variance}
}
```

### Comments

Write comments that explain **why**, not **what**:

```javascript
// ❌ Bad: Obvious comment
// Multiply x by 2
let double = x => x * 2

// ✅ Good: Explains reasoning
// Use trapezoid rule for better accuracy with non-smooth functions
let area = trapz(f, 0, 10)

// ✅ Good: Documents limitations
// Factorial (limited to n < 40 due to recursion depth)
let factorial = n =>
    if(n <= 1, 1, n * rec(n - 1))

// ✅ Good: Explains complex logic
// Normalize to [0, 1] range to prevent numerical instability
// in downstream calculations
let normalized = map(
    x => (x - min_val) / (max_val - min_val),
    data
)
```

## Naming Conventions

### Variables

Use **descriptive, snake_case names**:

```javascript
// ❌ Bad: Unclear abbreviations
let d = getData()
let n = length(d)
let m = sum(d) / n

// ✅ Good: Clear, descriptive
let data = getData()
let count = length(data)
let mean_value = sum(data) / count

// ✅ Good: Mathematical conventions are OK
let x = 5
let y = 10
let theta = 3.14159 / 4
```

### Functions

Use **descriptive, verb-based names**:

```javascript
// ❌ Bad: Unclear purpose
let proc = x => x * 2 + 5

// ✅ Good: Clear intent
let calculateScore = x => x * 2 + 5
let normalizeData = data => map(x => x / max(data), data)
let isValid = value => value > 0 && value < 100

// ✅ Good: Boolean functions use 'is', 'has', 'can'
let isEven = n => n % 2 == 0
let hasValue = arr => length(arr) > 0
let canProcess = state => state.ready == true
```

### Records

Use **PascalCase for constructors**, **camelCase for fields**:

```javascript
// ✅ Good: Constructor in PascalCase
let Point = {
    new: (x, y) => {
        x: x,
        y: y,
        distance: () => sqrt(self.x^2 + self.y^2)
    }
}

// ✅ Good: Instance fields in camelCase or snake_case
let user = {
    firstName: "Alice",
    lastName: "Smith",
    email_address: "alice@example.com",
    isActive: true
}
```

### Constants

Use **UPPER_SNAKE_CASE** for constants:

```javascript
let PI = 3.14159265359
let SPEED_OF_LIGHT = 299792458
let MAX_ITERATIONS = 1000
let DEFAULT_TOLERANCE = 1e-6

let circleArea = radius => PI * radius^2
```

## Function Design

### Keep Functions Small and Focused

Each function should do **one thing well**:

```javascript
// ❌ Bad: Does too much
let processAndAnalyze = data => do {
    let cleaned = filter(x => x > 0, data)
    let normalized = map(x => x / 100, cleaned)
    let mean = sum(normalized) / length(normalized)
    let std = sqrt(sum(map(x => (x - mean)^2, normalized)) / length(normalized))
    let report = concat("Mean: ", mean)
    {data: normalized, mean: mean, std: std, report: report}
}

// ✅ Good: Separate concerns
let cleanData = data => filter(x => x > 0, data)

let normalizeData = data => map(x => x / max(data), data)

let calculateStats = data => do {
    let mean = sum(data) / length(data)
    let variance = sum(map(x => (x - mean)^2, data)) / length(data)
    {mean: mean, std: sqrt(variance)}
}

let formatReport = stats =>
    concat("Mean: ", concat(stats.mean, concat(", Std: ", stats.std)))

// Compose them
let analyze = data => do {
    let cleaned = cleanData(data)
    let normalized = normalizeData(cleaned)
    let stats = calculateStats(normalized)
    {data: normalized, stats: stats, report: formatReport(stats)}
}
```

### Prefer Expression Bodies

Use simple expressions when possible:

```javascript
// ✅ Good: Simple expression
let square = x => x^2
let double = x => x * 2
let isPositive = x => x > 0

// ✅ Good: Use do blocks for multi-step
let complex = x => do {
    let doubled = x * 2
    let squared = doubled^2
    squared + 10
}
```

### Avoid Deep Nesting

Flatten nested conditions:

```javascript
// ❌ Bad: Deep nesting
let categorize = x =>
    if(x < 0,
        "negative",
        if(x == 0,
            "zero",
            if(x < 10,
                "small",
                if(x < 100,
                    "medium",
                    "large"))))

// ✅ Good: Use piecewise
let categorize = x => piecewise(
    [x < 0, "negative"],
    [x == 0, "zero"],
    [x < 10, "small"],
    [x < 100, "medium"],
    "large"
)

// ✅ Good: Early returns with if chains
let categorize = x =>
    if(x < 0, "negative",
    if(x == 0, "zero",
    if(x < 10, "small",
    if(x < 100, "medium", "large"))))
```

### Use Descriptive Parameters

Make parameter purpose clear:

```javascript
// ❌ Bad: Unclear parameters
let calc = (a, b, c) => a * b + c

// ✅ Good: Clear parameters
let calculatePrice = (quantity, unitPrice, shipping) =>
    quantity * unitPrice + shipping

// ✅ Good: Use records for many parameters
let createUser = params => {
    name: params.name,
    email: params.email,
    age: params.age,
    role: params.role
}

let user = createUser({
    name: "Alice",
    email: "alice@example.com",
    age: 30,
    role: "admin"
})
```

## Working with Data

### Prefer Immutability

Don't try to mutate; create new values:

```javascript
// ✅ Good: Create new arrays
let numbers = [1, 2, 3]
let doubled = map(x => x * 2, numbers)
let extended = [...numbers, 4, 5, 6]

// ✅ Good: Create new records
let user = {name: "Alice", age: 30}
let updated = {...user, age: 31}
let withRole = {...user, role: "admin"}
```

### Use Shadowing for "Updates"

Shadowing creates new bindings:

```javascript
// ✅ Good: Shadow to "update"
let x = 10
let x = x + 5
let x = x * 2
// x is now 30

// ✅ Good: Shadow in do blocks
let result = do {
    let data = [1, 2, 3, 4, 5]
    let data = filter(x => x > 2, data)
    let data = map(x => x * 2, data)
    data
}
```

### Leverage Higher-Order Functions

Use `map`, `filter`, `reduce` instead of recursion:

```javascript
// ❌ Avoid: Manual recursion
let doubleAll = arr =>
    if(length(arr) == 0, [], [arr[0] * 2, ...rec(arr[1..])])

// ✅ Good: Use map
let doubleAll = arr => map(x => x * 2, arr)

// ❌ Avoid: Manual accumulation
let sumAll = arr =>
    if(length(arr) == 0, 0, arr[0] + rec(arr[1..]))

// ✅ Good: Use reduce or built-in
let sumAll = arr => reduce((acc, x) => acc + x, 0, arr)
let sumAll = arr => sum(arr)  // Even better
```

### Use Pipe for Transformations

Chain operations with `pipe`:

```javascript
// ❌ Nested function calls (hard to read)
let result = reduce(
    (acc, x) => acc + x,
    0,
    map(x => x^2, filter(x => x > 0, data))
)

// ✅ Good: Use pipe (reads left-to-right)
let result = pipe(
    data,
    x => filter(n => n > 0, x),
    x => map(n => n^2, x),
    x => reduce((acc, n) => acc + n, 0, x)
)
```

### Destructure with Indexing

Access record fields clearly:

```javascript
// ✅ Good: Direct field access
let user = {name: "Alice", age: 30, email: "alice@example.com"}
let name = user.name
let age = user.age

// ✅ Good: Process record fields
let displayUser = user =>
    concat(user.name, concat(" (", concat(user.age, ")")))
```

## Performance Guidelines

### Avoid Deep Recursion

**Limit recursion to ~40 calls**:

```javascript
// ❌ Bad: Deep recursion
let range = n => (
    (left, current, vector) =>
        if(left == 0, vector, rec(left - 1, current + 1, [...vector, current]))
)(n, 0, [])

range(100)  // Stack overflow!

// ✅ Good: Use built-ins
let range = n => linspace(0, n - 1, n)
range(1000)  // Works!
```

### Use Built-in Functions

Built-in functions are optimized:

```javascript
// ❌ Slower: Manual implementation
let mySum = arr => reduce((acc, x) => acc + x, 0, arr)

// ✅ Faster: Built-in
let total = sum(arr)

// Built-ins to prefer:
// - sum, mean, std, min, max
// - map, filter, reduce
// - linspace, zeros, ones
// - fft, conv, dot, transpose
```

### Minimize Array Copying

Avoid unnecessary array spreading:

```javascript
// ❌ Bad: Creates many intermediate arrays
let result = do {
    let arr = [1, 2, 3]
    let arr = [...arr, 4]
    let arr = [...arr, 5]
    let arr = [...arr, 6]
    arr
}

// ✅ Good: Build once
let result = [...[1, 2, 3], 4, 5, 6]

// ✅ Even better: Use literals
let result = [1, 2, 3, 4, 5, 6]
```

### Cache Expensive Computations

Store results in variables:

```javascript
// ❌ Bad: Recomputes max three times
let normalize = data => do {
    let normalized = map(x => x / max(data), data)
    let scaled = map(x => x * max(data), normalized)
    {normalized: normalized, max: max(data)}
}

// ✅ Good: Compute once
let normalize = data => do {
    let max_value = max(data)
    let normalized = map(x => x / max_value, data)
    let scaled = map(x => x * max_value, normalized)
    {normalized: normalized, max: max_value}
}
```

### Be Aware of Exponential Complexity

Avoid exponentially branching recursion:

```javascript
// ❌ Bad: Exponential time complexity
let fib = n =>
    if(n <= 1, n, rec(n - 1) + rec(n - 2))

fib(30)  // Very slow!

// ✅ Better: Document limitation
// Fibonacci (use only for n < 20)
let fib = n =>
    if(n <= 1, n, rec(n - 1) + rec(n - 2))
```

## Error Handling

### Validate Input

Check preconditions early:

```javascript
// ✅ Good: Validate input
let safeDivide = (a, b) =>
    if(b == 0, error("Division by zero"), a / b)

let safeSqrt = x =>
    if(x < 0, error("Cannot take square root of negative"), sqrt(x))

// ✅ Good: Range validation
let factorial = n =>
    if(n < 0, error("Factorial undefined for negative numbers"),
    if(n > 40, error("Factorial limited to n <= 40 (recursion depth)"),
    if(n <= 1, 1, n * rec(n - 1))))
```

### Provide Meaningful Error Messages

Help users understand what went wrong:

```javascript
// ❌ Bad: Vague error
let process = x =>
    if(x <= 0, error("Invalid"), process_internal(x))

// ✅ Good: Specific error
let process = x =>
    if(x <= 0,
        error("Input must be positive, got: " + x),
        process_internal(x))

// ✅ Good: Explain constraints
let factorial = n =>
    if(n > 40,
        error("Factorial limited to n <= 40 due to recursion depth limit"),
        if(n <= 1, 1, n * rec(n - 1)))
```

### Use Piecewise for Multiple Conditions

```javascript
// ✅ Good: Clear validation
let validateAge = age => piecewise(
    [age < 0, error("Age cannot be negative")],
    [age > 150, error("Age unrealistic (> 150)")],
    [age < 18, "minor"],
    "adult"
)
```

### Document Edge Cases

```javascript
// ✅ Good: Document behavior
// Returns 0 for empty array (mathematical convention)
let mean = arr =>
    if(length(arr) == 0, 0, sum(arr) / length(arr))

// ✅ Good: Handle null/undefined
let safeAccess = record =>
    if(record == null,
        error("Record is null"),
        record.field)
```

## Code Organization

### Group Related Functions

Organize code by functionality:

```javascript
// ✅ Good: Group related operations

// === Vector operations ===
let vectorAdd = (v1, v2) => map((x, i) => x + v2[i], v1)
let vectorScale = (v, scalar) => map(x => x * scalar, v)
let vectorDot = (v1, v2) => sum(map((x, i) => x * v2[i], v1))

// === Statistical functions ===
let mean = data => sum(data) / length(data)
let variance = data => do {
    let m = mean(data)
    sum(map(x => (x - m)^2, data)) / length(data)
}
let stdDev = data => sqrt(variance(data))

// === Data cleaning ===
let removeOutliers = data => do {
    let m = mean(data)
    let s = stdDev(data)
    filter(x => abs(x - m) < 2 * s, data)
}
```

### Use Records for Namespacing

Group related functionality:

```javascript
// ✅ Good: Namespace with records
let Math = {
    square: x => x^2,
    cube: x => x^3,
    pow: (x, n) => x^n,

    isEven: n => n % 2 == 0,
    isOdd: n => n % 2 == 1
}

let Stats = {
    mean: data => sum(data) / length(data),

    median: data => do {
        let sorted = sort(data)
        let n = length(sorted)
        let mid = floor(n / 2)
        if(n % 2 == 0,
            (sorted[mid - 1] + sorted[mid]) / 2,
            sorted[mid])
    },

    std: data => sqrt(Stats.variance(data)),

    variance: data => do {
        let m = Stats.mean(data)
        sum(map(x => (x - m)^2, data)) / length(data)
    }
}

// Usage
let avg = Stats.mean([1, 2, 3, 4, 5])
let s = Stats.std([1, 2, 3, 4, 5])
```

### Build Reusable Components

Create composable utilities:

```javascript
// ✅ Good: Reusable components
let compose = (f, g) => x => f(g(x))

let partial = (f, ...args) => (...rest) => f(...args, ...rest)

let curry = f => a => b => f(a, b)

// Usage
let double = x => x * 2
let addOne = x => x + 1
let doubleAndAddOne = compose(addOne, double)

doubleAndAddOne(5)  // 11
```

## Common Patterns

### Factory Pattern

Create object constructors:

```javascript
// ✅ Good: Factory pattern
let Point = {
    new: (x, y) => {
        x: x,
        y: y,

        distance: () => sqrt(self.x^2 + self.y^2),

        add: other => Point.new(
            self.x + other.x,
            self.y + other.y
        ),

        scale: factor => Point.new(
            self.x * factor,
            self.y * factor
        )
    }
}

// Usage
let p1 = Point.new(3, 4)
let p2 = Point.new(1, 2)
let p3 = p1.add(p2)
```

### Builder Pattern

Construct objects step-by-step:

```javascript
// ✅ Good: Builder pattern
let QueryBuilder = {
    empty: {
        table: "",
        columns: [],
        where: [],
        limit: null,

        from: t => {...self, table: t},
        select: cols => {...self, columns: cols},
        where: cond => {...self, where: [...self.where, cond]},
        limit: n => {...self, limit: n}
    }
}

// Usage
let query = QueryBuilder.empty
    .from("users")
    .select(["name", "email"])
    .where("age > 18")
    .limit(10)
```

### Pipeline Pattern

Transform data through stages:

```javascript
// ✅ Good: Pipeline pattern
let processPipeline = data => pipe(
    data,

    // Stage 1: Clean
    x => filter(n => n != null, x),

    // Stage 2: Transform
    x => map(n => n * 2, x),

    // Stage 3: Aggregate
    x => reduce((acc, n) => acc + n, 0, x)
)
```

### Strategy Pattern

Select algorithm dynamically:

```javascript
// ✅ Good: Strategy pattern
let Sorter = {
    quick: arr => quicksort(arr),
    bubble: arr => bubblesort(arr),
    merge: arr => mergesort(arr)
}

let sort = (arr, strategy) => strategy(arr)

// Usage
sort(data, Sorter.quick)
```

### Guard Pattern

Validate before processing:

```javascript
// ✅ Good: Guard pattern
let processUser = user =>
    if(user == null,
        error("User is null"),
    if(user.age < 0,
        error("Invalid age"),
    if(user.name == "",
        error("Name is empty"),
        // Process valid user
        {...user, processed: true})))
```

## Anti-Patterns to Avoid

### Don't Use Magic Numbers

```javascript
// ❌ Bad: Magic numbers
let score = points * 0.85 + bonus * 1.5

// ✅ Good: Named constants
let POINTS_MULTIPLIER = 0.85
let BONUS_MULTIPLIER = 1.5
let score = points * POINTS_MULTIPLIER + bonus * BONUS_MULTIPLIER
```

### Don't Repeat Yourself (DRY)

```javascript
// ❌ Bad: Repetition
let processA = data => filter(x => x > 0, map(x => x * 2, data))
let processB = data => filter(x => x > 0, map(x => x * 3, data))
let processC = data => filter(x => x > 0, map(x => x * 4, data))

// ✅ Good: Extract common pattern
let processWithMultiplier = (data, multiplier) =>
    filter(x => x > 0, map(x => x * multiplier, data))

let processA = data => processWithMultiplier(data, 2)
let processB = data => processWithMultiplier(data, 3)
let processC = data => processWithMultiplier(data, 4)
```

### Don't Over-Abstract

```javascript
// ❌ Bad: Over-engineered
let AbstractFactory = {
    create: type => FactoryRegistry[type].instantiate()
}

// ✅ Good: Keep it simple
let createUser = (name, age) => {name: name, age: age}
```

### Don't Use Cryptic Names

```javascript
// ❌ Bad: Unclear abbreviations
let proc = d => d.map(x => x.val * 2).flt(x => x > 0)

// ✅ Good: Clear names
let processData = data =>
    filter(x => x > 0, map(x => x.value * 2, data))
```

### Don't Ignore Edge Cases

```javascript
// ❌ Bad: Doesn't handle empty array
let average = arr => sum(arr) / length(arr)

average([])  // Division by zero!

// ✅ Good: Handle edge cases
let average = arr =>
    if(length(arr) == 0,
        0,  // or error("Cannot average empty array")
        sum(arr) / length(arr))
```

### Don't Write Monolithic Functions

```javascript
// ❌ Bad: Does everything
let analyzeAndReport = data => do {
    // 100 lines of code...
}

// ✅ Good: Break into pieces
let cleanData = data => ...
let analyzeData = data => ...
let formatReport = analysis => ...

let analyzeAndReport = data => do {
    let cleaned = cleanData(data)
    let analysis = analyzeData(cleaned)
    formatReport(analysis)
}
```

## Summary

**Code Style**:
- Consistent indentation and formatting
- Meaningful whitespace
- Comments explain "why", not "what"

**Naming**:
- snake_case for variables and functions
- PascalCase for constructors
- UPPER_SNAKE_CASE for constants
- Descriptive, clear names

**Functions**:
- Small and focused (one responsibility)
- Prefer expressions over complex bodies
- Use do blocks for multi-step logic
- Descriptive parameters

**Data**:
- Embrace immutability
- Use higher-order functions
- Leverage pipe for transformations
- Shadow for "updates"

**Performance**:
- Avoid deep recursion (> 40 calls)
- Use built-in functions
- Cache expensive computations
- Be aware of complexity

**Organization**:
- Group related functions
- Use records for namespacing
- Build reusable components
- Document edge cases

**Patterns**:
- Factory for constructors
- Builder for complex objects
- Pipeline for transformations
- Strategy for algorithms
- Guard for validation

**Avoid**:
- Magic numbers
- Repetition (DRY)
- Over-abstraction
- Cryptic names
- Ignoring edge cases
- Monolithic functions

---

**See Also**:
- [Functions and Lambdas](06-functions.md) - Function basics
- [Do Blocks](21-do-blocks.md) - Multi-statement blocks
- [Recursion Patterns](22-recursion.md) - Recursive best practices
- [Performance Limitations](25-performance-limitations.md) - Performance constraints
- [Examples](24-examples.md) - Practical code examples
