---
title: "Loop Control"
description: "Break, continue, and for-in loops in Achronyme"
section: "advanced-topics"
order: 13
---


Achronyme provides powerful loop control mechanisms for managing iteration flow, including `break` and `continue` statements, and the `for-in` loop for iterating over collections.

## break Statement

The `break` statement immediately exits the current loop.

### Basic Usage

```achronyme
mut i = 0
while(i < 100) {
    if(i == 10) { break }
    i += 1
}
i  // 10
```

### break with Value

`break` can return a value from the loop:

```achronyme
let result = while(true) {
    let x = calculateSomething()
    if(x > 100) { break x }
}
result  // The value that was > 100
```

### Search Pattern

```achronyme
let findFirst = (predicate, arr) => {
    mut i = 0
    mut found = null
    while(i < length(arr)) {
        if(predicate(arr[i])) {
            found = arr[i]
            break
        }
        i += 1
    }
    found
}

let isEven = x => x % 2 == 0
findFirst(isEven, [1, 3, 4, 5, 7])  // 4
```

### Nested Loops

`break` only exits the innermost loop:

```achronyme
mut outer = 0
mut inner_total = 0

while(outer < 3) {
    mut inner = 0
    while(inner < 10) {
        if(inner == 5) { break }  // Exits inner loop only
        inner_total += 1
        inner += 1
    }
    outer += 1
}

inner_total  // 15 (5 iterations x 3 outer loops)
```

## continue Statement

The `continue` statement skips to the next iteration of the current loop.

### Basic Usage

```achronyme
mut sum = 0
mut i = 0
while(i < 10) {
    i += 1
    if(i % 2 == 0) { continue }  // Skip even numbers
    sum += i
}
sum  // 25 (1 + 3 + 5 + 7 + 9)
```

### Filter Pattern

```achronyme
mut oddNumbers = []
mut i = 0
while(i < 10) {
    i += 1
    if(i % 2 == 0) { continue }
    oddNumbers = [...oddNumbers, i]
}
oddNumbers  // [1, 3, 5, 7, 9]
```

### Processing with Skip Conditions

```achronyme
let processItems = (items) => {
    mut results = []
    mut i = 0
    while(i < length(items)) {
        let item = items[i]
        i += 1

        // Skip invalid items
        if(item < 0) { continue }
        if(item > 100) { continue }

        // Process valid items
        results = [...results, item * 2]
    }
    results
}

processItems([10, -5, 50, 200, 30])  // [20, 100, 60]
```

## for-in Loop

The `for-in` loop iterates over elements in a collection (Vector, Tensor, or Generator).

### Basic Syntax

```achronyme
for(element in collection) {
    // body
}
```

### Iterating over Vectors

```achronyme
let numbers = [1, 2, 3, 4, 5]
mut sum = 0
for(x in numbers) {
    sum += x
}
sum  // 15
```

### Iterating over Tensors

```achronyme
let tensor = linspace(0, 1, 5)
mut values = []
for(val in tensor) {
    values = [...values, val]
}
values  // [0, 0.25, 0.5, 0.75, 1]
```

### for-in with break

```achronyme
mut found = -1
for(x in [10, 20, 30, 40]) {
    if(x == 30) {
        found = x
        break
    }
}
found  // 30
```

### for-in with continue

```achronyme
mut evens = []
for(x in [1, 2, 3, 4, 5, 6]) {
    if(x % 2 != 0) { continue }
    evens = [...evens, x]
}
evens  // [2, 4, 6]
```

### Processing Collections

```achronyme
let names = ["Alice", "Bob", "Charlie"]
mut greetings = []
for(name in names) {
    let greeting = 'Hello, ${name}!'
    greetings = [...greetings, greeting]
}
greetings
// ["Hello, Alice!", "Hello, Bob!", "Hello, Charlie!"]
```

### Nested for-in Loops

```achronyme
let matrix = [[1, 2], [3, 4], [5, 6]]
mut sum = 0
for(row in matrix) {
    for(value in row) {
        sum += value
    }
}
sum  // 21
```

### with Generators

```achronyme
let range = (start, end) => generate {
    mut i = start
    while(i < end) {
        yield i
        i += 1
    }
}

mut total = 0
for(i in range(0, 5)) {
    total += i
}
total  // 10 (0 + 1 + 2 + 3 + 4)
```

## Common Patterns

### Early Exit Search

```achronyme
let contains = (arr, target) => {
    for(item in arr) {
        if(item == target) {
            break true
        }
    }
    false
}

contains([1, 2, 3, 4], 3)  // true
contains([1, 2, 3, 4], 5)  // false
```

### Counting with Conditions

```achronyme
let countIf = (arr, predicate) => {
    mut count = 0
    for(item in arr) {
        if(predicate(item)) {
            count += 1
        }
    }
    count
}

let isPositive = x => x > 0
countIf([-1, 2, -3, 4, 5], isPositive)  // 3
```

### Find Index

```achronyme
let findIndex = (arr, target) => {
    mut i = 0
    for(item in arr) {
        if(item == target) {
            break i
        }
        i += 1
    }
    -1  // Not found
}

findIndex(["a", "b", "c"], "b")  // 1
findIndex(["a", "b", "c"], "z")  // -1
```

### Accumulate with Filtering

```achronyme
let sumPositives = (arr) => {
    mut sum = 0
    for(x in arr) {
        if(x <= 0) { continue }
        sum += x
    }
    sum
}

sumPositives([-1, 2, -3, 4, 5])  // 11
```

### Transform and Collect

```achronyme
let mapFilter = (arr, transform, predicate) => {
    mut result = []
    for(item in arr) {
        let transformed = transform(item)
        if(!predicate(transformed)) { continue }
        result = [...result, transformed]
    }
    result
}

let doubled = mapFilter(
    [1, 2, 3, 4, 5],
    x => x * 2,
    x => x > 5
)
doubled  // [6, 8, 10]
```

## Error Cases

### break Outside of Loop

```achronyme
// ERROR: 'break' can only be used inside a loop
let x = break
```

### continue Outside of Loop

```achronyme
// ERROR: 'continue' can only be used inside a loop
let y = continue
```

### Invalid for-in Target

```achronyme
// ERROR: Cannot iterate over Number
for(x in 42) {
    // ...
}
```

## Best Practices

### 1. Prefer for-in for Collections

```achronyme
// Good - clear intent
for(item in items) {
    process(item)
}

// Avoid - manual indexing
mut i = 0
while(i < length(items)) {
    process(items[i])
    i += 1
}
```

### 2. Use break for Early Exit

```achronyme
// Good - explicit early exit
for(item in items) {
    if(found(item)) { break }
}

// Avoid - flag variable
mut shouldContinue = true
mut i = 0
while(shouldContinue && i < length(items)) {
    if(found(items[i])) {
        shouldContinue = false
    }
    i += 1
}
```

### 3. Use continue to Reduce Nesting

```achronyme
// Good - flat structure
for(item in items) {
    if(!isValid(item)) { continue }
    if(!shouldProcess(item)) { continue }

    process(item)
}

// Avoid - deeply nested
for(item in items) {
    if(isValid(item)) {
        if(shouldProcess(item)) {
            process(item)
        }
    }
}
```

### 4. Combine with Compound Assignment

```achronyme
// Clean accumulation pattern
mut total = 0
for(value in [10, 20, 30]) {
    total += value
}
```

## Performance Considerations

- `for-in` is optimized for sequential access
- `break` immediately terminates without cleanup overhead
- `continue` skips remaining body without function call overhead
- Prefer `for-in` over manual while loops for collections

## Summary

- **break**: Exit loop immediately, optionally with a value
- **continue**: Skip to next iteration
- **for-in**: Iterate over Vectors, Tensors, or Generators
- Break/continue only affect the innermost loop
- Use these constructs for clearer, more maintainable loop logic

## See Also

- [While Loops](29-while-loops.md) - Basic while loop syntax
- [Generators](38-generators.md) - Creating lazy sequences with yield
- [Higher-Order Functions](11-higher-order-functions.md) - Functional alternatives (map, filter, reduce)
- [Mutability](26-mutability.md) - Using mutable variables in loops
