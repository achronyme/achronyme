---
title: "Recursion Patterns"
description: "Recursive functions and self-reference with rec keyword in Achronyme"
section: "functional-programming"
order: 3
---


Recursion is a powerful technique where a function calls itself to solve problems by breaking them down into smaller subproblems. Achronyme supports recursion through the `rec` keyword, which provides self-reference within lambda functions.

## Table of Contents

1. [Basic Recursion](#basic-recursion)
2. [The `rec` Keyword](#the-rec-keyword)
3. [Recursion Patterns](#recursion-patterns)
4. [Recursion with Do Blocks](#recursion-with-do-blocks)
5. [Performance Considerations](#performance-considerations)
6. [Safe Recursive Patterns](#safe-recursive-patterns)
7. [Alternatives to Recursion](#alternatives-to-recursion)
8. [Common Pitfalls](#common-pitfalls)

## Basic Recursion

### What is Recursion?

Recursion is when a function calls itself to solve a problem. Every recursive function needs:

1. **Base case**: Condition to stop recursion
2. **Recursive case**: Function calls itself with smaller input
3. **Progress**: Each call must move toward the base case

### Simple Example

```javascript
// Factorial: n! = n * (n-1) * (n-2) * ... * 1
let factorial = n =>
    if(n <= 1, 1, n * rec(n - 1))

factorial(5)  // 120 (5 * 4 * 3 * 2 * 1)
```

**How it works**:
```
factorial(5)
= 5 * factorial(4)
= 5 * (4 * factorial(3))
= 5 * (4 * (3 * factorial(2)))
= 5 * (4 * (3 * (2 * factorial(1))))
= 5 * (4 * (3 * (2 * 1)))
= 120
```

## The `rec` Keyword

### Why `rec`?

In Achronyme, lambda functions are anonymous and don't have names. The `rec` keyword provides a way to reference the current function from within itself.

```javascript
// ❌ This doesn't work - 'factorial' not in scope
let factorial = n =>
    if(n <= 1, 1, n * factorial(n - 1))  // ERROR

// ✅ Use 'rec' for self-reference
let factorial = n =>
    if(n <= 1, 1, n * rec(n - 1))
```

### `rec` Refers to Current Function

```javascript
let countdown = n =>
    if(n <= 0,
        "Done!",
        concat(n, " ", rec(n - 1)))

countdown(5)
// "5 4 3 2 1 Done!"
```

### `rec` in Anonymous Functions

```javascript
// Anonymous recursive function
let result = (n => if(n <= 1, 1, n * rec(n - 1)))(5)
// result = 120
```

## Recursion Patterns

### 1. Linear Recursion

Function makes one recursive call per invocation.

#### Countdown

```javascript
let countdown = n =>
    if(n <= 0, 0, 1 + rec(n - 1))

countdown(5)  // 5
```

#### Sum of Natural Numbers

```javascript
let sumN = n =>
    if(n <= 0, 0, n + rec(n - 1))

sumN(10)  // 55 (1+2+3+...+10)
```

#### List Sum (Conceptual)

```javascript
let listSum = arr =>
    if(length(arr) == 0,
        0,
        arr[0] + rec(arr[1..]))

listSum([1, 2, 3, 4, 5])  // 15
```

**Note**: For actual list operations, prefer `reduce` or `sum` built-ins.

### 2. Multiple Recursion

Function makes multiple recursive calls.

#### Fibonacci

```javascript
let fibonacci = n =>
    if(n <= 1, n, rec(n - 1) + rec(n - 2))

fibonacci(0)   // 0
fibonacci(1)   // 1
fibonacci(5)   // 5
fibonacci(10)  // 55
```

**Execution tree for `fibonacci(5)`**:
```
                fibonacci(5)
              /              \
        fib(4)                fib(3)
       /      \              /      \
   fib(3)    fib(2)      fib(2)    fib(1)
   /   \      /   \       /   \
fib(2) fib(1) ...  ...   ...  ...
```

**Warning**: Exponentially slow without memoization. Use sparingly.

#### Binary Tree Depth

```javascript
let treeDepth = node =>
    if(node == null, 0,
        1 + max([
            rec(node.left),
            rec(node.right)
        ]))

// Usage with tree structure
let tree = {
    value: 1,
    left: {value: 2, left: null, right: null},
    right: {value: 3, left: null, right: null}
}

treeDepth(tree)  // 2
```

### 3. Tail Recursion

Recursive call is the last operation (no computation after).

#### Tail-Recursive Factorial

```javascript
let factorial = n => (
    (current, acc) =>
        if(current <= 1, acc, rec(current - 1, acc * current))
)(n, 1)

factorial(5)  // 120
```

**Comparison**:

| Type | Example | After recursive call |
|------|---------|---------------------|
| **Regular** | `n * rec(n-1)` | Multiplication needed |
| **Tail** | `rec(n-1, acc*n)` | Nothing - return directly |

**Note**: Achronyme doesn't currently optimize tail calls, so this doesn't avoid stack usage.

#### Tail-Recursive Sum

```javascript
let sum = arr => (
    (remaining, acc) =>
        if(length(remaining) == 0,
            acc,
            rec(remaining[1..], acc + remaining[0]))
)(arr, 0)

sum([1, 2, 3, 4, 5])  // 15
```

### 4. Recursion with Accumulators

Use additional parameters to carry state through recursion.

#### Range Generation

```javascript
let range = n => (
    (left, current, vector) =>
        if(left == 0,
            vector,
            rec(left - 1, current + 1, [...vector, current]))
)(n, 0, [])

range(5)  // [0, 1, 2, 3, 4]
```

**Warning**: Limited to ~40 elements due to stack depth. Use `linspace(0, n-1, n)` instead.

#### Reverse List

```javascript
let reverse = arr => (
    (remaining, result) =>
        if(length(remaining) == 0,
            result,
            rec(remaining[1..], [remaining[0], ...result]))
)(arr, [])

reverse([1, 2, 3, 4, 5])  // [5, 4, 3, 2, 1]
```

### 5. Mutual Recursion

Two or more functions call each other.

```javascript
// Even/odd checker (conceptual)
let isEven = n =>
    if(n == 0, true,
    if(n == 1, false,
        isOdd(n - 1)))

let isOdd = n =>
    if(n == 0, false,
    if(n == 1, true,
        isEven(n - 1)))

// Note: This pattern is difficult in Achronyme
// because functions aren't hoisted
```

**Challenge**: Mutual recursion is tricky in Achronyme because functions must be defined before use. Consider using records or different approaches.

### 6. Tree Recursion

Processing hierarchical structures.

#### Tree Sum

```javascript
let treeSum = node =>
    if(node == null,
        0,
        node.value + rec(node.left) + rec(node.right))

let tree = {
    value: 1,
    left: {value: 2, left: null, right: null},
    right: {value: 3, left: null, right: null}
}

treeSum(tree)  // 6
```

#### Tree Traversal (In-order)

```javascript
let inorder = node => do {
    if(node == null,
        [],
        [...rec(node.left), node.value, ...rec(node.right)])
}
```

## Recursion with Do Blocks

Do blocks enable more complex recursive patterns with local variables.

### Factorial with Do Block

```javascript
let factorial = n => do {
    if(n <= 1, 1, n * rec(n - 1))
}

factorial(10)  // 3628800
```

### Fibonacci with Do Block

```javascript
let fib = n => do {
    if(n <= 1,
        n,
        rec(n - 1) + rec(n - 2))
}

fib(10)  // 55
```

### Complex Recursive Processing

```javascript
let processTree = tree => do {
    let current_value = tree.value * 2
    let left_result = if(tree.left == null, 0, rec(tree.left))
    let right_result = if(tree.right == null, 0, rec(tree.right))

    current_value + left_result + right_result
}
```

### Quicksort (Conceptual)

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
        })
}

// Warning: Limited to small arrays due to recursion depth
quicksort([3, 1, 4, 1, 5, 9, 2, 6])
```

## Performance Considerations

### ⚠️ Critical Limitation: ~50 Call Depth

Achronyme has a **strict recursion depth limit of approximately 50 calls** due to stack constraints.

```javascript
let countdown = n =>
    if(n <= 0, 0, 1 + rec(n - 1))

countdown(10)   // ✅ Works
countdown(40)   // ✅ Works (near limit)
countdown(50)   // ❌ Stack overflow!
countdown(100)  // ❌ Stack overflow!
```

### Why This Limit Exists

Each recursive call involves:
1. **Environment cloning**: All variables copied
2. **Function cloning**: Function object duplicated
3. **Scope management**: New scope pushed onto stack
4. **Stack frame creation**: New Rust stack frame

At depth 50, memory usage becomes unsustainable.

### Memory Usage Pattern

```javascript
// Example: range(50)
let range = n => (
    (left, current, vector) =>
        if(left == 0, vector, rec(left - 1, current + 1, [...vector, current]))
)(n, 0, [])

// Creates intermediate vectors:
// Call 1:  [0]
// Call 2:  [0, 1]
// Call 3:  [0, 1, 2]
// ...
// Call 50: [0, 1, 2, ..., 49]
// Total elements created: ~1,275
```

### Recursion Depth Testing

Always test with increasing sizes:

```javascript
// Progressive testing
myFunction(5)    // ✅ Test first
myFunction(10)   // ✅ Increase
myFunction(20)   // ✅ Keep going
myFunction(40)   // ⚠️ Near limit
myFunction(50)   // ❌ Likely fails
```

## Safe Recursive Patterns

These patterns are safe because they have naturally limited depth:

### 1. GCD (Euclidean Algorithm)

```javascript
let gcd = (a, b) =>
    if(b == 0, a, rec(b, a % b))

gcd(48, 18)     // 6
gcd(1000, 35)   // 5
gcd(12345, 678) // 3
```

**Why safe**: Typically terminates in < 20 iterations even for large numbers.

### 2. Power (Logarithmic Recursion)

```javascript
let power = (base, exp) =>
    if(exp == 0, 1,
    if(exp == 1, base,
    if(exp % 2 == 0,
        rec(base * base, exp / 2),
        base * rec(base, exp - 1))))

power(2, 10)  // 1024
```

**Why safe**: Logarithmic depth (log₂ n).

### 3. Binary Search

```javascript
let binarySearch = (arr, target, low, high) =>
    if(low > high,
        -1,
        do {
            let mid = floor((low + high) / 2)
            let midVal = arr[mid]

            if(midVal == target, mid,
            if(midVal < target,
                rec(arr, target, mid + 1, high),
                rec(arr, target, low, mid - 1)))
        })

// Usage
let sorted = [1, 3, 5, 7, 9, 11, 13, 15, 17, 19]
binarySearch(sorted, 7, 0, length(sorted) - 1)  // 3
```

**Why safe**: Logarithmic depth (log₂ n).

### 4. Small Factorials

```javascript
let factorial = n =>
    if(n <= 1, 1, n * rec(n - 1))

factorial(10)  // ✅ Safe: 3628800
factorial(20)  // ✅ Safe (but large number)
factorial(40)  // ⚠️ Near limit
```

**Why safe**: Useful factorials are typically small (< 40).

### 5. Balanced Tree Traversal

```javascript
let treeDepth = node =>
    if(node == null, 0,
        1 + max([rec(node.left), rec(node.right)]))
```

**Why safe**: Balanced trees rarely exceed depth 30-40.

## Alternatives to Recursion

When recursion depth is a concern, use these alternatives:

### 1. Built-in Functions

```javascript
// ❌ Recursive sum (limited)
let sumRec = arr =>
    if(length(arr) == 0, 0, arr[0] + rec(arr[1..]))

// ✅ Built-in sum (unlimited)
let sumBuiltin = arr => sum(arr)

sum([1, 2, 3, ..., 1000])  // ✅ Works!
```

### 2. Higher-Order Functions

```javascript
// ❌ Recursive map (limited)
let mapRec = (f, arr) =>
    if(length(arr) == 0,
        [],
        [f(arr[0]), ...rec(f, arr[1..])])

// ✅ Built-in map (unlimited)
let mapBuiltin = (f, arr) => map(f, arr)

map(x => x * 2, linspace(0, 999, 1000))  // ✅ Works!
```

### 3. Reduce for Accumulation

```javascript
// ❌ Recursive accumulation (limited)
let factorialRec = n =>
    if(n <= 1, 1, n * rec(n - 1))

// ✅ Reduce-based (better for large ranges)
let factorialIter = n =>
    reduce((acc, x) => acc * x, 1, linspace(1, n, n))

// Note: Still limited by number size, not recursion
```

### 4. linspace for Ranges

```javascript
// ❌ Recursive range (limited to ~50)
let rangeRec = n => (
    (left, current, vector) =>
        if(left == 0, vector, rec(left - 1, current + 1, [...vector, current]))
)(n, 0, [])

// ✅ Built-in linspace (unlimited)
let rangeBuiltin = n => linspace(0, n - 1, n)

linspace(0, 999, 1000)  // ✅ Works!
```

### 5. Iterative Thinking

Express problems iteratively using functional operations:

```javascript
// ❌ Recursive filter
let filterRec = (pred, arr) =>
    if(length(arr) == 0,
        [],
        if(pred(arr[0]),
            [arr[0], ...rec(pred, arr[1..])],
            rec(pred, arr[1..])))

// ✅ Built-in filter
let filterBuiltin = (pred, arr) => filter(pred, arr)
```

## Common Pitfalls

### 1. Forgetting Base Case

```javascript
// ❌ Infinite recursion
let bad = n => rec(n - 1)

// ✅ Always include base case
let good = n =>
    if(n <= 0, 0, rec(n - 1))
```

### 2. Using Function Name Instead of `rec`

```javascript
// ❌ Name not in scope
let factorial = n =>
    if(n <= 1, 1, n * factorial(n - 1))  // ERROR

// ✅ Use rec
let factorial = n =>
    if(n <= 1, 1, n * rec(n - 1))
```

### 3. Not Making Progress

```javascript
// ❌ Doesn't approach base case
let bad = n =>
    if(n == 0, 0, rec(n))  // Infinite!

// ✅ Decrements toward base
let good = n =>
    if(n == 0, 0, rec(n - 1))
```

### 4. Excessive Recursion Depth

```javascript
// ❌ Too deep for large n
let range = n => (
    (left, current, vector) =>
        if(left == 0, vector, rec(left - 1, current + 1, [...vector, current]))
)(n, 0, [])

range(100)  // ❌ Stack overflow

// ✅ Use built-in
let range = n => linspace(0, n - 1, n)
range(100)  // ✅ Works
```

### 5. Exponential Complexity

```javascript
// ❌ Fibonacci without memoization
let fib = n =>
    if(n <= 1, n, rec(n - 1) + rec(n - 2))

fib(30)  // Very slow!

// ✅ For larger n, consider iterative approach
// (though Achronyme doesn't have built-in memoization)
```

### 6. Growing Intermediate Structures

```javascript
// ❌ Creates increasingly large vectors
let zeros = n => (
    (left, vector) =>
        if(left == 0, vector, rec(left - 1, [0, ...vector]))
)(n, [])

// ✅ Use map instead
let zeros = n => map(_ => 0, linspace(0, n - 1, n))
```

## Recursion Decision Guide

Use this flowchart to decide if recursion is appropriate:

```
Is the problem naturally recursive?
├─ No → Use built-in functions or higher-order functions
└─ Yes
   └─ Will depth exceed 40?
      ├─ Yes → Use iterative approach or built-ins
      └─ No
         └─ Is it exponentially branching (like naive Fibonacci)?
            ├─ Yes → Consider alternatives
            └─ No → ✅ Recursion is appropriate
```

### Examples:

| Problem | Recursive? | Why |
|---------|-----------|-----|
| Sum array | ❌ | Use `sum()` or `reduce()` |
| Factorial < 40 | ✅ | Natural recursion, safe depth |
| Range 0..n | ❌ | Use `linspace()` |
| Tree traversal | ✅ | Natural recursion, limited depth |
| GCD | ✅ | Natural recursion, logarithmic depth |
| Fibonacci | ⚠️ | Natural but slow; limit to small n |
| Binary search | ✅ | Natural recursion, logarithmic depth |

## Best Practices

### 1. Always Test Depth Limits

```javascript
// Test progressively
factorial(5)   // ✅
factorial(10)  // ✅
factorial(20)  // ✅
factorial(40)  // ⚠️ Near limit
```

### 2. Prefer Built-ins When Available

```javascript
// ✅ Use built-in
sum(numbers)

// ❌ Avoid unnecessary recursion
let sum = arr =>
    if(length(arr) == 0, 0, arr[0] + rec(arr[1..]))
```

### 3. Document Depth Limits

```javascript
// Factorial (safe for n < 40)
let factorial = n =>
    if(n <= 1, 1, n * rec(n - 1))
```

### 4. Use Do Blocks for Complex Recursion

```javascript
// ✅ Clear and readable
let process = tree => do {
    let leftSum = if(tree.left == null, 0, rec(tree.left))
    let rightSum = if(tree.right == null, 0, rec(tree.right))
    tree.value + leftSum + rightSum
}
```

### 5. Guard Against Invalid Input

```javascript
let factorial = n =>
    if(n < 0, error("Negative input"),
    if(n <= 1, 1, n * rec(n - 1)))
```

### 6. Consider Tail Recursion for Clarity

Even though not optimized, tail recursion can be clearer:

```javascript
// Clearer intent with accumulator
let factorial = n => (
    (current, acc) =>
        if(current <= 1, acc, rec(current - 1, acc * current))
)(n, 1)
```

## Summary

**Key Points**:
- Use `rec` for self-reference in lambda functions
- Recursion depth limited to ~50 calls
- Always include base case
- Test with increasing input sizes
- Prefer built-in functions when available

**Recursion Patterns**:
- Linear recursion: One call per invocation
- Multiple recursion: Multiple calls (e.g., Fibonacci)
- Tail recursion: Recursive call is last operation
- Accumulator pattern: Carry state through recursion

**Safe Patterns**:
- GCD, binary search (logarithmic depth)
- Small factorials (< 40)
- Balanced tree traversal (< 40 levels)

**When to Avoid Recursion**:
- Large ranges (use `linspace`)
- Array operations (use `map`, `filter`, `reduce`)
- Deep iterations (> 40 levels)
- Exponential branching without memoization

**Alternatives**:
- Built-in functions: `sum`, `map`, `filter`, `reduce`
- `linspace` for range generation
- Higher-order functions for transformations

---

**Next**: [Best Practices](23-best-practices.md)

**See Also**:
- [Functions and Lambdas](06-functions.md) - Basic recursion with `rec`
- [Do Blocks](21-do-blocks.md) - Recursion with do blocks
- [Performance Limitations](25-performance-limitations.md) - Detailed depth limits
- [Higher-Order Functions](11-higher-order-functions.md) - Alternatives to recursion
