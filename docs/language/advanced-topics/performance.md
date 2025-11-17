---
title: "Performance and Limitations"
description: "Performance characteristics and limitations of Achronyme"
section: "advanced-topics"
order: 3
---


This document describes current performance limitations in Achronyme and workarounds.

## Stack Overflow with Deep Recursion

### Problem

Achronyme currently has a **strict recursion depth limit of approximately 50-100 calls** before encountering stack overflow.

```javascript
// This WILL cause stack overflow:
let range = n => (
    (left, current, vector) =>
        if(left == 0, vector, rec(left - 1, current + 1, [...vector, current]))
)(n, 0, [])

range(5)    // ✅ Works: [0, 1, 2, 3, 4]
range(50)   // ❌ Stack overflow!
```

### Why This Happens

Each recursive call with `rec` involves:

1. **Environment Cloning**: The entire evaluation environment is cloned (all variables)
2. **Function Cloning**: The function itself is cloned to bind to `rec`
3. **Scope Management**: New scopes are pushed and popped
4. **Vector Growth**: With patterns like `[...vector, element]`, progressively larger vectors are created
5. **Stack Frames**: Each recursion creates a new Rust stack frame

**Example with `range(50)`:**
- Call 1: Creates `[0]`
- Call 2: Creates `[0, 1]`
- Call 3: Creates `[0, 1, 2]`
- ...
- Call 50: Creates `[0, 1, 2, ..., 49]`

At depth 50, you have:
- 50 nested stack frames
- 50 cloned environments
- 50 cloned functions
- Intermediate vectors totaling ~1,275 elements (sum of 1+2+3+...+50)

This quickly exhausts Rust's default **2MB stack size**.

### Root Cause

The implementation in `crates/achronyme-eval/src/handlers/functions.rs` (line 32-107) clones the environment and function on every recursive call:

```rust
// Line 51: Clone entire environment
let saved_env = evaluator.environment().clone();

// Line 58: Clone closure environment
*evaluator.environment_mut() = (**closure_env).clone();

// Line 62: Clone and bind 'rec'
evaluator.environment_mut().define("rec".to_string(), Value::Function(function.clone()))?;
```

This is necessary for correctness (proper scoping and closure capture) but has performance implications.

## Workarounds

### 1. Use Built-in Functions

When available, use built-in functions instead of recursion:

```javascript
// ❌ Don't use recursive range for large n
let range = n => (
    (left, current, vector) =>
        if(left == 0, vector, rec(left - 1, current + 1, [...vector, current]))
)(n, 0, [])

// ✅ Use built-in linspace instead
let range = n => linspace(0, n - 1, n)

range(100)   // ✅ Works!
range(1000)  // ✅ Works!
```

### 2. Limit Recursion Depth

Keep recursive calls under **~40-50** for safety:

```javascript
// Safe: Small recursion depth
let factorial = n =>
    if(n <= 1, 1, n * rec(n - 1))

factorial(10)   // ✅ Safe
factorial(20)   // ✅ Safe
factorial(50)   // ❌ Stack overflow risk
```

### 3. Use Iteration Over Recursion

When possible, express problems using higher-order functions instead of recursion:

```javascript
// ❌ Recursive sum (limited depth)
let sum_recursive = arr => (
    (remaining, acc) =>
        if(remaining[0] == remaining[-1],
           acc + remaining[0],
           rec(remaining[1..], acc + remaining[0]))
)(arr, 0)

// ✅ Use built-in reduce (handles any size)
let sum_iterative = arr => reduce((acc, x) => acc + x, 0, arr)

sum_iterative([1, 2, 3, ..., 100])  // ✅ Works!
```

### 4. Break Large Problems into Chunks

Instead of one deep recursion, process in smaller batches:

```javascript
// Process 10 elements at a time
let process_batch = (data, batch_size) => (
    // ... implementation using smaller recursive depth
)
```

## Performance Comparison

| Approach | Max Size | Performance | Stack Safety |
|----------|----------|-------------|--------------|
| Deep recursion | ~50 | Fast for small n | ❌ Unsafe |
| Built-in functions | Unlimited | Very fast | ✅ Safe |
| Higher-order (map/reduce) | Unlimited | Fast | ✅ Safe |
| Chunked processing | Unlimited | Moderate | ✅ Safe |

## Affected Patterns

These recursive patterns are **limited to ~50 iterations**:

### Range Generation
```javascript
let range = n => (
    (left, current, vector) =>
        if(left == 0, vector, rec(left - 1, current + 1, [...vector, current]))
)(n, 0, [])

// ✅ Use instead: linspace(0, n-1, n)
```

### Repeat/Fill
```javascript
let zeros = n => (
    (left, vector) =>
        if(left == 0, vector, rec(left - 1, [0, ...vector]))
)(n, [])

// ✅ Use instead: map(_ => 0, linspace(0, n-1, n))
```

### Factorial with Accumulator
```javascript
let factorial_acc = n => (
    (current, acc) =>
        if(current <= 1, acc, rec(current - 1, acc * current))
)(n, 1)

// ⚠️ Limited to n < 50
```

### Fibonacci
```javascript
let fibonacci = n =>
    if(n <= 1, n, rec(n - 1) + rec(n - 2))

// ⚠️ Limited to n < 50
// Note: Also exponentially slow without memoization
```

## Safe Recursive Patterns

These patterns are safe because they have naturally small depth:

### Tree Traversal (Limited Depth)
```javascript
let tree_depth = node =>
    if(node.left == undefined && node.right == undefined,
       1,
       1 + max([
           if(node.left == undefined, 0, rec(node.left)),
           if(node.right == undefined, 0, rec(node.right))
       ]))

// ✅ Safe for balanced trees with depth < 50
```

### GCD (Euclidean Algorithm)
```javascript
let gcd = (a, b) => (
    (x, y) => if(y == 0, x, rec(y, x % y))
)(a, b)

// ✅ Safe - typically terminates in < 20 iterations
gcd(48, 18)   // 6
gcd(1000, 35) // 5
```

### Small Factorials
```javascript
let factorial = n =>
    if(n <= 1, 1, n * rec(n - 1))

// ✅ Safe for n < 40
factorial(10)  // 3628800
```

## Future Improvements

Potential optimizations being considered:

1. **Tail Call Optimization**: Detect tail-recursive patterns and optimize them
2. **Iterative Lowering**: Compile certain recursive patterns to loops
3. **Lazy Evaluation**: Delay vector construction until needed
4. **Stack Size Increase**: Configure larger stack size for Rust runtime
5. **Reference Counting**: Reduce cloning by using Rc/Arc more aggressively

## Best Practices

1. ✅ **Prefer built-in functions** over recursion when available
2. ✅ **Test with realistic data sizes** - don't assume recursion scales
3. ✅ **Keep recursion depth < 40** for safety margin
4. ✅ **Use `map`, `reduce`, `filter`** instead of manual recursion
5. ⚠️ **Avoid recursive patterns with vector growth** (like `[...acc, elem]`)
6. ⚠️ **Profile before optimizing** - measure actual performance

## Testing Recursion Limits

To test if your recursive function will work:

```javascript
// Test with small input first
let test = my_recursive_fn(5)    // ✅ Works

// Gradually increase
let test = my_recursive_fn(10)   // ✅ Works
let test = my_recursive_fn(20)   // ✅ Works
let test = my_recursive_fn(40)   // ⚠️ Check carefully
let test = my_recursive_fn(50)   // ❌ Likely overflow
```

## Summary

- **Current limit**: ~50 recursive calls
- **Root cause**: Environment/function cloning on each `rec` call
- **Workaround**: Use built-in functions and higher-order functions
- **Safe patterns**: GCD, small factorials, shallow tree traversal
- **Unsafe patterns**: Large ranges, deep recursion, recursive vector building

---

**See Also**:
- [Functions and Lambdas](06-functions.md) - Recursion basics
- [Higher-Order Functions](11-higher-order-functions.md) - Alternatives to recursion
- [Advanced Recursion Patterns](../examples/soc/37-advanced-recursion-patterns.soc) - Examples

