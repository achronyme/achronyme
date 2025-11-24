---
title: "Performance and Limitations"
description: "Performance characteristics and limitations of the Achronyme VM"
section: "advanced-topics"
order: 3
---

This document describes performance characteristics and known limitations of the Achronyme Virtual Machine (VM).

## Recursion Depth

### Current Status

Achronyme uses a register-based Virtual Machine with a fixed-size call stack. While significantly more efficient than previous tree-walker implementations, deep recursion is still limited by the VM's stack size configuration.

```javascript
// Deep recursion may eventually hit the stack limit
let factorial = n =>
    if(n <= 1, 1, n * rec(n - 1))

factorial(1000)   // May trigger a stack overflow error depending on VM settings
```

### Best Practices

1.  **Prefer Iteration**: Use `while` loops or `for-in` loops for deep iterations. They operate within a single stack frame and are much faster.
    ```javascript
    // Efficient iterative factorial
    let factorial = n => do {
        mut acc = 1
        mut i = n
        while (i > 0) {
            acc *= i
            i -= 1
        }
        acc
    }
    ```

2.  **Use Built-in Functions**: Built-ins like `sum`, `map`, `reduce`, and `linspace` are implemented in Rust and are highly optimized, avoiding VM overhead entirely.
    ```javascript
    // ❌ Slow and stack-heavy
    let sum_rec = arr => if(len(arr) == 0, 0, arr[0] + rec(arr[1..]))

    // ✅ Fast and constant memory
    let sum_fast = arr => sum(arr)
    ```

## Memory Management

### Reference Counting

Achronyme uses Reference Counting (RC) for complex types (Vectors, Records, Strings). This means:
*   **Deterministic Cleanup**: Memory is freed as soon as the last reference is dropped.
*   **Copy-on-Write (Optimization)**: Cloning a value typically just increments a counter. Deep copies only happen when mutating a shared value (if explicitly requested or required).

### Circular References

Because of Reference Counting, **circular references** (e.g., two records referencing each other) can lead to memory leaks as their reference counts never reach zero.

```javascript
// ⚠️ Potential Memory Leak
let a = { name: "A" }
let b = { name: "B" }
a.friend = b
b.friend = a  // Cycle created
```

The VM does not currently have a cycle garbage collector. Avoid circular data structures when possible.

## Numerical Performance

### Tensors vs Vectors

*   **Tensors**: Homogeneous numerical arrays. Operations are vectorized and highly efficient.
*   **Vectors**: Heterogeneous arrays. Operations require boxing/unboxing and dynamic type checking per element.

**Recommendation**: Always use Tensors (arrays of pure numbers) for mathematical computations.

```javascript
// ✅ Fast (Tensor)
let data = [1.0, 2.0, 3.0, 4.0]
let result = data * 2.0

// ⚠️ Slower (Vector)
let mixed = [1.0, "label", 3.0]
// Operations here involve more overhead
```

## VM Architecture

Achronyme runs on a **Register-Based VM**, similar to Lua 5.0.
*   **Registers**: Local variables are stored in a virtual register window, minimizing stack manipulation overhead.
*   **Bytecode**: Source code is compiled to compact bytecode before execution.
*   **Dispatch**: Efficient instruction dispatch loop.

This architecture provides significantly better performance than AST interpreters, but still incurs interpretation overhead compared to native code.

## Summary

*   **Recursion**: Limited by stack size; prefer loops.
*   **Memory**: Ref-counted; avoid cycles.
*   **Math**: Use Tensors and built-ins for near-native speed.
*   **Loops**: `for-in` and `while` are optimized.