# While Loops

While loops allow you to execute a block of code repeatedly while a condition is true.

## Syntax

```achronyme
while(condition) {
    // body
}
```

## Behavior

- **Condition**: Evaluated before each iteration. Must evaluate to a boolean or number (0 = false, non-zero = true)
- **Body**: Executed repeatedly while condition is true
- **Return Value**: The value of the last iteration, or `0` if the loop never executed
- **Early Exit**: Use `return` statement to exit early from within the loop

## Basic Examples

### Simple Counter

```achronyme
mut i = 0
while(i < 5) {
    i = i + 1
}
i  // 5
```

### Sum Calculation

```achronyme
mut i = 1
mut sum = 0
while(i <= 10) {
    sum = sum + i
    i = i + 1
}
sum  // 55 (1+2+...+10)
```

### Factorial

```achronyme
mut n = 5
mut result = 1
while(n > 0) {
    result = result * n
    n = n - 1
}
result  // 120 (5!)
```

## Return Value Behavior

The while loop returns the value of its last iteration:

```achronyme
mut i = 0
while(i < 3) {
    i = i + 1
    i * 10
}
// Returns: 30 (last iteration: 3 * 10)
```

If the loop never executes, it returns `0`:

```achronyme
while(false) {
    42
}
// Returns: 0
```

## Comparison Operators

While loops support all comparison operators:

```achronyme
mut x = 10
while(x > 0) {
    x = x - 2
}
x  // 0
```

```achronyme
mut x = 1
while(x != 10) {
    x = x + 1
}
x  // 10
```

## Logical Operators

Use `&&` (and) and `||` (or) for complex conditions:

```achronyme
mut x = 0
mut y = 0
while(x < 5 && y < 3) {
    x = x + 1
    y = y + 1
}
x  // 3 (stops when y reaches 3)
```

## Nested While Loops

While loops can be nested:

```achronyme
mut i = 0
mut sum = 0
while(i < 3) {
    mut j = 0
    while(j < 2) {
        sum = sum + 1
        j = j + 1
    }
    i = i + 1
}
sum  // 6 (3 * 2 iterations)
```

## Early Return

Use `return` to exit early from a while loop inside a function:

```achronyme
let find = (target) => do {
    mut i = 0
    while(i < 10) {
        if(i == target) {
            return i
        }
        i = i + 1
    }
    -1  // Not found
}

find(5)   // 5
find(15)  // -1
```

### break Statement

Use `break` to exit a loop immediately:

```achronyme
mut i = 0
while(i < 100) {
    if(i == 10) { break }
    i += 1
}
i  // 10
```

`break` can also return a value:

```achronyme
let result = while(true) {
    let x = calculateSomething()
    if(x > 100) { break x }
}
```

### continue Statement

Use `continue` to skip to the next iteration:

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

See **[Loop Control](39-loop-control.md)** for comprehensive documentation on `break` and `continue`.

### Early Return Pattern

Use `return` to exit early from a while loop inside a function:

```achronyme
let process = () => do {
    mut i = 0
    while(true) {
        i = i + 1
        if(i >= 5) {
            return i
        }
    }
}
process()  // 5
```

## While Loops in Functions

While loops work naturally in lambda functions:

```achronyme
let countdown = (n) => do {
    mut i = n
    while(i > 0) {
        i = i - 1
    }
    i
}
countdown(5)  // 0
```

```achronyme
let sumUpTo = (n) => do {
    mut i = 1
    mut sum = 0
    while(i <= n) {
        sum = sum + i
        i = i + 1
    }
    sum
}
sumUpTo(100)  // 5050
```

## Common Patterns

### Fibonacci Sequence

```achronyme
let fibonacci = (n) => do {
    mut a = 0
    mut b = 1
    mut i = 0
    while(i < n) {
        let temp = a + b
        a = b
        b = temp
        i = i + 1
    }
    a
}
fibonacci(7)  // 13
```

### Power Calculation

```achronyme
let power = (base, exp) => do {
    mut result = 1
    mut i = 0
    while(i < exp) {
        result = result * base
        i = i + 1
    }
    result
}
power(2, 8)  // 256
```

### Search with Early Exit

```achronyme
let findFirst = (predicate, arr) => do {
    mut i = 0
    while(i < 10) {
        if(predicate(arr[i])) {
            return arr[i]
        }
        i = i + 1
    }
    -1
}

let isEven = x => x % 2 == 0
findFirst(isEven, [1, 3, 4, 5, 7])  // 4
```

## Important Notes

### Mutable Variables Required

While loops typically require mutable variables for the loop counter and accumulator:

```achronyme
mut i = 0        // Mutable counter
mut sum = 0      // Mutable accumulator
while(i < 5) {
    sum = sum + i
    i = i + 1
}
```

### Infinite Loops

Be careful to ensure the condition eventually becomes false, or use `return` to exit:

```achronyme
// ⚠️ INFINITE LOOP - will hang!
while(true) {
    // No exit condition
}

// ✅ SAFE - has exit condition
let process = () => do {
    while(true) {
        if(shouldExit) {
            return result
        }
    }
}
```

### Condition Re-evaluation

The condition is re-evaluated before **every** iteration:

```achronyme
let isValid = (n) => n < 10

mut x = 0
while(isValid(x)) {  // Function called each iteration
    x = x + 1
}
x  // 10
```

## Differences from Other Constructs

### While vs If

- `if`: Executes body **at most once**
- `while`: Executes body **zero or more times**

### While vs Recursion

Before generators are implemented, `while` loops are the primary iteration construct:

```achronyme
// Using while loop
let factorial = (n) => do {
    mut result = 1
    mut i = n
    while(i > 0) {
        result = result * i
        i = i - 1
    }
    result
}

// Using recursion (with rec)
let factorial = (n) => do {
    if(n <= 1) {
        return 1
    }
    n * rec(n - 1)
}
```

Both approaches work, but `while` avoids stack overflow for large values.

## Related Features

Achronyme now supports comprehensive loop control:

- **`break` statement**: Exit loop immediately with optional value
- **`continue` statement**: Skip to next iteration
- **`for-in` loops**: Iterate over collections (Vectors, Tensors, Generators)
- **Generators**: Lazy evaluation with `yield`

See:
- **[Loop Control](39-loop-control.md)** - Comprehensive break/continue/for-in documentation
- **[Generators](38-generators.md)** - Creating lazy sequences with yield

## See Also

- [Control Flow](08-control-flow.md) - Overview of if, while, and other constructs
- [Do Blocks](21-do-blocks.md) - Block expressions for multi-statement lambdas
- [Mutable Variables](26-mutability.md) - Using `mut` for loop counters
- [Loop Control](39-loop-control.md) - break, continue, and for-in loops
- [Generators](38-generators.md) - Lazy iterators with yield
