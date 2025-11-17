---
title: "Higher-Order Functions"
description: "Map, filter, reduce, pipe and functional programming patterns in Achronyme"
section: "functional-programming"
order: 1
---


Higher-order functions (HOFs) are functions that take other functions as arguments or return functions as results. They are fundamental to functional programming and enable powerful data transformations.

## Overview

Achronyme provides higher-order functions for transformation, filtering, aggregation, and searching:

### Core HOFs

| Function | Purpose | Signature |
|----------|---------|-----------|
| `map` | Transform elements | `map(fn, coll, ...)` |
| `filter` | Select elements | `filter(pred, coll)` |
| `reduce` | Aggregate values | `reduce(fn, init, coll)` |
| `pipe` | Compose functions | `pipe(value, f1, f2, ...)` |

### Predicate HOFs (Tier 2)

| Function | Purpose | Returns |
|----------|---------|---------|
| `any` | Check if any element matches | Boolean |
| `all` | Check if all elements match | Boolean |
| `find` | Find first matching element | Element or Error |
| `findIndex` | Find index of first match | Number (-1 if not found) |
| `count` | Count matching elements | Number |

All HOFs work with:
- **Vectors** (heterogeneous arrays)
- **Tensors** (numerical arrays)
- **ComplexTensors** (complex number arrays)

## map - Transform Collections

Apply a function to each element of one or more collections.

### Basic Usage

```javascript
let numbers = [1, 2, 3, 4, 5]

// Square each element
map(x => x^2, numbers)
// [1, 4, 9, 16, 25]

// Double each element
map(x => x * 2, numbers)
// [2, 4, 6, 8, 10]

// Apply built-in function
map(sin, numbers)
// [sin(1), sin(2), sin(3), sin(4), sin(5)]
```

### Multi-Collection Mapping

Map over multiple collections simultaneously:

```javascript
let xs = [1, 2, 3]
let ys = [10, 20, 30]

// Add corresponding elements
map((x, y) => x + y, xs, ys)
// [11, 22, 33]

// Multiply corresponding elements
map((x, y) => x * y, xs, ys)
// [10, 40, 90]
```

### Automatic Truncation

When mapping over collections of different lengths, results are truncated to the shortest:

```javascript
let short = [1, 2]
let long = [10, 20, 30, 40]

map((x, y) => x + y, short, long)
// [11, 22]  (stops at length of shortest)
```

### Arity Checking

Function arity must match the number of collections:

```javascript
// ✅ Correct: unary function, one collection
map(x => x * 2, [1, 2, 3])

// ✅ Correct: binary function, two collections
map((x, y) => x + y, [1, 2], [3, 4])

// ❌ Error: binary function, one collection
// map((x, y) => x + y, [1, 2, 3])
```

### Practical Examples

```javascript
// Extract field from records
let users = [
    {name: "Alice", age: 30},
    {name: "Bob", age: 25}
]
map(user => user.name, users)
// ["Alice", "Bob"]

// Extract column from table
let table = [
    [1, "Alice", 30],
    [2, "Bob", 25]
]
map(row => row[2], table)
// [30, 25]

// Generate signal
let t = linspace(0, 1, 100)
let signal = map(x => sin(2 * 3.14159 * 50 * x), t)
```

## filter - Select Elements

Keep only elements that satisfy a predicate.

### Basic Usage

```javascript
let numbers = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

// Keep even numbers
filter(x => x % 2 == 0, numbers)
// [2, 4, 6, 8, 10]

// Keep numbers greater than 5
filter(x => x > 5, numbers)
// [6, 7, 8, 9, 10]

// Keep numbers in range
filter(x => x >= 3 && x <= 7, numbers)
// [3, 4, 5, 6, 7]
```

### Truthiness

Filter accepts both boolean and numeric predicates:

```javascript
let data = [0, 1, 2, 3, 4, 5]

// Boolean predicate
filter(x => x > 2, data)
// [3, 4, 5]

// Numeric predicate (0 = false, non-zero = true)
filter(x => x % 2, data)
// [1, 3, 5] (odd numbers have remainder 1)

// Zero is treated as false
filter(x => x, data)
// [1, 2, 3, 4, 5] (0 is filtered out)
```

### Practical Examples

```javascript
// Filter records by field
let employees = [
    [1, "Alice", "IT", 50000, true],
    [2, "Bob", "HR", 45000, false],
    [3, "Charlie", "IT", 55000, true]
]

// Active employees only
filter(emp => emp[4], employees)
// [[1, "Alice", "IT", 50000, true], [3, "Charlie", "IT", 55000, true]]

// IT department only
filter(emp => emp[2] == "IT", employees)
// [[1, "Alice", "IT", 50000, true], [3, "Charlie", "IT", 55000, true]]

// High earners
filter(emp => emp[3] > 48000, employees)
// [[1, "Alice", "IT", 50000, true], [3, "Charlie", "IT", 55000, true]]
```

### Combining with Map

```javascript
let data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

// Square numbers greater than 5
let result = map(
    x => x^2,
    filter(x => x > 5, data)
)
// [36, 49, 64, 81, 100]
```

## reduce - Aggregate Values

Reduce a collection to a single value by repeatedly applying a function.

### Basic Usage

```javascript
let numbers = [1, 2, 3, 4, 5]

// Sum
reduce((acc, x) => acc + x, 0, numbers)
// 15

// Product
reduce((acc, x) => acc * x, 1, numbers)
// 120

// Maximum
reduce((acc, x) => if(x > acc, x, acc), numbers[0], numbers)
// 5
```

### Accumulator Pattern

The function takes two arguments:
1. **Accumulator** (current aggregated value)
2. **Element** (current element being processed)

```javascript
// Execution trace for sum:
// reduce((acc, x) => acc + x, 0, [1, 2, 3])
// Step 1: acc=0, x=1  → 0+1 = 1
// Step 2: acc=1, x=2  → 1+2 = 3
// Step 3: acc=3, x=3  → 3+3 = 6
// Result: 6
```

### Type-Agnostic Accumulator

The accumulator can be any type:

```javascript
let numbers = [1, 2, 3, 4, 5]

// Build a vector
reduce((acc, x) => [...acc, x * 2], [], numbers)
// [2, 4, 6, 8, 10]

// Build a record
reduce(
    (acc, x) => {...acc, [x]: x^2},
    {},
    [1, 2, 3]
)
// {1: 1, 2: 4, 3: 9}

// Count occurrences
let words = ["a", "b", "a", "c", "b", "a"]
reduce(
    (acc, word) => {...acc, [word]: (acc[word] || 0) + 1},
    {},
    words
)
// {a: 3, b: 2, c: 1}
```

### Practical Examples

```javascript
// Calculate average
let avg = data => reduce((acc, x) => acc + x, 0, data) / length(data)

// Find min/max
let minimum = data => reduce(
    (acc, x) => if(x < acc, x, acc),
    data[0],
    data
)

// Concatenate strings
let words = ["Hello", " ", "World", "!"]
reduce((acc, s) => concat(acc, s), "", words)
// "Hello World!"

// Flatten array
let nested = [[1, 2], [3, 4], [5, 6]]
reduce((acc, arr) => [...acc, ...arr], [], nested)
// [1, 2, 3, 4, 5, 6]
```

### Map-Filter-Reduce Pipeline

Combine all three HOFs for complex data processing:

```javascript
let data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

// Sum of squares of even numbers
reduce(
    (acc, x) => acc + x,
    0,
    map(x => x^2, filter(x => x % 2 == 0, data))
)
// 2^2 + 4^2 + 6^2 + 8^2 + 10^2 = 220
```

## pipe - Function Composition

Apply functions left-to-right, threading the result through each function.

### Basic Usage

```javascript
// Syntax: pipe(initial_value, fn1, fn2, fn3, ...)
// Equivalent to: fn3(fn2(fn1(initial_value)))

pipe(
    5,
    x => x * 2,      // 5 * 2 = 10
    x => x + 10,     // 10 + 10 = 20
    x => x^2         // 20^2 = 400
)
// 400
```

### Data Processing Pipeline

```javascript
let data = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

pipe(
    data,
    v => filter(x => x % 2 == 0, v),    // Keep evens: [2,4,6,8,10]
    v => map(x => x^2, v),               // Square: [4,16,36,64,100]
    v => reduce((acc, x) => acc + x, 0, v)  // Sum: 220
)
// 220
```

### Transformation Chains

```javascript
// Process signal
let process_signal = signal => pipe(
    signal,
    s => map(x => x - mean(s), s),           // Remove DC offset
    s => map(x => x / std(s), s),            // Normalize
    s => fft(s)                              // Apply FFT
)

// Process text
let process_text = text => pipe(
    text,
    s => lowercase(s),
    s => split(s, " "),
    words => filter(w => length(w) > 3, words),
    words => length(words)
)
```

### Limitations

- All functions in the pipe must be **unary** (take exactly 1 argument)
- For multi-argument functions, use lambdas to adapt:

```javascript
// ❌ Won't work: add requires 2 arguments
// pipe(5, add(3))

// ✅ Works: wrap in lambda
pipe(5, x => x + 3)
```

## Predicate Functions (Tier 2)

These higher-order functions use predicates to search, test, and count elements in collections.

### any - Check if Any Element Matches

Returns `true` if at least one element satisfies the predicate. Short-circuits on first match.

**Signature:** `any(collection, predicate) -> Boolean`

```javascript
any([1, 2, 3, 4], x => x > 3)     // true (4 > 3)
any([1, 2, 3], x => x > 10)       // false
any([], x => x > 0)               // false (empty array)

// With range
any(range(1, 100), x => x == 50)  // true

// Complex predicates
any([1, 2, 3, 4, 5], x => x % 2 == 0 && x > 3)  // true (4 matches)
```

**Performance:** O(n) with short-circuit optimization - stops at first `true`.

### all - Check if All Elements Match

Returns `true` if all elements satisfy the predicate. Short-circuits on first failure.

**Signature:** `all(collection, predicate) -> Boolean`

```javascript
all([2, 4, 6, 8], x => x % 2 == 0)  // true (all even)
all([1, 2, 3], x => x > 0)          // true (all positive)
all([1, 2, 3], x => x > 2)          // false (1 and 2 fail)
all([], x => x > 0)                 // true (vacuous truth)

// Validate data
let data = [1.5, 2.3, 3.7, 4.2]
all(data, x => x > 0 && x < 10)     // true (all in range)
```

**Performance:** O(n) with short-circuit optimization - stops at first `false`.

### find - Find First Matching Element

Returns the first element that satisfies the predicate. Throws error if not found.

**Signature:** `find(collection, predicate) -> Element or Error`

```javascript
find([1, 2, 3, 4, 5], x => x > 3)   // 4 (first element > 3)
find([2, 4, 6], x => x % 2 == 0)    // 2 (first even, they all are)
find([1, 2, 3], x => x > 10)        // Error: "Element not found"

// Find in range
find(range(1, 100), x => x * x > 50)  // 8 (8² = 64 > 50)

// Find record
let users = [
    {name: "Alice", age: 30},
    {name: "Bob", age: 25}
]
find(users, u => u.age > 26)  // {name: "Alice", age: 30}
```

**Performance:** O(n) with short-circuit - stops at first match.

### findIndex - Find Index of First Match

Returns the 0-based index of the first matching element. Returns `-1` if not found.

**Signature:** `findIndex(collection, predicate) -> Number`

```javascript
findIndex([1, 2, 3, 4, 5], x => x > 3)  // 3 (index of 4)
findIndex([1, 2, 3], x => x > 10)       // -1 (not found)
findIndex([5, 4, 3, 2, 1], x => x == 5) // 0 (first element)
findIndex([1, 2, 3, 4, 5], x => x == 5) // 4 (last element)

// Use with indexing
let arr = [10, 20, 30, 40, 50]
let idx = findIndex(arr, x => x == 30)
arr[idx]  // 30
```

**Performance:** O(n) with short-circuit - stops at first match.

### count - Count Matching Elements

Counts how many elements satisfy the predicate.

**Signature:** `count(collection, predicate) -> Number`

```javascript
count([1, 2, 3, 4, 5], x => x > 2)     // 3 (elements: 3, 4, 5)
count([1, 2, 3], x => x > 10)          // 0
count(range(1, 11), x => x % 2 == 0)   // 5 (evens: 2,4,6,8,10)

// Count in range
count(range(1, 101), x => x % 3 == 0)  // 33 (multiples of 3)

// Complex conditions
let data = [1.5, 2.3, 3.7, 4.2, 5.1]
count(data, x => x > 2 && x < 5)       // 3 (2.3, 3.7, 4.2)
```

**Performance:** O(n) - always scans entire collection.

### Practical Examples with Predicates

#### Data Validation

```javascript
let data = [1.2, 3.4, 2.1, 4.5, 3.2]

// Check if all values are positive
all(data, x => x > 0)  // true

// Check if any value exceeds threshold
any(data, x => x > 4)  // true

// Count values in range
count(data, x => x >= 2 && x <= 4)  // 4
```

#### Finding in Collections

```javascript
let numbers = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

// Find first perfect square > 20
find(numbers, x => x * x > 20)  // 5 (5² = 25)

// Get index for slicing
let idx = findIndex(numbers, x => x > 5)
numbers[idx..]  // [6, 7, 8, 9, 10]
```

#### Combining Predicates with Other HOFs

```javascript
let data = range(1, 20)

// Filter evens, then check if any > 10
let evens = filter(x => x % 2 == 0, data)
any(evens, x => x > 10)  // true

// Count vs length
let nums = range(1, 11)
let even_count = count(nums, x => x % 2 == 0)
let total_len = len(nums)
even_count < total_len  // true
```

## Common Patterns

### Pattern 1: Extract-Transform-Aggregate

```javascript
let table = [
    [1, "Alice", 30, 50000],
    [2, "Bob", 25, 45000],
    [3, "Charlie", 35, 55000]
]

// Average salary
let avg_salary = reduce(
    (sum, row) => sum + row[3],
    0,
    table
) / length(table)
```

### Pattern 2: Custom Pipeline

```javascript
// Define pipeline as list of functions
let apply_pipeline = (funcs, value) =>
    reduce((acc, f) => f(acc), value, funcs)

// Use it
let pipeline = [
    x => x * 2,
    x => x + 10,
    x => x^2
]

apply_pipeline(pipeline, 5)  // 400
```

### Pattern 3: Partition

```javascript
// Split into two groups based on predicate
let partition = (pred, arr) => [
    filter(pred, arr),
    filter(x => !pred(x), arr)
]

partition(x => x % 2 == 0, [1, 2, 3, 4, 5, 6])
// [[2, 4, 6], [1, 3, 5]]
```

### Pattern 4: Zip (Using Map)

```javascript
// Combine two arrays into pairs
let zip = (xs, ys) => map((x, y) => [x, y], xs, ys)

zip([1, 2, 3], [10, 20, 30])
// [[1, 10], [2, 20], [3, 30]]
```

### Pattern 5: Group By

```javascript
// Group elements by key function
let group_by = (key_fn, arr) =>
    reduce(
        (acc, x) => {
            ...acc,
            [key_fn(x)]: [...(acc[key_fn(x)] || []), x]
        },
        {},
        arr
    )

// Example: group by first letter
group_by(s => s[0], ["apple", "apricot", "banana", "blueberry"])
// {a: ["apple", "apricot"], b: ["banana", "blueberry"]}
```

## Advanced Examples

### Composition Helpers

```javascript
// Function composition (right-to-left)
let compose = f => g => x => f(g(x))

let add1 = x => x + 1
let double = x => x * 2

let add1_then_double = compose(double)(add1)
add1_then_double(5)  // (5 + 1) * 2 = 12
```

### Currying

```javascript
// Manually curry a binary function
let add = x => y => x + y

let add5 = add(5)
add5(10)  // 15

// Use in map
map(add(10), [1, 2, 3, 4, 5])
// [11, 12, 13, 14, 15]
```

### Functional Data Processing

```javascript
// Process employee data
let employees = [
    {name: "Alice", dept: "IT", salary: 50000, active: true},
    {name: "Bob", dept: "HR", salary: 45000, active: false},
    {name: "Charlie", dept: "IT", salary: 55000, active: true}
]

// Average salary of active IT employees
pipe(
    employees,
    emps => filter(e => e.active, emps),
    emps => filter(e => e.dept == "IT", emps),
    emps => map(e => e.salary, emps),
    salaries => reduce((sum, s) => sum + s, 0, salaries) / length(salaries)
)
```

## Type Behavior

### Input Types

All HOFs accept these collection types:

```javascript
// Vector (heterogeneous)
map(x => x, [1, "hello", true])

// Tensor (homogeneous numbers)
map(x => x^2, [1, 2, 3, 4, 5])

// ComplexTensor
map(z => z^2, [1+2i, 3+4i])
```

### Output Types

```javascript
// map always returns Vector
map(x => x^2, [1, 2, 3])  // Vector

// filter always returns Vector
filter(x => x > 2, [1, 2, 3, 4, 5])  // Vector

// reduce returns any type
reduce((acc, x) => acc + x, 0, [1, 2, 3])  // Number
reduce((acc, x) => [...acc, x], [], [1, 2, 3])  // Vector

// pipe returns any type (depends on final function)
pipe(5, x => x * 2, x => x + 10)  // Number
```

## Performance Considerations

### Recursion Depth Limit

Due to environment cloning, avoid deep recursion in HOF callbacks:

```javascript
// ⚠️ Limited to ~50 recursive calls
let factorial = n =>
    if(n <= 1, 1, n * rec(n - 1))

map(factorial, [1, 2, 3, ..., 50])  // May overflow
```

### Prefer Built-ins

For large collections, use built-in functions when available:

```javascript
// ❌ Slower: manual reduce
reduce((acc, x) => acc + x, 0, large_array)

// ✅ Faster: built-in sum
sum(large_array)
```

### Chain Efficiency

```javascript
// ❌ Multiple passes
let result = reduce(
    (acc, x) => acc + x,
    0,
    map(x => x^2, filter(x => x > 5, data))
)

// ✅ Single pass with reduce (if applicable)
let result = reduce(
    (acc, x) => if(x > 5, acc + x^2, acc),
    0,
    data
)
```

## Summary

- **map**: Transform collections element-wise
  - Multi-collection support
  - Arity checking
  - Automatic truncation

- **filter**: Select elements by predicate
  - Boolean or numeric predicates
  - Flexible truthiness

- **reduce**: Aggregate to single value
  - Type-agnostic accumulator
  - Left-fold semantics

- **pipe**: Left-to-right composition
  - Unary functions only
  - Clear data flow

**Common patterns**:
- Map-filter-reduce pipelines
- Custom transformations
- Data aggregation
- Functional composition

**Best practices**:
- Use HOFs instead of manual loops
- Prefer built-ins for performance
- Chain operations for clarity
- Watch recursion depth limits

---

**Next**: [Mathematical Functions](12-mathematical-functions.md)

