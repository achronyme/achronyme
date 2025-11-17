---
title: "Generators"
description: "Lazy iterators with yield and generate blocks in Achronyme"
section: "advanced-topics"
order: 12
---


Generators are functions that can pause execution and yield multiple values over time, enabling lazy evaluation and memory-efficient processing of sequences.

## Basic Syntax

Generators are created using the `generate` keyword:

```achronyme
let myGenerator = () => generate {
    yield 1
    yield 2
    yield 3
}

let gen = myGenerator()
gen.next().value  // 1
gen.next().value  // 2
gen.next().value  // 3
```

## Generator Object

When a generator function is called, it returns a generator object with a `next()` method:

```achronyme
let counter = () => generate {
    yield "first"
    yield "second"
    yield "third"
}

let gen = counter()
let result1 = gen.next()  // {value: "first", done: false}
let result2 = gen.next()  // {value: "second", done: false}
let result3 = gen.next()  // {value: "third", done: false}
let result4 = gen.next()  // {value: null, done: true}
```

### next() Method

- Returns a record with `value` and `done` fields
- `value`: The yielded value
- `done`: Boolean indicating if the generator is exhausted

## yield Statement

The `yield` statement pauses the generator and returns a value:

```achronyme
let simpleGen = () => generate {
    yield 10
    // Execution pauses here
    yield 20
    // Execution pauses here
    yield 30
}
```

### yield in Control Flow

`yield` now works inside `while`, `if`, and `for` statements:

```achronyme
let range = (n) => generate {
    mut i = 0
    while(i < n) {
        yield i
        i += 1
    }
}

let gen = range(5)
gen.next().value  // 0
gen.next().value  // 1
gen.next().value  // 2
gen.next().value  // 3
gen.next().value  // 4
gen.next().done   // true
```

### yield in if Statements

```achronyme
let conditionalYield = (flag) => generate {
    yield "start"
    if(flag) {
        yield "flag is true"
    } else {
        yield "flag is false"
    }
    yield "end"
}

let gen1 = conditionalYield(true)
gen1.next().value  // "start"
gen1.next().value  // "flag is true"
gen1.next().value  // "end"
```

### yield in for Loops

```achronyme
let iterateArray = (arr) => generate {
    for(item in arr) {
        yield item * 2
    }
}

let gen = iterateArray([1, 2, 3])
gen.next().value  // 2
gen.next().value  // 4
gen.next().value  // 6
```

## Infinite Sequences

Generators excel at creating infinite sequences:

### Fibonacci Sequence

```achronyme
let fibonacci = () => generate {
    mut a = 0
    mut b = 1
    while(true) {
        yield a
        let temp = a
        a = b
        b = temp + b
    }
}

let fib = fibonacci()
fib.next().value  // 0
fib.next().value  // 1
fib.next().value  // 1
fib.next().value  // 2
fib.next().value  // 3
fib.next().value  // 5
fib.next().value  // 8
```

### Natural Numbers

```achronyme
let naturals = () => generate {
    mut n = 1
    while(true) {
        yield n
        n += 1
    }
}

let nums = naturals()
nums.next().value  // 1
nums.next().value  // 2
nums.next().value  // 3
// ... continues infinitely
```

### Powers of Two

```achronyme
let powersOfTwo = () => generate {
    mut n = 1
    while(true) {
        yield n
        n *= 2
    }
}

let powers = powersOfTwo()
powers.next().value  // 1
powers.next().value  // 2
powers.next().value  // 4
powers.next().value  // 8
```

## Practical Examples

### Range Generator

```achronyme
let range = (start, end, step = 1) => generate {
    mut i = start
    while(i < end) {
        yield i
        i += step
    }
}

// Use with for-in
mut sum = 0
for(i in range(0, 10, 2)) {
    sum += i
}
sum  // 20 (0 + 2 + 4 + 6 + 8)
```

### Filter Generator

```achronyme
let filterGen = (predicate, source) => generate {
    for(item in source) {
        if(predicate(item)) {
            yield item
        }
    }
}

let evens = filterGen(x => x % 2 == 0, range(0, 10))
for(n in evens) {
    // 0, 2, 4, 6, 8
}
```

### Map Generator

```achronyme
let mapGen = (transform, source) => generate {
    for(item in source) {
        yield transform(item)
    }
}

let squares = mapGen(x => x^2, range(1, 6))
for(sq in squares) {
    // 1, 4, 9, 16, 25
}
```

### Take First N

```achronyme
let take = (n, source) => {
    mut count = 0
    mut results = []
    for(item in source) {
        if(count >= n) { break }
        results = [...results, item]
        count += 1
    }
    results
}

let fib = fibonacci()
take(10, fib)  // [0, 1, 1, 2, 3, 5, 8, 13, 21, 34]
```

### Prime Number Generator

```achronyme
let primes = () => generate {
    let isPrime = (n) => {
        if(n < 2) { false }
        else {
            mut i = 2
            mut result = true
            while(i <= sqrt(n)) {
                if(n % i == 0) {
                    result = false
                    break
                }
                i += 1
            }
            result
        }
    }

    mut n = 2
    while(true) {
        if(isPrime(n)) {
            yield n
        }
        n += 1
    }
}

let p = primes()
p.next().value  // 2
p.next().value  // 3
p.next().value  // 5
p.next().value  // 7
p.next().value  // 11
```

## Generator Composition

Generators can be composed to create complex pipelines:

```achronyme
let pipeline = () => {
    // Generate numbers
    let nums = range(1, 100)

    // Filter evens
    let evens = filterGen(x => x % 2 == 0, nums)

    // Square them
    let squared = mapGen(x => x^2, evens)

    // Take first 5
    take(5, squared)
}

pipeline()  // [4, 16, 36, 64, 100]
```

## Using Generators with for-in

Generators integrate seamlessly with `for-in` loops:

```achronyme
let countdown = (n) => generate {
    while(n > 0) {
        yield n
        n -= 1
    }
    yield "Liftoff!"
}

for(step in countdown(3)) {
    // 3, 2, 1, "Liftoff!"
}
```

## State Management

Generators maintain their state between calls:

```achronyme
let statefulGen = () => generate {
    mut state = 0
    while(true) {
        state += 1
        yield state
    }
}

let gen = statefulGen()
gen.next().value  // 1
gen.next().value  // 2
// ... later
gen.next().value  // 3 (remembers state)
```

## Memory Efficiency

Generators are memory-efficient because they compute values on-demand:

```achronyme
// Memory-efficient: only one value at a time
let largeRange = range(0, 1000000)
for(i in largeRange) {
    if(i == 100) { break }  // Only generates 101 values
}

// vs. Eager evaluation (stores all values)
let allNumbers = linspace(0, 999999, 1000000)  // All in memory
```

## Common Patterns

### Cycle

```achronyme
let cycle = (arr) => generate {
    while(true) {
        for(item in arr) {
            yield item
        }
    }
}

let colors = cycle(["red", "green", "blue"])
colors.next().value  // "red"
colors.next().value  // "green"
colors.next().value  // "blue"
colors.next().value  // "red"
```

### Repeat

```achronyme
let repeat = (value, n) => generate {
    mut count = 0
    while(count < n) {
        yield value
        count += 1
    }
}

let zeros = repeat(0, 5)
for(z in zeros) {
    // 0, 0, 0, 0, 0
}
```

### Zip

```achronyme
let zip = (gen1, gen2) => generate {
    mut done = false
    while(!done) {
        let r1 = gen1.next()
        let r2 = gen2.next()
        if(r1.done || r2.done) {
            done = true
        } else {
            yield [r1.value, r2.value]
        }
    }
}

let nums = range(1, 4)
let letters = (() => generate {
    yield "a"
    yield "b"
    yield "c"
})()

let zipped = zip(nums, letters)
for(pair in zipped) {
    // [1, "a"], [2, "b"], [3, "c"]
}
```

## Best Practices

### 1. Use Generators for Large/Infinite Sequences

```achronyme
// Good - lazy evaluation
let infiniteSequence = () => generate {
    mut n = 0
    while(true) {
        yield n
        n += 1
    }
}

// Avoid - eager evaluation of large sequences
let largeArray = linspace(0, 1000000, 1000000)
```

### 2. Compose Small Generators

```achronyme
// Good - composable
let evens = filterGen(x => x % 2 == 0, range(0, 100))
let evenSquares = mapGen(x => x^2, evens)

// Avoid - monolithic generator
let evenSquaresDirect = () => generate {
    mut i = 0
    while(i < 100) {
        if(i % 2 == 0) {
            yield i^2
        }
        i += 1
    }
}
```

### 3. Use for-in for Consumption

```achronyme
// Good - clean iteration
for(value in myGenerator()) {
    process(value)
}

// Avoid - manual next() calls (unless needed)
let gen = myGenerator()
mut result = gen.next()
while(!result.done) {
    process(result.value)
    result = gen.next()
}
```

## Limitations

### Single Iteration

Generators can only be iterated once:

```achronyme
let gen = range(0, 3)

// First iteration works
for(i in gen) { /* 0, 1, 2 */ }

// Second iteration is empty (generator exhausted)
for(i in gen) { /* nothing */ }
```

To re-iterate, create a new generator:

```achronyme
for(i in range(0, 3)) { /* 0, 1, 2 */ }
for(i in range(0, 3)) { /* 0, 1, 2 again */ }
```

### No Return Value

Generators don't have a final return value; they just stop yielding:

```achronyme
let gen = () => generate {
    yield 1
    yield 2
    // No explicit return
}

let g = gen()
g.next()  // {value: 1, done: false}
g.next()  // {value: 2, done: false}
g.next()  // {value: null, done: true}
```

## Summary

- Generators create lazy, pausable sequences
- Use `generate { ... }` to define a generator
- Use `yield` to produce values
- `yield` works inside `while`, `if`, and `for` loops
- Call `.next()` to get next value as `{value, done}`
- Perfect for infinite sequences and memory-efficient processing
- Integrate with `for-in` loops for clean iteration
- Compose generators for powerful data pipelines

## See Also

- [Loop Control](39-loop-control.md) - break, continue, and for-in loops
- [While Loops](29-while-loops.md) - Basic iteration with while
- [Higher-Order Functions](11-higher-order-functions.md) - Functional alternatives (map, filter, reduce)
- [Mutability](26-mutability.md) - Using mutable state in generators
