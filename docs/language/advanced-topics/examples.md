---
title: "Examples"
description: "Complete programs and use cases in Achronyme"
section: "advanced-topics"
order: 2
---


This document contains complete, practical examples demonstrating various features of Achronyme.

## Table of Contents

1. [Basic Calculations](#basic-calculations)
2. [Data Processing](#data-processing)
3. [Signal Processing](#signal-processing)
4. [Numerical Analysis](#numerical-analysis)
5. [Object-Oriented Patterns](#object-oriented-patterns)
6. [Graph Algorithms](#graph-algorithms)
7. [Functional Programming](#functional-programming)

## Basic Calculations

### Statistical Analysis

```javascript
// Calculate statistics for a dataset
let data = [23, 45, 67, 12, 89, 34, 56, 78, 90, 23]

let analysis = {
    count: 10,
    total: sum(data),
    average: mean(data),
    spread: std(data),
    range: () => max(data) - min(data)
}

analysis
```

### Compound Interest

```javascript
// Calculate compound interest
let principal = 1000
let rate = 0.05        // 5% annual
let years = 10
let frequency = 12     // Monthly compounding

let calculateFuture = (p, r, t, n) =>
    p * (1 + r/n)^(n*t)

let future = calculateFuture(principal, rate, years, frequency)

// Result
{
    principal: principal,
    rate: rate,
    years: years,
    future: future,
    interest: future - principal
}
```

### Fibonacci Sequence

```javascript
// Generate Fibonacci numbers
let fibonacci = n =>
    if(n <= 1, n, rec(n-1) + rec(n-2))

// Generate first 10 Fibonacci numbers
let range = linspace(0, 9, 10)
map(fibonacci, range)
// [0, 1, 1, 2, 3, 5, 8, 13, 21, 34]
```

## Data Processing

### Heterogeneous Data Collections

```javascript
// Mixed-type data row (like CSV or database record)
let user = [
    1,                      // ID
    "Alice Smith",          // Name
    "alice@example.com",    // Email
    30,                     // Age
    true,                   // Active
    {role: "admin", dept: "IT"}  // Metadata
]

// Access fields by index
user[0]            // 1
user[1]            // "Alice Smith"
user[5].role       // "admin"

// Collection of mixed operations
let processors = [
    x => x * 2,              // Double
    x => x + 10,             // Add 10
    x => x^2,                // Square
    x => if(x > 0, x, -x)    // Absolute value
]

// Apply different processors
processors[0](5)   // 10
processors[2](5)   // 25
processors[3](-5)  // 5

// Data with different types per field
let records = [
    [1, "Product A", 99.99, true],
    [2, "Product B", 149.50, false],
    [3, "Product C", 79.99, true]
]

// Access: records[row][column]
records[0][1]      // "Product A"
records[1][2]      // 149.50
records[2][3]      // true
```

### Normalize Data (Z-Score)

```javascript
// Normalize data to mean=0, std=1
let raw_data = [1.2, 3.4, 2.1, 4.5, 3.2, 2.8, 3.9]

let normalize = data => (
    params => map(x => (x - params[0]) / params[1], data)
)([mean(data), std(data)])

let normalized = normalize(raw_data)
normalized
```

### Moving Average

```javascript
// Calculate simple moving average (simplified)
let prices = [100, 102, 98, 105, 103, 107, 110]

// For now, just show the mean
let simple_average = mean(prices)
simple_average  // 103.57...
```

### Filter and Transform

```javascript
// Complex data pipeline
let numbers = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

let result = pipe(
    numbers,                                   // Start with data
    x => filter(n => n % 2 == 0, x),          // Keep evens
    x => map(n => n^2, x),                     // Square them
    x => reduce((acc, n) => acc + n, 0, x)    // Sum
)

result  // 220 (2^2 + 4^2 + 6^2 + 8^2 + 10^2)
```

## Signal Processing

### FFT Analysis

```javascript
// Generate and analyze a signal
let sampleRate = 1000
let duration = 1
let n = sampleRate * duration

// Generate time vector
let t = linspace(0, duration, n)

// Create signal: 50Hz + 120Hz
let signal = map(x =>
    sin(2 * 3.14159 * 50 * x) +
    0.5 * sin(2 * 3.14159 * 120 * x),
    t
)

// Analyze with FFT
let spectrum = fft(signal)
let magnitude = fft_mag(signal)
let phase = fft_phase(signal)

{
    signal: signal,
    spectrum: spectrum,
    magnitude: magnitude
}
```

### Convolution and Filtering

```javascript
// Apply a simple moving average filter
let signal = [1, 2, 3, 4, 5, 4, 3, 2, 1]
let kernel = [0.25, 0.5, 0.25]  // Averaging kernel

let filtered = conv(signal, kernel)
filtered
```

### Window Functions

```javascript
// Create different window functions
let n = 64

let windows = {
    rectangular: rectangular(n),
    hanning: hanning(n),
    hamming: hamming(n),
    blackman: blackman(n)
}

windows
```

## Numerical Analysis

### Differentiation

```javascript
// Find derivative of a function
let f = x => x^3 - 2*x^2 + x - 5

// Derivative at x = 2
let df = diff(f)
let slope = df(2)

{
    function: "x^3 - 2x^2 + x - 5",
    derivative_at_2: slope
}
```

### Integration

```javascript
// Calculate definite integral
let f = x => x^2

// Area under curve from 0 to 10
let area = integral(f, 0, 10)

// Different methods
let trapezoid = trapz(f, 0, 10)
let simpsons = simpson(f, 0, 10)

{
    function: "x^2",
    integral_0_to_10: area,
    trapezoid: trapezoid,
    simpson: simpsons
}
```

### Root Finding

```javascript
// Find root of equation
let f = x => x^2 - 2  // Find sqrt(2)

let root = solve(f, 1, 2)

{
    function: "x^2 - 2",
    root: root,
    verification: f(root)  // Should be ~0
}
```

## Object-Oriented Patterns

### Point Class

```javascript
// Point with methods
let Point = {
    // Constructor
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

// Create and use points
let p1 = Point.new(3, 4)
let p2 = Point.new(1, 2)

let p3 = p1.add(p2)  // (4, 6)
let dist = p1.distance()  // 5

{
    p1: p1,
    p2: p2,
    p3: p3,
    distance: dist
}
```

### Shape Hierarchy

```javascript
// Base shape
let Shape = {
    type: "shape",
    describe: () => concat("A ", self.type)
}

// Circle
let Circle = {
    ...Shape,
    type: "circle",
    radius: 5,
    area: () => 3.14159 * self.radius^2,
    perimeter: () => 2 * 3.14159 * self.radius
}

// Rectangle
let Rectangle = {
    ...Shape,
    type: "rectangle",
    width: 10,
    height: 20,
    area: () => self.width * self.height,
    perimeter: () => 2 * (self.width + self.height)
}

// Use them
let shapes = [Circle, Rectangle]
map(s => s.area(), shapes)
```

### Builder Pattern

```javascript
// Query builder
let Query = {
    table: "",
    columns: [],
    conditions: [],

    from: t => {...self, table: t},

    select: cols => {...self, columns: cols},

    where: cond => {
        ...self,
        conditions: [...self.conditions, cond]
    },

    build: () => concat("SELECT ", concat(join(self.columns, ", "), concat(" FROM ", self.table)))
}

// Build a query
let query = Query
    .from("users")
    .select(["id", "name", "email"])
    .where("age > 18")
    .where("active = true")

query.build()
```

## Graph Algorithms

### Simple Graph

```javascript
// Create a simple graph
let edges = [
    A -> B,
    B -> C,
    C -> D,
    D -> A,
    A -> C
]

let g = network(edges)

// Analyze
let nodeList = nodes(g)
let edgeList = edges(g)

// Algorithms
let bfsResult = bfs(g, "A")
let path = bfs_path(g, "A", "D")

{
    nodes: nodeList,
    bfs: bfsResult,
    path: path
}
```

### Weighted Graph (Shortest Path)

```javascript
// Weighted graph
let edges = [
    A -> B : {weight: 5},
    A -> C : {weight: 3},
    B -> D : {weight: 2},
    C -> D : {weight: 6},
    C -> E : {weight: 4},
    D -> E : {weight: 1}
]

let g = network(edges)

// Find shortest path
let path = dijkstra(g, "A", "E")

path
```

## Functional Programming

### Function Composition

```javascript
// Compose multiple operations
let double = x => x * 2
let square = x => x^2
let addTen = x => x + 10

let composed = x => pipe(
    x,
    double,
    square,
    addTen
)

composed(3)  // ((3*2)^2)+10 = 46
```

### Currying

```javascript
// Curry a function
let multiply = a => b => a * b

let double = multiply(2)
let triple = multiply(3)

double(5)  // 10
triple(5)  // 15
```

### Map, Filter, Reduce

```javascript
// Complex data transformation
let numbers = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

// Sum of squares of even numbers
let result = reduce(
    (acc, x) => acc + x,
    0,
    map(
        x => x^2,
        filter(x => x % 2 == 0, numbers)
    )
)

result  // 220
```

### Recursive Patterns

```javascript
// Tree traversal (simulated with records)
let tree = {
    value: 1,
    left: {
        value: 2,
        left: {value: 4},
        right: {value: 5}
    },
    right: {
        value: 3,
        left: {value: 6},
        right: {value: 7}
    }
}

// Would need proper tree traversal implementation
// This is a simplified example
tree.value  // 1
```

## Advanced Examples

### Monte Carlo Simulation

```javascript
// Placeholder for Monte Carlo π estimation
// (Would require random number generation)
let pi_approx = 3.14159
pi_approx
```

### Matrix Operations

```javascript
// Matrix computations
let A = [[1, 2], [3, 4]]
let B = [[5, 6], [7, 8]]

let operations = {
    transpose_A: transpose(A),
    determinant_A: det(A),
    dot_product: dot([1, 2, 3], [4, 5, 6])
}

operations
```

### Time Series Analysis

```javascript
// Analyze time series data
let data = [100, 102, 98, 105, 103, 107, 110, 108, 112]

let analysis = {
    mean: mean(data),
    std: std(data),
    trend: "increasing",  // Would calculate
    volatility: std(data) / mean(data)
}

analysis
```

## Summary

These examples demonstrate:
- ✅ Basic to advanced computations
- ✅ Data processing pipelines
- ✅ Heterogeneous collections (mixed-type arrays)
- ✅ Signal processing workflows
- ✅ Numerical methods
- ✅ OOP patterns with records
- ✅ Graph algorithms
- ✅ Functional programming
- ✅ Real-world applications

All examples are runnable in Achronyme and can be used as starting points for your own programs.

---

**See Also**: [Best Practices](23-best-practices.md) for code style guidelines.
