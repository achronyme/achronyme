---
title: "Modules"
description: "Import/export system and code organization in Achronyme"
section: "advanced-topics"
order: 6
---


The Achronyme module system allows you to organize code into reusable modules, import functionality from built-in modules, and create your own user-defined modules.

## Table of Contents

- [Overview](#overview)
- [Built-in Modules](#built-in-modules)
- [Import Statement](#import-statement)
- [Export Statement](#export-statement)
- [User-Defined Modules](#user-defined-modules)
- [Module Resolution](#module-resolution)
- [Best Practices](#best-practices)
- [Examples](#examples)

## Overview

The module system in Achronyme provides:

1. **Built-in modules**: Pre-defined modules with mathematical, statistical, and utility functions
2. **User-defined modules**: Create your own reusable modules with `export`
3. **Selective imports**: Import only what you need from a module
4. **Import aliases**: Rename imports to avoid naming conflicts
5. **Relative paths**: Modules are resolved relative to the importing file

## Built-in Modules

Achronyme provides several built-in modules:

| Module | Description | Example Functions |
|--------|-------------|-------------------|
| `stats` | Statistical functions | `mean`, `std`, `variance`, `median` |
| `math` | Advanced math functions | `sin`, `cos`, `exp`, `log`, `asin`, `sinh` |
| `linalg` | Linear algebra operations | `dot`, `cross`, `norm`, `normalize` |
| `prelude` | Always available (no import needed) | `map`, `filter`, `reduce`, `len`, `sum` |

### Prelude Functions

The `prelude` module is special—its functions are **always available** without importing:

```javascript
// These work without any imports
let data = [1, 2, 3, 4, 5]
let doubled = map(x => x * 2, data)
let total = sum(data)
let count = len(data)
```

## Import Statement

The `import` statement brings functionality from modules into your code.

### Basic Import

```javascript
import { mean, std } from "stats"

let data = [10, 20, 30, 40, 50]
let average = mean(data)
let stdDev = std(data)
```

### Multiple Imports

```javascript
import { mean, std, variance, median } from "stats"
```

### Import with Alias

Use `as` to rename an imported function:

```javascript
import { mean as average, std as standardDeviation } from "stats"

let data = [1, 2, 3, 4, 5]
let avg = average(data)  // Uses the alias
let sd = standardDeviation(data)
```

### Import from Multiple Modules

```javascript
import { mean, std } from "stats"
import { sin, cos, exp } from "math"
import { dot, norm } from "linalg"

let data = [1, 2, 3]
let avg = mean(data)
let magnitude = norm(data)
```

## Export Statement

The `export` statement makes values available for import in other modules.

### Basic Export

```javascript
// math_utils.soc
let double = x => x * 2
let triple = x => x * 3
let square = x => x * x

export { double, triple, square }
```

### Export with Computed Values

```javascript
// constants.soc
let pi = 3.141592653589793
let e = 2.718281828459045
let goldenRatio = 1.618033988749895

export { pi, e, goldenRatio }
```

### Export Functions with Dependencies

You can export functions that use other imported functions:

```javascript
// statistics.soc
import { mean, std } from "stats"

let coefficientOfVariation = data => do {
    let m = mean(data);
    let s = std(data);
    (s / m) * 100
}

let zscore = (data, value) => do {
    let m = mean(data);
    let s = std(data);
    (value - m) / s
}

export { coefficientOfVariation, zscore }
```

### What Can Be Exported?

You can export:
- ✅ Functions (lambdas)
- ✅ Numbers
- ✅ Strings
- ✅ Vectors
- ✅ Records
- ✅ Any computed value

```javascript
// exports_example.soc
let myFunction = x => x * 2
let myNumber = 42
let myString = "Hello"
let myVector = [1, 2, 3]
let myRecord = { name: "Achronyme", version: 1 }

export { myFunction, myNumber, myString, myVector, myRecord }
```

## User-Defined Modules

Create reusable modules by combining functions and exporting them.

### Example: Math Utilities Module

```javascript
// src/math_utils.soc
let double = x => x * 2
let triple = x => x * 3
let square = x => x * x
let cube = x => x * x * x

// Private helper (not exported)
let privateHelper = x => x + 1

export { double, triple, square, cube }
```

### Example: Data Processing Module

```javascript
// src/data_processing.soc
import { mean, std } from "stats"

let normalize = data => do {
    let m = mean(data);
    let s = std(data);
    map(x => (x - m) / s, data)
}

let rescale = (data, newMin, newMax) => do {
    let dataMin = min(data);
    let dataMax = max(data);
    let range = dataMax - dataMin;
    map(x => newMin + ((x - dataMin) / range) * (newMax - newMin), data)
}

export { normalize, rescale }
```

### Using User-Defined Modules

```javascript
// main.soc
import { double, square } from "src/math_utils"
import { normalize } from "src/data_processing"

let data = [10, 20, 30, 40, 50]
let normalized = normalize(data)
let doubled = map(double, data)
```

## Module Resolution

### Relative Paths

Module paths are resolved **relative to the importing file**:

```
project/
├── main.soc
├── src/
│   ├── utils.soc
│   └── math/
│       └── geometry.soc
```

```javascript
// main.soc
import { helper } from "src/utils"

// src/utils.soc
import { distance } from "math/geometry"  // Relative to src/
```

### File Extensions

The `.soc` extension is optional—it will be added automatically:

```javascript
// These are equivalent:
import { mean } from "src/stats"
import { mean } from "src/stats.soc"
```

### Built-in vs User Modules

The system automatically detects whether you're importing from:
- **Built-in modules**: `stats`, `math`, `linalg`
- **User modules**: Any other path (treated as file path)

```javascript
// Built-in module
import { mean } from "stats"

// User module (file path)
import { helper } from "src/utils"
```

## Best Practices

### 1. Export Only Public API

Don't export internal helper functions:

```javascript
// Good: Only export public functions
let publicFunction = x => x * 2
let privateHelper = x => x + 1  // Not exported

export { publicFunction }
```

### 2. Group Related Functions

Organize related functionality into modules:

```javascript
// src/math.soc - Math utilities
// src/stats.soc - Statistical functions
// src/io.soc - Input/output operations
```

### 3. Use Descriptive Names

```javascript
// Good
import { coefficientOfVariation } from "src/statistics"

// Avoid
import { cv } from "src/stats"  // Unless cv is well-known
```

### 4. Prefer Relative Imports

Use relative paths for maintainability:

```javascript
// Good
import { helper } from "src/utils"

// Avoid absolute paths from project root when possible
```

### 5. Document Your Modules

Add comments to explain module purpose and exports:

```javascript
// ============================================================================
// Data Processing Utilities
// ============================================================================
// This module provides functions for data cleaning, normalization,
// and transformation.
//
// Exports:
// - normalize(data): Z-score normalization
// - rescale(data, min, max): Min-max scaling
// ============================================================================

import { mean, std } from "stats"

// Implementation...
export { normalize, rescale }
```

## Examples

### Example 1: Simple Math Module

```javascript
// src/calculator.soc
let add = (a, b) => a + b
let subtract = (a, b) => a - b
let multiply = (a, b) => a * b
let divide = (a, b) => a / b

export { add, subtract, multiply, divide }
```

```javascript
// main.soc
import { add, multiply } from "src/calculator"

let result1 = add(10, 5)        // 15
let result2 = multiply(3, 4)    // 12
```

### Example 2: Statistical Analysis Module

```javascript
// src/analysis.soc
import { mean, std } from "stats"

let summary = data => do {
    let m = mean(data);
    let s = std(data);
    {
        mean: m,
        std: s,
        count: len(data),
        min: min(data),
        max: max(data),
        cv: (s / m) * 100
    }
}

let outliers = (data, threshold) => do {
    let m = mean(data);
    let s = std(data);
    let lower = m - threshold * s;
    let upper = m + threshold * s;
    filter(x => x < lower || x > upper, data)
}

export { summary, outliers }
```

```javascript
// main.soc
import { summary, outliers } from "src/analysis"

let data = [10, 12, 11, 13, 10, 12, 100]  // 100 is an outlier
let stats = summary(data)
let badPoints = outliers(data, 2)

print("Statistics:", stats)
print("Outliers:", badPoints)
```

### Example 3: Nested Module Imports

```javascript
// src/geometry/shapes.soc
let circleArea = radius => 3.14159 * radius * radius
let rectangleArea = (width, height) => width * height

export { circleArea, rectangleArea }
```

```javascript
// src/geometry/utils.soc
import { circleArea } from "shapes"  // Relative to geometry/

let circlePerimeter = radius => 2 * 3.14159 * radius

export { circlePerimeter }
```

```javascript
// main.soc
import { circleArea } from "src/geometry/shapes"
import { circlePerimeter } from "src/geometry/utils"

let r = 5
print("Area:", circleArea(r))
print("Perimeter:", circlePerimeter(r))
```

### Example 4: Module with Mixed Imports

```javascript
// src/advanced_stats.soc
import { mean, std, variance } from "stats"
import { sqrt, abs } from "math"
import { normalize } from "data_processing"  // User module

let robustStd = data => do {
    let normalized = normalize(data);
    let deviations = map(x => abs(x), normalized);
    let medianDev = median(deviations);
    medianDev * 1.4826  // MAD estimator
}

export { robustStd }
```

### Example 5: Counter with Closures

```javascript
// src/counter.soc
let createCounter = initialValue => do {
    let value = initialValue;

    {
        getValue: () => value,
        increment: () => do {
            value = value + 1;
            value
        },
        decrement: () => do {
            value = value - 1;
            value
        },
        reset: () => do {
            value = initialValue;
            value
        }
    }
}

export { createCounter }
```

```javascript
// main.soc
import { createCounter } from "src/counter"

let counter = createCounter(0)
print(counter.getValue())     // 0
print(counter.increment())    // 1
print(counter.increment())    // 2
print(counter.decrement())    // 1
print(counter.reset())        // 0
```

## Module Caching

Modules are cached after first load:
- ✅ Each module is parsed and evaluated only once
- ✅ Subsequent imports use the cached exports
- ✅ Improves performance for modules imported multiple times

```javascript
// Both imports use the same cached module
import { helper } from "src/utils"
// ...later in the file...
import { anotherHelper } from "src/utils"  // Uses cached version
```

## Limitations

Current limitations of the module system:

1. **No circular imports**: Module A cannot import Module B if B imports A
2. **No dynamic imports**: Import paths must be string literals
3. **No re-exports**: Cannot re-export imported functions (yet)
4. **No default exports**: Must use named exports with `{ name }`

## See Also

- [Functions](06-functions.md) - Learn about function definitions
- [Do Blocks](21-do-blocks.md) - Multi-statement expressions for exports
- [Records](07-records.md) - Export records and objects
- [Best Practices](23-best-practices.md) - Code organization tips
