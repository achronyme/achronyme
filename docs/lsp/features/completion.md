---
title: "Code Completion"
description: "Intelligent autocompletion in Achronyme LSP"
section: "lsp-features"
order: 1
---

# Code Completion

The Achronyme LSP server provides intelligent code completion with **151 items** organized into categories.

## Overview

Code completion helps you write Achronyme code faster by suggesting:
- Function names
- Keywords
- Built-in constants
- Type names

Each completion item includes:
- Full documentation
- Usage examples
- Parameter information
- Return type hints

## Completion Categories

### Functions (109 items)

Built-in functions covering:

#### Mathematical Functions (25+ items)
- **Trigonometric:** `sin`, `cos`, `tan`, `asin`, `acos`, `atan`, `atan2`, `sinh`, `cosh`, `tanh`
- **Exponential/Logarithmic:** `exp`, `ln`, `log`, `log10`, `log2`
- **Rounding:** `floor`, `ceil`, `round`, `abs`
- **Comparison:** `min`, `max`
- **Power:** `pow`, `sqrt`, `cbrt`

#### Array Functions (20+ items)
- **Manipulation:** `map`, `filter`, `reduce`, `push`, `pop`, `shift`, `unshift`
- **Access:** `head`, `tail`, `at`, `slice`
- **Properties:** `len`, `length`, `reverse`
- **Aggregation:** `sum`, `product`, `concat`, `flatten`
- **Searching:** `find`, `findIndex`, `includes`, `indexOf`

#### Statistical Functions (10+ items)
- `mean` - Arithmetic mean
- `median` - Middle value
- `std`, `stddev` - Standard deviation
- `variance` - Statistical variance
- `quantile` - Percentile values
- `covariance`, `correlation` - Relationship metrics
- `histogram`, `frequencies` - Distribution analysis

#### Signal Processing (15+ items)
- `fft` - Fast Fourier Transform
- `ifft` - Inverse FFT
- `convolve` - Convolution operation
- `correlate` - Cross-correlation
- Window functions: `hann`, `hamming`, `blackman`, `bartlett`

#### Linear Algebra (20+ items)
- `dot` - Dot product
- `cross` - Cross product
- `norm` - Vector/matrix norm
- `det` - Determinant
- `inv` - Matrix inverse
- `transpose` - Matrix transpose
- `eigenvalues`, `eigenvectors` - Eigen decomposition
- `solve` - Linear system solver

#### Numerical Analysis (10+ items)
- `diff` - Numerical differentiation
- `integral` - Numerical integration
- `newton_raphson` - Root finding
- `bisect` - Bisection method
- `secant` - Secant method

#### Graph Theory (10+ items)
- `dijkstra` - Shortest path
- `bfs` - Breadth-first search
- `dfs` - Depth-first search
- `kruskal` - Minimum spanning tree
- `prim` - Prim's algorithm
- `topological_sort` - Topological ordering

### Keywords (19 items)

```javascript
let        // Variable binding (immutable)
mut        // Mutable variable
if         // Conditional branching
else       // Else clause
while      // While loop
for        // For-in loop
in         // Iteration operator
match      // Pattern matching
type       // Type definition
import     // Module import
export     // Module export
return     // Return value
break      // Break from loop
continue   // Continue loop iteration
try        // Exception handling
catch      // Exception handler
throw      // Throw exception
yield      // Generator yield
do         // Do-block expression
```

### Constants (9 items)

```javascript
PI         // π (3.14159...)
E          // e (2.71828...)
PHI        // φ (1.61803...)
SQRT2      // √2 (1.41421...)
Infinity   // Positive infinity
NaN        // Not a number
null       // Null value
true       // Boolean true
false      // Boolean false
```

### Types (14 items)

```javascript
Number     // Numeric value
String     // Text value
Boolean    // True/false
Complex    // Complex number (a + bi)
Vector     // 1D array
Tensor     // Multi-dimensional array
Generator  // Generator function
Function   // Function type
Error      // Exception type
Record     // Object/record type
Edge       // Graph edge
Null       // Null type
Array      // Array type
Any        // Any type
```

## Using Code Completion

### Triggering Completions

**Automatic Triggers:**
- Typing `.` after an identifier (field access)
- Typing `:` after an identifier (type annotation)

**Manual Trigger:**
- `Ctrl+Space` (most editors)
- `Cmd+Space` (macOS)

**Example:**

```javascript
// Type "ma" and press Ctrl+Space:
map       → Map over array
max       → Maximum value
match     → Pattern matching
mean      → Arithmetic mean
hamming   → Hamming window
```

### Context Awareness

The server analyzes context to provide smart suggestions:

**After `let` or `mut`:**
```javascript
let |  // No completions - user is naming a variable
mut counter|
```

**After `.`:**
```javascript
obj.|  // Future: Will show object fields/methods
vec.|
```

**After `import {`:**
```javascript
import {|  // Future: Will show module exports
```

**Default context:**
```javascript
|  // Shows all available completions
sum(data)  // At beginning of line
```

## Completion Details

Each completion item includes:

### Documentation

Full markdown documentation with:
- Function description
- Parameter types
- Return type
- Examples

### Type Information

For functions, shows:
```
sin(x: Number) -> Number
```

For constants:
```
PI: Number (3.14159...)
```

### Snippets

Some completions insert snippet templates:

```javascript
map(|$1, $2)  // Parameters filled in as snippets
// Cursor at first parameter, Tab to next
```

### Example Usage

Documentation includes practical examples:

```javascript
// For 'mean' completion:

map(x => x * 2, [1, 2, 3])  // [2, 4, 6]

// Returns the arithmetic mean of values
mean([1, 2, 3, 4, 5])  // 3
```

## Advanced Completion Features

### Filtering

Most editors let you filter completions by type:

**VS Code:**
- Type to filter: `map` shows functions starting with "map"
- Press `@` to filter by kind (functions, keywords, etc.)

**Neovim (with completion plugins):**
- Filter using completion framework
- Check documentation for your setup

### Sorting

Completions are sorted by:
1. **Relevance** - Keywords first, then built-ins
2. **Category** - Functions grouped together
3. **Frequency** - Common functions ranked higher

### Documentation Display

Hover over a completion item to see full documentation:

**Example for `reduce`:**

```
reduce(f: Function, initial: Any, arr: Array) -> Any

Reduce an array to a single value using a function.

Parameters:
  f: Function - (accumulator, value) => new_accumulator
  initial: Any - Starting value
  arr: Array - Array to reduce

Example:
  let sum = reduce((a, b) => a + b, 0, [1,2,3,4,5])
  // sum = 15
```

## Completion Categories by Use Case

### Data Processing
```
map, filter, reduce, flatten,
find, includes, slice, reverse
```

### Mathematical Computing
```
sin, cos, sqrt, pow, exp, log,
mean, std, sum, product, integral
```

### Statistics
```
mean, median, std, variance,
quantile, histogram, correlation
```

### Signal Processing
```
fft, ifft, convolve, correlate,
hamming, hann, blackman
```

### Graph Algorithms
```
dijkstra, bfs, dfs, kruskal,
prim, topological_sort
```

### Control Flow
```
if, else, while, for, match,
break, continue, yield, return
```

## Customizing Completions

### Disabling Completion

In your editor configuration, you can disable completion:

**VS Code:**
```json
"[achronyme]": {
  "editor.suggest.enabled": false
}
```

**Neovim:**
```lua
require('lspconfig').achronyme.setup {
  handlers = {
    ['textDocument/completion'] = function() end
  }
}
```

### Sorting by Category

Some editors allow sorting completion results. To prefer functions over keywords:

**VS Code:**
```json
"editor.suggest.sortByLabel": true
```

## Keyboard Shortcuts

Common completion shortcuts in different editors:

| Action | VS Code | Neovim | Emacs |
|--------|---------|--------|-------|
| Trigger | `Ctrl+Space` | varies | `M-/` |
| Accept | `Enter` | `Enter` | `Enter` |
| Next | `Down` | varies | `Down` |
| Prev | `Up` | varies | `Up` |
| Dismiss | `Esc` | `Esc` | `C-g` |

## Performance

The LSP server:
- Caches all 151 completions at startup
- Returns suggestions in <10ms on modern hardware
- Handles large files efficiently

If completions are slow:
1. Check if your file has parse errors
2. Try disabling other editor extensions
3. Check available system memory

## Future Enhancements

Planned completion improvements:
- Record field completion after `.`
- Module export completion after `import {`
- User-defined function suggestions
- Custom completion providers
- Completion filtering and sorting

---

**Next**: [Signature Help](signature-help.md)
