---
title: "Syntax Basics"
description: "Fundamental syntax of the Achronyme programming language including expressions, operators, and literals"
section: "getting-started"
order: 3
---

This chapter covers the fundamental syntax of Achronyme.

## Expressions vs. Statements

Achronyme is **expression-oriented**: most constructs are expressions that produce values. However, it also supports several statement-like constructs.

```javascript
// Expressions (return values)
42                    // Number literal
x + y                 // Arithmetic
if(x > 0, 1, -1)      // Conditional function
match x { 0 => "zero", _ => "other" }  // Pattern matching
```

### Statements

Achronyme includes several types of statements:
1. **Variable declarations** (`let`, `mut`)
2. **Control flow statements** (`if-else`, `while`, `for-in`)
3. **Error handling** (`throw`)
4. **Loop control** (`break`, `continue`)
5. **Early returns** (`return`)
6. **Module statements** (`import`, `export`)

```javascript
let x = 10                    // Variable declaration
mut counter = 0               // Mutable declaration
for(i in [1, 2, 3]) { ... }  // For-in loop
import { sin } from "math"    // Module import
throw "Error message"         // Throw statement
```

Many statements (like if-else blocks and loops) are also expressions that return values.

## Comments

Single-line comments start with `//`:

```javascript
// This is a comment
let x = 42  // End-of-line comment

// Comments can span multiple lines
// by using multiple // markers
let y = 10
```

## Literals

### Number Literals

```javascript
42            // Integer
3.14          // Floating point
-17           // Negative
1.5e-10       // Scientific notation
2.5E+3        // Also scientific (2500)
```

### Boolean Literals

```javascript
true
false
```

### String Literals

Strings are enclosed in double quotes:

```javascript
"hello"
"Hello, World!"
""             // Empty string
```

#### Escape Sequences

| Sequence | Meaning |
|----------|---------|
| `\"` | Double quote |
| `\\` | Backslash |
| `\n` | Newline |
| `\t` | Tab |
| `\r` | Carriage return |

```javascript
"He said \"Hello\""     // He said "Hello"
"Line 1\nLine 2"        // Two lines
"Tab\tseparated"        // Tab separated
```

### Complex Number Literals

Complex numbers use the `i` suffix:

```javascript
3i              // Pure imaginary: 0 + 3i
-2i             // Negative imaginary: 0 - 2i
2 + 3i          // Complex: 2 + 3i (parsed as addition)
```

### Array Literals

Arrays are enclosed in square brackets:

```javascript
[]                      // Empty array
[1, 2, 3]              // Vector
[[1, 2], [3, 4]]       // Matrix (2x2)
[1, 2, 3, 4, 5]        // Vector (becomes Tensor)
```

### Record Literals

Records (like objects) use curly braces:

```javascript
{}                                  // Empty record
{ x: 10, y: 20 }                   // Record with two fields
{ name: "Alice", age: 30 }         // Mixed types
```

**IMPORTANT**: Curly braces `{ }` always create a **record**, NOT a code block. To create a block of statements, you must use a keyword like `do`, `if`, `while`, `for`, or `generate`:

```javascript
// ❌ ERROR: { } alone is a record literal
let result = {
    if (x > 0) { 1 } else { -1 }
}
// Parse error: expected record_field_or_spread

// ✅ CORRECT: Use do { } for statement blocks
let result = do {
    if (x > 0) { 1 } else { -1 }
}

// ✅ CORRECT: Direct if-else (no outer block needed)
let result = if (x > 0) { 1 } else { -1 }
```

See [Do Blocks](../functional-programming/do-blocks.md) for more information.

## Identifiers

Identifiers name variables, functions, and record fields.

### Rules

- Start with a letter or underscore: `x`, `_temp`, `MyVar`
- Can contain letters, numbers, and underscores: `x1`, `my_var`, `temp_2`
- Case-sensitive: `var` and `Var` are different
- Cannot be keywords

```javascript
// Valid identifiers
x
myVariable
_private
temp_1
calculateArea

// Invalid identifiers
1x          // Cannot start with digit
my-var      // Hyphen not allowed
```

### Reserved Keywords

These cannot be used as identifiers:

- `let` - Variable declaration
- `mut` - Mutable variable declaration
- `true`, `false` - Boolean literals
- `null` - Null literal
- `self` - Self-reference in records
- `rec` - Recursive function reference
- `if`, `else` - Conditional statements
- `while` - While loops
- `for`, `in` - For-in loops
- `break`, `continue` - Loop control
- `return` - Early return
- `match` - Pattern matching
- `try`, `catch`, `throw` - Error handling
- `import`, `export`, `from` - Module system
- `generate`, `yield` - Generators
- `type` - Type aliases

**Note**: `if()` and `piecewise()` can also be used as built-in **functions** for functional-style conditionals.

## Operators

### Precedence (Highest to Lowest)

1. **Postfix**: `()` call, `[]` index, `.` field access
2. **Power**: `^` (right-associative)
3. **Unary**: `-` negate, `!` not
4. **Multiplicative**: `*`, `/`, `%`
5. **Additive**: `+`, `-`
6. **Edge**: `->`, `<>` (graph edges)
7. **Comparison**: `==`, `!=`, `<`, `>`, `<=`, `>=`
8. **Logical AND**: `&&`
9. **Logical OR**: `||`

### Associativity

Most operators are **left-associative**:
```javascript
a - b - c    // (a - b) - c
```

Power is **right-associative**:
```javascript
2^3^4        // 2^(3^4) = 2^81
```

### Operator Examples

```javascript
// Arithmetic
1 + 2 * 3    // 7 (multiplication first)
(1 + 2) * 3  // 9 (parentheses override)
2^3^2        // 512 (right-associative)

// Comparison
x > 10
y <= 5
a == b

// Logical
x > 0 && y > 0      // AND
x < 0 || y < 0      // OR
!(x > 0)            // NOT
```

## Semicolons and Sequences

### Single Expressions

Single expressions don't need semicolons:

```javascript
42
x + y
sin(3.14)
```

### Sequences

Multiple statements separated by semicolons form a sequence:

```javascript
let a = 1; let b = 2; a + b    // Result: 3
```

The value of a sequence is the **last expression**:

```javascript
let x = 10;
let y = 20;
x + y              // Returns 30
```

### Optional Trailing Semicolon

The last statement in a sequence can optionally end with `;`:

```javascript
let a = 1;
let b = 2;
a + b;             // Semicolon optional here
```

## Parentheses

Parentheses control evaluation order and group expressions:

```javascript
// Without parentheses
2 + 3 * 4          // 14

// With parentheses
(2 + 3) * 4        // 20

// Nested
((1 + 2) * (3 + 4))  // 21
```

## Line Breaks and Whitespace

Whitespace (spaces, tabs, newlines) is generally ignored:

```javascript
// These are equivalent:
let x = 10
let x=10
let   x   =   10

// Multi-line expressions
let y = 1 + 2 +
        3 + 4 +
        5
```

## Complex Expressions

### IIFE (Immediately Invoked Function Expression)

For complex expressions with intermediate values, use the IIFE pattern:

```javascript
// IIFE pattern
(params => params[0] + params[1])([10, 20])   // Returns 30
```

IIFE is often used in lambda bodies for complex calculations:

```javascript
let process = x => (
    doubled => doubled^2 + 10
)(x * 2)
```

## Edge Syntax (Graphs)

Special syntax for creating graph edges:

```javascript
// Directed edge
A -> B

// Undirected edge
A <> B

// Edge with metadata
A -> B : { weight: 5 }
```

## Chaining Operations

Operations can be chained left-to-right:

```javascript
// Field access
point.x

// Method calls
obj.method()

// Indexing
array[0]

// Combination
data[0].field.method()[1]
```

## Examples

### Simple Script

```javascript
// Calculate compound interest
let principal = 1000
let rate = 0.05
let years = 10

let final = principal * (1 + rate)^years
final
```

### Using Sequences

```javascript
// Multi-step calculation
let data = [1, 2, 3, 4, 5];
let doubled = map(x => x * 2, data);
let total = sum(doubled);
total
```

### Complex Expression

```javascript
// Nested operations with if()
let result = if(x > 0, (y + 2) * 3, -(y - 2) * 3)
```

## Style Guidelines

### Naming Conventions

- **Variables**: Use `camelCase` or `snake_case`
  ```javascript
  let userName = "Alice"
  let user_count = 10
  ```

- **Constants**: Often use `UPPER_CASE`
  ```javascript
  let PI = 3.14159
  let MAX_SIZE = 100
  ```

### Indentation

Use consistent indentation (2 or 4 spaces):

```javascript
let factorial = n =>
    if(n <= 1, 1, n * rec(n - 1))
```

### Line Length

Keep lines under 80-100 characters when possible:

```javascript
// Good
let result = calculateComplexValue(
    param1,
    param2,
    param3
)

// Avoid
let result = calculateComplexValue(param1, param2, param3, param4, param5, param6)
```

## Common Pitfalls

### 1. Missing Parentheses

```javascript
// Wrong - parse error
let f = x, y => x + y

// Correct
let f = (x, y) => x + y
```

### 2. Using `->` Instead of `=>`

```javascript
// Wrong
let f = x -> x^2

// Correct
let f = x => x^2
```

### 3. Forgetting `let`

```javascript
// Wrong - undefined variable
x = 10

// Correct
let x = 10
```

### 4. Semicolons in Wrong Places

```javascript
// Wrong - semicolon in expression
let f = x => (x; + 2)

// Correct - use IIFE for intermediate values
let f = x => (y => y + 2)(x)
```

## Summary

- Achronyme is primarily expression-oriented with statement support
- Comments use `//`
- Numbers, strings, booleans, null, arrays, and records are literals
- Operators have well-defined precedence
- Semicolons separate statements in sequences
- Whitespace is generally ignored
- IIFE pattern for complex expressions with intermediate values
- `if()` and `piecewise()` are functions, but `if-else` blocks are also supported
- Full support for loops (`while`, `for-in`), error handling (`try/catch/throw`), and pattern matching (`match`)

---

**Next**: [Data Types](../core-language/data-types.md)
