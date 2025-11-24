---
title: "Operators"
description: "Complete guide to operators in Achronyme including arithmetic, comparison, logical, and special operators"
section: "core-language"
order: 2
---

Achronyme provides a comprehensive set of operators for arithmetic, comparison, logical operations, and more.

## Arithmetic Operators

### Basic Arithmetic

```javascript
// Addition
2 + 3          // 5
1.5 + 2.5      // 4.0

// Subtraction
10 - 3         // 7
5.5 - 1.5      // 4.0

// Multiplication
4 * 5          // 20
2.5 * 2        // 5.0

// Division
10 / 2         // 5
7 / 2          // 3.5

// Modulo (remainder)
10 % 3         // 1
7 % 2          // 1
```

### Power Operator

```javascript
// Exponentiation (right-associative)
2^3            // 8
10^2           // 100
2^10           // 1024

// Right-associative
2^3^2          // 2^(3^2) = 2^9 = 512
```

### Unary Minus

```javascript
// Negation
-5             // -5
-(10 + 5)      // -15
-x             // Negative of x
```

## Comparison Operators

All comparison operators return boolean values.

```javascript
// Equal to
5 == 5         // true
3 == 4         // false

// Not equal to
5 != 3         // true
2 != 2         // false

// Less than
3 < 5          // true
10 < 5         // false

// Greater than
10 > 5         // true
3 > 10         // false

// Less than or equal
5 <= 5         // true
3 <= 5         // true
10 <= 5        // false

// Greater than or equal
10 >= 5        // true
5 >= 5         // true
3 >= 10        // false
```

## Logical Operators

### AND Operator (&&)

Short-circuit AND operator: returns the first falsy value or the last value if all are truthy.

**Falsy values**: `false`, `null`, `0`, `NaN`, `""`

```javascript
// Boolean values
true && true      // true
true && false     // false
false && true     // false
false && false    // false

// Short-circuit with non-boolean values
5 && 10           // 10 (both truthy, returns last)
0 && 10           // 0 (first is falsy, returns first)
"hello" && ""     // "" (first is truthy, second is falsy, returns second)
null && 42        // null (first is falsy, returns first)

// Common pattern: conditional action
let result = user && user.name
// If user is null/false, returns null/false
// If user is truthy, returns user.name

// With expressions
(x > 0) && (y > 0)        // Both must be positive
(age >= 18) && (age < 65) // Age between 18 and 64
```

### OR Operator (||)

Short-circuit OR operator: returns the first truthy value or the last value if all are falsy.

```javascript
// Boolean values
true || false     // true
false || true     // true
true || true      // true
false || false    // false

// Short-circuit with non-boolean values
5 || 10           // 5 (first is truthy, returns first)
0 || 10           // 10 (first is falsy, continues to second)
"" || "default"   // "default" (first is falsy, returns second)
null || 42        // 42 (first is falsy, returns second)

// Common pattern: default values
let name = userInput || "Anonymous"
// If userInput is truthy, use it; otherwise use "Anonymous"

let config = customConfig || defaultConfig
// Fallback to default if custom is null/false

// With expressions
(x < 0) || (x > 100)      // Outside range [0, 100]
(score >= 90) || (bonus)  // High score or bonus
```

### NOT Operator (!)

Negates a boolean value.

```javascript
!true          // false
!false         // true
!(5 > 3)       // false
!(x < 0)       // true if x >= 0

// Double negation (converts to boolean)
!!true         // true
!!false        // false
!!5            // true (5 is truthy)
!!0            // false (0 is falsy)
```

### Short-Circuit Evaluation

Logical operators use short-circuit evaluation - they stop evaluating as soon as the result is determined:

```javascript
// AND: if first is false, second is not evaluated
false && (1/0)    // false (no division by zero error)
true && (println("evaluated"), 5)  // Prints, then returns 5

// OR: if first is true, second is not evaluated
true || (1/0)     // true (no division by zero error)
false || (println("evaluated"), 5) // Prints, then returns 5

// Falsy values short-circuit OR and return from AND
let result = 0 && expensive_function()  // function not called
let result = null || get_default()       // get_default() is called
```

## Operator Precedence

From highest to lowest precedence:

| Level | Operators | Description | Associativity |
|-------|-----------|-------------|---------------|
| 1 | `()` `[]` `.` | Function call, indexing, field access | Left |
| 2 | `^` | Power/exponentiation | Right |
| 3 | `-` `!` | Unary minus, logical NOT | Right |
| 4 | `*` `/` `%` | Multiplication, division, modulo | Left |
| 5 | `+` `-` | Addition, subtraction | Left |
| 6 | `..` `..=` | Exclusive and inclusive range | Left |
| 7 | `==` `!=` `<` `>` `<=` `>=` | Comparison | Left |
| 8 | `&&` | Logical AND (short-circuit) | Left |
| 9 | `||` | Logical OR (short-circuit) | Left |

### Precedence Examples

```javascript
// Multiplication before addition
2 + 3 * 4          // 2 + 12 = 14
(2 + 3) * 4        // 5 * 4 = 20

// Power before multiplication
2 * 3^2            // 2 * 9 = 18
(2 * 3)^2          // 6^2 = 36

// Comparison before logical
x > 0 && y > 0     // Parsed as: (x > 0) && (y > 0)

// Right-associative power
2^3^2              // 2^(3^2) = 2^9 = 512
```

## Associativity

### Left-Associative Operators

Most operators are left-associative:

```javascript
// Subtraction
10 - 5 - 2         // (10 - 5) - 2 = 3

// Division
100 / 10 / 2       // (100 / 10) / 2 = 5

// Addition
1 + 2 + 3          // (1 + 2) + 3 = 6
```

### Right-Associative Operators

Power operator is right-associative:

```javascript
// Power
2^3^2              // 2^(3^2) = 2^9 = 512
NOT: (2^3)^2       // Would be 8^2 = 64

// Why? Mathematical convention
a^b^c = a^(b^c)
```

## Operator Overloading

Some operators work with multiple types.

### Addition (+)

```javascript
// Numbers
5 + 3              // 8

// Tensors (element-wise)
[1, 2, 3] + [4, 5, 6]    // [5, 7, 9]

// Complex numbers
(2 + 3i) + (1 + 4i)      // 3 + 7i

// Broadcast with scalar
[1, 2, 3] + 10           // [11, 12, 13]
```

### Multiplication (*)

```javascript
// Numbers
5 * 3              // 15

// Tensors (element-wise)
[1, 2, 3] * [2, 2, 2]    // [2, 4, 6]

// Scalar multiplication
[1, 2, 3] * 2            // [2, 4, 6]

// Complex numbers
(2 + 3i) * (1 - 2i)      // 8 - i
```

### Subtraction (-)

```javascript
// Numbers
10 - 3             // 7

// Tensors (element-wise)
[5, 6, 7] - [1, 2, 3]    // [4, 4, 4]

// Complex numbers
(5 + 3i) - (2 + i)       // 3 + 2i
```

### Division (/)

```javascript
// Numbers
10 / 2             // 5

// Tensors (element-wise)
[10, 20, 30] / [2, 4, 5]  // [5, 5, 6]

// Scalar division
[10, 20, 30] / 10         // [1, 2, 3]

// Complex numbers
(4 + 2i) / 2              // 2 + i
```

### Power (^)

```javascript
// Numbers
2^10               // 1024

// Tensors (element-wise)
[2, 3, 4]^2        // [4, 9, 16]

// Complex exponentiation
(1 + i)^2          // 2i
```

## Special Operators

### Field Access (.)

Access record fields:

```javascript
let point = {x: 10, y: 20}

point.x            // 10
point.y            // 20

// Chained access
let obj = {inner: {value: 42}}
obj.inner.value    // 42
```

### Indexing ([])

Access array/tensor elements:

```javascript
// Array indexing (0-based)
let arr = [10, 20, 30, 40]
arr[0]             // 10
arr[3]             // 40

// Matrix indexing
let matrix = [[1, 2], [3, 4]]
matrix[0, 0]       // 1
matrix[1, 1]       // 4

// Slicing with ranges
arr[1..3]          // [20, 30]
arr[..2]           // [10, 20]
arr[2..]           // [30, 40]
```

### Range Operator (.. and ..=)

Create ranges of numbers, useful for iteration and slicing.

```javascript
// Exclusive range (end is not included)
1..5               // [1, 2, 3, 4]
0..10              // [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

// Inclusive range (end is included)
1..=5              // [1, 2, 3, 4, 5]
0..=10             // [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

// With variables
let n = 5
1..n               // [1, 2, 3, 4]
1..=n              // [1, 2, 3, 4, 5]

// In slicing
let arr = [10, 20, 30, 40, 50]
arr[1..4]          // [20, 30, 40]
arr[1..=4]         // [20, 30, 40, 50]

// In for-in loops
for(i in 0..5) {
    print(i)       // 0, 1, 2, 3, 4
}

for(i in 1..=5) {
    print(i)       // 1, 2, 3, 4, 5
}

// Creating sequences
let numbers = 1..10        // [1, 2, 3, 4, 5, 6, 7, 8, 9]
let inclusive = 0..=100    // [0, 1, 2, ..., 100]
```

### Function Call (())

Call functions:

```javascript
sin(3.14159)       // ~0
sqrt(16)           // 4

let f = x => x^2
f(5)               // 25
```

## Operator Examples

### Mathematical Expressions

```javascript
// Quadratic formula: (-b +/- sqrt(b^2 - 4ac)) / (2a)
let a = 1
let b = -5
let c = 6

let discriminant = b^2 - 4*a*c
let root1 = (-b + sqrt(discriminant)) / (2*a)  // 3
let root2 = (-b - sqrt(discriminant)) / (2*a)  // 2
```

### Boolean Logic

```javascript
// Check if number is in range [0, 100]
let in_range = x => (x >= 0) && (x <= 100)
in_range(50)       // true
in_range(150)      // false

// Check if number is outside range
let out_of_range = x => (x < 0) || (x > 100)
out_of_range(-5)   // true
out_of_range(50)   // false
```

### Complex Calculations

```javascript
// Distance between two points
let distance = (x1, y1, x2, y2) =>
    sqrt((x2 - x1)^2 + (y2 - y1)^2)

distance(0, 0, 3, 4)  // 5.0

// Compound interest
let compound = (p, r, n, t) => p * (1 + r/n)^(n*t)
compound(1000, 0.05, 12, 10)  // ~1647.01
```

### Tensor Operations

```javascript
// Normalize vector
let v = [3, 4]
let magnitude = sqrt(sum(v * v))      // 5
let normalized = v / magnitude        // [0.6, 0.8]

// Dot product
let a = [1, 2, 3]
let b = [4, 5, 6]
sum(a * b)         // 32
```

## Common Patterns

### Conditional Logic with Operators

```javascript
// Age validation
let is_adult = age => age >= 18

// Range check
let is_valid_percentage = x => x >= 0 && x <= 100

// Multiple conditions
let can_vote = (age, citizen) => age >= 18 && citizen
```

### Mathematical Formulas

```javascript
// Area of circle
let circle_area = r => 3.14159 * r^2

// Pythagorean theorem
let hypotenuse = (a, b) => sqrt(a^2 + b^2)

// Kinetic energy
let kinetic_energy = (m, v) => 0.5 * m * v^2
```

### Vector/Tensor Algebra

```javascript
// Element-wise operations
let a = [1, 2, 3]
let b = [4, 5, 6]

a + b              // [5, 7, 9]
a - b              // [-3, -3, -3]
a * b              // [4, 10, 18]

// Broadcasting
a * 2              // [2, 4, 6]
a + 10             // [11, 12, 13]
```

## Operator Chaining

```javascript
// Multiple operations
let result = 2 + 3 * 4 - 5 / 2    // 2 + 12 - 2.5 = 11.5

// With parentheses for clarity
let result2 = (2 + 3) * (4 - 5) / 2  // 5 * (-1) / 2 = -2.5

// Field access and indexing
data.values[0].field
arr[i].method()[j]
```

## Best Practices

### 1. Use Parentheses for Clarity

```javascript
// Unclear precedence
let x = a + b * c - d / e

// Clear intention
let x = a + (b * c) - (d / e)
```

### 2. Avoid Deep Nesting

```javascript
// Hard to read
let result = ((a + b) * (c - d)) / ((e + f) * (g - h))

// Better: break into steps
let sum1 = a + b
let diff1 = c - d
let sum2 = e + f
let diff2 = g - h
let result = (sum1 * diff1) / (sum2 * diff2)
```

### 3. Be Explicit with Boolean Expressions

```javascript
// Unclear
if(x && y || z) ...

// Clear
if((x && y) || z) ...
```

### 4. Use Named Constants

```javascript
// Bad: magic numbers
let area = 3.14159 * r^2

// Good: named constant
let PI = 3.14159
let area = PI * r^2
```

## Summary

- **Arithmetic**: `+`, `-`, `*`, `/`, `%`, `^`
- **Comparison**: `==`, `!=`, `<`, `>`, `<=`, `>=`
- **Logical**: `&&`, `||`, `!`
- **Special**: `.` (field), `[]` (index), `()` (call)
- **Precedence**: Use parentheses when in doubt
- **Associativity**: Most left-to-right, except `^` (right-to-left)
- **Overloading**: Operators work with numbers, tensors, complex numbers

---

**Next**: [Variables](variables.md)
