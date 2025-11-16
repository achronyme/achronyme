# Gradual Type System

Achronyme supports a gradual type system that allows you to add optional type annotations to your code. This provides the flexibility of dynamic typing with the safety benefits of static typing when you need them.

## Overview

The gradual type system in Achronyme:
- Is **optional** - all existing untyped code continues to work
- Provides **type annotations** for variables, parameters, and return types
- Supports **union types** for values that can be multiple types
- Allows **type aliases** for creating custom type names
- Includes **type inference** that propagates type information from annotations
- Offers **Any** type for opting out of type checking

## Basic Type Annotations

### Variable Type Annotations

Add type annotations after the variable name with a colon:

```javascript
let x: Number = 42
let name: String = "Alice"
let active: Boolean = true
let z: Complex = 3 + 4i
```

### Function Parameter Annotations

Annotate function parameters to specify expected types:

```javascript
let square = (x: Number) => x^2
let greet = (name: String) => concat("Hello, ", name)
let toggle = (flag: Boolean) => !flag
```

### Return Type Annotations

Specify the return type after the parameter list:

```javascript
let square = (x: Number): Number => x^2
let isPositive = (x: Number): Boolean => x > 0
let describe = (x: Number): String => concat("Value: ", str(x))
```

### Complete Function Signatures

```javascript
// Full type signature
let add = (a: Number, b: Number): Number => a + b

// Multiple parameters with different types
let formatValue = (label: String, value: Number): String =>
    concat(label, ": ", str(value))

// Complex number operations
let magnitude = (z: Complex): Number => sqrt(real(z)^2 + imag(z)^2)
```

## Core Types

Achronyme provides the following built-in type names:

| Type | Description | Example |
|------|-------------|---------|
| `Number` | 64-bit floating point | `42`, `3.14` |
| `String` | Text strings | `"hello"` |
| `Boolean` | Logical values | `true`, `false` |
| `Complex` | Complex numbers | `3 + 4i` |
| `Edge` | Graph edges | `A -> B` |
| `Any` | Any type (opt-out) | All values |

## Union Types

Union types allow a value to be one of several types, using the `|` operator:

### Basic Union Types

```javascript
// Value can be Number or String
let value: Number | String = 42
let value: Number | String = "hello"

// Multiple union members
let result: Number | String | Boolean = true
```

### Optional Types with null

The most common use of union types is for optional values:

```javascript
// Optional number (can be Number or null)
let maybeNumber: Number | null = 42
let maybeNumber: Number | null = null

// Optional string
let maybeName: String | null = "Alice"
let maybeName: String | null = null
```

### Union Types in Functions

```javascript
// Function that returns optional value
let findIndex = (arr: Any, target: Any): Number | null => do {
    let idx = 0;
    let found = false;
    // search logic...
    if(found, idx, null)
}

// Parameter that accepts multiple types
let stringify = (value: Number | String | Boolean): String => do {
    str(value)
}

// Return different types based on condition
let parse = (input: String): Number | String => do {
    // Try to parse as number, return string on failure
    let num = parseNumber(input);
    if(num != null, num, input)
}
```

### Practical Union Type Examples

```javascript
// Configuration value that can be multiple types
let config: Number | String | Boolean = "development"

// Safe division returning null on error
let safeDivide = (a: Number, b: Number): Number | null =>
    if(b == 0, null, a / b)

// Result type pattern
let validateAge = (age: Number): String | null =>
    if(age < 0 || age > 150,
       "Invalid age",
       null)
```

## Function Types

Function types describe the signature of a function using colon syntax for consistency with other type annotations:

### Basic Function Type Syntax

```javascript
// Type for a function that takes Number and returns Number
(Number): Number

// Type for a function that takes two Numbers and returns Number
(Number, Number): Number

// Type for a function that takes no arguments
(): Number
```

### Annotating Higher-Order Functions

```javascript
// Function that takes a function as parameter
let applyTwice = (f: (Number): Number, x: Number): Number =>
    f(f(x))

let square = (x: Number): Number => x^2
applyTwice(square, 3)  // 81

// Function that returns a function
let makeMultiplier = (factor: Number): (Number): Number =>
    (x: Number) => x * factor

let double = makeMultiplier(2)
double(5)  // 10

// Predicate function type
let findFirst = (arr: Any, predicate: (Any): Boolean): Any | null => do {
    // Find first element matching predicate
    let found = filter(predicate, arr);
    if(len(found) > 0, found[0], null)
}
```

### Complex Function Types

```javascript
// Transformer function type
let mapValues = (data: Any, transform: (Any): Any): Any =>
    map(transform, data)

// Reducer function type
let customReduce = (
    arr: Any,
    reducer: (Any, Any): Any,
    initial: Any
): Any => reduce(reducer, initial, arr)

// Comparison function type
let sortBy = (
    arr: Any,
    compare: (Any, Any): Number
): Any => do {
    // Sort implementation using compare function
    arr
}
```

## Type Aliases

Create custom type names using the `type` keyword:

### Basic Type Aliases

```javascript
// Alias for a primitive type
type Age = Number
type Name = String
type Active = Boolean

let userAge: Age = 30
let userName: Name = "Bob"
let isActive: Active = true
```

### Alias for Union Types

```javascript
// Optional types
type OptionalNumber = Number | null
type OptionalString = String | null

// Result types
type Result = String | Number | Boolean

// Status codes
type Status = Number | String

let maybeValue: OptionalNumber = 42
let errorMessage: OptionalString = null
```

### Alias for Function Types

```javascript
// Common function signatures
type NumberTransform = (Number): Number
type Predicate = (Any): Boolean
type BinaryOp = (Number, Number): Number
type Comparator = (Any, Any): Number

// Use the aliases
let square: NumberTransform = (x: Number) => x^2
let isPositive: Predicate = (x: Any) => x > 0
let add: BinaryOp = (a: Number, b: Number) => a + b
```

### Complex Type Alias Examples

```javascript
// Mathematical function type
type MathFunc = (Number): Number

// Callback with optional result
type Callback = (Any): Any | null

// Event handler type
type EventHandler = (String, Any): Boolean

// Data processor
type Processor = (Any): Any

// Using aliases for cleaner signatures
let compose = (
    f: MathFunc,
    g: MathFunc
): MathFunc => (x: Number) => f(g(x))

let processWithCallback = (
    data: Any,
    callback: Callback
): Any | null => callback(data)
```

## Edge Type for Graphs

The `Edge` type represents graph edges:

```javascript
// Typed edge creation
let edge: Edge = A -> B

// Function working with edges
let getWeight = (e: Edge): Number => do {
    // Extract weight from edge metadata
    e.weight
}

// Creating typed graph edges
let createEdge = (from: String, to: String): Edge =>
    from -> to

// With metadata
let weightedEdge = (from: String, to: String, weight: Number): Edge =>
    from -> to : {weight: weight}
```

## Type Inference

Achronyme's type system infers types from annotations:

### Inference from Annotations

```javascript
// Type is inferred from annotation
let x: Number = 10
let y = x + 5  // y is inferred as Number

// Function return type inference
let multiply = (a: Number, b: Number) => a * b
// Return type inferred as Number from operation

// Inference through function calls
let numbers = [1, 2, 3]
let doubled = map((x: Number) => x * 2, numbers)
// doubled inferred as array of Numbers
```

### Lambda Parameter Inference

When a lambda is passed to a typed function, its parameters can be inferred:

```javascript
// Typed higher-order function
let applyToAll = (f: (Number) => Number, arr: Any): Any =>
    map(f, arr)

// Lambda parameter type inferred from context
applyToAll(x => x * 2, [1, 2, 3])
// x is inferred as Number from the function type
```

### Inference in Complex Scenarios

```javascript
// Chain of inferred types
let processData = (input: Number): String => do {
    let doubled = input * 2;      // Number (inferred)
    let squared = doubled^2;       // Number (inferred)
    str(squared)                   // String (explicit return)
}

// Inference with conditionals
let classify = (x: Number): String =>
    if(x < 0, "negative", if(x > 0, "positive", "zero"))
    // All branches return String, type is consistent
```

## The Any Type

The `Any` type opts out of type checking for maximum flexibility:

### Using Any for Dynamic Code

```javascript
// Accept any type
let identity = (x: Any): Any => x

// Process unknown data
let processUnknown = (data: Any): Any => do {
    // Handle different types at runtime
    data
}

// Mixed type collections
let mixedArray: Any = [1, "hello", true, {x: 10}]
```

### Any in Type Aliases

```javascript
// Generic container
type Container = Any

// Flexible function type
type AnyTransform = (Any) => Any

// Mixed result type
type FlexibleResult = Any | null
```

### When to Use Any

```javascript
// Working with external/untyped data
let parseJSON = (text: String): Any => do {
    // Parse and return arbitrary structure
    {}
}

// Interoperating with dynamic code
let callDynamic = (func: Any, args: Any): Any =>
    func(args)

// Prototyping before adding types
let experimentalFeature = (input: Any): Any => do {
    // Quick prototype, add types later
    input
}
```

## Best Practices

### 1. Start with Critical Functions

```javascript
// Good: Type critical mathematical functions
let computeInterest = (
    principal: Number,
    rate: Number,
    time: Number
): Number => principal * (1 + rate)^time

// Good: Type public API functions
let validateInput = (value: Any): Boolean => do {
    // Validation logic
    true
}
```

### 2. Use Union Types for Safety

```javascript
// Good: Explicit optional types
let findUser = (id: Number): Any | null => do {
    // Return null if not found
    null
}

// Good: Error handling with unions
let parseConfig = (text: String): Any | String => do {
    // Return error message string on failure
    "Error: invalid config"
}
```

### 3. Create Meaningful Type Aliases

```javascript
// Good: Domain-specific types
type UserId = Number
type Email = String
type Timestamp = Number
type ValidationResult = Boolean | String

// Better than raw types
let sendNotification = (
    userId: UserId,
    email: Email,
    timestamp: Timestamp
): ValidationResult => true
```

### 4. Document Complex Function Signatures

```javascript
// Good: Clear function type documentation
type DataProcessor = (Any) => Any | null
type ErrorHandler = (String) => Boolean

let processWithRetry = (
    data: Any,
    processor: DataProcessor,
    onError: ErrorHandler,
    maxRetries: Number
): Any | null => do {
    // Implementation
    null
}
```

### 5. Gradual Migration

```javascript
// Start untyped
let oldFunction = x => x * 2

// Add parameter type
let partiallyTyped = (x: Number) => x * 2

// Add return type
let fullyTyped = (x: Number): Number => x * 2

// Create type alias for reuse
type Transform = (Number) => Number
let aliasedType: Transform = (x: Number): Number => x * 2
```

### 6. Use Any Sparingly

```javascript
// Avoid: Too much Any defeats the purpose
let badFunction = (x: Any, y: Any, z: Any): Any => x

// Better: Specific types where possible
let betterFunction = (x: Number, y: String, z: Boolean): Number =>
    if(z, x, x * 2)

// OK: Any for truly dynamic scenarios
let jsonParse = (text: String): Any => do {
    // Parsing returns unknown structure
    {}
}
```

## Common Patterns

### Optional Parameters

```javascript
type OptionalConfig = Any | null

let initialize = (config: OptionalConfig): Boolean => do {
    if(config == null,
       do {
           // Use defaults
           true
       },
       do {
           // Use provided config
           true
       })
}
```

### Result Types

```javascript
type Success = {status: String, data: Any}
type Error = {status: String, message: String}
type Result = Success | Error

let fetchData = (url: String): Result => do {
    // Return success or error
    {status: "success", data: []}
}
```

### Callback Patterns

```javascript
type Callback = (Any) => Any | null
type ErrorCallback = (String) => Boolean

let asyncOperation = (
    onSuccess: Callback,
    onError: ErrorCallback
): Boolean => do {
    // Perform operation
    true
}
```

### Pipeline Types

```javascript
type Transform = (Any) => Any

let pipeline = (transforms: Any, initial: Any): Any =>
    reduce((acc, f: Transform) => f(acc), initial, transforms)
```

## Summary

The gradual type system in Achronyme provides:

- **Basic type annotations**: `Number`, `String`, `Boolean`, `Complex`, `Edge`
- **Union types**: `Type1 | Type2` for values that can be multiple types
- **Optional types**: `Type | null` for nullable values
- **Function types**: `(Params): ReturnType` for function signatures
- **Type aliases**: `type Name = TypeDefinition` for custom type names
- **Any type**: Opt-out of type checking for dynamic code
- **Type inference**: Automatic type propagation from annotations

Key benefits:
- **Gradual adoption**: Add types incrementally to existing code
- **Safety**: Catch type errors before runtime
- **Documentation**: Types serve as documentation
- **Flexibility**: Use `Any` when needed for dynamic scenarios
- **Expressiveness**: Union and function types handle complex scenarios

Remember:
- Types are **optional** - untyped code still works
- Use types for **critical** functions first
- Create **meaningful aliases** for domain concepts
- Union types are great for **error handling** and **optional values**
- **Any** should be used sparingly and intentionally

---

**Next**: Continue exploring the language with [Examples](24-examples.md) or review [Best Practices](23-best-practices.md)
