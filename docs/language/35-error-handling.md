# Error Handling

Achronyme provides a comprehensive error handling system with `try/catch/throw` expressions, structured error values, and type-safe error management.

## Overview

The error handling system features:
- **try/catch expressions** - Catch and handle errors gracefully
- **throw statements** - Explicitly throw errors with structured data
- **Error type** - First-class error values with message, kind, and source fields
- **Expression-based** - try/catch returns a value, integrating with functional style
- **Runtime error capture** - Automatically catches division by zero, type errors, etc.

## Basic Error Handling

### Try/Catch Expressions

The `try/catch` construct is an expression that returns a value:

```javascript
let result = try {
    riskyOperation()
} catch (e) {
    "default value"
};
```

If the try block succeeds, its value is returned. If an error occurs, the catch block handles it.

### Throw Statements

Throw errors explicitly with the `throw` keyword:

```javascript
throw "Simple error message"

throw {
    message: "Detailed error",
    kind: "ValidationError"
}
```

## Error Values

### Error Structure

Error values have three fields:
- **message** (String) - Human-readable error message
- **kind** (String, optional) - Error category/type (e.g., "TypeError", "ValueError")
- **source** (Error, optional) - Original error for error chaining

### Creating Errors

```javascript
// Simple error with just a message
throw "Something went wrong"

// Structured error with kind
throw {
    message: "Invalid input: negative number",
    kind: "ValueError"
}

// Full error with source for chaining
throw {
    message: "Database operation failed",
    kind: "DatabaseError",
    source: originalError
}
```

### Accessing Error Fields

In catch blocks, access error fields with dot notation:

```javascript
try {
    throw { message: "Not found", kind: "NotFoundError" }
} catch (e) {
    print("Error: " + e.message);  // "Not found"
    print("Kind: " + e.kind);       // "NotFoundError"
}
```

## Practical Examples

### Safe Division

```javascript
let safeDivide = (a, b) => try {
    a / b
} catch (e) {
    0  // Return 0 on division by zero
};

safeDivide(10, 2)   // => 5
safeDivide(10, 0)   // => 0
```

### Input Validation

```javascript
let validateAge = (age: Number): Number => do {
    if (age < 0) {
        throw { message: "Age cannot be negative", kind: "ValidationError" }
    };
    if (age > 150) {
        throw { message: "Age seems unrealistic", kind: "ValidationError" }
    };
    age
};

let processAge = (input) => try {
    validateAge(input)
} catch (e) {
    print("Validation failed: " + e.message);
    0
};
```

### Nested Error Handling

```javascript
let innerOperation = () => throw "Inner error";

let outerOperation = () => try {
    innerOperation()
} catch (inner) {
    // Re-throw with context
    throw {
        message: "Outer operation failed: " + inner.message,
        kind: "ChainedError"
    }
};

let result = try {
    outerOperation()
} catch (outer) {
    "Caught: " + outer.kind + " - " + outer.message
};
// => "Caught: ChainedError - Outer operation failed: Inner error"
```

### Result Pattern

```javascript
// Function returning success value or error
let parseConfig = (text) => try {
    // Parsing logic that might fail
    let parsed = parse(text);
    { success: true, value: parsed }
} catch (e) {
    { success: false, error: e.message }
};

let config = parseConfig("invalid");
if (config.success) {
    print("Config loaded: " + str(config.value))
} else {
    print("Failed to load config: " + config.error)
}
```

### Error Type Checking

```javascript
// Declare variable as Error type
let lastError: Error = null;

let recordError = (operation) => do {
    try {
        operation()
    } catch (e) {
        lastError = e;
        null
    }
};

// Check error type at runtime
let err = try { throw "test" } catch (e) { e };
typeof(err)  // => "Error"
```

### Multiple Error Sources

```javascript
let fetchData = (url) => throw { message: "Network error", kind: "NetworkError" };
let parseData = (data) => throw { message: "Parse error", kind: "ParseError" };

let loadData = (url) => try {
    let raw = fetchData(url);
    parseData(raw)
} catch (e) {
    // Handle both network and parse errors
    if (e.kind == "NetworkError") {
        print("Check your connection")
    } else {
        print("Data format issue")
    };
    null
};
```

## Error Handling with Control Flow

### With Early Returns

```javascript
let processItems = (items) => do {
    for (i in range(0, len(items))) {
        let result = try {
            validateItem(items[i])
        } catch (e) {
            return { error: e.message, index: i }
        };
        // Continue processing...
    };
    { success: true }
}
```

### With Generators

Errors in generators are caught when iterating:

```javascript
let gen = generate {
    yield 1;
    yield 2;
    throw "Generator error";
    yield 3  // Never reached
};

let result = try {
    let sum = 0;
    for (x in gen) {
        sum = sum + x
    };
    sum
} catch (e) {
    print("Generator failed: " + e.message);
    0
}
```

## Runtime Errors

The try/catch system automatically captures runtime errors:

```javascript
// Division by zero
try { 10 / 0 } catch (e) { e.message }
// => "Division by zero"

// Type errors
try { "text" + 5 } catch (e) { e.kind }
// => "TypeError"

// Index out of bounds
try { [1, 2, 3][10] } catch (e) { e.message }
// => "Index out of bounds"
```

## Best Practices

1. **Use structured errors** - Include kind for categorization
2. **Catch specific errors** - Check e.kind to handle different error types
3. **Provide context** - Add meaningful messages when re-throwing
4. **Handle at boundaries** - Catch errors at API/module boundaries
5. **Default values** - Use try/catch for safe defaults instead of null checks
6. **Fail fast** - Throw early with descriptive messages
7. **Log and recover** - In catch blocks, log errors before returning defaults

## Type System Integration

Error is a first-class type in the gradual type system:

```javascript
// Type annotation
let e: Error = try { throw "test" } catch (err) { err };

// Union with Error
let result: Number | Error = try {
    riskyCalculation()
} catch (e) {
    e
};

// Function returning Error
let validate = (x: Any): null | Error => do {
    if (!isValid(x)) {
        throw { message: "Invalid", kind: "ValidationError" }
    };
    null
};

// Type alias
type ValidationResult = String | Error;
```
