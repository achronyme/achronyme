---
title: "Mutability"
description: "Mutable variables, mutable record fields, and stateful objects in Achronyme"
section: "advanced-topics"
order: 4
---


While Achronyme follows an **immutable-by-default** philosophy, it provides controlled mutability through the `mut` keyword for scenarios where mutable state is more natural or efficient.

## Why Mutability?

Immutability is powerful for functional programming, but some use cases benefit from mutation:

- **Stateful objects**: Counters, accumulators, configuration objects
- **Performance**: Avoiding unnecessary copies in hot loops
- **Natural modeling**: Some algorithms are clearer with mutable state
- **Records as objects**: Object-oriented patterns with encapsulated state

## Mutable Variables

### Declaration

Use `mut` instead of `let` to declare a mutable variable:

```javascript
// Immutable (default)
let x = 10
// x = 20  // ERROR: Cannot reassign immutable variable

// Mutable
mut counter = 0
counter = counter + 1  // OK: counter is now 1
counter = 5            // OK: counter is now 5
```

### Reassignment

Once declared with `mut`, a variable can be reassigned to any value:

```javascript
mut total = 0
total = total + 10
total = total + 20
total  // Returns: 30

// Can reassign to different types (dynamic typing)
mut x = 10
x = 20        // Number to Number
x = "text"    // Number to String - OK
x = [1, 2, 3] // String to Array - OK
x = () => 42  // Array to Function - OK
```

**Note**: Achronyme uses dynamic typing. While you *can* change types, it's the programmer's responsibility to maintain type consistency for code clarity and correctness.

## Mutable Record Fields

Records can have a mix of mutable and immutable fields:

### Syntax

```javascript
let config = {
    mut valor: 10,        // Mutable field
    inmutable: 20,        // Immutable field
    mut debug: true       // Mutable field
}
```

### Field Assignment

```javascript
// Mutable fields can be reassigned
config.valor = 30      // OK
config.debug = false   // OK

// Immutable fields cannot
// config.inmutable = 25  // ERROR: Cannot assign to immutable field
```

### Complete Example

```javascript
let settings = {
    // Immutable configuration
    appName: "Calculator",
    version: "1.0",

    // Mutable state
    mut windowWidth: 800,
    mut windowHeight: 600,
    mut darkMode: false,

    // Methods
    toggleDarkMode: () => do {
        self.darkMode = !self.darkMode
    },

    resize: (w, h) => do {
        self.windowWidth = w
        self.windowHeight = h
    }
}

// Usage
settings.toggleDarkMode()
settings.resize(1024, 768)
```

## Methods with Self-Reference

Records can have methods that mutate their own fields using `self`:

### Basic Counter

```javascript
let contador = {
    mut valor: 0,

    incrementar: () => do {
        self.valor = self.valor + 1
    },

    decrementar: () => do {
        self.valor = self.valor - 1
    },

    reset: () => do {
        self.valor = 0
    },

    obtener: () => self.valor
}

// Usage
contador.incrementar()
contador.incrementar()
contador.incrementar()
contador.obtener()  // Returns: 3

contador.reset()
contador.obtener()  // Returns: 0
```

### Accumulator

```javascript
let acumulador = {
    mut total: 0,
    mut count: 0,

    agregar: (x) => do {
        self.total = self.total + x
        self.count = self.count + 1
    },

    promedio: () => if(
        self.count == 0,
        0,
        self.total / self.count
    ),

    reset: () => do {
        self.total = 0
        self.count = 0
    }
}

// Usage
acumulador.agregar(10)
acumulador.agregar(20)
acumulador.agregar(30)
acumulador.promedio()  // Returns: 20
```

### Bank Account Example

```javascript
let cuenta = {
    titular: "Alice",          // Immutable
    mut saldo: 1000,           // Mutable
    mut transacciones: [],     // Mutable

    depositar: (monto) => do {
        self.saldo = self.saldo + monto
        self.transacciones = [...self.transacciones, {
            tipo: "deposito",
            monto: monto
        }]
    },

    retirar: (monto) => if(
        monto > self.saldo,
        "Fondos insuficientes",
        do {
            self.saldo = self.saldo - monto
            self.transacciones = [...self.transacciones, {
                tipo: "retiro",
                monto: monto
            }]
            "Retiro exitoso"
        }
    ),

    consultarSaldo: () => self.saldo
}

// Usage
cuenta.depositar(500)
cuenta.consultarSaldo()  // Returns: 1500
cuenta.retirar(200)
cuenta.consultarSaldo()  // Returns: 1300
```

### Nested Configuration Example

Records can have deeply nested mutable state:

```javascript
let application = {
    name: "MyApp",  // Immutable
    mut settings: {
        mut theme: "dark",
        mut fontSize: 14,
        mut notifications: {
            mut email: true,
            mut push: false,
            mut sound: true
        }
    },

    // Methods that mutate nested state
    toggleTheme: () => do {
        self.settings.theme = if(
            self.settings.theme == "dark",
            "light",
            "dark"
        )
    },

    enableAllNotifications: () => do {
        self.settings.notifications.email = true
        self.settings.notifications.push = true
        self.settings.notifications.sound = true
    },

    increaseFontSize: () => do {
        self.settings.fontSize = self.settings.fontSize + 2
    }
}

// Usage - nested field assignment works!
application.settings.theme = "light"
application.settings.notifications.push = true
application.toggleTheme()  // back to "dark"
```

## Closures and Mutable Captures

Lambdas can capture and mutate variables from outer scopes:

```javascript
mut counter = 0

let increment = () => do {
    counter = counter + 1
}

// Each call mutates the captured variable
increment()  // counter = 1
increment()  // counter = 2
increment()  // counter = 3
counter      // Returns: 3
```

### Factory Pattern

```javascript
let createCounter = (initial) => {
    mut count = initial

    {
        increment: () => do { count = count + 1 },
        decrement: () => do { count = count - 1 },
        get: () => count,
        reset: () => do { count = initial }
    }
}

// Create independent counters
let counter1 = createCounter(0)
let counter2 = createCounter(100)

counter1.increment()
counter1.increment()
counter1.get()  // Returns: 2

counter2.increment()
counter2.get()  // Returns: 101
```

## Do Blocks and Assignment

Assignments are statements, not expressions, so they require `do` blocks in certain contexts:

### In Lambda Bodies

```javascript
// ERROR: Assignment not allowed in expression context
// let f = () => x = 10

// Correct: Use do block
let f = () => do {
    x = 10
}
```

### Multiple Assignments

```javascript
mut x = 0
mut y = 0

let update = () => do {
    x = x + 1
    y = y + 2
    x + y  // Return value of do block
}

update()  // Returns: 3 (x=1, y=2)
```

## Validation and Restrictions

### Lvalue Validation

Only valid lvalues can be assignment targets:

```javascript
mut x = 10
x = 20           // OK: Variable

let config = { mut valor: 5 }
config.valor = 8  // OK: Mutable field

// Invalid assignments
// 42 = x                  // ERROR: Cannot assign to literal
// (x + y) = 10            // ERROR: Cannot assign to expression
// getData() = x           // ERROR: Cannot assign to function call
// arr[0] = 10             // ERROR: Index assignment not yet supported
```

### Immutability Enforcement

```javascript
// Cannot reassign immutable variable
let x = 10
// x = 20  // ERROR: Cannot assign to immutable variable 'x'

// Cannot reassign immutable field
let config = { valor: 5 }
// config.valor = 8  // ERROR: Cannot assign to immutable field 'valor'
```

### Dynamic Typing

Achronyme uses dynamic typing, so variables can be reassigned to different types:

```javascript
mut x = 10
x = 20        // OK: Number to Number
x = "text"    // OK: Reassign to String
x = [1, 2, 3] // OK: Reassign to Array
x = () => 42  // OK: Reassign to Function

// This is the programmer's responsibility
// Type checking happens at runtime when operations are performed
```

**Note**: While this provides flexibility, it's the programmer's responsibility to maintain type consistency. Future versions may add optional type annotations.

## Patterns and Best Practices

### 1. Prefer Immutability

Use mutation only when it improves clarity or performance:

```javascript
// Prefer immutable
let sum = reduce((a, b) => a + b, 0, numbers)

// Use mutable only if clearer
mut total = 0
let addToTotal = x => do {
    total = total + x
}
map(addToTotal, numbers)
```

### 2. Encapsulate Mutable State

Keep mutable state private in records:

```javascript
let createStack = () => {
    mut items = []

    {
        push: (x) => do { items = [...items, x] },
        pop: () => do { items = items[0:-1] },
        peek: () => items[-1],
        size: () => length(items)
    }
}
```

### 3. Clear Intent with Naming

Use descriptive names for mutable variables:

```javascript
// Clear that this will change
mut currentIndex = 0
mut accumulator = 0
mut isRunning = true

// Vs less clear
mut x = 0
mut val = 0
mut flag = true
```

### 4. Minimize Scope

Declare mutable variables in the smallest scope possible:

```javascript
let processData = (items) => do {
    // Mutable only within this function
    mut processed = []
    mut errorCount = 0

    // Process items...

    { processed: processed, errors: errorCount }
}
```

### 5. Document Side Effects

```javascript
// BAD: Hidden mutation
let incrementCounter = () => do {
    globalCounter = globalCounter + 1
}

// GOOD: Clear that it mutates
let contador = {
    mut valor: 0,
    // Clearly a mutating method
    incrementar: () => do {
        self.valor = self.valor + 1
    }
}
```

## Common Patterns

### State Machine

```javascript
let trafficLight = {
    mut state: "red",

    next: () => do {
        self.state = if(self.state == "red", "green",
                     if(self.state == "green", "yellow",
                     "red"))
    },

    getState: () => self.state
}
```

### Iterator

```javascript
let createIterator = (arr) => {
    mut index = 0

    {
        hasNext: () => index < length(arr),
        next: () => do {
            let value = arr[index]
            index = index + 1
            value
        },
        reset: () => do { index = 0 }
    }
}
```

### Builder Pattern

```javascript
let createQueryBuilder = () => {
    mut filters = []
    mut sortBy = ""
    mut limit = 100

    {
        where: (field, op, value) => do {
            self.filters = [...self.filters, {field, op, value}]
            self  // Return self for chaining
        },

        sort: (field) => do {
            self.sortBy = field
            self
        },

        take: (n) => do {
            self.limit = n
            self
        },

        build: () => {
            filters: self.filters,
            sort: self.sortBy,
            limit: self.limit
        }
    }
}

// Usage with chaining
let query = createQueryBuilder()
    .where("age", ">", 18)
    .where("active", "=", true)
    .sort("name")
    .take(50)
    .build()
```

## Performance Considerations

### When Mutation Helps

```javascript
// Immutable: Creates many intermediate arrays
let result = reduce(
    (acc, x) => [...acc, x * 2],
    [],
    largeArray
)

// Mutable: More efficient for large datasets
mut result = []
map(x => do {
    result = [...result, x * 2]
}, largeArray)
```

### When Immutability is Better

```javascript
// Immutable: Clear and composable
let processed = pipe(
    x => filter(y => y > 0, x),
    x => map(y => y * 2, x),
    x => reduce((a, b) => a + b, 0, x)
)(data)

// Mutable: More complex, harder to reason about
mut filtered = []
mut doubled = []
mut sum = 0
// ... imperative logic
```

## Limitations

### Index Assignment Not Supported

Direct index assignment is not yet implemented:

```javascript
mut arr = [1, 2, 3]
// arr[0] = 10  // ERROR: Index assignment not supported

// Workaround: Reconstruct array
arr = [10, ...arr[1:]]  // [10, 2, 3]
```

### Nested Field Assignment

Nested field assignment works correctly when all intermediate fields are mutable:

```javascript
let app = {
    mut config: {
        mut debug: true,
        version: "1.0"
    }
}

// ✅ Works: app.config.debug is mutable
app.config.debug = false  // OK

// ❌ Error: app.config itself must be mutable to reassign
// app.config = newConfig  // ERROR unless config is mut

// ✅ To reassign the whole config object, declare it as mut
let app2 = {
    mut config: {debug: true}
}
app2.config = {debug: false, newField: 10}  // OK
```

## Comparison: Mutable vs Immutable

| Aspect | Immutable | Mutable |
|--------|-----------|---------|
| **Safety** | No accidental changes | Can introduce bugs |
| **Predictability** | Always returns same value | Value changes over time |
| **Concurrency** | Thread-safe | Requires synchronization |
| **Performance** | Can create copies | Updates in place |
| **Composability** | Easy to chain | Side effects complicate |
| **Debugging** | Easier to trace | State changes harder to track |

## When to Use Each

### Use Immutable (Default)

- Pure functions and algorithms
- Data transformations
- Functional pipelines
- Mathematical computations
- When reasoning about code is critical

### Use Mutable

- Counters and accumulators
- Stateful objects (games, UIs)
- Performance-critical loops
- Natural OOP patterns
- When mutation is clearer

## Summary

- **Declaration**: `mut x = value` for mutable variables
- **Record fields**: `{mut field: value}` for mutable fields
- **Assignment**: `x = newValue` to reassign
- **Self-reference**: Methods can mutate via `self.field = value`
- **Validation**: Only valid lvalues, type-safe, immutability enforced
- **Best practice**: Prefer immutability, use mutation intentionally

Mutability in Achronyme is designed to be **explicit**, **controlled**, and **type-safe**, giving you power when needed while maintaining the benefits of functional programming by default.
