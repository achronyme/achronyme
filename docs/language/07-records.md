# Records

Records are key-value structures similar to objects in other languages. They support methods, self-reference, mutable fields, and OOP patterns.

## Creating Records

### Basic Syntax

```javascript
{
    name: "Alice",
    age: 30,
    city: "Madrid"
}
```

### Empty Record

```javascript
{}
```

## Accessing Fields

```javascript
let person = {name: "Bob", age: 25}

person.name    // "Bob"
person.age     // 25
```

## Nested Records

```javascript
let user = {
    name: "Alice",
    address: {
        street: "Main St",
        city: "Madrid",
        zip: "28001"
    }
}

user.address.city  // "Madrid"
```

## Optional Fields

Records can have optional fields using the `?` syntax in type annotations. Optional fields may be absent from the record.

### Defining Optional Fields

```achronyme
// Type with optional fields
type User = {name: String, email?: String, age?: Number}

// The field can be present or absent
let user1: User = {name: "Alice"}  // OK - email and age are optional
let user2: User = {name: "Bob", email: "bob@example.com"}  // OK
let user3: User = {name: "Charlie", email: "charlie@example.com", age: 30}  // OK
```

### Optional Fields as Union Types

An optional field `field?: Type` is equivalent to `field: Type | null`. The field can hold a value of the specified type or be absent (treated as `null`).

```achronyme
type Config = {
    timeout?: Number,      // timeout is Number | null
    retries?: Number,      // retries is Number | null
    verbose?: Boolean      // verbose is Boolean | null
}

let defaultConfig: Config = {}  // All optional fields absent
let customConfig: Config = {timeout: 5000, verbose: true}
```

### Working with Optional Fields

Use pattern matching or conditionals to handle optional fields:

```achronyme
type User = {name: String, email?: String}

let sendGreeting = (user: User) => match user.email {
    null => 'Hello, ${user.name}!'
    email => 'Hello, ${user.name}! We\'ll contact you at ${email}'
}

let user1 = {name: "Alice"}
let user2 = {name: "Bob", email: "bob@example.com"}

sendGreeting(user1)  // "Hello, Alice!"
sendGreeting(user2)  // "Hello, Bob! We'll contact you at bob@example.com"
```

### Use Cases

**Configuration Objects:**
```achronyme
type DatabaseConfig = {
    host: String,
    port?: Number,        // Defaults to 5432 if not provided
    username: String,
    password: String,
    ssl?: Boolean         // Defaults to false if not provided
}

let config: DatabaseConfig = {
    host: "localhost",
    username: "admin",
    password: "secret"
}
```

**API Responses:**
```achronyme
type ApiResponse = {
    status: Number,
    data?: Record,
    error?: String
}

let successResponse: ApiResponse = {
    status: 200,
    data: {id: 1, name: "Alice"}
}

let errorResponse: ApiResponse = {
    status: 404,
    error: "Not found"
}
```

**User Profiles:**
```achronyme
type Profile = {
    id: Number,
    username: String,
    bio?: String,
    avatar?: String,
    location?: String
}

let minimalProfile: Profile = {id: 1, username: "alice"}
let fullProfile: Profile = {
    id: 2,
    username: "bob",
    bio: "Software developer",
    avatar: "https://example.com/bob.jpg",
    location: "Madrid"
}
```

## Records with Methods

### Using `self` Reference

The `self` keyword refers to the current record:

```javascript
let circle = {
    radius: 5,
    area: () => 3.14159 * self.radius^2,
    circumference: () => 2 * 3.14159 * self.radius
}

circle.area()           // 78.53975
circle.circumference()  // 31.4159
```

### Method Calls

Methods automatically have access to `self`:

```javascript
let point = {
    x: 3,
    y: 4,
    distance: () => sqrt(self.x^2 + self.y^2)
}

point.distance()  // 5.0
```

## OOP Patterns

### Constructor Pattern

```javascript
let Point = {
    new: (x, y) => {
        x: x,
        y: y,
        distance: () => sqrt(self.x^2 + self.y^2)
    }
}

let p1 = Point.new(3, 4)
p1.distance()  // 5.0
```

### Inheritance with Spread

```javascript
let Animal = {
    name: "Unknown",
    speak: () => "..."
}

let Dog = {
    ...Animal,
    speak: () => "Woof!",
    breed: "Labrador"
}

Dog.speak()    // "Woof!"
Dog.breed      // "Labrador"
```

### Prototype Pattern

```javascript
let prototype = {
    getValue: () => self.value,
    double: () => self.value * 2
}

let obj1 = {...prototype, value: 10}
let obj2 = {...prototype, value: 20}

obj1.getValue()  // 10
obj2.double()    // 40
```

## Spread Operator

### Copying Records

```javascript
let original = {a: 1, b: 2}
let copy = {...original}
```

### Merging Records

```javascript
let defaults = {timeout: 1000, retries: 3}
let options = {retries: 5, verbose: true}

let config = {...defaults, ...options}
// {timeout: 1000, retries: 5, verbose: true}
```

### Extending Records

```javascript
let base = {
    x: 0,
    y: 0
}

let point = {
    ...base,
    z: 0,
    magnitude: () => sqrt(self.x^2 + self.y^2 + self.z^2)
}
```

## Advanced Patterns

### Mixins

```javascript
let Serializable = {
    toJSON: () => "..." // implementation
}

let Comparable = {
    equals: other => self.id == other.id
}

let Entity = {
    ...Serializable,
    ...Comparable,
    id: 1
}
```

### State Machine

```javascript
let machine = {
    state: "idle",
    setState: newState => {...self, state: newState},
    isIdle: () => self.state == "idle",
    isRunning: () => self.state == "running"
}
```

### Builder Pattern

```javascript
let QueryBuilder = {
    table: "",
    filters: [],
    from: t => {...self, table: t},
    where: f => {...self, filters: [...self.filters, f]},
    build: () => "SQL: ..."
}

let query = QueryBuilder
    .from("users")
    .where("age > 18")
    .where("active = true")
```

## Record Functions

### keys()

Get record keys:

```javascript
let obj = {a: 1, b: 2, c: 3}
keys(obj)  // Count: 3
```

### values()

Get record values:

```javascript
let obj = {a: 1, b: 2}
values(obj)  // Vector of values
```

### has_field()

Check if field exists:

```javascript
let obj = {name: "Alice"}
has_field(obj, "name")  // true
has_field(obj, "age")   // false
```

## Best Practices

### 1. Group Related Data

```javascript
// Good
let user = {
    id: 1,
    name: "Alice",
    email: "alice@example.com"
}

// Avoid
let userId = 1
let userName = "Alice"
let userEmail = "alice@example.com"
```

### 2. Use Methods for Computed Values

```javascript
// Good
let rect = {
    width: 10,
    height: 20,
    area: () => self.width * self.height
}

// Avoid storing computed values
let rect = {
    width: 10,
    height: 20,
    area: 200  // What if width/height change?
}
```

### 3. Consistent Field Naming

```javascript
// Good
{firstName: "Alice", lastName: "Smith"}

// Avoid mixing styles
{first_name: "Alice", LastName: "Smith"}
```

## Common Patterns

### Configuration Objects

```javascript
let config = {
    debug: false,
    timeout: 5000,
    retries: 3,
    logLevel: "info"
}
```

### Data Transfer Objects

```javascript
let response = {
    status: 200,
    data: {id: 1, name: "Alice"},
    timestamp: 1640000000
}
```

### Virtual Fields

```javascript
let user = {
    firstName: "Alice",
    lastName: "Smith",
    fullName: () => concat(self.firstName, concat(" ", self.lastName))
}
```

## Summary

- Records are key-value structures
- Access fields with `.` notation
- Optional fields with `field?: Type` syntax
- Methods use `self` to reference the record
- Spread operator (`...`) for copying/merging
- Support OOP patterns (inheritance, mixins)
- Immutable by default (operations create new records)
- **For mutable fields, see [Mutability](26-mutability.md)**

---

**Next**: [Control Flow](08-control-flow.md)
