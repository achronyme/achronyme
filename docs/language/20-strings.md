# String Manipulation in Achronyme

Strings in Achronyme are a fundamental data type for text processing. This guide covers string literals, functions, operations, and advanced features including case conversion, trimming, searching, and padding.

## String Literals

### Basic String Syntax

Achronyme supports two types of string literals:

1. **Double-quoted strings** - Literal strings (no interpolation)
2. **Single-quoted strings** - Template strings with interpolation

```achronyme
let greeting = "Hello"          // Literal string
let name = "Achronyme"          // Literal string
let empty = ""                  // Empty string

let message = 'Hello, ${name}!' // Interpolated string
```

### Escape Sequences

Achronyme supports the following escape sequences within string literals:

| Escape Sequence | Result | Description |
|---|---|---|
| \n | Newline | Line break |
| \t | Tab | Horizontal tab |
| \r | Carriage Return | Carriage return character |
| \\ | Backslash | Literal backslash character |
| \" | Double Quote | Literal double quote character |
| \' | Single Quote | Literal single quote character |
| \$ | Dollar Sign | Literal $ (in single-quoted strings) |

### Unicode Support

Strings fully support Unicode characters, including emoji and international characters.

## String Interpolation

Single-quoted strings support string interpolation using `${expression}` syntax.

### Basic Interpolation

```achronyme
let name = "Alice"
let age = 30

'Hello, ${name}!'                    // "Hello, Alice!"
'You are ${age} years old'           // "You are 30 years old"
'Next year you will be ${age + 1}'   // "Next year you will be 31"
```

### Expressions in Interpolation

You can use any valid expression inside `${}`:

```achronyme
// Arithmetic
'Sum: ${10 + 20}'                    // "Sum: 30"
'Product: ${5 * 7}'                  // "Product: 35"

// Function calls
'Square root: ${sqrt(16)}'           // "Square root: 4"
'Uppercase: ${upper("hello")}'       // "Uppercase: HELLO"

// Conditional expressions
let age = 25
'Status: ${if(age >= 18) { "adult" } else { "minor" }}'  // "Status: adult"
```

### Record Field Access

```achronyme
let point = {x: 10, y: 20}
'Point: (${point.x}, ${point.y})'    // "Point: (10, 20)"

let user = {name: "Bob", email: "bob@example.com"}
'User ${user.name} - ${user.email}'  // "User Bob - bob@example.com"
```

### Multiple Interpolations

```achronyme
let first = "John"
let last = "Doe"
let age = 42

'Name: ${first} ${last}, Age: ${age}'
// "Name: John Doe, Age: 42"
```

### Escaping in Interpolated Strings

To include a literal `${` in an interpolated string, escape the dollar sign:

```achronyme
'Price: \${100}'                     // "Price: ${100}"
'Use \${variable} syntax'            // "Use ${variable} syntax"
'It\'s working!'                     // "It's working!"
```

### Important: Double vs Single Quotes

**Single quotes (`'...'`)** - Interpolation enabled:
```achronyme
let name = "Alice"
'Hello, ${name}!'                    // "Hello, Alice!"
```

**Double quotes (`"..."`)** - Literal string, NO interpolation:
```achronyme
let name = "Alice"
"Hello, ${name}!"                    // "Hello, ${name}!" (literal)
```

### Practical Examples

**Formatting Messages:**
```achronyme
let formatGreeting = (name, time) => 'Good ${time}, ${name}!'
formatGreeting("Alice", "morning")   // "Good morning, Alice!"
```

**Building URLs:**
```achronyme
let userId = 123
let action = "profile"
let url = 'https://api.com/users/${userId}/${action}'
// "https://api.com/users/123/profile"
```

**Logging with Values:**
```achronyme
let value = 42
let max = 100
'Progress: ${value}/${max} (${(value / max) * 100}%)'
// "Progress: 42/100 (42%)"
```

**Conditional Formatting:**
```achronyme
let count = 5
'You have ${count} ${if(count == 1) { "item" } else { "items" }}'
// "You have 5 items"
```

**Mathematical Expressions:**
```achronyme
let radius = 5
'Circle area: ${PI * radius^2}'     // "Circle area: 78.53981633974483"
'Circumference: ${2 * PI * radius}' // "Circumference: 31.41592653589793"
```

## String Operators

### String Concatenation with +

Strings can be concatenated using the `+` operator:

```achronyme
"hello" + " " + "world"  // "hello world"
"a" + "b" + "c"          // "abc"

let greeting = "Hello"
let name = "Alice"
greeting + ", " + name + "!"  // "Hello, Alice!"
```

### String Equality

Strings support equality and inequality comparison operators.

**Operators:** ==, !=

**Examples:**
```achronyme
"hello" == "hello"  // true
"hello" != "world"  // true
```

**Case Sensitivity:** String comparison is case-sensitive.

## String Functions

### Basic Functions

#### concat(s1, s2)

Concatenates two strings.

**Signature:** concat(String, String) -> String

**Note:** String concatenation is now also available via the `+` operator.

**Examples:**
```achronyme
concat("Hello", " World")      // "Hello World"
concat("Achronyme", " Language")

// Equivalent using + operator
"Hello" + " World"             // "Hello World"
```

#### length(s)

Returns the length of a string in characters.

**Signature:** length(String) -> Number

**Examples:**
```achronyme
length("hello")    // 5
length("testing")  // 7
length("")         // 0
```

### Case Conversion

#### upper(s)

Converts a string to uppercase.

**Signature:** upper(String) -> String

**Examples:**
```achronyme
upper("hello")         // "HELLO"
upper("Hello World")   // "HELLO WORLD"
upper("ALREADY UPPER") // "ALREADY UPPER"
```

#### lower(s)

Converts a string to lowercase.

**Signature:** lower(String) -> String

**Examples:**
```achronyme
lower("HELLO")        // "hello"
lower("Hello World")  // "hello world"
lower("already lower")// "already lower"
```

### Whitespace Handling

#### trim(s)

Removes whitespace from both ends of a string.

**Signature:** trim(String) -> String

**Examples:**
```achronyme
trim("  hello  ")      // "hello"
trim("\n\thello\t\n")  // "hello"
trim("hello")          // "hello"
trim("   ")            // ""
```

#### trim_start(s)

Removes whitespace from the start of a string.

**Signature:** trim_start(String) -> String

**Examples:**
```achronyme
trim_start("  hello  ")  // "hello  "
trim_start("\n\thello")  // "hello"
```

#### trim_end(s)

Removes whitespace from the end of a string.

**Signature:** trim_end(String) -> String

**Examples:**
```achronyme
trim_end("  hello  ")  // "  hello"
trim_end("hello\n\t")  // "hello"
```

### Search Functions

#### starts_with(s, prefix)

Checks if a string starts with a given prefix.

**Signature:** starts_with(String, String) -> Boolean

**Examples:**
```achronyme
starts_with("hello world", "hello")  // true
starts_with("hello world", "world")  // false
starts_with("hello", "hello")        // true
starts_with("hello", "")             // true (empty prefix)
```

#### ends_with(s, suffix)

Checks if a string ends with a given suffix.

**Signature:** ends_with(String, String) -> Boolean

**Examples:**
```achronyme
ends_with("hello world", "world")  // true
ends_with("hello world", "hello")  // false
ends_with("world", "world")        // true
```

#### contains(s, substring)

Checks if a string contains a substring.

**Signature:** contains(String, String) -> Boolean

**Note:** This function also works with arrays. See [Higher-Order Functions](11-higher-order-functions.md) for array usage.

**Examples:**
```achronyme
contains("hello world", "world")  // true
contains("hello", "bye")          // false
```

### String Manipulation

#### replace(s, pattern, replacement)

Replaces all occurrences of a pattern with a replacement string.

**Signature:** replace(String, String, String) -> String

**Examples:**
```achronyme
replace("hello world", "world", "rust")  // "hello rust"
replace("aaa", "a", "b")                 // "bbb"
replace("hello", "xyz", "abc")           // "hello" (no match)
```

#### split(s, delimiter)

Splits a string by a delimiter into an array of strings.

**Signature:** split(String, String) -> Vector

**Examples:**
```achronyme
split("a,b,c", ",")              // ["a", "b", "c"]
split("hello world test", " ")   // ["hello", "world", "test"]
split("hello", ",")              // ["hello"] (no delimiter found)
```

#### join(array, delimiter)

Joins an array of strings with a delimiter.

**Signature:** join(Vector, String) -> String

**Examples:**
```achronyme
join(["a", "b", "c"], ",")       // "a,b,c"
join(["hello", "world"], " ")    // "hello world"
join(["a", "b", "c"], "")        // "abc"
join(["hello"], ",")             // "hello"
```

### Padding Functions

#### pad_start(s, length, fill_char?)

Pads a string at the start to reach a target length.

**Signature:** pad_start(String, Number, String?) -> String

**Default fill character:** space (' ')

**Examples:**
```achronyme
pad_start("5", 3)         // "  5"
pad_start("5", 3, "0")    // "005"
pad_start("hello", 3)     // "hello" (already long enough)
pad_start("42", 10, "0")  // "0000000042"
```

#### pad_end(s, length, fill_char?)

Pads a string at the end to reach a target length.

**Signature:** pad_end(String, Number, String?) -> String

**Default fill character:** space (' ')

**Examples:**
```achronyme
pad_end("5", 3)        // "5  "
pad_end("5", 3, "0")   // "500"
pad_end("hello", 3)    // "hello" (already long enough)
```

## String Indexing and Slicing

Strings support both single-character indexing and range-based slicing.

### Single Character Indexing

**Syntax:** string[index]

Returns a single character as a string.

**Examples:**
```achronyme
let word = "hello"
word[0]    // "h"
word[-1]   // "o" (last character)
```

### String Slicing

**Syntax:** string[start..end], string[start..], string[..end], string[..]

Returns a substring as a string.

**Examples:**
```achronyme
let message = "Hello, World!"
message[0..5]   // "Hello"
message[7..]    // "World!"
message[..5]    // "Hello"
message[-6..]   // "World!"
```

**Implementation:** index_string() in crates/achronyme-eval/src/handlers/indexing.rs (lines 127-147)

## Practical Examples

### Text Processing Pipeline

```achronyme
// Clean and normalize text
let process_text = text => {
    let cleaned = trim(text);
    let normalized = lower(cleaned);
    normalized
}

process_text("  HELLO WORLD  ")  // "hello world"
```

### CSV Processing

```achronyme
// Parse CSV line
let csv_line = "Alice,30,Engineer"
let fields = split(csv_line, ",")
// ["Alice", "30", "Engineer"]

// Join fields back
join(fields, "|")  // "Alice|30|Engineer"
```

### String Formatting with map

```achronyme
// Format list of names
let names = ["alice", "bob", "charlie"]
let formatted = map(name => upper(name), names)
join(formatted, ", ")  // "ALICE, BOB, CHARLIE"
```

### Table Formatting

```achronyme
// Create formatted table row
let name = "Alice"
let age = "25"
let city = "NYC"

let row = pad_end(name, 15) + pad_end(age, 5) + city
// "Alice          25   NYC"
```

### Text Transformation

```achronyme
// Convert semicolon-separated to comma-separated
let text = "a;b;c;d"
let normalized = replace(text, ";", ",")
split(normalized, ",")  // ["a", "b", "c", "d"]
```

### Case-Insensitive Comparison

```achronyme
let compare_ignore_case = (s1, s2) => lower(s1) == lower(s2)

compare_ignore_case("HELLO", "hello")  // true
compare_ignore_case("World", "WORLD")  // true
```

## Limitations

### No Regex Support

Pattern matching and regular expressions are not supported. Use `contains`, `starts_with`, `ends_with`, and `replace` for basic pattern operations.

### No Direct String Iteration

Higher-order functions (map, filter, reduce) do not work with strings directly. Use `split` to convert to an array first:

```achronyme
// Split into characters, transform, rejoin
let chars = split("hello", "")
let upper_chars = map(c => upper(c), chars)
join(upper_chars, "")  // "HELLO"
```

### Printf-style Formatting

While Achronyme now supports string interpolation with `'${}'`, there is no printf-style format specifiers (like `%d`, `%f`, etc.). For precise formatting:

```achronyme
let name = "Alice"
let age = 30

// Use string interpolation (recommended)
let message = 'Name: ${name}, Age: ${age}'

// Or concatenation with formatting functions
let formatted = "Score: " + pad_start(age, 3, "0")
```

## Implementation Details

### String Storage

- Type: Value::String(String) in the value enum
- Storage: UTF-8 encoded Rust String
- Memory: Heap-allocated, supports arbitrary length

### Built-in Functions

| Function | Arity | Location |
|---|---|---|
| concat | 2 | crates/achronyme-eval/src/function_modules/strings.rs |
| length | 1 | crates/achronyme-eval/src/function_modules/strings.rs |
| upper | 1 | crates/achronyme-eval/src/function_modules/strings.rs |
| lower | 1 | crates/achronyme-eval/src/function_modules/strings.rs |
| trim | 1 | crates/achronyme-eval/src/function_modules/strings.rs |
| trim_start | 1 | crates/achronyme-eval/src/function_modules/strings.rs |
| trim_end | 1 | crates/achronyme-eval/src/function_modules/strings.rs |
| starts_with | 2 | crates/achronyme-eval/src/function_modules/strings.rs |
| ends_with | 2 | crates/achronyme-eval/src/function_modules/strings.rs |
| contains | 2 | crates/achronyme-eval/src/function_modules/array.rs (also works with arrays) |
| replace | 3 | crates/achronyme-eval/src/function_modules/strings.rs |
| split | 2 | crates/achronyme-eval/src/function_modules/strings.rs |
| join | 2 | crates/achronyme-eval/src/function_modules/strings.rs |
| pad_start | 2-3 | crates/achronyme-eval/src/function_modules/strings.rs |
| pad_end | 2-3 | crates/achronyme-eval/src/function_modules/strings.rs |

### Operators

| Operator | Operation | Location |
|---|---|---|
| + | String concatenation | crates/achronyme-eval/src/handlers/binary_ops.rs (lines 160-163) |
| == | String equality | crates/achronyme-eval/src/handlers/binary_ops.rs |
| != | String inequality | crates/achronyme-eval/src/handlers/binary_ops.rs |

### String Parsing

String literals are parsed by the Pest PEG parser:

- Grammar Rule: string_literal in crates/achronyme-parser/src/grammar.pest (lines 49-56)
- Character Matching: string_char rule supports escape sequences
- Processing: process_escape_sequences() in crates/achronyme-parser/src/pest_parser.rs (lines 416-445)

## Summary

Achronyme provides comprehensive string manipulation capabilities:

**String Literals:**
- Double quotes (`"..."`) - Literal strings
- Single quotes (`'...'`) - Interpolated strings with `${expression}`

**Operators:**
- `+` for concatenation
- `==` and `!=` for comparison

**Functions:**
- **Basic**: `concat`, `length`
- **Case**: `upper`, `lower`
- **Whitespace**: `trim`, `trim_start`, `trim_end`
- **Search**: `starts_with`, `ends_with`, `contains`
- **Manipulation**: `replace`, `split`, `join`
- **Padding**: `pad_start`, `pad_end`

**Features:**
- Unicode support
- String interpolation (`'Hello, ${name}!'`)
- Escape sequences
- Indexing and slicing
- Immutable operations

## Related Documentation

- [Data Types](03-data-types.md)
- [Operators](04-operators.md)
- [Indexing and Slicing](10-indexing-slicing.md)
- [Higher-Order Functions](11-higher-order-functions.md)
- [Functions](06-functions.md)

## See Also

- Test file: crates/achronyme-eval/tests/test_strings.rs
- Test file: crates/achronyme-eval/tests/test_string_functions.rs
