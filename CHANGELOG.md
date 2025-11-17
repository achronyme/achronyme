# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

> **Note:** This is a summary changelog. For detailed changelogs organized by version, see the [docs/changelog/](./docs/changelog/) directory.

## Quick Navigation

- **[Full Changelog Index](./docs/changelog/README.md)** - Comprehensive index with all versions
- **[Unreleased / v0.6.x](./docs/changelog/v0.6.x.md)** - Current development features
- **[Version 0.5.x](./docs/changelog/v0.5.x.md)** - Rust WASM Integration & SDK v2.0
- **[Version 0.4.x](./docs/changelog/v0.4.x.md)** - Advanced Linear Algebra
- **[Archive](./docs/changelog/archive/)** - Older versions (0.1.x - 0.3.x)

---

## [0.6.4] - 2025-11-17

### New Features

**IEEE 754 Compliance**
- Special values: `Infinity`, `-Infinity`, `NaN`
- `1/0` → `Infinity`, `0/0` → `NaN`
- `sqrt(-1)` → `0+1i` (complex, not NaN)
- Functions: `isnan()`, `isinf()`, `isfinite()`
- `NaN` is falsy and `NaN == NaN` → `false`

**Short-Circuit Logical Operators**
- `||` returns first truthy or last falsy value
- `&&` returns first falsy or last truthy value
- Falsy values: `false`, `null`, `0`, `NaN`, `""`
- Patterns: `value || default`, `condition && action`

**Range Operator**
- `1..5` → `[1, 2, 3, 4]` (exclusive)
- `1..=5` → `[1, 2, 3, 4, 5]` (inclusive)
- Works with variables: `0..n`
- In for-in loops: `for(i in 0..10) { }`

**Default Values in Destructuring**
- Record defaults: `let { name, age = 25 } = user`
- Vector defaults: `let [a, b, c = 100] = list`
- Type patterns with defaults: `let { x: Number = 10 } = data` (validation-first semantics)
- Lazy evaluation: defaults only computed when needed
- Outer scope access: defaults can use surrounding variables
- Works with `let` and `mut` bindings
- Type patterns validate types at runtime, default only used when field is missing (not as fallback)
- 55 tests verify complete implementation

**LSP Code Completion**
- 151 completion items (110 functions, 19 keywords, 9 constants, 14 types)
- Context-aware suggestions (after `let`, `import`, etc.)
- Fuzzy matching with Jaro-Winkler similarity
- Rich documentation and parameter snippets
- 13 tests

**LSP Code Formatting**
- Automatic code formatting with consistent style rules
- Operator spacing, comma normalization, brace formatting
- String-aware parsing (preserves string contents)
- 24 tests

**LSP Signature Help**
- 56+ function signatures with parameter documentation
- Active parameter highlighting
- Nested call support
- 19 tests

**CLI Format Command**
- `achronyme format file.ach` - Format source files
- `--check` flag for CI/CD pipelines
- `--diff` flag for reviewing changes

**CLI Lint Command**
- `achronyme lint file.ach` - Check for syntax errors
- `--json` flag for tooling integration

**CLI Symbols Command**
- `achronyme symbols file.ach` - List document symbols
- `--json` flag for programmatic access

**Enhanced REPL**
- Fuzzy code completion with 151 items
- Inline signature help showing active parameter
- Real-time error detection distinguishing incomplete vs invalid input
- 28 tests

**LSP-Core Shared Library**
- New `achronyme-lsp-core` crate
- Shared completion and signature data between LSP and CLI
- Eliminates ~1000 lines of code duplication

**LSP Documentation**
- 14 documentation files in `docs/lsp/`
- Installation, editor setup, features, and advanced topics
- 5,675 lines of comprehensive documentation

### Bug Fixes

- **Type patterns in destructuring now correctly bind variables**: Previously `let {x: String = "Hi"} = {}` would not create variable `x`; now properly binds `x` to the default value when field is missing

### Improvements

- Enhanced operator documentation with short-circuit semantics
- Added IEEE 754 special values section to data types
- Operator precedence updated for range operators
- Falsy value semantics clarified
- Type pattern validation-first behavior documented clearly
- 59 LSP tests, 28 REPL helper tests added
- Total test suite: 700+ tests all passing

---

## [0.6.3] - 2025-11-16

### New Features

**For-In Loops**
- Iterate over Vectors and Tensors: `for(item in collection) { ... }`
- Returns the last expression value from the loop body
- Supports nested loops

**Break and Continue Statements**
- `break` exits loops, `break value` returns a value
- `continue` skips to next iteration
- Works in both `while` and `for-in` loops

**Optional and Nullable Parameters**
- Optional parameters: `(param?: Type)` defaults to `null`
- Nullable types: `Type | null` or `?Type`
- Pattern matching for safe null handling

**Type Export in Modules**
- Export type aliases: `export { TypeName }`
- Import types from other modules
- Full module system support for custom types

**Pattern Matching Improvements**
- Fixed guard clause parsing with required parentheses
- Improved pattern compilation for nested structures

**Language Server Protocol (LSP) Server**
- Initial implementation for IDE integration
- Real-time diagnostics with parse error reporting
- Hover information for 80+ built-in functions and 20+ keywords
- Go to definition for variables and functions
- Find references across document
- Document symbols outline (variables, mutables, types)
- Tower-LSP framework with async operation

**Documentation Overhaul**
- Migrated to Astro Content Collections format
- Restructured docs/language/ into logical subdirectories
- Individual changelog files per version with YAML frontmatter
- Documentation site live at docs.achrony.me
- Corrected language philosophy and syntax documentation

### Improvements

- Clarified `{ }` creates records, `do { }` creates code blocks
- Guard clauses now require parentheses: `n if (n < 0) =>`
- Updated installation to prioritize binary downloads
- Fixed README links to new documentation structure

---

## [0.6.2] - 2025-11-15 (Unreleased)

### New Features

**Comprehensive Pattern Matching**
- Full `match` expression with pattern-based control flow
- Literal patterns for numbers, strings, and booleans
- Variable binding patterns with scoped bindings
- Wildcard pattern `_` for catch-all cases
- Record destructuring with nested patterns
- Vector/array patterns with rest syntax (`...tail`)
- Type patterns (Number, String, Boolean, Error, etc.)
- Guard clauses with `if` conditions
- First-match-wins semantics

**Pattern Matching Examples**
```javascript
// Literal and guard patterns
match x {
    0 => "zero",
    n if n > 0 => "positive",
    _ => "negative"
}

// Record destructuring
match person {
    { name: n, age: a } if a >= 18 => n + " (adult)",
    { name: n } => n + " (minor)",
    _ => "unknown"
}

// Vector patterns with rest
match list {
    [] => "empty",
    [head, ...tail] => head
}

// Type patterns
match value {
    Number => "number",
    String => "string",
    Error => "error",
    _ => "other"
}
```

**Comprehensive Error Handling System**
- Added `try/catch/throw` expressions for robust error management
- `throw` statement for explicit error throwing with structured data
- `Error` type as first-class value with `message`, `kind`, and `source` fields
- Expression-based try/catch returns value from either block
- Runtime errors (division by zero, type errors) automatically caught
- Error type integration with gradual type system

**Error Value Structure**
```javascript
// Simple throw
throw "Error message"

// Structured throw
throw { message: "Invalid input", kind: "ValidationError" }

// Try/catch expression
let result = try { riskyOp() } catch (e) { "default" }

// Access error fields
catch (e) { e.message + " (" + e.kind + ")" }
```

**Error Type in Type System**
- `Error` type annotation for variables and function signatures
- Union types with Error: `Number | Error`
- Runtime type checking: `typeof(error)` returns "Error"
- Type aliases: `type Result = Number | Error`

**Destructuring Assignment**
- Pattern-based destructuring in `let` and `mut` bindings
- Record destructuring: `let { name, age } = person`
- Vector destructuring with rest: `let [head, ...tail] = list`
- Nested patterns: `let { user: { name: n } } = data`
- Partial matching: `let { x } = { x: 1, y: 2, z: 3 }`
- Mutable destructuring: `mut { x, y } = point`
- Wildcard support: `let [first, _, third] = triple`

**Destructuring Examples**
```javascript
// Extract from records
let person = { name: "Alice", age: 30, city: "NYC" }
let { name, age } = person

// Split arrays
let list = [1, 2, 3, 4, 5]
let [head, ...tail] = list  // head=1, tail=[2,3,4,5]

// Nested extraction
let data = { result: { value: 42 } }
let { result: { value: v } } = data  // v=42
```

### Breaking Changes

**Guard Clause Syntax**
- Guard conditions now require parentheses: `if (condition)` instead of `if condition`
- This eliminates ambiguity with lambda arrow `=>` in expressions
- Consistent with if-statement syntax: `if (cond) { ... }`
- Example: `{ x: a, y: b } if (a == b) => "equal"`

---

## [0.6.1] - 2025-11-15

### Breaking Changes

**Function Type Syntax Change**
- Changed function type syntax from `(Params) => Return` to `(Params): Return`
- This eliminates grammar ambiguity with lambda arrows
- Provides consistency: `:` always means "has type" (variables, parameters, return types, function types)
- Example: `let f: (Number, Number): Number = (a, b) => a + b`

### New Features

**Opaque `Function` Type**
- Added `Function` as an opaque type (like `Generator`)
- Useful for higher-order functions that accept any callable
- Runtime type checking: `let higher: (Function, Number): Number = (f, n) => f(n)`
- `typeof(myFunc)` returns "Function"

### Bug Fixes

- Fixed parsing ambiguity that caused `test_lambda_with_function_return_type` to fail in CI
- Lambda return type with function signature now parses correctly:
  `(): ((Number): Number) => (x: Number) => x^2`

---

## [0.6.0] - 2025-11-15

### Major Features

**Phase 1 Iterators Complete**
- Generators with `yield` and `generate` blocks
- For-in loops with iterator protocol
- Generator state preservation across yields
- `return` statement in generators (sticky done)
- Environment capture in generators

**Generator as Static Type**
- Added `Generator` as opaque type in the type system
- Variable annotations: `let gen: Generator`
- Function signatures: `(Generator) => Vector`
- Union types: `Generator | null`
- Record fields: `{ source: Generator }`
- Type aliases: `type LazySequence = Generator`
- Runtime type checking: `typeof(gen)` returns "Generator"

**Tier 3 Array Transformation Functions**
- `zip(array1, array2)` - Combine two arrays into pairs
- `flatten(array, depth?)` - Flatten nested arrays/tensors
- `take(array, n)` - Take first n elements
- `drop(array, n)` - Skip first n elements
- `slice(array, start, end?)` - Extract subarray
- `unique(array)` - Remove duplicates
- `chunk(array, size)` - Split into groups

**CI/CD Infrastructure**
- GitHub Actions CI workflow (tests on Linux, Windows, macOS)
- GitHub Actions Release workflow (automatic binary builds)
- Cross-platform releases with checksums

**CLI Enhancements**
- Command-line argument parsing with clap
- `--version`, `--help` flags
- `--eval` for direct expression evaluation
- Subcommands: `repl`, `run`, `eval`, `check`
- Syntax checking without execution

**Advanced Type System**
- Function types with arrow syntax: `(Number, Number) => Number`
- Edge type for graph programming: `let e: Edge = A -> B`
- Type aliases: `type Point = { x: Number, y: Number }`
- Union types: `Number | String | null`
- Type inference from annotations to lambda parameters

**Control Flow Enhancements**
- if-else statements with multi-statement blocks
- else-if chains
- return statement for early exit
- Guard clauses pattern support

**Module System**
- `import` and `export` statements
- Built-in modules: `stats`, `math`, `linalg`
- User-defined modules
- Module resolution with relative paths

**Mutability System**
- `mut` keyword for mutable variables
- Mutable record fields
- Stateful objects with `self`

**Environment I/O**
- `save_env()` - Save REPL environment
- `restore_env()` - Load environment
- `env_info()` - Inspect `.ach` files

**Graph Theory & PERT/CPM**
- Graph algorithms: BFS, DFS, Dijkstra, Kruskal, Prim
- Critical path analysis
- Probabilistic PERT calculations

**Test Suite Stabilization**
- Fixed 27 obsolete tests (TCO, utility functions, type annotations)
- All 700+ tests passing
- Codebase refactoring (all files under 500 lines)

**[Full details...](./docs/changelog/v0.6.x.md)**

---

## [0.5.3] - 2025-11-06

### Highlights
- **Conditional Expressions** - Boolean logic with `if()` function
- **Piecewise Functions** - Multi-branch conditionals
- **Parser Migration** - Migrated to Pest PEG parser generator
- **Linear Programming Docs** - Standard form conventions

**[Full details...](./docs/changelog/v0.5.x.md#053---2025-11-06)**

---

## [0.5.2] - 2025-11-05

### Highlights
- **Built-in Function Reference** - Complete documentation of all functions
- **Modular Function Registry** - Domain-specific modules for better organization

**[Full details...](./docs/changelog/v0.5.x.md#052---2025-11-05)**

---

## [0.5.1] - 2025-01-05

### Highlights
- **Numerical Calculus Module** - Differentiation, integration, root finding
- **Dependency Injection** - `LambdaEvaluator` trait for clean architecture
- **WASM Bindings** - 10 new numerical function exports
- **TypeScript SDK** - `NumericalOps` module

**[Full details...](./docs/changelog/v0.5.x.md#051---2025-01-05)**

---

## [0.5.0] - 2025-11-04

### Highlights
- **Rust WASM Integration** - Complete rewrite from C++ to Rust
- **TypeScript SDK v2.0** - Session-based resource management
- **5.25x Performance** - Faster than JavaScript V8
- **SOC Language Evaluator** - Full expression evaluation with lambdas

**[Full details...](./docs/changelog/v0.5.x.md#050---2025-11-04)**

---

## [0.4.0] - 2025-11-01

### Highlights
- **Matrix Decompositions** - LU, QR, Cholesky, SVD
- **Eigensolvers** - Power iteration, QR algorithm
- **Memory Safety Fix** - Critical dangling pointer bug fixed

**[Full details...](./docs/changelog/v0.4.x.md)**

---

## [0.3.0] - 2025-11-01

### Highlights
- **Performance Revolution** - 10-1000x improvement with handles system
- **Complex Types** - Complex numbers, vectors, matrices
- **Vectorized Math** - Native C++ implementations
- **DSP Fast Path** - Optimized FFT and signal processing

**[Full details...](./docs/changelog/archive/v0.3.x.md)**

---

## [0.2.0] - 2025-10-26

### Highlights
- **Mathematical Functions** - 25+ functions (trig, exp, log, rounding)
- **Constants Registry** - PI, E, PHI, SQRT2, etc.
- **Function Registry** - Extensible function system

**[Full details...](./docs/changelog/archive/v0.2.x.md)**

---

## [0.1.0] - 2025-10-26

### Highlights
- **Initial Release** - Arithmetic evaluator
- **WebAssembly Core** - C++ with Emscripten
- **Basic Operators** - +, -, *, /, ^ with correct precedence

**[Full details...](./docs/changelog/archive/v0.1.x.md)**

---

## Repository Links

[0.6.0]: https://github.com/eddndev/achronyme-core/compare/v0.5.3...v0.6.0
[0.5.3]: https://github.com/eddndev/achronyme-core/compare/v0.5.2...v0.5.3
[0.5.2]: https://github.com/eddndev/achronyme-core/compare/v0.5.1...v0.5.2
[0.5.1]: https://github.com/eddndev/achronyme-core/compare/v0.5.0...v0.5.1
[0.5.0]: https://github.com/eddndev/achronyme-core/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/eddndev/achronyme-core/compare/v0.3.0...v0.4.0
[0.3.0]: https://github.com/eddndev/achronyme-core/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/eddndev/achronyme-core/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/eddndev/achronyme-core/releases/tag/v0.1.0
