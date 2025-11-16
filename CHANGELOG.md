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
