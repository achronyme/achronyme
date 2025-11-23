# Achronyme VM Compatibility Testing System

This directory contains a comprehensive testing infrastructure to verify that the Achronyme VM produces correct results and maintains compatibility with the language specification.

## Directory Structure

```
tests/
├── README.md                    # This file
├── compatibility/               # Compatibility test suite
│   └── mod.rs                   # Unit tests comparing VM vs expected results
├── compatibility.rs             # Integration test entry point
├── corpus/                      # Test programs (.ach files)
│   ├── basic_arithmetic.ach
│   ├── factorial.ach
│   ├── fibonacci.ach
│   ├── map_filter.ach
│   ├── closures.ach
│   ├── records.ach
│   ├── nested_functions.ach
│   ├── array_operations.ach
│   ├── conditionals.ach
│   └── loops.ach
├── test_corpus.rs               # Corpus-based testing
└── run_compatibility_tests.sh   # Test runner script
```

## Overview

The Achronyme project is transitioning from a tree-walker evaluator to a bytecode-based VM. The compatibility testing system ensures that the VM:

1. **Produces correct results** for all valid Achronyme programs
2. **Maintains semantic equivalence** with the language specification
3. **Handles edge cases** properly (NaN, Infinity, empty collections, etc.)
4. **Supports all language features** (functions, closures, HOFs, loops, etc.)

## Test Categories

### 1. Compatibility Tests (`compatibility/mod.rs`)

Unit tests that verify VM output matches expected results for specific language features:

- **Basic arithmetic**: Addition, subtraction, multiplication, division, exponentiation
- **Variables**: Declaration, assignment, reassignment
- **Functions**: Definition, invocation, closures, higher-order functions
- **Arrays**: Literals, indexing, length, operations
- **Built-in functions**: Math functions, array functions, utilities
- **Higher-order functions**: `map`, `filter`, `reduce`
- **Conditionals**: `if-else` expressions, nested conditionals
- **Comparison operators**: `==`, `!=`, `<`, `>`, `<=`, `>=`
- **Logical operators**: `&&`, `||`, `!`
- **Loops**: `for-in` loops, range iteration
- **Recursion**: Factorial, Fibonacci, tail recursion
- **Strings**: Literals, concatenation
- **Records**: Object literals, field access
- **Blocks**: Block expressions, multiple statements
- **Complex expressions**: Nested function calls, composed operations

Run compatibility tests:
```bash
cargo test --test compatibility
```

### 2. Corpus Tests (`test_corpus.rs`)

Integration tests that run complete Achronyme programs from the `corpus/` directory:

- **basic_arithmetic.ach**: Variable arithmetic operations
- **factorial.ach**: Recursive factorial calculation
- **fibonacci.ach**: Fibonacci sequence generation
- **map_filter.ach**: Higher-order function composition
- **closures.ach**: Closure creation and state
- **records.ach**: Record operations and field access
- **nested_functions.ach**: Deep nesting and scope
- **array_operations.ach**: Array transformations
- **conditionals.ach**: Conditional logic
- **loops.ach**: Iterative computation

Run corpus tests:
```bash
cargo test --test test_corpus
```

## CLI Usage

The Achronyme CLI now uses the VM backend exclusively. You can run programs directly:

```bash
# Run a file
cargo run --bin achronyme -- tests/corpus/factorial.ach

# Evaluate an expression
cargo run --bin achronyme -- -e "2 + 2"

# Start REPL (VM-powered)
cargo run --bin achronyme
```

## Running Tests

### Run all compatibility tests:
```bash
cargo test --test compatibility
```

### Run specific test:
```bash
cargo test --test compatibility test_arithmetic
```

### Run corpus tests:
```bash
cargo test --test test_corpus
```

### Run all tests with detailed output:
```bash
./tests/run_compatibility_tests.sh
```

## Writing New Tests

### Adding a Compatibility Test

Edit `tests/compatibility/mod.rs`:

```rust
#[test]
fn test_my_feature() {
    test_compatibility("let x = 5; x * 2");
}
```

The `test_compatibility` function:
1. Parses the source code
2. Executes it with the VM
3. Compares the result against the expected value
4. Handles edge cases (NaN, Infinity, etc.)

### Adding a Corpus Test

1. Create a new `.ach` file in `tests/corpus/`:

```achronyme
// tests/corpus/my_test.ach
let x = 10
let y = 20
x + y
```

2. Run the corpus tests - it will automatically discover and test the new file:

```bash
cargo test --test test_corpus
```

## Expected Results

### Success Output

```
running 50 tests
test test_arithmetic_add ... ok
test test_arithmetic_subtract ... ok
test test_functions ... ok
...
test result: ok. 50 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out
```

### Failure Output

When a test fails, you'll see detailed information:

```
test test_arithmetic_add ... FAILED

failures:

---- test_arithmetic_add stdout ----
thread 'test_arithmetic_add' panicked at 'Number mismatch for '2 + 2': tree=4.0, vm=5.0'
```

## Current Status

### Implemented Features

- Core arithmetic operations
- Variable binding and scoping
- Function definitions and calls
- Closures and upvalues
- Arrays and indexing
- Built-in functions (math, array ops)
- Higher-order functions (map, filter, reduce)
- Conditionals (if-else)
- Comparison and logical operators
- Records (objects)
- For-in loops
- Recursion and tail call optimization
- Generators (yield, generator state)
- Exception handling (throw, try-catch)
- Break and continue
- Early return

### Known Limitations

- **Module system**: Import/export not yet implemented in VM
- **Type system**: Gradual typing not yet enforced at compile time

## Troubleshooting

### Test Failures

If tests fail:

1. **Check the error message**: It shows exactly which expression failed and what the mismatch was
2. **Run the test individually**: `cargo test --test compatibility test_name -- --nocapture`
3. **Try the expression in REPL**: `cargo run --bin achronyme` and type the expression
4. **Check VM bytecode**: Add debug prints in the compiler to see generated bytecode

### Corpus File Errors

If corpus tests fail:

1. **Syntax errors**: Ensure your `.ach` file uses valid Achronyme syntax
2. **Parser issues**: Test with `cargo run --bin achronyme -- check tests/corpus/file.ach`
3. **Runtime errors**: Run directly with `cargo run --bin achronyme -- tests/corpus/file.ach`

## Future Work

- **Property-based testing**: Use `proptest` to generate random programs
- **Fuzzing**: Integrate `cargo-fuzz` for robustness testing
- **Performance benchmarking**: Optimize VM execution performance
- **Coverage analysis**: Ensure all VM opcodes are tested
- **Regression tests**: Capture known bugs as tests

## Contributing

When adding new language features to the VM:

1. Add compatibility tests in `tests/compatibility/mod.rs`
2. Add at least one corpus test file demonstrating the feature
3. Update this README with the new feature
4. Ensure all existing tests still pass

## References

- [VM Architecture](../crates/achronyme-vm/README.md) (if exists)
- [Language Specification](../LANGUAGE_SPEC.md) (if exists)
- [Compiler Design](../crates/achronyme-vm/src/compiler/README.md) (if exists)
