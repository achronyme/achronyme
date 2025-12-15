# Achronyme Compiler

Compiles Achronyme source code into VM bytecode.

## Architecture

- **codegen.rs**: Main compiler logic using `pest` for AST traversal and `vm::opcode` for emission.
- **error.rs**: Compiler specific errors.
- **interner.rs**: String interning for efficient string storage.

### FunctionCompiler Stack

The compiler uses a LIFO stack of `FunctionCompiler` instances to handle nested function compilation:

```rust
pub struct Compiler {
    pub compilers: Vec<FunctionCompiler>,  // Stack for nested functions
    pub prototypes: Vec<Function>,         // Flat global function table
    pub global_symbols: HashMap<String, u16>,
    // ...
}
```

Each `FunctionCompiler` manages per-function state: bytecode, constants, locals, and register allocation.

## Usage

```rust
use compiler::Compiler;

let mut compiler = Compiler::new();
let bytecode = compiler.compile("fn add(a, b) { return a + b }").unwrap();
// Access function prototypes: compiler.prototypes
```

## Features

- **User-Defined Functions**: `fn name(params) { body }`, anonymous `fn (x) { x * 2 }`, nested functions.
- **Recursion**: Functions can call themselves (name registered before body compilation).
- **Control Flow**: `if`, `while`, `block` expressions.
- **Register Hygiene**: Uses a LIFO (Stack) register allocation strategy to minimize register pressure and prevent leaks.
- **Scope Management**: Blocks create new scopes. Variables are automatically freed when scope ends.
- **Shadowing**: Inner variables correctly shadow outer ones (LIFO lookup).
