# Achronyme Compiler

Compiles Achronyme source code into VM bytecode.

## Architecture

- **codegen.rs**: Main compiler logic using `pest` for AST traversal and `vm::opcode` for emission.
- **error.rs**: Compiler specific errors.

## Usage

```rust
use compiler::Compiler;

let mut compiler = Compiler::new();
let bytecode = compiler.compile("1 + 2").unwrap();
```

## Features

- **Control Flow**: `if`, `while`, `block` expressions.
- **Register Hygiene**: Uses a LIFO (Stack) register allocation strategy to minimize register pressure and prevent leaks. All temporary registers are strictly freed after use.
- **Scope Management**: Blocks create new scopes. Variables declared inside blocks are automatically freed when the scope ends.
