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
