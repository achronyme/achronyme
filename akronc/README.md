# Achronyme Compiler

Compiles Achronyme source code into VM bytecode, R1CS constraints, or Plonkish gates.

## Architecture

### Bytecode Compiler

- **codegen.rs**: Main compiler orchestrator with LIFO `FunctionCompiler` stack.
- **function_compiler.rs**: Per-function state: bytecode, constants, locals, register allocation, line tracking.
- **statements/**: Statement compilation (let/mut/assignment/control flow).
- **expressions/**: Expression compilation (arithmetic, calls, closures).
- **functions.rs**: Function definition compilation and prototype emission.

### R1CS Backend (`r1cs_backend.rs`)

- `R1CSCompiler`: Walks SSA IR instructions, builds `HashMap<SsaVar, LinearCombination>`.
- Compiles arithmetic, builtins (poseidon, range_check, mux, merkle_verify), and assertions into R1CS constraints.
- `compile_ir_with_witness()`: Full pipeline from IR + inputs → constraint system + witness.

### Plonkish Backend (`plonkish_backend.rs`)

- `PlonkishCompiler`: Lazy evaluation with `PlonkVal` (deferred add/sub/neg, materialized on mul/builtin).
- Standard arithmetic gate: `s_arith * (a*b + c - d) = 0`.
- Range checks via lookup tables (1 constraint vs bits+1 in R1CS).

## Usage

```rust
use compiler::Compiler;

let mut compiler = Compiler::new();
let bytecode = compiler.compile("let x = 2 + 3").unwrap();
```

## Features

- User-defined functions, recursion, closures, control flow
- Register hygiene with LIFO allocation
- Source line tracking for runtime error reporting
- Dual-backend constraint compilation (R1CS + Plonkish)
