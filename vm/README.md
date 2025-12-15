# Achronyme VM

The Virtual Machine crate for the Achronyme language.

## Architecture

This crate is divided into the following modules:

- **machine/vm.rs**: Contains the `VM` struct and the main interpretation loop.
- **machine/control.rs**: Function call/return handling (`Call`, `Return`, `Closure`).
- **machine/frame.rs**: `CallFrame` for function call stack management.
- **opcode.rs**: Defines the instruction set (`OpCode` enum).
- **error.rs**: Defines `RuntimeError` types.
- **globals.rs**: Defines `GlobalEntry` for global variable storage.

## Features

- **NaN Boxing**: Uses NaN-boxed `Value` types (via `memory` crate).
- **Flat Prototype Table**: `vm.prototypes: Vec<u32>` for O(1) function dispatch.
- **Function Calls**: 
    - `Call A, B, C` - Call function in R[B] with C args, result to R[A].
    - `Closure A, Bx` - Load prototype[Bx] into R[A].
    - `Return A, B` - Return R[A] if B=1, else nil.
- **Stack Safety**: Validates `new_bp + func.max_slots < STACK_MAX` before each call.
- **Globals**: Supports mutable (`var`) and immutable (`let`) globals.
- **Control Flow**:
    - `Jump` (Unconditional)
    - `JumpIfFalse` (Used for `if` and `while`)

## Adding Instructions

1. Add the variant to `OpCode` enum in `opcode.rs`.
2. Implement encoding/decoding in `opcode.rs`.
3. Add the case to the `match op` block in `machine.rs` or `control.rs`.
4. Write tests in the `tests/` directory.
