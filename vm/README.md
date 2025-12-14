# Achronyme VM

The Virtual Machine crate for the Achronyme language.

## Architecture

This crate is divided into the following modules:

- **machine.rs**: Contains the `VM` struct and the main interpretation loop.
- **opcode.rs**: Defines the instruction set (`OpCode` enum) and instruction encoding/decoding logic.
- **error.rs**: Defines `RuntimeError` types.

## Adding Instructions

1.  Add the variant to `OpCode` enum in `opcode.rs`.
2.  Implement encoding/decoding in `opcode.rs`.
3.  Add the case to the `match op` block in `machine.rs`.
4.  Write tests in `machine.rs` or `lib.rs` (via integration tests).
