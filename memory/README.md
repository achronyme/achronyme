# Achronyme Memory

manages the Heap and Values for the Achronyme VM.

## Architecture

- **value.rs**: Defines the `Value` enum which represents runtime values (both stack primitives and heap handles).
- **heap.rs**: Implements `Heap` using Typed Arenas for efficient memory locality and simplified GC potential.

## NaN Boxing

Achronyme uses NaN boxing for `Value` representation (`u64` wrapper):
- **Double (f64)**: Payload.
- **Tags**: Stored in high bits of NaN space (bits 32-35).
- **Objects**: Pointers (handles) stored in low 32 bits (masked with tag).

## GC Strategy

Currently using a placeholder logic. The plan is to implement a Mark-and-Sweep garbage collector over the arenas.
