# Achronyme Memory

manages the Heap and Values for the Achronyme VM.

## Architecture

- **value.rs**: Defines the `Value` enum which represents runtime values (both stack primitives and heap handles).
- **heap.rs**: Implements `Heap` using Typed Arenas for efficient memory locality and simplified GC potential.

## GC Strategy

Currently using a placeholder logic. The plan is to implement a Mark-and-Sweep garbage collector over the arenas.
