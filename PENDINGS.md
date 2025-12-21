# PENDING.md

## 1. Virtual Machine Optimizations

### Critical Performance

- [ ] **Instruction Dispatch**: The main loop uses a Rust `match` statement.
    - *Target*: Investigate "Computed GOTO" or "Threaded Code".

### Arithmetic & Types
- [ ] **Inline Caching for Binary Ops**: Check types (Number vs Complex) incurs overhead.
    - *Target*: Implement monomorphic inline caching (MIC) or specialized opcodes.

## 2. Memory Management (GC & Heap)



## 3. Compiler & Features

### Architecture & Debugging (Priority)


### Language Features
- [ ] **Control Flow (For Loops)**: Syntactic sugar for `while`.

- [ ] **Escaped Characters**: Current parser does not support escaped quotes (`\"`).
    - *Target*: Update `grammar.pest` atoms to handle escape sequences.

## 4. Native & Standard Library

- [x] **FFI/Native Interface**: The `NativeFn` signature is rigid.
    - *Completed*: Implemented robust stdlib in `vm/src/stdlib/core.rs`.
    - `len`, `push`, `pop`, `keys` with arity/type safety.
- [x] **Serialization**:
    - *Completed*: Implemented binary format support for Complex numbers (`SER_TAG_COMPLEX` = 9).
    - Added `ComplexTable` to `.achb` format (re, im).
- [x] **Pretty Printing (VM::val_to_string)**:
    - *Completed*: Complex numbers, Strings, Numbers, Nils, Lists, Maps.
    - Added `VM::val_to_string` support for deep recursion.

## 5. Security & Architecture (PR3 Recommendations)

### Security


### Architecture

