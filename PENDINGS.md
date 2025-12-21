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

- [ ] **FFI/Native Interface**: The `NativeFn` signature is rigid.
    - *Target*: Safer binding macros.
- [x] **Serialization**:
    - *Completed*: Implemented binary format support for Complex numbers (`SER_TAG_COMPLEX` = 9).
    - Added `ComplexTable` to `.achb` format (re, im).
- [ ] **Pretty Printing (VM::val_to_string)**:
    - *Target*: Add support for `Map` type once implemented.

## 5. Security & Architecture (PR3 Recommendations)

### Security


### Architecture

