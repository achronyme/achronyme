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
- [x] **Control Flow (For Loops)**: Syntactic sugar for `while`.
    - *Completed*: Implemented `for`, `forever`, `break`, `continue`.
    - Added `GetIter`, `ForIter` opcodes and `IteratorObj`.

- [x] **Escaped Characters**: Current parser does not support escaped quotes (`\"`).
    - *Completed*: Updated `grammar.pest` to support escapes via `inner` rule.
    - Added `unescape_string` in compiler to handle `\n`, `\r`, `\t`, `\"`, `\\`.

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

## 6. Technical Debt (Post-Audit)

- [ ] **Map Iteration Performance (Critical)**:
    - Current `for k in map` implementation reifies all keys into a List (O(N) allocation) via `Object::keys_to_list`.
    - *Target*: Implement opaque native iterator for Maps to avoid allocation.
- [ ] **List Iteration Logic**:
    - Current `for x in list` implementation needs verification on whether it copies the list or iterates efficiently.
- [ ] **Global Mutability Check**:
    - `SetGlobal` enforces mutability at runtime. Compiler could enforce this statically for better DX.

