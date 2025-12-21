# PENDING.md

## 1. Virtual Machine Optimizations

### Critical Performance
- [x] **Remove Stack Bounds Checking**: The `set_reg` and `get_reg` methods in `VM` use `Vec::get` and `Vec::resize`.
    - *Completed*: Using `unsafe` with pre-allocated fixed-size stack (64KB). `debug_assert!` for development safety.
- [ ] **Instruction Dispatch**: The main loop uses a Rust `match` statement.
    - *Target*: Investigate "Computed GOTO" or "Threaded Code".

### Arithmetic & Types
- [ ] **Inline Caching for Binary Ops**: Check types (Number vs Complex) incurs overhead.
    - *Target*: Implement monomorphic inline caching (MIC) or specialized opcodes.

## 2. Memory Management (GC & Heap)

- [x] **GC Trigger Strategy**: `should_collect()` uses a naive byte threshold.
    - *Completed*: Implemented "2x Rule" and `stress_mode` validation.
- [x] **Map & List Implementation** (Task 3):
    - *Completed*: Supported `[...]` and `{...}` literals, indexing (`a[i]`), and smart assignment (`a[i] = v`).
    - *Features*: Allocator-aware Heap, Strict type checking (Map keys must be strings).

## 3. Compiler & Features

### Architecture & Debugging (Priority)
- [x] **Debug Symbol Table**: The move to O(1) globals removed variable names from runtime errors.
    - *Completed*: Implemented sidecar debug symbol map with binary serialization.

### Language Features
- [x] **User-Defined Functions (`fn`)**: Implemented with flat prototype architecture.
    - Recursion, nested functions, anonymous functions all supported.
    - `return` statement for explicit returns.
- [x] **String Literals**: Implemented with interner and binary serialization.
- [ ] **Control Flow (For Loops)**: Syntactic sugar for `while`.
- [x] **Closures & Upvalues**: `CallFrame` has a `closure` field, but capturing is missing.
    - *Completed*: Implemented `Closure` opcode, `capture_upvalue`, `close_upvalues`, and GC rooting.
- [ ] **Escaped Characters**: Current parser does not support escaped quotes (`\"`).
    - *Target*: Update `grammar.pest` atoms to handle escape sequences.

## 4. Native & Standard Library

- [ ] **FFI/Native Interface**: The `NativeFn` signature is rigid.
    - *Target*: Safer binding macros.
- [ ] **Serialization**:
    - *Target*: Complete binary format serialization (`.achb`) for Complex numbers.
- [ ] **Pretty Printing (VM::val_to_string)**:
    - *Target*: Add support for `Map` type once implemented.

## 5. Security & Architecture (PR3 Recommendations)

### Security
- [x] **Allocation Bomb Protection (DoS)**: Validate sizes during binary deserialization.
    - *Completed*: Enforced `name_len <= 1024` and count limits in `vm/src/loader.rs`.

### Architecture
- [x] **Decouple Loader**: `cli/src/commands/run.rs` knows too many VM internals.
    - *Completed*: Moved all binary loading logic to `vm::loader::load_executable`. CLI is now agnostic.
- [x] **Named Constants for Tags**: Replace magic numbers (`0`, `1`, `255`) in serialization.
    - *Completed*: Defined `SER_TAG_NUMBER`, `SER_TAG_STRING`, `SER_TAG_NIL` in `vm/src/specs.rs` as SSOT.
