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

- [ ] **GC Trigger Strategy**: `should_collect()` uses a naive byte threshold.
    - *Target*: Implement stress metric (allocations per cycle) or generational logic.
- [ ] **Map & List Implementation**:
    - *Target*: Maps (custom definition tracing keys/values) and Lists (efficient resizing).

## 3. Compiler & Features

### Architecture & Debugging (Priority)
- [ ] **Debug Symbol Table**: The move to O(1) globals removed variable names from runtime errors.
    - *Target*: Create a separate "Debug Symbol Map" (Index -> Name) for error reporting ("Undefined variable 'x'") and disassembly.
- [x] **String Literals**: The grammar currently lacks string literals (only identifiers/keywords).
    - *Target*: Implement string parsing `grammar.pest`, compilation to `Value::String` handles via Interner. (COMPLETED)

### Language Features
- [ ] **User-Defined Functions (`fn`)**: Not yet implemented.
    - *CRITICAL*: When implementing, `Compiler::new()` must accept `arity` and initialize `reg_top = arity` and `max_reg_touched = arity as u16` to avoid argument/local collision.
- [ ] **Control Flow (For Loops)**: Syntactic sugar for `while`.
- [ ] **Closures & Upvalues**: `CallFrame` has a `closure` field, but capturing is missing.
    - *Target*: Implement `make_closure`, `get_upvalue`, `set_upvalue`.
- [ ] **Escaped Characters**: Current parser does not support escaped quotes (`\"`).
    - *Target*: Update `grammar.pest` atoms to handle escape sequences.

## 4. Native & Standard Library

- [ ] **FFI/Native Interface**: The `NativeFn` signature is rigid.
    - *Target*: Safer binding macros.
- [ ] **Serialization**:
    - *Target*: Complete binary format serialization (`.achb`) for Complex numbers. (Strings are now supported).
- [ ] **Pretty Printing (VM::val_to_string)**:
    - *Target*: Add support for `Map` type once implemented.