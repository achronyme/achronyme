# PENDING.md

## 1. Virtual Machine Optimizations

### Critical Performance
- [ ] **Optimize Global Variable Access**: Currently, `globals` is implemented as a `HashMap<u32, GlobalEntry>`. This requires hashing on every access.
    - *Target*: Convert globals to a flat `Vec<GlobalEntry>` and resolve indices at compile-time to allow O(1) direct array access.
- [ ] **Remove Stack Bounds Checking**: The `set_reg` and `get_reg` methods in `VM` use `Vec::get` and `Vec::resize`, which incur runtime bounds checking overhead per instruction.
    - *Target*: Use `unsafe` raw pointers or a pre-allocated fixed-size array (`[Value; STACK_MAX]`) for the stack once the VM is stable.
- [ ] **Instruction Dispatch**: The main loop uses a Rust `match` statement.
    - *Target*: Investigate "Computed GOTO" or "Threaded Code" techniques if Rust stable allows it (or via assembly shim) to reduce branch prediction misses.

### Arithmetic & Types
- [ ] **Inline Caching for Binary Ops**: The `binary_op` function checks types (Number vs Complex) on every execution.
    - *Target*: Implement monomorphic inline caching (MIC) or specialized opcodes (e.g., `ADD_FLOAT`, `ADD_COMPLEX`) emitted by the compiler when types can be inferred.

## 2. Memory Management (GC & Heap)

- [ ] **String Interning Overhead**: The current `interner` duplicates strings (one in `StringInterner`, one in `Heap` arena).
    - *Target*: Unify storage so the Interner just holds references/indices to the Heap's string arena to reduce memory footprint.
- [ ] **GC Trigger Strategy**: `should_collect()` is currently based on a naive byte threshold.
    - *Target*: Implement a more sophisticated stress metric (allocations per cycle) or generational logic (Nursery/Tenured) to prevent "GC thrashing".
- [ ] **Map & List Implementation**:
    - *Target*: Maps are currently using Rust's `HashMap`. Requires a custom definition to interact properly with the GC (tracing keys/values).
    - *Target*: Lists are `Vec<Value>`. They need efficient resizing and potentially a specialized array type for numeric-only lists (bytearrays/floatarrays).

## 3. Compiler Improvements

### Register Allocation
- [ ] **Register Reuse**: The current allocator (`alloc_reg`) simply increments `reg_top` until it hits 255. It does not free registers when scopes end.
    - *Target*: Implement a "Linear Scan Register Allocator" or simple liveness analysis to reuse registers (e.g., `R0` can be reused after `temp` computation is done).
- [ ] **Constant Pool Deduplication**: While implemented for numbers, ensure string constants and complex numbers are strictly deduplicated across the entire compilation unit.

### Missing Features (Architecture)
- [ ] **Control Flow**: The current `OpCode` enum lacks `JUMP`, `JUMP_IF_FALSE`, or loop constructs.
    - *Target*: Implement relative jump instructions to support `if`, `while`, and `for`.
- [ ] **Closures & Upvalues**: `CallFrame` has a `closure` field, but the compiler does not yet support capturing local variables from outer scopes (Upvalues).
    - *Target*: Implement `make_closure`, `get_upvalue`, and `set_upvalue` opcodes.

## 4. Native & Standard Library

- [ ] **FFI/Native Interface**: The `NativeFn` signature is rigid.
    - *Target*: Create a safer binding macro system to automatically convert `Value` to Rust types (f64, string, etc.) inside native functions without manual unwrapping.
- [ ] **Serialization**:
    - *Target*: Complete binary format serialization for Strings and Complex numbers (currently returns error in `run.rs`).
