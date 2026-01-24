# PENDING.md - Achronyme ZK-Engine Roadmap

## 1. Core Engine & Type System (High Priority)
The immediate goal is to transition from a general-purpose scripting engine to a domain-specific runtime for Cryptography and Zero-Knowledge Proofs.

- [ ] **Native Integer Support (No-Float Logic)**
    - *Context*: `f64` is unsuitable for crypto. We need precise integers.
    - [x] Implement `TAG_INT` (SMI) for small loop counters (utilizing the 50-bit payload).
    - [ ] Implement `TAG_BIGINT` (Heap) for 256-bit+ field elements.
    - [ ] Update `arithmetic.rs` to handle hybrid math (SMI + BigInt promotion).

- [ ] **Finite Field Arithmetic**
    - *Target*: Abstract `BigInt` operations to support modular arithmetic natively (`x + y` implies `(x + y) % P`).

- [ ] **Tensor System (N-Dimensional Arrays)**
    - *Context*: Required for polynomial representation and ML-adjacent ZK operations (FFT/MSM).
    - [ ] Implement `TAG_TENSOR` backed by `Vec<BigInt>` in the Heap.
    - [ ] Add `OpCode::MatMul` and `OpCode::VecAdd` for native Rust speed.

## 2. Memory Management (GC Hardening)
- [ ] **Heap-Aware GC Triggers**:
    - Current GC triggers on *allocation count*. Needs to trigger on *actual byte size* (crucial for large Tensors/BigInts).
    - Update `Heap::alloc_*` to track `mem::size_of_val`.

## 3. Virtual Machine Optimizations
- [ ] **Map/List Iteration Performance**:
    - *Critical*: `for k in map` currently allocates O(N) lists. Needs an opaque iterator to avoid GC pressure during heavy crypto loops.
    - *Refactor*: Implement `IteratorObj` for Maps directly.

- [ ] **Instruction Dispatch** (Lower Priority):
    - Defer "Computed GOTO" until the Type System is stable.

## 4. Standard Library (Cryptography Domain)
- [ ] **Native Crypto Primitives**:
    - Implement `poseidon_hash(x)` or `pedersen_hash(x)` as native functions.
    - Implement `verify_signature(pub_key, msg, sig)`.

## 5. Technical Debt
- [ ] **Global Mutability Check**: Move from runtime check to compile-time check where possible.
    - [x] **Arithmetic Boilerplate Refactor**:
    - *Context*: `arithmetic.rs` has significant code duplication for integer vs float checks.
    - *Action*: Refactor using macros to centralize dispatch logic and improve maintainability.
- [ ] **Integer Wrapping Semantics Review**:
    - *Context*: Current `TAG_INT` implementation uses silent wrapping (`wrapping_add`, etc.).
    - *Action*: Validate if this is desired for a crypto-focused VM. Consider `checked_*` with explicit overflow errors or automatic promotion to BigInt.