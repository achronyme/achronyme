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
    - [x] **Heap-Aware GC Triggers**:
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

---

## 6. ZK Audit Findings (from Phase 9 comprehensive audit)

### HIGH — Cryptographic

- [x] **H1: Non-standard Poseidon round constants** — Fixed: Grain LFSR (Poseidon paper Appendix E)
- [x] **H2: Range table exponential growth in Plonkish** — Fixed: capped at 16 bits max
- [x] **H3: Unbounded for-loop static unrolling** — Fixed: MAX_UNROLL_ITERATIONS = 10,000
- [x] **H5: `from_i64(i64::MIN)` panics due to overflow** — Fixed: uses `unsigned_abs()`

### MEDIUM — Language & Parser

- [x] **M1: `-a^2` parses as `(-a)^2` instead of `-(a^2)`** — Fixed: reordered grammar precedence
- [x] **M2: `if`/`else` missing from keyword list** — Fixed: added to keyword exclusion
- [x] **M3: Chained comparisons produce silent wrong results** — Fixed: limited to single comparison
- [x] **M4: Constant folding misses identities** — Fixed: added x+0, x*1, x-0, x/1 rules
- [x] **M5: Mux constant folding incomplete** — Fixed: added equal-branches rule
- [x] **M6: Side effects in both if/else branches always emitted** — Documented as known limitation
- [x] **M7: HashMap indexing panics in compile_ir** — Fixed: lookup helpers with proper errors
- [x] **M8: Multiple `unwrap()`/`expect()` in library code** — Fixed: replaced with `?` error propagation

### LOW — Testing & Feature Gaps

- [x] **L1: Poseidon not fully implemented in Plonkish** — Fixed: 3 Plonkish Poseidon tests (single, chained, with arithmetic)
- [x] **L2: No negative tests for Plonkish backend** — Fixed: 5 negative tests (wrong mul/eq/mux/cmp, missing input)
- [x] **L3: No cross-backend parity tests** — Fixed: proptest parity for Poseidon, neq, lt, assert + rejection
- [x] **L4: Missing division-by-zero tests for all paths** — Fixed: 7 tests covering both backends, computed zero, valid paths

### RESOLVED

- [x] **C1–C3**: All CRITICAL findings resolved
- [x] **H1–H5**: All HIGH findings resolved
- [x] **M1–M8**: All MEDIUM findings resolved
- [x] **L1–L4**: All LOW findings resolved — full audit clean