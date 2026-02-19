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

- [ ] **H1: Non-standard Poseidon round constants**
    - *Context*: Round constants use a custom PRG instead of Grain LFSR (the Poseidon spec standard). Hashes are incompatible with other ZK implementations (circomlib, halo2, etc.).
    - *Action*: Replace PRG with Grain LFSR for round constant generation, or document non-standard constants.
    - *File*: `constraints/src/poseidon.rs`

- [ ] **H2: Range table exponential growth in Plonkish**
    - *Context*: `emit_range_check(x, 32)` creates a table with 2^32 rows. No upper bound enforced.
    - *Action*: Cap `bits` parameter (e.g., max 24) or reject large values with an error.
    - *File*: `compiler/src/plonkish_backend.rs` → `ensure_range_table()`

- [ ] **H3: Unbounded for-loop static unrolling**
    - *Context*: `for i in 0..1000000` generates 1M IR instructions with no iteration cap.
    - *Action*: Add a configurable iteration limit (e.g., 10000) in `IrLowering` and `compile_circuit`.
    - *File*: `ir/src/lower.rs`, `compiler/src/r1cs_backend.rs`

- [ ] **H5: `from_i64(i64::MIN)` panics due to overflow**
    - *Context*: `(-i64::MIN)` causes arithmetic overflow panic.
    - *Action*: Handle `i64::MIN` as a special case in `FieldElement::from_i64`.
    - *File*: `memory/src/field.rs`

### MEDIUM — Language & Parser

- [ ] **M1: `-a^2` parses as `(-a)^2` instead of `-(a^2)`**
    - *Context*: Unary negation has higher precedence than `^` in the PEG grammar. Standard math convention is `-(a^2)`.
    - *Action*: Reorder grammar so `prefix_expr` wraps `pow_expr`, not the other way around.
    - *File*: `achronyme-parser/src/grammar.pest`

- [ ] **M2: `if`/`else` missing from keyword list**
    - *Context*: These can be used as variable identifiers: `let if = 5` is valid.
    - *Action*: Add `if` and `else` to the keyword exclusion rule in the grammar.
    - *File*: `achronyme-parser/src/grammar.pest`

- [ ] **M3: Chained comparisons produce silent wrong results**
    - *Context*: `a < b < c` compiles without error but doesn't mean `a < b && b < c`.
    - *Action*: Reject chained comparisons at parse or IR level with a clear error.
    - *File*: `achronyme-parser/src/grammar.pest` or `ir/src/lower.rs`

- [ ] **M4: Constant folding misses identities**
    - *Context*: `x * 1`, `x + 0`, `x - 0`, `x / 1` are not folded by the optimizer.
    - *Action*: Add identity folding rules to `ir/src/passes/const_fold.rs`.
    - *File*: `ir/src/passes/const_fold.rs`

- [ ] **M5: Mux constant folding incomplete**
    - *Context*: `Mux` only folds when cond is constant, not when both branches are equal.
    - *Action*: Add `if t == f then result = t` rule.
    - *File*: `ir/src/passes/const_fold.rs`

- [ ] **M6: Side effects in both if/else branches always emitted**
    - *Context*: `if c { assert_eq(a, b) } else { assert_eq(c, d) }` emits both assert_eq constraints unconditionally. The MUX only selects the return value.
    - *Action*: Document this limitation clearly, or implement conditional constraint emission.
    - *File*: `ir/src/lower.rs`, documentation

- [ ] **M7: HashMap indexing panics in compile_ir**
    - *Context*: `&vars[&var]` and `&lc_map[&var]` will panic if a variable is missing.
    - *Action*: Replace with `.get()` + proper error propagation.
    - *Files*: `compiler/src/r1cs_backend.rs`, `compiler/src/plonkish_backend.rs`

- [ ] **M8: Multiple `unwrap()`/`expect()` in library code**
    - *Context*: Potential DoS vectors through panics in parser/compiler library code.
    - *Action*: Audit and replace with `?` or proper error handling.

### LOW — Testing & Feature Gaps

- [ ] **L1: Poseidon not fully implemented in Plonkish**
    - *Context*: Plonkish Poseidon works but has no dedicated tests.
    - *Action*: Add Plonkish Poseidon tests and cross-backend parity checks.

- [ ] **L2: No negative tests for Plonkish backend**
    - *Context*: All Plonkish tests verify correct execution; none test rejection of invalid witnesses.
    - *Action*: Add tests that construct invalid witnesses and verify gate/copy failures.

- [ ] **L3: No cross-backend parity tests**
    - *Context*: R1CS and Plonkish backends should produce equivalent results for the same circuit.
    - *Action*: Add parameterized tests that compile the same IR and verify both backends accept/reject the same inputs.

- [ ] **L4: Missing division-by-zero tests for all paths**
    - *Context*: Div-by-zero is handled differently across constant/variable/witness paths.
    - *Action*: Comprehensive test coverage for all division paths in both backends.

### RESOLVED (this session)

- [x] **C1: `emit_is_zero` check constraint was a tautology in Plonkish** — Fixed: `d` set to constant 0 instead of computed by ArithRow.
- [x] **C2: `&&`/`||` in direct AST compiler lacked boolean enforcement** — Fixed: added `x * (1-x) = 0` enforcement for both operands.
- [x] **C3: IsLt/IsLe unsound for unbounded field elements** — Fixed: 252-bit range checks on both operands in R1CS and Plonkish.
- [x] **H4: Silent division by zero in Plonkish witness gen** — Fixed: `InverseRow` now returns error instead of silently skipping.