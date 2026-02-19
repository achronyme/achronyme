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

---

## 7. Deep Audit Findings (Phase 10 — 8-agent cryptographic & systems audit)

All findings below were confirmed against the source code. Each includes
the exact file:line where the issue was verified.

### CRITICAL — Plonkish Soundness (systemic architectural flaw)

All C1–C4 stem from a single root cause: `col_constant` (fixed column,
`plonkish_backend.rs:97`) is allocated but **never referenced in the gate
polynomial** (`plonkish_backend.rs:104-110`). The gate is:
`s_arith * (a * b + c - d) = 0` — only uses `col_a..col_d` (all advice).
`SetConstant` (`PlonkWitnessOp`, L43) only sets witness values; it creates
zero constraints. A malicious prover controls all advice columns freely.

**The R1CS backend is NOT affected** — all gadgets use `enforce()` which
creates proper verifiable constraint equations.

- [x] **C1: IsZero gadget under-constrained** — `plonkish_backend.rs:974-993`
    - `d=1` (enforce row) and `d=0` (check row) set via `SetConstant` on advice `col_d`
    - *Fixed*: `constrain_constant()` writes to fixed column + copy constraint to advice cell

- [x] **C2: Division gadget under-constrained** — `plonkish_backend.rs:666-696`
    - `den * inv = 1` has `d=1` via `SetConstant` on advice → prover sets `d=0, inv=0`
    - *Fixed*: `constrain_constant()` writes to fixed column + copy constraint to advice cell

- [x] **C3: Bit decomposition coefficients not constrained** — `plonkish_backend.rs:1004-1031, 1040-1111`
    - Powers-of-two (`2^i`) set in `col_b` (advice) via `SetConstant`
    - *Fixed*: `constrain_constant()` writes to fixed column + copy constraint to advice cell

- [x] **C4: Arithmetic identity col_b not constrained** — `plonkish_backend.rs:304-306, 337-339, 521-527, 558-563`
    - `col_b=1` or `col_b=-1` for DeferredAdd/Sub/Neg via `SetConstant` on advice
    - *Fixed*: `constrain_constant()` writes to fixed column + copy constraint to advice cell

**Systemic fix applied**: `constrain_constant()` helper writes each constant to
`col_constant` (fixed, verifier-committed) and adds a copy constraint to the
advice cell. Gate polynomial unchanged — copy constraints alone ensure soundness.

### HIGH — Correctness & Security

- [x] **H1: `nPubOut`/`nPubIn` inverted in R1CS export** — `export.rs:59-66`
    - All public vars mapped as `nPubOut`, `nPubIn=0`
    - *Fixed*: Swapped to `nPubOut=0`, `nPubIn=num_pub_inputs`

- [x] **H2: `public x` + `witness x` creates duplicate unconstrained wire** — `ir/lower.rs:37-55`
    - Both `declare_public` and `declare_witness` call `env.insert(name, v)` without duplicate check
    - *Fixed*: `DuplicateInput` error variant; HashSet check in `lower_circuit` and `lower_self_contained`

- [x] **H3: `let` rebinding in if/else branches pollutes outer scope** — `ir/lower.rs:849-893`
    - **False positive**: `lower_block` correctly restores env via `retain(outer_keys)`, confirmed by `if_branch_let_does_not_leak` test

- [x] **H4: And/Or short-circuit fold removes boolean enforcement** — `ir/passes/const_fold.rs`
    - **False positive**: audit fix `649c4bb` added `is_bool()` guards; short-circuit only folds on boolean constants; DCE conservatively preserves all boolean ops

- [x] **H5: Lookup zero-value bypass in Plonkish** — `plonkish.rs:382-384`
    - All-zero skip conflated inactive rows with valid `range_check(0)`
    - *Fixed*: Added `selector` field to `Lookup`; `register_lookup_with_selector` uses explicit selector for row activity; range table uses new API

### MEDIUM — Efficiency, Robustness, Interop

- [ ] **M1: IsLt/IsLe ~760 constraints per comparison** — `r1cs_backend.rs:887-931, 1205-1232`
    - Two 252-bit range checks (504 constraints) + 253-bit decomposition (254) per comparison
    - For bounded inputs (already range-checked): reuse existing range proofs → ~66 constraints
    - Depth-3 Merkle: ~7,099 → ~2,201 constraints possible (69% reduction)

- [ ] **M2: Boolean propagation pass missing** — IR passes
    - No tracking of known-boolean variables across instructions
    - `Not`, `And`, `Or` always emit boolean enforcement even when operand is already boolean
    - *Fix*: Add boolean-tracking pass that marks variables proven boolean by prior constraints

- [ ] **M3: LinearCombination terms not deduplicated** — `r1cs.rs:121-148`
    - Add/Sub extend terms vector without merging: `[(x,3),(x,-3)]` not simplified
    - `is_constant()` returns `false` for effectively-constant LCs → unnecessary materialization
    - *Fix*: Add `simplify()` method, call before `is_constant()`, `constant_value()`, `as_single_variable()`

- [ ] **M4: `from_le_bytes` accepts values >= p silently** — `field.rs:242-248`
    - `from_canonical` (L215) says "already reduced mod p" but doesn't check
    - `montgomery_mul` wraps silently → different FieldElement than expected
    - *Fix*: Add range check in `from_le_bytes`, return `Option` or reduce explicitly

- [ ] **M5: Integer literals limited to u64** — `ir/lower.rs:317-319`
    - `digits.parse::<u64>()` rejects values > 2^64
    - Field supports ~2^254 — blocks large constants needed for crypto
    - *Fix*: Use `from_decimal_str` for arbitrary-precision parsing

- [ ] **M6: Poseidon round constants without cross-validation** — `poseidon.rs:22-158`
    - Custom Grain LFSR generates constants — no test against reference implementation
    - Subtle LFSR bug → incompatible hash, broken interop with circomlibjs/iden3
    - *Fix*: Add test vector `poseidon(1, 2) == <known reference value>`

- [ ] **M7: Negative numbers in `--inputs` CLI fail** — `cli/src/commands/circuit.rs`
    - `-42` parsed incorrectly in comma-separated `--inputs "x=-42"`

- [ ] **M8: Taint analysis false negatives** — `ir/passes/taint.rs`
    - `w - w` tagged as Witness but is effectively Constant(0) → misses optimization opportunity

### LOW — Design & Ergonomics

- [ ] **L1: `compile_circuit()` vs `compile_ir()` feature gap** — `r1cs_backend.rs:436-453`
    - Direct AST path rejects comparison operators (`==`, `<`, etc.)
    - IR path supports them — same source behaves differently depending on path
    - *Fix*: Deprecate/remove direct path, or document discrepancy

- [ ] **L2: `pow_expr` is left-associative** — `grammar.pest:108`
    - `2^3^2 = (2^3)^2 = 64` instead of mathematical convention `2^(3^2) = 512`
    - *Fix*: Change grammar to right-recursive or document

- [ ] **L3: No arrays, type system, or circuit composition**
    - Major expressiveness gaps vs Noir (arrays+structs+generics), Circom (templates+signals)
    - Blocks reusable subcircuit patterns and indexed witness access

- [ ] **L4: MAX_UNROLL_ITERATIONS = 10,000 without memory guard** — `ir/lower.rs:13`
    - `for i in 0..10000` generates 10K IR instructions without memory limit
    - *Fix*: Add instruction count budget or progressive memory check

### Test Coverage Gaps (P0 security-critical)

- [ ] **T1: IsLt/IsLe untested near 2^252 boundary** — boundary values for 253-bit decomposition
- [ ] **T2: Division constraint soundness vs malicious prover** — manual witness with divisor=0
- [ ] **T3: Plonkish boolean enforcement** — no test that flag=2 fails in Plonkish mux
- [ ] **T4: DCE safety for RangeCheck/PoseidonHash** — unused result must not be eliminated
- [ ] **T5: Optimization soundness proptest** — optimized vs unoptimized circuits for random inputs

### Test Coverage Gaps (P1 important)

- [ ] **T6: Negative witness for direct AST compile path** — only IR path has negative tests
- [ ] **T7: Poseidon zero inputs E2E** — `poseidon(0,0)` only tested natively, not through circuit pipeline
- [ ] **T8: range_check edge cases** — bits=0, bits=1, bits=253, max valid value (2^bits-1)
- [ ] **T9: Missing Plonkish equivalents** — for loops, if/else, poseidon with expressions, power
- [ ] **T10: Witness corruption detection** — corrupt intermediate value, verify must fail
- [ ] **T11: Field serialization round-trip for multi-limb values** — only single-limb tested
- [ ] **T12: `from_decimal_str` edge cases** — "0", p, p+1, invalid chars, empty string
- [ ] **T13: snarkjs integration tests in CI** — currently `#[ignore]`, need Node.js in CI
- [ ] **T14: CLI integration tests** — zero test coverage for `circuit` command