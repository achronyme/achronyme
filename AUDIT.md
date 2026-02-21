# Achronyme Security & Engineering Audit

**Date**: 2026-02-21
**Last updated**: 2026-02-21
**Scope**: All 7 workspace crates — 646 tests passing at time of audit
**Severity scale**: CRITICAL > HIGH > MEDIUM > LOW
**Resolved**: 4 findings fixed (M-01, M-02, M-03, M-04), 1 partially (M-09)

---

## Summary

| Crate | CRITICAL | HIGH | MEDIUM | LOW | Total |
|-------|----------|------|--------|-----|-------|
| memory | 0 | 6 | 4 | 5 | 15 |
| vm | 6 | 5 | 4 | 5 | 20 |
| compiler | 0 | 1 | 2 | 6 | 9 |
| ir | 2 | 2 | 3 | 3 | 10 |
| constraints | 2 | 1 | 2 | 4 | 9 |
| cli | 2 | 5 | 5 | 1 | 13 |
| parser | 0 | 0 | 7 | 10 | 17 |
| **TOTAL** | **12** | **20** | **27** | **34** | **93** |

---

## Memory Crate (15 findings)

### M-01 — O(n) Linear Search in GC Sweep [HIGH] [RESOLVED]

**File**: `memory/src/heap.rs`
**Category**: Performance
**Resolved**: `e594a96` — Added `free_set: HashSet<u32>` to `Arena<T>` with `is_free()`, `mark_free()`, `reclaim_free()`, `clear_free()` methods. All sweep and alloc sites updated.

Each sweep iteration called `Vec::contains()` on `free_indices`, which was O(n). Replaced with O(1) HashSet lookup.

---

### M-02 — ProofObject Strings Not Deducted on Sweep [HIGH] [RESOLVED]

**File**: `memory/src/heap.rs`
**Category**: Correctness
**Resolved**: `e4e3edb` — Sweep now deducts `size_of::<ProofObject>() + proof_json.capacity() + public_json.capacity() + vkey_json.capacity()`, symmetric with `alloc_proof()`.

Previously only ~72 bytes (struct size) were credited, ignoring string buffers (~10-15KB per proof). `bytes_allocated` drifted upward, causing premature GC.

---

### M-03 — Arena Index Overflow to u32::MAX [HIGH] [RESOLVED]

**File**: `memory/src/heap.rs`
**Category**: Safety
**Resolved**: `e4e3edb` — Centralized allocation in `Arena::alloc()` with `u32::try_from(data.len())` check. All 9 `alloc_*` methods now delegate to `Arena::alloc()`, eliminating duplicated patterns and the unchecked `as u32` cast.

Previously 9 sites cast `data.len() as u32` without overflow check.

---

### M-04 — Missing Bounds Check on Arena Access (get_*) [HIGH] [RESOLVED]

**File**: `memory/src/heap.rs`, `vm/src/machine/gc.rs`
**Category**: Safety
**Resolved**: `c31ed78` — Added `Arena::get()` and `Arena::get_mut()` with `is_free()` guard. All 14 `get_*` methods now delegate to `Arena::get/get_mut`. Also fixed two pre-existing GC rooting bugs exposed by this change: `mark_roots` used `Value::function()` for closure indices (wrong tag), and `prototypes` were not rooted.

Previously all `get_*` methods returned data from freed slots, allowing stale handles to silently access wrong data.

---

### M-05 — Upvalue Self-Referential Raw Pointer [HIGH] [RESOLVED]

**File**: `memory/src/heap.rs` (lines 5-13)
**Category**: Safety

`Upvalue.location` is a `*mut Value` that points either to the VM stack (open) or to `&mut self.closed` (closed). The self-referential pointer is unsound if the `Box<Upvalue>` is moved during Vec reallocation of the upvalues arena. Clone was intentionally removed to mitigate, but the fundamental issue remains.

**Fix**: Replaced `*mut Value` + `closed: Value` with `UpvalueLocation` enum (`Open(usize)` / `Closed(Value)`). Removed `Box<Upvalue>` wrapper — no longer needed since there are no self-referential pointers.

---

### M-06 — import_strings Doesn't Track Allocation Cost [HIGH]

**File**: `memory/src/heap.rs` (lines 537-540)
**Category**: Correctness

`import_strings()` replaces the entire strings arena but does not update `bytes_allocated`. The heap now owns potentially large strings without GC awareness, breaking threshold logic.

**Fix**: Sum capacities of imported strings and add to `bytes_allocated`. Call `check_gc()` afterwards.

---

### M-07 — NaN Boxing Tag Validation [MEDIUM]

**File**: `memory/src/value.rs` (lines 7, 24)
**Category**: Safety

Tags occupy bits 32-35 (4 bits), allowing values 0-15. With `TAG_INT = 13` and `TAG_PROOF = 9`, 14 of 16 slots are used. No compile-time assertion prevents a future tag from exceeding 15, which would cause tag aliasing.

**Fix**: Add `const _: () = assert!(TAG_INT < 16, "tags must fit in 4 bits");` for all tags.

---

### M-08 — Bytes Allocated Drift via Saturation [MEDIUM]

**File**: `memory/src/heap.rs` (line 489)
**Category**: Correctness

`saturating_sub(freed_bytes)` prevents underflow but masks accounting errors. Combined with M-02 (ProofObject undercount), `bytes_allocated` gradually diverges from reality.

**Fix**: Fix M-02 first. Then add debug assertions that `freed_bytes <= bytes_allocated`.

---

### M-09 — Code Duplication in alloc_*/sweep (8x) [MEDIUM] [PARTIALLY RESOLVED]

**File**: `memory/src/heap.rs`
**Category**: Maintainability
**Partially resolved**: `e4e3edb` — `Arena::alloc()` centralized 9x alloc patterns into one method. `Arena::get/get_mut` (M-04, `c31ed78`) centralized 14x access patterns. Sweep blocks remain duplicated (type-specific cleanup logic prevents full generalization).

Remaining: 9 sweep blocks still have per-type reset patterns (String::new vs Vec::new vs FieldElement::ZERO, etc.).

---

### M-10 — Public Fields Bypass Allocation Tracking [MEDIUM]

**File**: `memory/src/heap.rs` (lines 50-84)
**Category**: Safety

`Arena.data`, `Arena.free_indices`, and all `Heap` arena fields are `pub`. External code can push objects directly, bypassing `bytes_allocated` tracking and GC invariants.

**Fix**: Make arena fields `pub(crate)` or private, expose via accessor methods.

---

### M-11 — Map Tracing Comment Ambiguity [LOW]

**File**: `memory/src/heap.rs` (line 342)
**Category**: Documentation

Comment questions whether map keys (owned Strings in HashMap) need tracing. They don't (they're Rust heap, not GC arena), but the ambiguity could mislead future maintainers.

**Fix**: Clarify that HashMap keys are Rust-owned, not arena-allocated.

---

### M-12 — GC Threshold Hysteresis [LOW]

**File**: `memory/src/heap.rs` (lines 494-497)
**Category**: Performance

After sweep, threshold = max(bytes_allocated * 2, 1MB). If a program consistently allocates ~600KB, GC thrashes at every cycle.

**Fix**: Use `max(bytes_allocated * 2, previous_threshold * 3/2, 1MB)` for hysteresis.

---

### M-13 — Montgomery Reduction Documentation [LOW]

**File**: `memory/src/field.rs` (lines 119-159)
**Category**: Documentation

The Montgomery reduction is correct (from bellman/ff) but has no citation or proof sketch in comments. A single carry bug would corrupt all field arithmetic silently.

**Fix**: Add algorithm citation and reference test vectors.

---

### M-14 — Field Inverse via Exponentiation [LOW]

**File**: `memory/src/field.rs` (lines 406-417)
**Category**: Performance/Design

Uses Fermat's little theorem (a^(p-2) mod p), requiring ~256 field multiplications. Extended GCD would be faster but not constant-time. Current approach is correct for side-channel resistance.

**Fix**: Document the constant-time tradeoff. No code change needed.

---

### M-15 — NaN Canonicalization [LOW]

**File**: `memory/src/value.rs` (lines 34-42)
**Category**: Design

All NaN variants are mapped to `f64::NAN.to_bits()`. This is correct — Rust guarantees quiet NaN propagation. No issue.

**Fix**: None needed. Document as intentional.

---

## VM Crate (20 findings)

### V-01 — get_reg/set_reg Without Bounds Check [CRITICAL] [RESOLVED `dafb313`]

**File**: `vm/src/machine/stack.rs` (lines 12-17)
**Category**: Memory Safety

`self.stack[base + reg]` indexes without bounds checking. Crafted bytecode with arbitrary base/reg values can read/write arbitrary stack positions.

**Fix**: Changed `get_reg`/`set_reg` to use `.get()`/`.get_mut()` with `ok_or(StackOverflow)`. Updated 58 call sites across 7 files.

---

### V-02 — Return Writes to Unchecked dest_reg [CRITICAL] [RESOLVED `79f1aa0`]

**File**: `vm/src/machine/control.rs` (line 109)
**Category**: Memory Safety

`self.set_reg(0, frame.dest_reg, ret_val)` uses absolute addressing (base=0). If `dest_reg >= STACK_MAX`, the write is OOB. `dest_reg` is computed from `base + a` during Call without upper bound validation.

**Fix**: Added `base.checked_add(a).filter(|&d| d < STACK_MAX)` validation at Call time.

---

### V-03 — ForIter Mutation-During-Iteration [CRITICAL] [RESOLVED `40965a1`]

**File**: `vm/src/machine/vm.rs` (lines 481-524)
**Category**: Memory Safety

Iterator captures list handle at creation, then accesses `heap.get_list(handle)` each iteration. If the list is mutated (push/pop) during iteration, the iterator reads stale length/indices. Can cause OOB access or UAF.

**Fix**: GetIter now clones list contents into a new heap-allocated snapshot at iterator creation.

---

### V-04 — GetIter Map Allocation During Borrow [CRITICAL] [FALSE POSITIVE]

**File**: `vm/src/machine/vm.rs` (lines 449-471)
**Category**: Memory Safety

Code holds a reference to a map via `get_map(handle)`, then calls `alloc_string()` inside the same scope. Allocation may trigger GC, which can reallocate the map arena, invalidating the reference.

**Analysis**: False positive — the existing code already collects map keys in an inner block (`{ let map = ...; keys.collect() }`) ending the borrow before any allocations. GC only sets `request_gc` flag during allocation, never runs inline.

---

### V-05 — Upvalue Pointer Dereference Without Validation [CRITICAL] [RESOLVED]

**File**: `vm/src/machine/vm.rs` (lines 364, 379, 662, 667)
**Category**: Memory Safety

`unsafe { *upval.location }` dereferences a raw pointer without validating it points to valid memory. After upvalue close, `location` is set to `&mut self.closed`, creating a self-referential pointer that can be invalidated by arena growth.

**Fix**: Replaced `*mut Value` with `UpvalueLocation` enum (`Open(usize)` / `Closed(Value)`). All `unsafe` removed from VM crate. Upvalues are no longer `Box`-wrapped. See also M-05.

---

### V-06 — close_upvalues Pointer Comparison [CRITICAL] [RESOLVED]

**File**: `vm/src/machine/vm.rs` (lines 649-678)
**Category**: Memory Safety

`upval.location >= last` compares raw pointers that may span different allocations (stack vs heap). Pointer comparison across allocations is undefined behavior in Rust. Also, `next_open.unwrap()` can panic if the linked list is corrupted, and no cycle detection is present.

**Fix**: `close_upvalues` now takes `usize` (stack index) and compares `UpvalueLocation::Open(si)` against it — pure integer comparison, no raw pointers.

---

### V-07 — Prove Handler Pre-check Insufficient [HIGH]

**File**: `vm/src/machine/prove.rs` (lines 122-129)
**Category**: Robustness

If `prove_handler` is None, returns `ProveHandlerNotConfigured`. But if `frames` is empty when the Prove opcode executes, accessing the current frame's closure fails before the handler check. Error path leaks implementation details.

**Fix**: Check frames non-empty before accessing frame context in `handle_prove`.

---

### V-08 — GC Missing Proof Roots [HIGH]

**File**: `vm/src/machine/gc.rs` (lines 46-63)
**Category**: Memory Safety

`mark_roots()` collects stack Values as roots. These include proof handles (TAG_PROOF), which the trace function must follow to mark `ProofObject` in the heap. If `heap.trace()` doesn't handle TAG_PROOF, proofs are swept while still referenced.

**Fix**: Verify that `heap.trace()` marks `TAG_PROOF` values as leaf objects (same as TAG_FIELD).

---

### V-09 — Frames Vector Mutation During Interpret Loop [HIGH]

**File**: `vm/src/machine/vm.rs` (lines 166-184)
**Category**: Robustness

`frame_idx` is computed from `self.frames.len() - 1`. If a Return pops the last frame (line 179) and the loop continues, `frame_idx` is stale and `self.frames[frame_idx]` panics on OOB.

**Fix**: After pop, break the inner loop and re-fetch `frame_idx` at the top.

---

### V-10 — Interner HashMap Performance [HIGH]

**File**: `vm/src/machine/vm.rs` (lines 438-478)
**Category**: Performance

String interning uses `HashMap<String, u32>`. For map iteration in GetIter, each key triggers a `.get()` lookup. With large maps, this is O(n) per key, O(n^2) total.

**Fix**: Use a proper string pool with O(1) lookup and deduplication.

---

### V-11 — BuildList/BuildMap Insufficient Bounds Check [HIGH]

**File**: `vm/src/machine/data.rs` (lines 26, 48)
**Category**: Robustness

`start = base + b` can overflow if `base` is invalid. No check that `base < stack.len()` before computing `start`. Error message says "Stack underflow" when it's actually OOB.

**Fix**: Validate `base < stack.len()` before computing `start`.

---

### V-12 — Closure Upvalue Capture Linear Scan [MEDIUM]

**File**: `vm/src/machine/vm.rs` (lines 599-647)
**Category**: Performance

`capture_upvalue()` linearly scans the open upvalues linked list. For deeply nested closures with many captures, this is O(n^2).

**Fix**: Use a HashMap keyed by pointer/index for O(1) lookup.

---

### V-13 — val_to_string Allocates on Every Call [MEDIUM]

**File**: `vm/src/machine/vm.rs` (lines 88-110)
**Category**: Performance

`fe.to_decimal_string()` allocates a new String on every call. This is invoked by Print opcode, error formatting, and debugging.

**Fix**: Use a reusable buffer or cache formatted strings.

---

### V-14 — Non-Exhaustive Opcode Match [MEDIUM]

**File**: `vm/src/machine/vm.rs` (lines 192-532)
**Category**: Maintainability

The opcode dispatch uses `_ => Err(Unknown)` as default. Adding a new opcode without a match arm silently fails at runtime instead of compile time.

**Fix**: Match on all enum variants explicitly, or add a compile-time exhaustiveness test.

---

### V-15 — as_handle().unwrap() After Type Check [MEDIUM]

**File**: `vm/src/machine/vm.rs` (line 134), `vm/src/stdlib/core.rs` (line 226)
**Category**: Robustness

After `is_proof()` check, code calls `as_handle().unwrap()`. If Value encoding is corrupted, `as_handle()` returns None and panics.

**Fix**: Use `.as_handle().ok_or(RuntimeError::TypeMismatch(...))`.

---

### V-16 — ForIter Stack Frame Overlap [LOW]

**File**: `vm/src/machine/vm.rs` (line 485)
**Category**: Correctness

ForIter writes to `R[A+1]` without checking if it overlaps with the caller's frame locals. Could silently overwrite another variable.

**Fix**: Verify `base + a + 1 < base + max_slots` for the current frame.

---

### V-17 — Proof Equality by JSON Only [LOW]

**File**: `vm/src/machine/vm.rs` (lines 134-140)
**Category**: Semantics

Two proofs are equal iff their `proof_json` strings match. Different proofs for the same circuit or same proof serialized differently could compare incorrectly.

**Fix**: Consider adding circuit identity to equality comparison, or document the semantics.

---

### V-18 — Stack Not Zeroed on Reset [LOW]

**File**: `vm/src/machine/vm.rs` (lines 75-86)
**Category**: Information Leak

`reset()` doesn't zero the stack, leaving old values readable in debug contexts.

**Fix**: Optional: zero stack in debug builds.

---

### V-19 — USER_GLOBAL_START Coupling [LOW]

**File**: `vm/src/specs.rs` (line 29)
**Category**: Maintainability

`USER_GLOBAL_START = NATIVE_TABLE.len()`. Reordering or inserting natives silently shifts all user global indices. A test checks alignment at runtime, but not at compile time.

**Fix**: Use named constants per native index, or add compile-time assertion.

---

### V-20 — Missing Test Coverage for Edge Cases [LOW]

**File**: `vm/tests/`
**Category**: Testing

No tests for: stack overflow with deep recursion, GC during upvalue capture, malicious bytecode with raw instruction encoding, iterator mutation during loops, Prove with empty frames.

**Fix**: Add proptest fuzzing and edge case test suite.

---

## Compiler Crate (9 findings)

### C-01 — O(n) Power-of-Two Computation [HIGH]

**File**: `compiler/src/r1cs_backend.rs` (lines 1112-1120, 1436-1446), `compiler/src/plonkish_backend.rs` (lines 1277-1288)
**Category**: Performance

Computing 2^i for range check bit coefficients uses a loop: `pow = pow.add(&pow)` repeated i times. For 252-bit range checks (IsLt/IsLe), this is O(252) field additions per bit, O(252^2) total per comparison.

**Fix**: Pre-compute a lookup table `[FieldElement; 256]` of powers of 2 during compiler initialization.

---

### C-02 — Plonkish materialize_val Recursion Depth [MEDIUM]

**File**: `compiler/src/plonkish_backend.rs` (lines 557-635)
**Category**: Robustness

`materialize_val()` recursively materializes `DeferredAdd/Sub/Neg` expressions. Deeply nested arithmetic (e.g., 10,000 chained additions) can cause stack overflow.

**Fix**: Implement iterative materialization or add a depth limit.

---

### C-03 — Prove Block Array Size Unbounded [MEDIUM]

**File**: `compiler/src/control_flow.rs` (lines 405-413)
**Category**: Input Validation

`public x[N]` in prove blocks parses N without upper bound. `public x[1_000_000]` allocates 1M names.

**Fix**: Add `if n > 10_000 { return Err(...) }`.

---

### C-04 — Bit Extraction Index Documentation [LOW]

**File**: `compiler/src/witness_gen.rs` (line 1387), `compiler/src/plonkish_backend.rs` (line 1257)
**Category**: Documentation

Bit extraction safely handles indices up to 255 (4 limbs * 64 bits), but no comment clarifies this invariant.

**Fix**: Add comment: `// Field elements are 256 bits, max bit_index is 255`.

---

### C-05 — LC Cloning in multiply_lcs/divide_lcs [LOW]

**File**: `compiler/src/r1cs_backend.rs` (lines 838-885)
**Category**: Performance

Witness ops clone full LinearCombinations. For LCs with many terms, this wastes memory. The ops only need the target Variable.

**Fix**: Store only Variable targets in WitnessOp::Multiply/Inverse.

---

### C-06 — Unused Imports in codegen.rs [LOW]

**File**: `compiler/src/codegen.rs` (lines 3, 19, 23-25)
**Category**: Code Quality

Several unused imports: `Local`, `UpvalueInfo`, `LoopContext`, `BinaryCompiler`, `AtomCompiler`, `PostfixCompiler`, `parse_expression`.

**Fix**: Remove unused imports.

---

### C-07 — Dual Binding Maps Documentation [LOW]

**File**: `compiler/src/r1cs_backend.rs` (lines 22-24)
**Category**: Documentation

`bindings` (Variable) and `lc_bindings` (LinearCombination) serve different purposes but naming doesn't clarify the distinction.

**Fix**: Rename to `declared_vars` and `expression_cache`, or add doc comments.

---

### C-08 — compile_ir_with_witness Multi-Pass Design [LOW]

**File**: `compiler/src/r1cs_backend.rs` (lines 1338-1432)
**Category**: Documentation

Three-pass design (evaluate, compile, witness) is intentional for early validation but undocumented.

**Fix**: Add doc comment explaining the three-pass rationale.

---

### C-09 — HashMap Iteration in compile_ir [LOW]

**File**: `compiler/src/r1cs_backend.rs` (line 996)
**Category**: Documentation

`HashMap<SsaVar, LC>` is used as a lookup cache, not iterated. No soundness issue, but the choice of HashMap vs BTreeMap is undocumented.

**Fix**: Add comment clarifying it's a lookup cache with arbitrary iteration order.

---

## IR Crate (10 findings)

### I-01 — Evaluator Mux Uses `== ONE` Instead of `!= ZERO` [CRITICAL]

**File**: `ir/src/eval.rs` (lines 110-114)
**Category**: Soundness

The evaluator selects the Mux branch with `if c == FieldElement::ONE { t } else { f }`. The constraint system enforces `c*(c-1)=0`, allowing only 0 and 1. But if the evaluator receives a non-boolean c (e.g., 2), it silently selects `if_false`, while the circuit would reject the witness entirely. This creates a semantic mismatch between evaluation and constraint verification.

**Fix**: Either (a) error on non-boolean c: `if !c.is_zero() && c != ONE { return Err(NonBoolean) }`, or (b) use `if !c.is_zero() { t } else { f }` to match the circuit's behavior for valid witnesses.

---

### I-02 — Function Body Reparse unwrap() Panic [CRITICAL]

**File**: `ir/src/lower.rs` (line 1257)
**Category**: Robustness

`body_parsed.into_iter().next().unwrap()` panics if parsing returns zero pairs. The FnDef stores raw source that is re-parsed on each call. If the stored source is empty or malformed, the unwrap panics.

**Fix**: Replace with `.next().ok_or_else(|| IrError::ParseError("empty function body".into()))?`.

---

### I-03 — FnDef Stores Raw Source Instead of IR [HIGH]

**File**: `ir/src/lower.rs` (line 1255)
**Category**: Fragility

`FnDef { body_source: String }` stores raw grammar text and re-parses it on every function call. If the grammar changes between compilation passes, the re-parse may fail or produce different results. Also wasteful (parsing is repeated per call site).

**Fix**: Store pre-lowered IR instructions or a serialized AST instead of raw source.

---

### I-04 — IsLt/IsLe Limb Order Verification [HIGH]

**File**: `ir/src/passes/const_fold.rs` (lines 316-350)
**Category**: Soundness

Both const_fold and evaluator compare canonical limbs as big-endian tuples: `(la[3], la[2], la[1], la[0]) < (lb[3], lb[2], lb[1], lb[0])`. This assumes `to_canonical()` returns little-endian limbs. If the assumption is wrong, all comparisons are reversed.

**Fix**: Add edge-case tests: values near 2^64, 2^128, 2^192, and near the field modulus.

---

### I-05 — DCE Conservatively Keeps All Logic Ops [MEDIUM]

**File**: `ir/src/passes/dce.rs` (lines 33-45)
**Category**: Efficiency

Dead code elimination keeps `Not`, `And`, `Or`, `IsEq`, `IsNeq`, `IsLt`, `IsLe` even if unused, because they generate constraints. This is correct for R1CS but suboptimal for Plonkish, where unused logic ops waste rows.

**Fix**: Future: add backend-aware DCE pass.

---

### I-06 — Array Literal Element Type Validation [MEDIUM]

**File**: `ir/src/lower.rs` (lines 1551-1565)
**Category**: Type Safety

Array literals like `[x, [1,2]]` (mixed scalar/array) are accepted at lowering but fail later during compilation. Better to catch type errors early.

**Fix**: Verify all elements produce scalar `SsaVar`s, reject nested arrays.

---

### I-07 — Taint Analysis Mux Conservatism [MEDIUM]

**File**: `ir/src/passes/taint.rs` (lines 127-139)
**Category**: Analysis Completeness

Taint analysis merges taints from all three Mux operands (cond, if_true, if_false). This is conservative: an unused witness appearing in a non-selected branch appears constrained. Not a soundness bug, but may miss under-constrained warnings.

**Fix**: Document as intentionally conservative. Future: branch-sensitive taint analysis.

---

### I-08 — Empty Array vs Zero-Loop Inconsistency [LOW]

**File**: `ir/src/lower.rs` (lines 1339-1347, 1555-1559)
**Category**: Consistency

`let a = []` is rejected ("empty arrays not allowed in circuits"), but `for i in 0..0 { }` is accepted and returns zero. Both represent empty constructs.

**Fix**: Document the distinction: arrays are data (must be non-empty for indexing), loops are control flow (zero iterations is valid).

---

### I-09 — ParseError Uses Debug Format for Rule [LOW]

**File**: `ir/src/lower.rs` (lines 353-355)
**Category**: UX

Unmatched grammar rules produce errors like `Rule::SomeVariant` instead of user-friendly descriptions.

**Fix**: Use descriptive strings instead of `{:?}` for Rule variants.

---

### I-10 — IrLowering Monolith (1600+ lines) [LOW]

**File**: `ir/src/lower.rs`
**Category**: Maintainability

Single file with all lowering logic. Consider splitting into `lower_atoms.rs`, `lower_binops.rs`, `lower_builtins.rs`, `lower_control_flow.rs`, `lower_functions.rs`.

**Fix**: Modularize in a future refactor pass.

---

## Constraints Crate (9 findings)

### X-01 — Plonkish Rotation Integer Underflow [CRITICAL]

**File**: `constraints/src/plonkish.rs` (lines 81-83)
**Category**: Soundness

```rust
let actual_row = (row as i64 + *rotation as i64) as usize;
```

When `rotation` is negative and `|rotation| > row`, the result wraps to a huge `usize` (e.g., row=0, rotation=-1 becomes usize::MAX). The assignments table returns `FieldElement::ZERO` for out-of-bounds access, allowing a malicious prover to satisfy gates using uninitialized cells.

**Fix**: Check `actual_row >= 0 && actual_row < num_rows` before accessing assignments.

---

### X-02 — LC::evaluate() Unchecked Array Index [CRITICAL]

**File**: `constraints/src/r1cs.rs` (lines 136-143)
**Category**: Robustness

`witness[var.0]` panics if `var.0 >= witness.len()`. While `ConstraintSystem::verify()` checks witness length, `evaluate()` is a public method callable with mismatched witnesses.

**Fix**: Return `Result<FieldElement, EvalError>` with bounds checking, or add `debug_assert!`.

---

### X-03 — O(N^2) Lookup Verification [HIGH]

**File**: `constraints/src/plonkish.rs` (lines 382-419)
**Category**: Performance

Lookup verification uses `Vec::contains()` to check membership in the table set. For N rows, this is O(N^2). With N=2^20 rows, this is ~10^12 comparisons.

**Fix**: Use `HashSet<Vec<FieldElement>>` (requires FieldElement: Hash) or sorted Vec with binary search.

---

### X-04 — Selector vs Legacy Heuristic Mixing [MEDIUM]

**File**: `constraints/src/plonkish.rs` (lines 394-411)
**Category**: Correctness

Two row-activation rules coexist: selector-based (skip if selector=0) and legacy (skip if all inputs=0). Registering the same lookup both with and without a selector can produce inconsistent verification.

**Fix**: Document as undefined behavior, or enforce that all lookups for a name use the same activation mode.

---

### X-05 — Export nPubOut Documentation [MEDIUM]

**File**: `constraints/src/export.rs` (lines 54-66)
**Category**: Documentation

`nPubOut = 0` is correct for Achronyme (no computed outputs), but the iden3 spec distinction between outputs and inputs is not documented. Could mislead someone extending the export.

**Fix**: Add doc comment explaining the wire layout and why nPubOut is always 0.

---

### X-06 — BN254 Prime Verified [LOW]

**File**: `constraints/src/export.rs` (lines 11-28)
**Category**: Verified Sound

`BN254_PRIME_LE` is verified correct by test `test_bn254_prime_bytes`. No issue.

---

### X-07 — WitnessBuilder No Bounds Check [LOW]

**File**: `constraints/src/witness.rs` (lines 24-26)
**Category**: Robustness

`self.values[var.index()] = val` panics on OOB. Used only in test code, not public API.

**Fix**: Add descriptive panic message with index and length.

---

### X-08 — Poseidon Hex Parsing Panics [LOW]

**File**: `constraints/src/poseidon.rs` (lines 44-57)
**Category**: Robustness

`fe_from_hex()` uses `assert!` and `.unwrap()` for parsing hardcoded hex constants. In practice, these never fail since the constants are compile-time literals.

**Fix**: Low priority. Optionally return `Result` for consistency.

---

### X-09 — Poseidon Capacity Constraint Verified [LOW]

**File**: `constraints/src/poseidon.rs` (lines 686-700)
**Category**: Verified Sound

Capacity wire is correctly constrained to zero via `enforce_equal(capacity, zero)`. Confirmed sound — the constraint prevents malicious provers from using non-zero capacity.

---

## CLI Crate (13 findings)

### L-01 — Hardcoded Entropy in Trusted Setup [CRITICAL]

**File**: `cli/src/prove_handler.rs` (lines 191-192, 228-229)
**Category**: Security

Both the Powers of Tau ceremony and zkey contribution use literal `"-e=entropy"` instead of cryptographically secure randomness. An attacker knowing this string can reconstruct the toxic waste and forge proofs for any statement.

**Fix**: Use `getrandom` or `rand::OsRng` to generate 32+ bytes of entropy. Alternatively, pipe `/dev/urandom` to snarkjs stdin.

---

### L-02 — Weak DefaultHasher for Cache Key [CRITICAL]

**File**: `cli/src/prove_handler.rs` (lines 150-155)
**Category**: Security

`DefaultHasher` (SipHash, 64-bit) hashes R1CS bytes to create cache directory names. Birthday attack: ~2^32 circuits to find a collision, allowing cached zkey reuse across different circuits.

**Fix**: Use SHA-256 (add `sha2` dependency) for collision-resistant cache keys.

---

### L-03 — Untrusted Cache Files [HIGH]

**File**: `cli/src/prove_handler.rs` (lines 159-160)
**Category**: Security

Cached zkey/vkey files are loaded without any validation. An attacker with write access to `~/.achronyme/cache/` can replace them with malicious files, compromising all subsequent proofs.

**Fix**: Validate file format headers, check Unix permissions (0600), optionally verify against a stored hash.

---

### L-04 — TOCTOU Race on Cache [HIGH]

**File**: `cli/src/prove_handler.rs` (lines 159-176)
**Category**: Security

Between `.exists()` check and file use, an attacker can replace cache files with symlinks or malicious content. Two concurrent processes can also race to create the cache.

**Fix**: Use advisory file locking (`flock`), or atomic rename after generation.

---

### L-05 — Temp Directory Cleanup [HIGH]

**File**: `cli/src/prove_handler.rs` (lines 90-91, 131-136)
**Category**: Security

`tempfile::tempdir()` auto-deletes on drop, but doesn't securely wipe files. Witness data and intermediate values can be recovered from disk via forensics.

**Fix**: Overwrite sensitive files with zeros before deletion.

---

### L-06 — HOME Environment Variable Injection [HIGH]

**File**: `cli/src/prove_handler.rs` (lines 21-23)
**Category**: Security

`std::env::var("HOME")` is used unsanitized for cache directory. Attacker can set `HOME=/etc/vulnerable` to redirect cache writes to privileged locations.

**Fix**: Validate HOME is absolute, or use `dirs::home_dir()` crate.

---

### L-07 — Unrestricted --ptau Path [HIGH]

**File**: `cli/src/args.rs` (line 22), `cli/src/prove_handler.rs` (line 26)
**Category**: Security

`--ptau` accepts any path without validation. Path traversal (`../../etc/passwd`) or special files (`/proc/self/environ`) can be passed to snarkjs, potentially leaking data via error messages.

**Fix**: Validate path is absolute, has no `..` components, exists, and is a regular file.

---

### L-08 — Unsanitized snarkjs stderr [MEDIUM]

**File**: `cli/src/prove_handler.rs` (lines 266-271)
**Category**: Information Disclosure

snarkjs stderr (including file paths, Node.js stack traces, npm cache paths) is displayed directly to the user.

**Fix**: Filter out lines containing `/home/`, `node_modules`, `at `, etc.

---

### L-09 — No Timeout on snarkjs Subprocess [MEDIUM]

**File**: `cli/src/prove_handler.rs` (lines 262-265)
**Category**: DoS

`Command::new("npx").output()` blocks indefinitely. A very large circuit can hang the CLI forever.

**Fix**: Use `timeout` command wrapper or spawn with a deadline.

---

### L-10 — Unbounded Cache Growth [MEDIUM]

**File**: `cli/src/prove_handler.rs`
**Category**: Resource Exhaustion

No limit on `~/.achronyme/cache/` size. Each unique circuit adds a cache entry (ptau ~100MB, zkey ~1-10GB).

**Fix**: Add LRU eviction with configurable max size.

---

### L-11 — Path to_str().unwrap() Panics [MEDIUM]

**File**: `cli/src/prove_handler.rs` (lines 114-237, 8 occurrences)
**Category**: Robustness

`.to_str().unwrap()` panics if temp path contains non-UTF8 characters. Unlikely but possible on some filesystems.

**Fix**: Use `path.to_str().ok_or("non-UTF8 path")?` or pass `OsStr` directly to Command args.

---

### L-12 — snarkjs_available() Called Per Prove Block [MEDIUM]

**File**: `cli/src/prove_handler.rs` (line 74)
**Category**: Performance

Each `prove {}` block spawns `npx snarkjs --version` to check availability. With 100 prove blocks, that's 100 subprocesses.

**Fix**: Cache the result in `DefaultProveHandler` at construction time.

---

### L-13 — Missing Input Length Validation [LOW]

**File**: `cli/src/commands/circuit.rs` (lines 39-48)
**Category**: Input Validation

The `--inputs` string has no length limit. A multi-GB string could exhaust memory during parsing.

**Fix**: Add `if inputs.len() > 1_000_000 { return Err(...) }`.

---

## Parser Crate (17 findings)

### P-01 — Empty Braces Ambiguity [MEDIUM]

**File**: `achronyme-parser/src/grammar.pest` (lines 40, 60, 67)
**Category**: Grammar

`{ }` parses as empty `map_literal` (not empty `block`) because `map_literal` appears first in `atom`. Semantically harmless for `if/while/for/fn` (which require `block`), but standalone `{ }` becomes an empty map.

**Fix**: Document behavior. `{ nil }` or `{ ; }` for empty blocks.

---

### P-02 — Missing String Escape Sequences [MEDIUM]

**File**: `achronyme-parser/src/grammar.pest` (lines 77-82)
**Category**: Grammar

Supported: `\"`, `\\`, `/`, `b`, `f`, `n`, `r`, `t`. Missing: `\uXXXX`, `\xXX`. Unknown escapes like `\x` fail the entire string parse.

**Fix**: Either add fallback `"\\" ~ ANY` for lenient parsing, or document supported escapes.

---

### P-03 — Number Parsing Allows Pathological Input [MEDIUM]

**File**: `achronyme-parser/src/grammar.pest` (lines 22-24)
**Category**: DoS

No length limit on integer literals. `123...` (millions of digits) is accepted by the parser and silently loses precision in f64 conversion.

**Fix**: Limit to `ASCII_DIGIT{1,20}` or add length validation in the compiler.

---

### P-04 — Builtins Not Reserved as Keywords [MEDIUM]

**File**: `achronyme-parser/src/grammar.pest` (line 30)
**Category**: Grammar

`poseidon`, `assert_eq`, `mux`, `range_check`, etc. are not in the `keyword` list. A user can shadow them: `let poseidon = 42`, then `poseidon(a, b)` fails with a confusing error.

**Fix**: Add builtins to keyword list, or detect and error on shadowing.

---

### P-05 — Rule Coupling (247 references, 44 variants) [MEDIUM]

**File**: Entire codebase
**Category**: Architecture

The `Rule` enum is pattern-matched 247 times across compiler, IR, and CLI. Any grammar rename breaks everything. No AST abstraction layer exists.

**Fix**: Long-term: introduce typed AST. Short-term: freeze grammar schema and document as stable API.

---

### P-06 — Power Operator Left-Associative [MEDIUM]

**File**: `achronyme-parser/src/grammar.pest` (line 129)
**Category**: Semantic Bug

`pow_expr = { postfix_expr ~ (pow_op ~ postfix_expr)* }` parses `2^3^2` as `(2^3)^2 = 64`. Standard math convention is right-associative: `2^(3^2) = 512`.

**Fix**: Change to `pow_expr = { postfix_expr ~ (pow_op ~ pow_expr)? }` for right-recursion.

---

### P-07 — No Recursion Depth Limit [MEDIUM]

**File**: `achronyme-parser/src/grammar.pest`
**Category**: DoS

Deeply nested expressions (10,000+ levels of parentheses or if/else) can cause stack overflow in pest's recursive descent parser.

**Fix**: Test practical limits. Add documentation or a pre-parse depth check.

---

### P-08 — Dangling-Else Confirmed Safe [RESOLVED]

**File**: `achronyme-parser/src/grammar.pest` (line 44)
**Category**: Verified Sound

PEG's greedy matching resolves the dangling-else unambiguously. No issue.

---

### P-09 — Decimal Rejection in Circuits [LOW]

**File**: `achronyme-parser/src/grammar.pest` (line 23)
**Category**: Design

Grammar permits decimals but R1CS compiler rejects them. Intentional (BN254 is integer field).

**Fix**: Document that decimals are VM-only.

---

### P-10 — Comparison Limited to Single [LOW]

**File**: `achronyme-parser/src/grammar.pest` (lines 135-138)
**Category**: Verified Sound

`cmp_expr` uses `?` (zero or one) to prevent chained comparisons like `a < b < c`. Intentional safeguard.

---

### P-11 — for...in Runtime Semantics [LOW]

**File**: `achronyme-parser/src/grammar.pest` (line 47)
**Category**: Documentation

Grammar allows `for x in expr` but compiler restricts `expr` to ranges or array identifiers.

**Fix**: Document the restriction.

---

### P-12 — `in` Keyword Reserved [LOW]

**File**: `achronyme-parser/src/grammar.pest` (lines 30, 47)
**Category**: Design

`in` is reserved but only used in `for...in`. Future-proofing reservation. No issue.

---

### P-13 — No Unicode Identifiers [LOW]

**File**: `achronyme-parser/src/grammar.pest` (line 26)
**Category**: Design

Identifiers are ASCII-only (`ASCII_ALPHA | "_"`). Design choice, not a bug.

**Fix**: Document as intentional. Consider `UNICODE_LETTER` for future internationalization.

---

### P-14 — No Nested Block Comments [LOW]

**File**: `achronyme-parser/src/grammar.pest` (line 14)
**Category**: Design

Block comments `/* ... */` don't nest. Standard behavior (same as C, Java).

**Fix**: Document as intentional.

---

### P-15 — Trailing Comma Inconsistency [LOW]

**File**: `achronyme-parser/src/grammar.pest` (lines 38, 40, 52, 102)
**Category**: Style

Lists and maps allow trailing commas. Function params and call args do not.

**Fix**: Add `","?` to `param_list` and `call_op` for consistency.

---

### P-16 — Number Precision Loss in f64 [LOW]

**File**: `compiler/src/expressions/atoms.rs` (line 199)
**Category**: Correctness

`s.parse::<f64>()` silently loses precision for integers > 2^53. VM-only issue (IR uses FieldElement).

**Fix**: Document IEEE 754 limits. Optionally warn on precision loss.

---

### P-17 — Missing Grammar Documentation [LOW]

**File**: `achronyme-parser/src/grammar.pest`
**Category**: Documentation

No operator precedence table, associativity rules, or escape sequence reference in the grammar file.

**Fix**: Add comprehensive header documentation.

---

## Recommended Fix Priority

### Immediate (Security-Critical)

1. **L-01** — Replace hardcoded entropy with cryptographic RNG
2. **L-02** — Replace DefaultHasher with SHA-256 for cache keys
3. ~~**V-01** — Add bounds checking to get_reg/set_reg~~ [RESOLVED `dafb313`]
4. ~~**V-02** — Validate dest_reg before Return write~~ [RESOLVED `79f1aa0`]
5. **I-01** — Fix Mux evaluator semantics
6. **X-01** — Fix Plonkish rotation underflow

### High Priority (Safety)

7. ~~**V-03** — Fix ForIter mutation-during-iteration~~ [RESOLVED `40965a1`]
8. ~~**V-04** — Fix GetIter GC-during-borrow~~ [FALSE POSITIVE]
9. ~~**V-05/V-06** — Fix upvalue pointer unsoundness~~ [RESOLVED]
10. **L-03/L-04** — Validate cache files, fix TOCTOU
11. **P-06** — Fix power operator associativity
12. ~~**M-02** — Fix ProofObject sweep accounting~~ [RESOLVED `e4e3edb`]
13. **I-02** — Replace unwrap with error handling

### Medium Priority (Robustness)

14. ~~**M-01** — HashSet for sweep free_indices~~ [RESOLVED `e594a96`]
15. **M-06** — Track import_strings allocation
16. **X-02** — Bounds check in LC::evaluate()
17. **X-03** — HashSet for lookup verification
18. **L-06/L-07** — Validate HOME and --ptau paths
19. **L-09** — Add snarkjs subprocess timeout
20. **L-12** — Cache snarkjs_available result

### Low Priority (Polish)

21-93. Documentation, trailing commas, code deduplication, naming, test coverage gaps.
