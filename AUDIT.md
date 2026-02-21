# Achronyme Security & Engineering Audit

**Date**: 2026-02-21
**Last updated**: 2026-02-21
**Scope**: All 7 workspace crates
**Severity scale**: CRITICAL > HIGH > MEDIUM > LOW

---

## Summary

| Crate | Open | Resolved | False Positive | Total |
|-------|------|----------|----------------|-------|
| memory | 0 | 14 (+1 partial) | 0 | 15 |
| vm | 0 | 14 | 6 | 20 |
| compiler | 0 | 9 | 0 | 9 |
| ir | 8 | 2 | 0 | 10 |
| constraints | 5 | 2 | 2 | 9 |
| cli | 11 | 2 | 0 | 13 |
| parser | 12 | 0 | 5 | 17 |
| **TOTAL** | **36** | **43 (+1)** | **13** | **93** |

### Open by severity

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 10 |
| MEDIUM | 14 |
| LOW | 12 |

---

## Resolved Findings (44)

| ID | Severity | Crate | Description | Commit |
|----|----------|-------|-------------|--------|
| M-01 | HIGH | memory | O(n) linear search in GC sweep → HashSet O(1) | `e594a96` |
| M-02 | HIGH | memory | ProofObject strings not deducted on sweep | `e4e3edb` |
| M-03 | HIGH | memory | Arena index overflow to u32::MAX → `try_from` | `e4e3edb` |
| M-04 | HIGH | memory | Missing bounds check on Arena get_* → `Arena::get/get_mut` | `c31ed78` |
| M-05 | HIGH | memory | Upvalue self-referential raw pointer → `UpvalueLocation` enum | — |
| M-09 | MEDIUM | memory | Code duplication in alloc_*/sweep (partial: alloc + get centralized) | `e4e3edb` |
| V-01 | CRITICAL | vm | get_reg/set_reg without bounds check → `.get()` + `ok_or` | `dafb313` |
| V-02 | CRITICAL | vm | Return writes to unchecked dest_reg → `checked_add` validation | `79f1aa0` |
| V-03 | CRITICAL | vm | ForIter mutation-during-iteration → snapshot clone | `40965a1` |
| V-05 | CRITICAL | vm | Upvalue pointer dereference → `UpvalueLocation` enum, all `unsafe` removed | — |
| V-06 | CRITICAL | vm | close_upvalues pointer comparison → integer comparison | — |
| V-07 | HIGH | vm | Prove handler pre-check insufficient → moved to top of `handle_prove` | — |
| V-11 | HIGH | vm | BuildList/BuildMap bounds check → `checked_add` chains | — |
| V-14 | MEDIUM | vm | Non-exhaustive opcode match → exhaustive dispatch | `f547ff5` |
| V-15 | MEDIUM | vm | `as_handle().unwrap()` after type check → `.ok_or()` in all 30 sites (6 files) | `0a314dd` |
| V-16 | LOW | vm | ForIter R[A+1] frame overlap → `max_slots` guard | `54a8e7f` |
| V-18 | LOW | vm | Stack not zeroed on reset → `fill(nil)` in debug builds | `b4d66d4` |
| V-19 | LOW | vm | USER_GLOBAL_START coupling → compile-time `NATIVE_COUNT` assertion | `d7758e8` |
| V-20 | LOW | vm | Missing edge case tests → 18 tests (bytecode, GC, recursion, prove) | `1d391ea` |
| M-06 | HIGH | memory | `import_strings` missing allocation tracking → sum capacities + `check_gc()` | `d7503c8` |
| M-07 | MEDIUM | memory | NaN boxing tag overflow → compile-time `assert!(TAG < 16)` for all 13 tags | `7e01699` |
| M-08 | MEDIUM | memory | `bytes_allocated` drift → `recount_live_bytes()` after sweep (self-correcting) | `d9dbf70` |
| M-10 | MEDIUM | memory | Public arena/mark fields → `pub(crate)` + public accessors | `41b249f` |
| M-11 | LOW | memory | Map tracing comment ambiguity → clarified + simplified to `m.values()` | `7a43535` |
| M-12 | LOW | memory | GC threshold thrashing → `max(2× live, 1.5× prev, 1MB)` hysteresis | `a27e0c7` |
| L-01 | CRITICAL | cli | Hardcoded entropy in trusted setup → `getrandom` 32-byte OS randomness | `3362252` |
| L-02 | CRITICAL | cli | Weak DefaultHasher cache key → SHA-256 collision-resistant hash | `512c3e0` |
| X-01 | CRITICAL | constraints | Plonkish rotation integer underflow → bounds check before access | `039e498` |
| C-01 | HIGH | compiler | O(n) power-of-two → `LazyLock` lookup table [FieldElement; 253] | `1b0c3e0` |
| I-01 | CRITICAL | ir | Mux evaluator `== ONE` → validate boolean + `!is_zero()`, `NonBooleanMuxCondition` error | `fcd99ef` |
| I-02 | CRITICAL | ir | Function body reparse `unwrap()` → `.ok_or_else()` error handling | `fcd99ef` |
| X-02 | CRITICAL | constraints | `LC::evaluate()` unchecked index → `.get()` with descriptive panic | `fcd99ef` |
| M-13 | LOW | memory | Montgomery reduction citation + reference test vectors | `5ebd77f` |
| M-14 | LOW | memory | Field inverse constant-time tradeoff documented in `inv()` doc comment | `08ac06c` |
| M-15 | LOW | memory | NaN canonicalization documented as intentional in `number()` | `08ac06c` |
| V-17 | LOW | vm | Proof equality compares all 3 fields + documented as structural | `a87efd3` |
| C-02 | MEDIUM | compiler | `materialize_val` recursion depth limit (1,000) | `fdbedc2` |
| C-03 | MEDIUM | compiler | Prove block array size bounded to 10,000 | `fdbedc2` |
| C-04 | LOW | compiler | Bit extraction index invariant documented (max 255) | `fdbedc2` |
| C-05 | LOW | compiler | LC cloning in `multiply_lcs` documented as necessary | `fdbedc2` |
| C-06 | LOW | compiler | Unused imports removed from codegen.rs, scopes.rs, types.rs | `fdbedc2` |
| C-07 | LOW | compiler | `bindings`/`lc_bindings` doc comments clarify purpose | `fdbedc2` |
| C-08 | LOW | compiler | `compile_ir_with_witness` three-pass design documented | `fdbedc2` |
| C-09 | LOW | compiler | `HashMap<SsaVar, LC>` documented as lookup cache | `fdbedc2` |

## False Positives & Confirmed Sound (13)

| ID | Crate | Reason |
|----|-------|--------|
| V-04 | vm | GetIter map borrow ends before allocation; GC is deferred |
| V-08 | vm | `heap.trace()` already handles TAG_PROOF as leaf type |
| V-09 | vm | `frame_idx` recomputed each loop iteration; emptiness checked |
| V-10 | vm | HashMap::get is O(1) amortized, not O(n) |
| V-12 | vm | Upvalue list is sorted with early-exit; standard CLox design |
| V-13 | vm | `val_to_string` allocation is inherent; Print is not hot path |
| X-06 | constraints | BN254_PRIME_LE verified by test |
| X-09 | constraints | Poseidon capacity wire correctly constrained to zero |
| P-08 | parser | PEG greedy matching resolves dangling-else unambiguously |
| P-10 | parser | Single comparison is intentional safeguard |
| P-12 | parser | `in` keyword reservation is future-proofing, no issue |
| P-13 | parser | ASCII-only identifiers is a design choice |
| P-14 | parser | Non-nested block comments is standard (C, Java) |

---

## Open Findings

### IR Crate (8 open)

#### I-03 — FnDef Stores Raw Source Instead of IR [HIGH]

**File**: `ir/src/lower.rs` (line 1255)
**Category**: Fragility

`FnDef { body_source: String }` stores raw grammar text and re-parses it on every function call. If the grammar changes between compilation passes, the re-parse may fail or produce different results. Also wasteful (parsing is repeated per call site).

**Fix**: Store pre-lowered IR instructions or a serialized AST instead of raw source.

---

#### I-04 — IsLt/IsLe Limb Order Verification [HIGH]

**File**: `ir/src/passes/const_fold.rs` (lines 316-350)
**Category**: Soundness

Both const_fold and evaluator compare canonical limbs as big-endian tuples: `(la[3], la[2], la[1], la[0]) < (lb[3], lb[2], lb[1], lb[0])`. This assumes `to_canonical()` returns little-endian limbs. If the assumption is wrong, all comparisons are reversed.

**Fix**: Add edge-case tests: values near 2^64, 2^128, 2^192, and near the field modulus.

---

#### I-05 — DCE Conservatively Keeps All Logic Ops [MEDIUM]

**File**: `ir/src/passes/dce.rs` (lines 33-45)
**Category**: Efficiency

Dead code elimination keeps `Not`, `And`, `Or`, `IsEq`, `IsNeq`, `IsLt`, `IsLe` even if unused, because they generate constraints. This is correct for R1CS but suboptimal for Plonkish, where unused logic ops waste rows.

**Fix**: Future: add backend-aware DCE pass.

---

#### I-06 — Array Literal Element Type Validation [MEDIUM]

**File**: `ir/src/lower.rs` (lines 1551-1565)
**Category**: Type Safety

Array literals like `[x, [1,2]]` (mixed scalar/array) are accepted at lowering but fail later during compilation. Better to catch type errors early.

**Fix**: Verify all elements produce scalar `SsaVar`s, reject nested arrays.

---

#### I-07 — Taint Analysis Mux Conservatism [MEDIUM]

**File**: `ir/src/passes/taint.rs` (lines 127-139)
**Category**: Analysis Completeness

Taint analysis merges taints from all three Mux operands (cond, if_true, if_false). This is conservative: an unused witness appearing in a non-selected branch appears constrained. Not a soundness bug, but may miss under-constrained warnings.

**Fix**: Document as intentionally conservative. Future: branch-sensitive taint analysis.

---

#### I-08 — Empty Array vs Zero-Loop Inconsistency [LOW]

**File**: `ir/src/lower.rs` (lines 1339-1347, 1555-1559)
**Category**: Consistency

`let a = []` is rejected ("empty arrays not allowed in circuits"), but `for i in 0..0 { }` is accepted and returns zero. Both represent empty constructs.

**Fix**: Document the distinction: arrays are data (must be non-empty for indexing), loops are control flow (zero iterations is valid).

---

#### I-09 — ParseError Uses Debug Format for Rule [LOW]

**File**: `ir/src/lower.rs` (lines 353-355)
**Category**: UX

Unmatched grammar rules produce errors like `Rule::SomeVariant` instead of user-friendly descriptions.

**Fix**: Use descriptive strings instead of `{:?}` for Rule variants.

---

#### I-10 — IrLowering Monolith (1600+ lines) [LOW]

**File**: `ir/src/lower.rs`
**Category**: Maintainability

Single file with all lowering logic. Consider splitting into `lower_atoms.rs`, `lower_binops.rs`, `lower_builtins.rs`, `lower_control_flow.rs`, `lower_functions.rs`.

**Fix**: Modularize in a future refactor pass.

---

### Constraints Crate (5 open)

#### X-03 — O(N^2) Lookup Verification [HIGH]

**File**: `constraints/src/plonkish.rs` (lines 382-419)
**Category**: Performance

Lookup verification uses `Vec::contains()` to check membership in the table set. For N rows, this is O(N^2). With N=2^20 rows, this is ~10^12 comparisons.

**Fix**: Use `HashSet<Vec<FieldElement>>` (requires FieldElement: Hash) or sorted Vec with binary search.

---

#### X-04 — Selector vs Legacy Heuristic Mixing [MEDIUM]

**File**: `constraints/src/plonkish.rs` (lines 394-411)
**Category**: Correctness

Two row-activation rules coexist: selector-based (skip if selector=0) and legacy (skip if all inputs=0). Registering the same lookup both with and without a selector can produce inconsistent verification.

**Fix**: Document as undefined behavior, or enforce that all lookups for a name use the same activation mode.

---

#### X-05 — Export nPubOut Documentation [MEDIUM]

**File**: `constraints/src/export.rs` (lines 54-66)
**Category**: Documentation

`nPubOut = 0` is correct for Achronyme (no computed outputs), but the iden3 spec distinction between outputs and inputs is not documented. Could mislead someone extending the export.

**Fix**: Add doc comment explaining the wire layout and why nPubOut is always 0.

---

#### X-07 — WitnessBuilder No Bounds Check [LOW]

**File**: `constraints/src/witness.rs` (lines 24-26)
**Category**: Robustness

`self.values[var.index()] = val` panics on OOB. Used only in test code, not public API.

**Fix**: Add descriptive panic message with index and length.

---

#### X-08 — Poseidon Hex Parsing Panics [LOW]

**File**: `constraints/src/poseidon.rs` (lines 44-57)
**Category**: Robustness

`fe_from_hex()` uses `assert!` and `.unwrap()` for parsing hardcoded hex constants. In practice, these never fail since the constants are compile-time literals.

**Fix**: Low priority. Optionally return `Result` for consistency.

---

### CLI Crate (11 open)

#### L-03 — Untrusted Cache Files [HIGH]

**File**: `cli/src/prove_handler.rs` (lines 159-160)
**Category**: Security

Cached zkey/vkey files are loaded without any validation. An attacker with write access to `~/.achronyme/cache/` can replace them with malicious files, compromising all subsequent proofs.

**Fix**: Validate file format headers, check Unix permissions (0600), optionally verify against a stored hash.

---

#### L-04 — TOCTOU Race on Cache [HIGH]

**File**: `cli/src/prove_handler.rs` (lines 159-176)
**Category**: Security

Between `.exists()` check and file use, an attacker can replace cache files with symlinks or malicious content. Two concurrent processes can also race to create the cache.

**Fix**: Use advisory file locking (`flock`), or atomic rename after generation.

---

#### L-05 — Temp Directory Cleanup [HIGH]

**File**: `cli/src/prove_handler.rs` (lines 90-91, 131-136)
**Category**: Security

`tempfile::tempdir()` auto-deletes on drop, but doesn't securely wipe files. Witness data and intermediate values can be recovered from disk via forensics.

**Fix**: Overwrite sensitive files with zeros before deletion.

---

#### L-06 — HOME Environment Variable Injection [HIGH]

**File**: `cli/src/prove_handler.rs` (lines 21-23)
**Category**: Security

`std::env::var("HOME")` is used unsanitized for cache directory. Attacker can set `HOME=/etc/vulnerable` to redirect cache writes to privileged locations.

**Fix**: Validate HOME is absolute, or use `dirs::home_dir()` crate.

---

#### L-07 — Unrestricted --ptau Path [HIGH]

**File**: `cli/src/args.rs` (line 22), `cli/src/prove_handler.rs` (line 26)
**Category**: Security

`--ptau` accepts any path without validation. Path traversal (`../../etc/passwd`) or special files (`/proc/self/environ`) can be passed to snarkjs, potentially leaking data via error messages.

**Fix**: Validate path is absolute, has no `..` components, exists, and is a regular file.

---

#### L-08 — Unsanitized snarkjs stderr [MEDIUM]

**File**: `cli/src/prove_handler.rs` (lines 266-271)
**Category**: Information Disclosure

snarkjs stderr (including file paths, Node.js stack traces, npm cache paths) is displayed directly to the user.

**Fix**: Filter out lines containing `/home/`, `node_modules`, `at `, etc.

---

#### L-09 — No Timeout on snarkjs Subprocess [MEDIUM]

**File**: `cli/src/prove_handler.rs` (lines 262-265)
**Category**: DoS

`Command::new("npx").output()` blocks indefinitely. A very large circuit can hang the CLI forever.

**Fix**: Use `timeout` command wrapper or spawn with a deadline.

---

#### L-10 — Unbounded Cache Growth [MEDIUM]

**File**: `cli/src/prove_handler.rs`
**Category**: Resource Exhaustion

No limit on `~/.achronyme/cache/` size. Each unique circuit adds a cache entry (ptau ~100MB, zkey ~1-10GB).

**Fix**: Add LRU eviction with configurable max size.

---

#### L-11 — Path to_str().unwrap() Panics [MEDIUM]

**File**: `cli/src/prove_handler.rs` (lines 114-237, 8 occurrences)
**Category**: Robustness

`.to_str().unwrap()` panics if temp path contains non-UTF8 characters. Unlikely but possible on some filesystems.

**Fix**: Use `path.to_str().ok_or("non-UTF8 path")?` or pass `OsStr` directly to Command args.

---

#### L-12 — snarkjs_available() Called Per Prove Block [MEDIUM]

**File**: `cli/src/prove_handler.rs` (line 74)
**Category**: Performance

Each `prove {}` block spawns `npx snarkjs --version` to check availability. With 100 prove blocks, that's 100 subprocesses.

**Fix**: Cache the result in `DefaultProveHandler` at construction time.

---

#### L-13 — Missing Input Length Validation [LOW]

**File**: `cli/src/commands/circuit.rs` (lines 39-48)
**Category**: Input Validation

The `--inputs` string has no length limit. A multi-GB string could exhaust memory during parsing.

**Fix**: Add `if inputs.len() > 1_000_000 { return Err(...) }`.

---

### Parser Crate (12 open)

#### P-01 — Empty Braces Ambiguity [MEDIUM]

**File**: `achronyme-parser/src/grammar.pest` (lines 40, 60, 67)
**Category**: Grammar

`{ }` parses as empty `map_literal` (not empty `block`) because `map_literal` appears first in `atom`. Semantically harmless for `if/while/for/fn` (which require `block`), but standalone `{ }` becomes an empty map.

**Fix**: Document behavior. `{ nil }` or `{ ; }` for empty blocks.

---

#### P-02 — Missing String Escape Sequences [MEDIUM]

**File**: `achronyme-parser/src/grammar.pest` (lines 77-82)
**Category**: Grammar

Supported: `\"`, `\\`, `/`, `b`, `f`, `n`, `r`, `t`. Missing: `\uXXXX`, `\xXX`. Unknown escapes like `\x` fail the entire string parse.

**Fix**: Either add fallback `"\\" ~ ANY` for lenient parsing, or document supported escapes.

---

#### P-03 — Number Parsing Allows Pathological Input [MEDIUM]

**File**: `achronyme-parser/src/grammar.pest` (lines 22-24)
**Category**: DoS

No length limit on integer literals. `123...` (millions of digits) is accepted by the parser and silently loses precision in f64 conversion.

**Fix**: Limit to `ASCII_DIGIT{1,20}` or add length validation in the compiler.

---

#### P-04 — Builtins Not Reserved as Keywords [MEDIUM]

**File**: `achronyme-parser/src/grammar.pest` (line 30)
**Category**: Grammar

`poseidon`, `assert_eq`, `mux`, `range_check`, etc. are not in the `keyword` list. A user can shadow them: `let poseidon = 42`, then `poseidon(a, b)` fails with a confusing error.

**Fix**: Add builtins to keyword list, or detect and error on shadowing.

---

#### P-05 — Rule Coupling (247 references, 44 variants) [MEDIUM]

**File**: Entire codebase
**Category**: Architecture

The `Rule` enum is pattern-matched 247 times across compiler, IR, and CLI. Any grammar rename breaks everything. No AST abstraction layer exists.

**Fix**: Long-term: introduce typed AST. Short-term: freeze grammar schema and document as stable API.

---

#### P-06 — Power Operator Left-Associative [MEDIUM]

**File**: `achronyme-parser/src/grammar.pest` (line 129)
**Category**: Semantic Bug

`pow_expr = { postfix_expr ~ (pow_op ~ postfix_expr)* }` parses `2^3^2` as `(2^3)^2 = 64`. Standard math convention is right-associative: `2^(3^2) = 512`.

**Fix**: Change to `pow_expr = { postfix_expr ~ (pow_op ~ pow_expr)? }` for right-recursion.

---

#### P-07 — No Recursion Depth Limit [MEDIUM]

**File**: `achronyme-parser/src/grammar.pest`
**Category**: DoS

Deeply nested expressions (10,000+ levels of parentheses or if/else) can cause stack overflow in pest's recursive descent parser.

**Fix**: Test practical limits. Add documentation or a pre-parse depth check.

---

#### P-09 — Decimal Rejection in Circuits [LOW]

**File**: `achronyme-parser/src/grammar.pest` (line 23)
**Category**: Design

Grammar permits decimals but R1CS compiler rejects them. Intentional (BN254 is integer field).

**Fix**: Document that decimals are VM-only.

---

#### P-11 — for...in Runtime Semantics [LOW]

**File**: `achronyme-parser/src/grammar.pest` (line 47)
**Category**: Documentation

Grammar allows `for x in expr` but compiler restricts `expr` to ranges or array identifiers.

**Fix**: Document the restriction.

---

#### P-15 — Trailing Comma Inconsistency [LOW]

**File**: `achronyme-parser/src/grammar.pest` (lines 38, 40, 52, 102)
**Category**: Style

Lists and maps allow trailing commas. Function params and call args do not.

**Fix**: Add `","?` to `param_list` and `call_op` for consistency.

---

#### P-16 — Number Precision Loss in f64 [LOW]

**File**: `compiler/src/expressions/atoms.rs` (line 199)
**Category**: Correctness

`s.parse::<f64>()` silently loses precision for integers > 2^53. VM-only issue (IR uses FieldElement).

**Fix**: Document IEEE 754 limits. Optionally warn on precision loss.

---

#### P-17 — Missing Grammar Documentation [LOW]

**File**: `achronyme-parser/src/grammar.pest`
**Category**: Documentation

No operator precedence table, associativity rules, or escape sequence reference in the grammar file.

**Fix**: Add comprehensive header documentation.

---

## Recommended Fix Priority

### Immediate (Security-Critical)

1. ~~**L-01** — Replace hardcoded entropy with cryptographic RNG~~ ✅
2. ~~**L-02** — Replace DefaultHasher with SHA-256 for cache keys~~ ✅
3. ~~**I-01** — Fix Mux evaluator semantics~~ ✅
4. ~~**X-01** — Fix Plonkish rotation underflow~~ ✅

### High Priority (Safety)

5. **L-03/L-04** — Validate cache files, fix TOCTOU
6. **P-06** — Fix power operator associativity
7. ~~**I-02** — Replace unwrap with error handling~~ ✅
8. ~~**M-06** — Track import_strings allocation~~ ✅
9. ~~**X-02** — Bounds check in LC::evaluate()~~ ✅

### Medium Priority (Robustness)

10. **X-03** — HashSet for lookup verification
11. **L-06/L-07** — Validate HOME and --ptau paths
12. **L-09** — Add snarkjs subprocess timeout
13. **L-12** — Cache snarkjs_available result
14. **C-02** — Iterative materialize_val
15. **M-07** — Tag validation assertions
16. **M-08** — Debug assertions for allocation drift

### Low Priority (Polish)

17-60. Documentation, trailing commas, code deduplication, naming.
