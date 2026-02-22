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
| ir | 0 | 5 | 5 | 10 |
| constraints | 3 | 2 | 4 | 9 |
| cli | 6 | 2 | 5 | 13 |
| parser | 10 | 1 | 6 | 17 |
| **TOTAL** | **19** | **47 (+1)** | **26** | **93** |

### Open by severity

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 2 |
| MEDIUM | 8 |
| LOW | 9 |

---

## Resolved Findings (48)

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
| I-03 | HIGH | ir | `FnDef` re-parsed source on every call → stores `body: Block` (AST) | `0543a81` |
| P-05 | MEDIUM | parser | 247 `Rule` matches, no AST layer → typed AST + `build_ast.rs` sole conversion point | `81845c9`, `33f5a6c` |
| I-04 | HIGH | ir | IsLt/IsLe limb order unverified → 15 tests at 2^64/2^128/2^192/p boundaries | `dd7e475` |
| I-05 | MEDIUM | ir | DCE conservatively kept all logic ops → removed conservative block, all non-side-effect instructions eliminated when unused | `73d0a7b` |

## False Positives & Confirmed Sound (26)

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
| X-03 | constraints | `verify()` is test-only; max table 2^16 rows (MAX_RANGE_TABLE_BITS=16); O(N²) not reachable |
| L-03 | cli | Cache is in `$HOME`; attacker with write access already has user-level shell. Proofs are re-verified after generation (line 121-128) |
| L-04 | cli | Same threat model as L-03; TOCTOU requires write access to `$HOME` which subsumes the attack |
| L-05 | cli | `/tmp` is typically `tmpfs` (RAM-backed); secure wiping ineffective on SSDs; snarkjs heap not zeroed either; requires root/physical access |
| L-07 | cli | CLI arg from user's own process; no privilege boundary crossed; snarkjs validates ptau format |
| L-06 | cli | `HOME` trusted by all Unix tools (git, cargo, ssh); `dirs::home_dir()` also reads `HOME`; no privilege escalation |
| P-01 | parser | By-design: `{}` as empty map is correct PEG parse; control flow (`if/while/for/fn`) references `block` directly, not through `atom`, so unaffected |
| I-06 | ir | Already handled: `Expr::Array` in expression position returns `TypeMismatch { expected: "scalar", got: "array" }`; nested arrays like `[x, [1,2]]` are rejected at lowering |
| I-07 | ir | Intentionally conservative: merging all Mux operand taints is sound (never misses real issues); branch-sensitive analysis is a future optimization, not a bug |
| I-08 | ir | By-design: arrays are data (must be non-empty for indexing), loops are control flow (zero iterations is valid unrolling) |
| I-09 | ir | Obsolete after AST refactor: zero `Rule::` references remain in `lower.rs`; all pest matching replaced by typed AST `match` arms |
| I-10 | ir | Obsolete after AST refactor: file reduced from 1600+ to 1316 lines; 10 precedence-layer methods collapsed into single `lower_expr` match on typed AST |
| X-04 | constraints | Each `Lookup` has fixed `selector: Option`; mixing impossible per-instance. Compiler exclusively uses `register_lookup_with_selector`; legacy `register_lookup` only used in unit tests |

---

## Open Findings

### Constraints Crate (3 open)

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

### CLI Crate (6 open)

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

### Parser Crate (10 open)

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

5. ~~**L-03/L-04** — Validate cache files, fix TOCTOU~~ (false positive)
6. **P-06** — Fix power operator associativity
7. ~~**I-02** — Replace unwrap with error handling~~ ✅
8. ~~**M-06** — Track import_strings allocation~~ ✅
9. ~~**X-02** — Bounds check in LC::evaluate()~~ ✅

### Medium Priority (Robustness)

10. ~~**X-03** — HashSet for lookup verification~~ (false positive)
11. **L-06/L-07** — Validate HOME and --ptau paths
12. **L-09** — Add snarkjs subprocess timeout
13. **L-12** — Cache snarkjs_available result
14. **C-02** — Iterative materialize_val
15. **M-07** — Tag validation assertions
16. **M-08** — Debug assertions for allocation drift

### Low Priority (Polish)

17-60. Documentation, trailing commas, code deduplication, naming.
