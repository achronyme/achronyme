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
| constraints | 0 | 2 | 7 | 9 |
| cli | 0 | 2 | 11 | 13 |
| parser | 2 | 1 | 14 | 17 |
| **TOTAL** | **2** | **47 (+1)** | **43** | **93** |

### Open by severity

| Severity | Count |
|----------|-------|
| CRITICAL | 0 |
| HIGH | 2 |
| MEDIUM | 0 |
| LOW | 2 |

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

## False Positives & Confirmed Sound (43)

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
| X-05 | constraints | `nPubOut = 0` is correct and self-documenting; adding a doc comment for a single constant is unnecessary overhead |
| X-07 | constraints | Test-only code; Rust's default OOB panic already includes index and length |
| X-08 | constraints | Hardcoded compile-time hex literals that can never fail; wrapping in `Result` adds complexity with zero benefit |
| L-08 | cli | CLI local sin frontera de privilegios; el usuario que ve stderr es quien ejecutó el comando. Filtrar paths dificultaría debugging |
| L-09 | cli | CLI local; circuito grande no es DoS (usuario ejecuta su propio circuito). `Ctrl+C` disponible. Timeout arbitrario causaría fallos legítimos |
| L-10 | cli | Cache opt-in (requiere `--ptau` + snarkjs). Mismo patrón que `~/.cargo/registry/`, `~/.npm/`; `rm -rf ~/.achronyme/cache/` suficiente |
| L-11 | cli | `std::env::temp_dir()` devuelve UTF-8 en todos los OS modernos; paths construidos internamente sin componentes de usuario |
| L-12 | cli | `prove {}` blocks son raros (1-3 por programa); `npx --version` ~200ms, insignificante vs generación Groth16 (~segundos) |
| L-13 | cli | `--inputs` viene de argv (límite OS ~2MB via `ARG_MAX`); parsing lineal sin amplificación |
| P-02 | parser | Set estándar JSON/JS; rechazar escapes desconocidos es correcto (no aceptar `\q` silenciosamente). `\uXXXX`/`\xXX` son features futuras, no bugs |
| P-03 | parser | Finding incorrecto: números usan `FieldElement::from_decimal_str()` (aritmética 256-bit `[u64;4]`), no f64. Sin pérdida de precisión. Parsing O(n) lineal, sin amplificación |
| P-04 | parser | Builtins se resuelven en `lower_call` por nombre antes de user functions (línea 658-667); shadow con `let poseidon = 42` no afecta calls. Patrón estándar (Rust/Python/Go) |
| P-07 | parser | Inherente a todo recursive descent parser (GCC, rustc, V8 tienen el mismo límite). Stack 8MB soporta ~10K+ niveles; ningún programa real se acerca |
| P-09 | parser | Rechazo intencional: IR lowering emite `TypeNotConstrainable("decimal")`; BN254 es campo de enteros. Gramática permite decimales para el VM (f64 scripting) |
| P-11 | parser | Restricción ya comunicada por error: `UnsupportedOperation("for-in over non-range/non-array...")`. Gramática permisiva + compilador restrictivo es patrón estándar |
| P-15 | parser | Decisión de estilo, no bug. Inconsistencia común en lenguajes (JS tuvo lo mismo). Parser rechaza coma extra con error de sintaxis claro |
| P-16 | parser | Comportamiento estándar IEEE 754 (mismo que JS, Lua). VM usa f64 por diseño; path de circuitos usa FieldElement 256-bit, no afectado |

---

## Open Findings

### Parser Crate (2 open)

#### P-06 — Power Operator Left-Associative [MEDIUM]

**File**: `achronyme-parser/src/grammar.pest` (line 129)
**Category**: Semantic Bug

`pow_expr = { postfix_expr ~ (pow_op ~ postfix_expr)* }` parses `2^3^2` as `(2^3)^2 = 64`. Standard math convention is right-associative: `2^(3^2) = 512`.

**Fix**: Change to `pow_expr = { postfix_expr ~ (pow_op ~ pow_expr)? }` for right-recursion.

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
