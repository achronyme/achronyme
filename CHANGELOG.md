# Achronyme Changelog

## [0.1.0-beta.12] - 2026-03-18

### Features

- **NativeModule trait** — Modular native function registration system. Each stdlib group (core, string, bigint, collections) implements `NativeModule`, replacing the monolithic 43-arm match in `bootstrap_natives()`. External modules can implement the same trait.
- **`achronyme-std` crate** — New standard library crate (9th workspace member) with 16 new native functions:
  - **Type conversion:** `to_string`, `parse_int`, `to_field`, `to_int`
  - **Math utilities:** `abs`, `min`, `max`, `pow`
  - **Extended strings:** `starts_with`, `ends_with`, `contains`, `join`, `repeat`
  - **I/O (feature-gated):** `read_line`, `read_file`, `write_file`
- **`VM::register_module()`** — Register external NativeModule implementations after VM bootstrap.
- **`Compiler::with_extra_natives()`** — Extend compiler's symbol table with additional native functions.
- **`#[ach_native]` proc-macro** — Attribute macro that transforms regular Rust functions into `NativeFn` wrappers with automatic arity checks, `FromValue` argument extraction, and `IntoValue` return wrapping.
- **`#[ach_module]` proc-macro** — Attribute macro that generates `NativeModule` trait implementations from annotated modules.
- **`FromValue` / `IntoValue` traits** — Type-safe conversion between VM `Value` and Rust types (`i64`, `bool`, `Value`, `()`).

### Hardening

- `repeat()`: maximum result size capped at 10 MB
- `pow()`: exponent validated ≤ u32::MAX before cast
- `read_file()`: maximum file size capped at 100 MB
- Compiler asserts no name collision between builtin and extra natives
- VM bootstrap asserts module name uniqueness
- `#[ach_module]` macro: proper negative arity parsing, `Debug`/`Clone`/`Copy` derives on generated structs

### Refactoring

- All 8 native modules (4 VM + 4 std) migrated to `#[ach_module]` + `#[ach_native]` macros — net reduction of 292 lines of registration boilerplate.
- `NATIVE_TABLE` reordered to group by module (core → string → bigint → collections).

### New Crates

- `achronyme-std` — Standard library natives (16 functions, feature-gated I/O)
- `ach-macros` — Proc-macros for native function registration

### Documentation

- Native functions reference updated from 43 to 59 entries (EN + ES)

## [0.1.0-beta.11] - 2026-03-16

### Features

- **`achronyme.toml` project manifest** — New project configuration file with walk-up directory search. Supports `[project]` (name, version, description, entry_point), `[circuit]` (backend, curve, solidity), and `[output]` (dir, format) sections. Resolution order: CLI flags > TOML > defaults.
- **`ach init` command** — Interactive project scaffolding that creates `achronyme.toml`, `src/main.ach` with a starter template, and `src/` directory. Detects existing projects and warns before overwriting.
- **Config resolution pipeline** — `resolve_config()` merges CLI arguments with TOML settings, allowing partial overrides. `find_project_root()` walks up from CWD to find the nearest `achronyme.toml`.

### Documentation

- **Project configuration reference** — New `project-config.mdx` page in docs covering all TOML fields, resolution order, and examples.
- **CLI commands update** — Updated `commands.mdx` with `ach init` documentation.

## [0.1.0-beta.10] - 2026-03-16

### Bug Fix

- **Plonkish lookup gap resolved** — `range_check` and `IsLtBounded` now generate real KZG proofs with halo2 PSE. Migrated from `meta.selector()` + `meta.lookup()` to `meta.fixed_column()` + `meta.lookup_any()` to avoid halo2's selector compression corrupting lookup arguments. Pattern from PSE zkEVM-circuits.

### Features

- **W003 warning** — Compiler warns when comparisons (`<`, `<=`) remain unbounded (~761 constraints) with a suggestion to add `range_check` for ~67 constraints (11x reduction).
- **Enhanced `ach circuit` output** — Shows bound inference optimization count ("N comparison(s) optimized via IsLtBounded") and Poseidon efficiency note ("362 constraints — Circom: 517, 30% more efficient").
- **`Styler::warning()`** — Bold yellow ANSI styling for W003.

### Robustness

- **Property-based testing expansion** (+19 properties): Mux (3), Division (4), IsLtBounded (3), Poseidon (3), adversarial witness rejection (6). Total: 62 properties × 30-200 cases ≈ 8,000+ random verifications.
- **cargo-fuzz targets** (3): Parser, IR lowering, full R1CS pipeline. 3.3M inputs in initial run, 0 crashes.
- **Systematic malicious prover tests** (23 tests, 11 attack vectors): Bit flip, zero witness, field boundary, output forgery, Poseidon state corruption, mux condition bypass, division inverse forgery, Dark Forest overflow, wire swap, constant wire attack, coherent forgery.

### Testing (+47 tests, 2,125 → 2,169)

Both ZK backends now fully functional for all primitives:
- R1CS/Groth16: range_check, IsLtBounded, Poseidon, Merkle ✓
- Plonkish/KZG: range_check, IsLtBounded, Poseidon, Merkle ✓ (NEW)

## [0.1.0-beta.9] - 2026-03-15

### Security Fix

- **R1CS export: simplify LCs before serialization** — `write_lc()` wrote unsimplified LinearCombinations with duplicate wire IDs to the iden3 `.r1cs` binary format. Duplicate wires (from MDS mixing in Poseidon) caused snarkjs `wtns check` to fail (228/362 Poseidon constraints). Internal verification was unaffected. Discovered by the new snarkjs cross-validation tests.

### Features

- **IsLtBounded optimization (D7 resolved)** — New `bound_inference` IR pass automatically rewrites `IsLt`/`IsLe` to bounded variants when both operands have proven bitwidth bounds from prior `range_check` instructions. Constraint count drops from 761 to 66 for 64-bit comparisons (parity with Circom's `LessThan(64)` at 67). Safe-by-default: unbounded comparisons remain at 252-bit fallback. Dark Forest anti-regression test included.
- **New IR instructions**: `IsLtBounded { result, lhs, rhs, bitwidth }`, `IsLeBounded { result, lhs, rhs, bitwidth }`
- **New IR pass**: `bound_inference` — scans `RangeCheck` to build bounds map, rewrites comparisons

### Testing (+326 tests, 1,799 → 2,125)

- **Phase III industry test vectors** (+290 tests):
  - `mux_select_vectors.rs` (127 tests): truth table, boundary exhaustive, nested, N-way, soundness
  - `division_vectors.rs` (115 tests): modular inverse, roundtrip, distributive, Dark Forest
  - `merkle_vectors.rs` (38 tests): depth 1-20 with Poseidon, constraint scaling
- **snarkjs cross-validation** (18 tests): independent verification via `snarkjs wtns check`, wire value comparison against circomlibjs golden vectors, full Groth16 prove+verify for Poseidon(1,2)
- **Plonkish cross-validation** (25 tests):
  - Level 1: cross-backend consistency (R1CS ↔ Plonkish same outputs)
  - Level 2: full halo2 KZG prove/verify cycle (7 circuits)
  - Level 3: JSON export re-evaluation (structural validation)
- **IsLtBounded tests**: 64-bit constraint count regression, Dark Forest anti-regression

### Benchmark (measured with circom 2.2.3 + circomlib)

| Primitive | Achronyme | Circom | Notes |
|-----------|-----------|--------|-------|
| Poseidon(t=3) | **362** | 517 | 30% more efficient |
| IsLt (64-bit bounded) | **66** | 67 | Parity (was 761) |
| IsEq | 3 | 3 | Parity |
| RangeCheck(8) | 9 | 9 | Parity |

Both ZK backends now have external verification:
- R1CS/Groth16: snarkjs `wtns check` + Groth16 prove/verify
- Plonkish/KZG: halo2 KZG prove/verify + cross-backend consistency

## [0.1.0-beta.3] - 2026-03-04

### Security & Robustness (16 fixes)

All `.expect()`, `.unwrap()`, and `assert!` panics across the compiler, VM, memory, and constraint backends have been replaced with proper `Result` error propagation. The entire codebase was audited for panic paths (AUDIT-2026-03-03).

- **Plonkish ZK soundness**: constrain unused advice columns to zero (#45)
- **VM call frame depth limit**: prevent stack overflow from deep/infinite recursion (#46)
- **GC precision**: root only active stack region, not entire 65K array (#47)
- **Upvalue safety**: replace `.unwrap()` with error propagation in upvalue operations (#48)
- **GC trace safety**: use `Arena::get()` bounds-checked access instead of direct `.data` (#49)
- **Jump target validation**: reject out-of-bounds jump targets at VM dispatch (#50)
- **i60 range validation**: enforce 60-bit signed range in `Value::int()` and all entry points (#51)
- **BigInt overflow**: `from_decimal_str` now rejects inputs >= 2^256 (#52)
- **Constraint evaluation**: `LC::evaluate` returns `Result` instead of panicking (#53)
- **Error trait compliance**: implement `Display` and `std::error::Error` for all error types (#54)
- **CLI entry points**: replace `.expect()` with `anyhow` error propagation (#55)
- **VM defense-in-depth**: bounds-check `LoadConst`, add instruction fuel budget, validate `upvalue_info` (#56)
- **GC accounting**: fix `bytes_allocated` drift for maps and lists with capacity growth (#57)
- **String import safety**: `import_strings` clears stale interner after arena swap (#58)
- **Plonkish range check**: `enforce_n_range(0)` constrains to zero instead of panicking (#59)
- **Compiler stacks**: `current()`/`current_ref()` return `Result` instead of panicking (#60)

### Architecture (13 refactors)

Monolithic source files split into focused submodules for maintainability:

- `vm.rs` → interpreter, upvalues, value ops (#39)
- `field.rs` → arithmetic primitives and parsers (#40)
- `bigint.rs` → extract tests (#41 deduplicate adc/sbb/mac into limb_ops)
- `parser.rs` → core, precedence, statements, expressions (#34)
- `poseidon.rs` → constants, params, LFSR, native, R1CS synthesis (#38)
- `plonkish_backend.rs` → types, primitives, compiler, gadgets, Poseidon emitter, witness (#35)
- `lower.rs` → 6 focused submodules
- `eval.rs` → extract tests
- `Arena<T>` extracted from `heap.rs` into standalone module (#42)
- R1CS gadgets and witness gen extracted (#43)
- String utilities extracted from `stdlib/core.rs` (#44)

### Documentation

- VS Code extension documentation (EN + ES)
- Secret voting circuit tutorial with integration tests
- Updated STRATEGY.md and crate READMEs

## [Unreleased] - Current Dev

### Added (Features)
- **Complex Number Serialization**: Full support for serializing and deserializing `Complex` numbers in `.achb` binaries. Introduced `SER_TAG_COMPLEX` (9) and `ComplexTable`.
- **User-Defined Functions**:
    - Declaración: `fn name(params) { body }` y funciones anónimas `fn (x) { x * 2 }`.
    - Recursión completa: `fn fib(n) { if n < 2 { n } else { fib(n-1) + fib(n-2) } }`.
    - Funciones anidadas: soporte para definir funciones dentro de funciones.
    - `return` statement para retorno explícito de valores.
- **Control Flow & Logic**:
    - Tipos literales: `true`, `false`, `nil`.
    - Expresiones de bloque: `{ stmt; expr }` retornan la última expresión.
    - Condicionales: `if` / `else` como expresiones (retornan valor).
    - Iteración: Bucle `while`.
    - **Advanced Control Flow**:
        - `for x in list/map`: Iteradores sintácticos con `OP_GET_ITER`/`OP_FOR_ITER`.
        - `forever { ... }`: Loop infinito optimizado.
        - `break` / `continue`: Salto de control estructurado.
        - `mut`: Palabra clave para variables mutables explícitas (diferente de `let`).
    - Operadores: Comparadores `==`, `<`, `>`.
- **Dynamic Data Structures** (Task 3):
    - **Listas**: Sintaxis `[1, 2, 3]`, acceso `list[0]`.
    - **Mapas**: Sintaxis `{ key: "val" }`, acceso `map.key` o `map["key"]`.
    - **Smart Assignment**: Soporte para asignar a índices `list[0] = 5` y `map.key = "new"`.
    - **Strict Typing**: Claves de mapas deben ser Strings (runtime check).
- **Natives**:
    - Funciones `print`, `len`, `typeof`, `assert`, `time`.
    - Arquitectura SSOT (Single Source of Truth) para sincronizar índices VM/Compiler.
- **Closures & Upvalues**:
    - Soporte completo para funciones de primera clase con `Closure` objects.
    - Captura léxica de variables (`Upvalues`) con soporte para estado mutable compartido.
    - `Upvalue` management: Open (stack) vs Closed (heap) optimizado.
- **Memory Management (GC Stress Mode)**:
    - `--stress-gc` flag CLI testing OOM stability.
    - "Inversion of Control" architecture for safe GC triggering.
- **Security Hardening**:
    - **Stack Pinning**: Migración a `Box<[Value]>` para evitar UAF en `open_upvalues`.
    - **VM Reset**: Limpieza automática de "Zombie Upvalues" en caso de pánico.
    - **DoS Prevention**: `Result` propagation en lugar de `panic!` en accesos al stack.
    - **GC Rooting**: Rastreo explícito de `open_upvalues` para evitar corrupción de memoria.
- **Developer Experience**:
    - **Debug Symbol Table (Sidecar)**: Mapeo de nombres de variables en binarios `.achb` para reportes de error detallados sin penalizar el rendimiento ("Happy Path" O(1)).
- **Disassembler**: Soporte para mostrar nombres de variables globales en lugar de variables crudos.
- **String Escapes**: Soporte completo para secuencias de escape en strings:
    - Newlines (`\n`, `\r`), Tabs (`\t`), Quotes (`\"`), Backslash (`\\`).
    - Implementado mediante `grammar.pest` (parsing) y `codegen.rs` (transformación `unescape_string`).

### Maturity Gaps (Phase 11)
- **VM Natives**: `poseidon()` and `poseidon_many()` available as VM natives (indices 20-21), no longer circuit-only
- **Proof Verification**: `verify_proof()` native (index 22) with `VerifyHandler` trait
- **Error Location Tracking**: VM runtime errors now include line numbers and function names (`last_error_location`)
- **Documentation**: Updated README, crate READMEs, and CLI reference

### Remove Silent Int→Field Promotion (Phase 10b)
- i60 overflow → `IntegerOverflow` runtime error (no silent promotion to Field)
- Int+Field mixing → `TypeMismatch` error at runtime
- Pow trivial-base fast-paths: `0^n`, `1^n`, `(-1)^n`
- `field()` remains as explicit conversion
- `prove {}` still auto-converts integers to field elements

### Type Annotation Soundness (Phase 10a)
- `let b: Bool = x` on untyped witness emits `RangeCheck(x, 1)` instead of stamping
- Bool array elements and fn params/returns enforce range checks
- `bool_prop` pass recognizes `RangeCheck(x,1)` and `Assert` as boolean seeds
- `Neg` propagates `IrType::Field`
- Array size validated vs type annotation
- 13 new tests including 3 malicious-prover soundness tests

### Arrays, Functions, Crypto (Phase 10)
- `EnvValue::Scalar|Array` for array support in circuits
- `fn` inlining at call sites (no dynamic dispatch, recursion detected via `call_stack`)
- `poseidon_many(a, b, c, ...)` left-fold Poseidon hash
- `merkle_verify(root, leaf, path, indices)` Merkle membership proof
- `len(arr)` compile-time array length

### Medium Audit Fixes (M2, M3, M8)
- LC dedup (`simplify()` merges duplicate Variable terms)
- `const_fold` self-ops (Sub-self→0, Div-self→1)
- `bool_prop` optimization pass (forward boolean propagation)

### SSA IR Pipeline (Phases 7-9)
- **SSA IR**: `SsaVar(u32)`, flat `IrProgram`, 18 instruction types
- **IR Lowering**: AST→IR with `IrLowering`, public/witness declarations, static unrolling
- **IR Evaluator**: Pure forward evaluation for witness generation and validation
- **Optimization Passes**: `const_fold`, `dce`, `bool_prop`, `taint` analysis
- **Dual Backend**: `R1CSCompiler::compile_ir()` and `PlonkishCompiler::compile_ir()` from same IR
- **Witness Generation**: `WitnessGenerator` with `WitnessOp` trace replay
- **Binary Export**: `.r1cs` (iden3 v1) and `.wtns` (iden3 v2), snarkjs-compatible
- **Prove Blocks**: `prove {}` syntax, `ProveHandler` trait, Groth16 pipeline, `ProofObject` on heap
- **Plonkish Backend**: Gates, lookups, copy constraints, `PlonkVal` lazy materialization

### R1CS Foundation (Phases 4-6)
- **R1CS Constraint System**: `Variable`, `LinearCombination`, `ConstraintSystem` with `enforce(A, B, C)`
- **R1CS Compiler**: Arithmetic, builtins (`assert_eq`, `poseidon`, `mux`, `range_check`), control flow
- **Comparison Operators**: `IsLt`, `IsLe`, `IsEq`, `IsNeq` with bounded 252-bit range checks
- **Boolean Logic**: `Not`, `And`, `Or` with enforcement constraints
- **Solidity Verifier**: `--solidity` CLI flag for on-chain verification contract generation
- **String Natives**: `substring`, `indexOf`, `split`, `trim`, `replace`, `toUpper`, `toLower`, `chars`

### Stdlib Robustness (Phase 3)
- **Robust Native Functions**:
    - `len(obj)`: Polymorphic (String, List, Map).
    - `push(list, item)`: Type-safe mutation.
    - `pop(list)`: Safe mutation with `nil` on empty.
    - `keys(map)`: Validated map introspection.
- **Engineering Standards**:
    - Validation of ArityStrict, Type Safety Defensivo (`is_X()` before `as_X()`).
    - **Memory Hygiene**: Strict borrow checker compliance (no `&` to Heap while `alloc`).

### Fixed
- **VM Equality (Critical)**: `OpCode::Eq` (`==`) now performs **Deep Equality** for Strings and Complex numbers instead of reference equality.
- `values_equal`: Helper for recursive value comparison.

### Changed (Architecture & Performance)
- **Flat Prototype Architecture**: Funciones almacenadas en tabla global plana con índices O(1) en lugar de jerarquía anidada.
- **FunctionCompiler Stack**: Compilador refactorizado con stack LIFO de `FunctionCompiler` para manejar funciones anidadas.
- **CallFrame.dest_reg**: El retorno de funciones ahora escribe directamente al registro destino del caller.
- **Stack Safety**: Validación de overflow usando `func.max_slots` (dato exacto del compilador) en lugar de números mágicos.
- **Global Variables**: Migración de `HashMap` a `Vec<GlobalEntry>` con resolución de índices en tiempo de compilación (Acceso O(1)).
- **Register Allocation**: Implementación de estrategia LIFO (Stack) con "Register Hygiene".
    - `free_reg` para liberar temporales inmediatamente.
    - Snapshot/Restore en bloques para limpiar variables locales automáticamente.
- **OpCode Optimization**: Nuevos opcodes ligeros `LoadTrue`, `LoadFalse`, `LoadNil`, `Closure` para reducir presión en la pool de constantes.

### Fixed
- Fugas de registros en operaciones binarias y condicionales.
- Recursividad infinita en `compile_if` (corregido target passing).
- Shadowing de variables: ahora respeta alcance léxico (LIFO).
- Parsing robusto de funciones: maneja todos los edge cases (`fn () {}`, `fn {}`, etc.).
- **Scope Management**: Fixed bug where locals were not popping from compiler stack at end of block (`forever` loop fix).
- **Register Contiguity**: Implemented `alloc_contiguous` to guarantee safe register adjacency for iterators.

### Performance
- **Benchmark** (10M iteraciones de loop vacío):
    - Achronyme VM: **~0.41s** ⚡
    - Python 3: **~0.62s**
    - **~50% más rápido que Python** en hot loops.