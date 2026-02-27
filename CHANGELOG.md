# Achronyme Changelog

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