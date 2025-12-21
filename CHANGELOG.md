# Achronyme Changelog

## [Unreleased] - Current Dev

### Added (Features)
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
    - **Disassembler**: Soporte para mostrar nombres de variables globales en lugar de índices crudos.

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

### Performance
- **Benchmark** (10M iteraciones de loop vacío):
    - Achronyme VM: **~0.41s** ⚡
    - Python 3: **~0.62s**
    - **~50% más rápido que Python** en hot loops.