# Achronyme Changelog

## [Unreleased] - Current Dev

### Added (Features)
- **Control Flow & Logic**:
    - Tipos literales: `true`, `false`, `nil`.
    - Expresiones de bloque: `{ stmt; expr }` retornan la última expresión.
    - Condicionales: `if` / `else` como expresiones (retornan valor).
    - Iteración: Bucle `while`.
    - Operadores: Comparadores `==`, `<`, `>`.
- **Natives**:
    - Funciones `print`, `len`, `typeof`, `assert`.
    - Arquitectura SSOT (Single Source of Truth) para sincronizar índices VM/Compiler.
- **Developer Experience**:
    - **Debug Symbol Table (Sidecar)**: Mapeo de nombres de variables en binarios `.achb` para reportes de error detallados sin penalizar el rendimiento ("Happy Path" O(1)).
    - **Disassembler**: Soporte para mostrar nombres de variables globales en lugar de índices crudos.

### Changed (Architecture & Performance)
- **Global Variables**: Migración de `HashMap` a `Vec<GlobalEntry>` con resolución de índices en tiempo de compilación (Acceso O(1)).
- **Register Allocation**: Implementación de estrategia LIFO (Stack) con "Register Hygiene".
    - `free_reg` para liberar temporales inmediatamente.
    - Snapshot/Restore en bloques para limpiar variables locales automáticamente.
- **OpCode Optimization**: Nuevos opcodes ligeros `LoadTrue`, `LoadFalse`, `LoadNil` para reducir presión en la pool de constantes.

### Fixed
- Fugas de registros en operaciones binarias y condicionales.
- Recursividad infinita en `compile_if` (corregido target passing).