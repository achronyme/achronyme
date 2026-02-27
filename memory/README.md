# Achronyme Memory

Manages the Heap and Values for the Achronyme VM.

## Architecture

- **value.rs**: Tagged u64 representation — 4-bit tag (bits 63-60) + 60-bit payload. No floats; all numeric values are i60 integers or BN254 FieldElements on heap.
- **heap.rs**: Typed arenas for strings, lists, maps, functions, closures, upvalues, iterators, fields, and proofs. Mark-sweep garbage collector.
- **field.rs**: BN254 scalar field arithmetic in Montgomery form (`[u64; 4]` limbs).

## Value Tags

| Tag | Type | Storage |
|-----|------|---------|
| 0 | Int | i60 inline (sign-extended) |
| 1 | Nil | — |
| 2 | False | — |
| 3 | True | — |
| 4 | String | Heap handle |
| 5 | List | Heap handle |
| 6 | Map | Heap handle |
| 7 | Function | Heap handle |
| 8 | Field | Heap handle |
| 9 | Proof | Heap handle |
| 10 | Native | Heap handle |
| 11 | Closure | Heap handle |
| 12 | Iter | Heap handle |

## Integer Semantics

- Range: -2^59 to 2^59-1
- Overflow: `IntegerOverflow` runtime error (no silent promotion)
- No Int+Field mixing at runtime — use `field()` for explicit conversion

## GC

Mark-and-sweep garbage collector over typed arenas. Roots: stack, globals, open upvalues, constants. Configurable stress mode for testing.
