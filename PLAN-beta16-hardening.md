# Plan: 0.1.0-beta.16 — Hardening + UX

## Status
**In progress** — updated 2026-03-24.

## Hardening

### Tier 1: Panics → Result (critical) — DONE

> **Note:** Investigation revealed that ~95% of the originally listed panics
> (ProveIR compiler, bound_inference, types.rs) are inside `#[cfg(test)]`
> modules, not production code. The only production panic was in
> `Arena::alloc()`. Additional production `unreachable!()` calls and
> defensive `unwrap()` conversions were identified and fixed.

**Completed:**
- **`Arena::alloc() -> Result<u32, ArenaError>`** — full Result propagation through 11 `Heap::alloc_*` methods and ~60 VM/stdlib call sites. `From<ArenaError> for RuntimeError` bridge.
- **4 `unreachable!()` → `Err(RuntimeError::InvalidOpcode)`** — `globals.rs`, `control.rs`, `arithmetic.rs`, `data.rs`. Corrupted bytecode no longer crashes the VM.
- **`prove.rs` handler unwrap → `ok_or(ProveHandlerNotConfigured)`** — defensive guard even though structurally safe.
- **~35 `as_int().unwrap()` / `as_handle().unwrap()` → `ok_or(InvalidOperand)?`** — in `arithmetic.rs`, `interpreter.rs`, `core.rs`. Behind type guards but now defensively coded.
- **`value_ops.rs` display unwraps → `unwrap_or` defaults** — non-Result context, safe fallback.

**Not applicable (test-only, no production impact):**
- ~~12+ `panic!` in ProveIR compiler~~ — all in `#[cfg(test)]` (test module starts at line ~1793)
- ~~3 `panic!` in bound_inference~~ — all in `#[cfg(test)]` (test module starts at line ~106)
- ~~1 `panic!` in ProveIR deserialization~~ — in `#[cfg(test)]` (test module starts at line ~482)
- ~~Direct IR body indexing~~ — in test code

### Tier 2: Robustness (important)
- **8 `unwrap()` in lexer** (`achronyme-parser/src/lexer.rs` lines 352, 384, 404, 416-417, 481, 501, 521, 547-548) — `from_utf8().unwrap()` assumes valid UTF-8 after parsing. Propagate with `?` or `.map_err()`.
- **Generic error variants** — `RuntimeError::Unknown(String)` and `SystemError(String)` are catch-all. Create specific variants: `StaleUpvalue`, `MissingProveBytes`, etc.
- **`compile_expr_with_scope()` 583 lines** — extract sub-methods to reduce cyclomatic complexity.

### Tier 3: Polish — DONE
- Document `.unwrap()` assumptions that are provably safe (lexer after validation)
- ~~Extract `isatty()` FFI to shared utility~~ — DONE (`5ba0c935`)
- ~~More detailed error messages in loader~~ — DONE (`4576f649`)
- ~~Refactor `config.rs`~~ — DONE, split into validation + resolution (`8910cbc1`)
- ~~Refactor `control_flow.rs`~~ — DONE, split into zk + loops submodules (`307282ad`)

## Features

### `--input-file inputs.toml`
Eliminate `_N` convention at CLI boundary. Arrays as native TOML:
```toml
root = "7853200..."
leaf = "1"
path = ["2", "3"]
indices = ["0", "1"]
```
Usage: `ach circuit merkle.ach --input-file inputs.toml`

### ~~W011: flat circuit format deprecation warning~~ → Flat format removed — DONE
Instead of deprecating with a warning, the flat format was removed entirely.
Top-level `public`/`witness` declarations are now a compile error. The
`circuit name(param: Public, ...) { body }` syntax is the only supported form.
- Compiler rejects top-level PublicDecl/WitnessDecl with clear error message
- ProveIR `compile_circuit()` requires CircuitDecl (no flat fallback)
- CLI `--public`/`--witness` flags and `[circuit]` TOML section removed
- IrLowering fallback removed (was only needed for flat format + imports)
- 30 documentation files (EN+ES) migrated to circuit syntax
- `ach migrate` is no longer needed (no flat format to migrate from)

### Keyword argument validation — DONE
Keyword arg names are validated against declared circuit parameter names.
Typos produce a "did you mean?" suggestion via Levenshtein distance.
`param_names` stored in `GlobalEntry` for both inline and imported circuits.

### ~~`ach migrate file.ach`~~ — Not needed
Flat format was removed entirely instead of deprecated. No migration tool needed.

### ProveIR import support
Remove IrLowering fallback in `cli/src/commands/circuit.rs`.
The fallback was already removed as part of the flat format removal.
What remains is adding actual import support to ProveIR itself so that
`circuit` files with `import` statements work through the ProveIR pipeline.
One test (`circuit_import_with_poseidon`) is `#[ignore]` pending this.

### `assert_eq` with custom message
```ach
assert_eq(computed, expected, "commitment mismatch")
```
Useful for debugging circuit constraint failures.

### WASM feasibility check
Verify `cargo build --target wasm32-unknown-unknown` compiles compiler + VM. Preparation for Playground (0.3.0). Not a full WASM runtime — just compilation validation.

## What's already solid (no work needed)
- Field arithmetic (Montgomery CIOS, constant-time reduction)
- ProveIR validation (magic header, version, size limits, structural)
- VM bounds checking
- Zero clippy allows
- Zero unsafe in arithmetic

## Future (not beta.16)
- Dynamic plugin system (`dlopen` for NativeModule) — needs DESIGN doc
- Circom/Noir frontend parsers → ProveIR
- Visual inspector + Playground (0.3.0)
