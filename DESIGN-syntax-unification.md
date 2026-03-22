# Design: Syntax Unification — Type Annotations, Visibility, and Keyword Arguments

## Status
**Draft** — 2026-03-22. Designing for 0.1.0-beta.16.

## Problem

The language has inconsistent syntax patterns across declarations and calls:

### Current state (5 different patterns)

```ach
// 1. Function params: name: Type
fn hash(a: Field, b: Field) -> Field { poseidon(a, b) }

// 2. Circuit params: visibility name (NO types, different order)
circuit merkle(public root, witness path[3], witness indices[3]) { ... }

// 3. Function calls: positional only
hash(x, y)

// 4. Circuit calls: keyword args only (LL-2 hack to disambiguate)
merkle(root: val, path: [a,b,c], indices: [1,1,1])

// 5. Input declarations: visibility name[N]: Type
public root: Field
witness path[3]: Bool
```

### Problems

1. **Circuit params have no type annotations** — `CircuitParam` doesn't even have a `type_ann` field
2. **Circuit params use inverted order** — `public root` vs `root: Public` (inconsistent with `name: Type` everywhere else)
3. **Circuit calls force keyword args** — can't call positionally; parser needs LL-2 hack
4. **Functions don't support keyword args** — can't write `hash(a: x, b: y)` for readability
5. **Two different AST nodes for calls** — `Expr::Call` vs `Expr::CircuitCall`

## Proposed Design

### 1. Unified type annotations with optional visibility

`TypeAnnotation` becomes structured to carry optional visibility:

```
TypeAnnotation = [Visibility] BaseType [ArraySize]

Visibility = "Public" | "Witness"
BaseType   = "Field" | "Bool"
ArraySize  = "[" integer "]"
```

**Examples:**
```ach
// Without visibility (functions, let bindings)
let x: Field = 42
fn hash(a: Field, b: Field) -> Field { ... }

// With visibility (circuit params, input declarations)
circuit merkle(root: Public, leaf: Witness, path: Witness Field[3]) { ... }

// Visibility defaults to Field when base type omitted
circuit simple(hash: Public, secret: Witness) { ... }
//              ↑ Public Field     ↑ Witness Field
```

**Rules:**
- `Public` alone → `Public Field` (Field is default)
- `Witness` alone → `Witness Field`
- `Public Bool` → public boolean input
- `Witness Field[3]` → private field array of size 3
- `Field` without visibility → no visibility (valid in fn params, let bindings)
- Visibility in non-circuit contexts → compile warning or error

### 2. Keyword arguments for all callables

Both functions and circuits support optional keyword args:

```ach
// Positional (current, unchanged)
hash(x, y)
merkle(root_val, leaf_val, my_path, my_idx)

// Keyword (new for functions, existing for circuits)
hash(a: x, b: y)
merkle(root: root_val, leaf: leaf_val, path: my_path, indices: my_idx)

// Mixed (positional first, then keyword)
merkle(root_val, leaf_val, path: my_path, indices: my_idx)
```

**Semantics:**
- Keyword arg names must match parameter names in the declaration
- Positional args fill params left-to-right
- Keyword args can be in any order (after positional args)
- Duplicate args → compile error
- Missing args → compile error (no default values for now)

### 3. AST changes

#### TypeAnnotation (parser)

```rust
// Before:
enum TypeAnnotation {
    Field,
    Bool,
    FieldArray(usize),
    BoolArray(usize),
}

// After:
struct TypeAnnotation {
    pub visibility: Option<Visibility>,
    pub base: BaseType,
    pub array_size: Option<usize>,
}

enum Visibility {
    Public,
    Witness,
}

enum BaseType {
    Field,
    Bool,
}
```

Display: `Public` → "Public", `Witness Field[3]` → "Witness Field[3]", `Bool` → "Bool"

#### CircuitParam → unified with TypedParam

```rust
// Before:
struct CircuitParam {
    pub name: String,
    pub visibility: CircuitVisibility,  // separate field
    pub array_size: Option<usize>,      // separate from type
}

// After: reuse TypedParam
struct TypedParam {
    pub name: String,
    pub type_ann: Option<TypeAnnotation>,  // visibility lives inside TypeAnnotation
}

// CircuitDecl uses TypedParam instead of CircuitParam
struct CircuitDecl {
    pub name: String,
    pub params: Vec<TypedParam>,  // was Vec<CircuitParam>
    pub body: Block,
    pub span: Span,
}
```

Circuit params REQUIRE visibility in their type annotation. The compiler validates:
- Every circuit param must have `type_ann.visibility` set
- Error: `circuit f(x: Field)` → "circuit parameters require Public or Witness visibility"

#### Call → unified with optional keyword args

```rust
// Before:
enum Expr {
    Call { callee: Box<Expr>, args: Vec<Expr>, span: Span },
    CircuitCall { name: String, args: Vec<(String, Expr)>, span: Span },
}

// After:
enum Expr {
    Call {
        callee: Box<Expr>,
        args: Vec<CallArg>,
        span: Span,
    },
    // CircuitCall removed
}

struct CallArg {
    pub name: Option<String>,  // None = positional, Some = keyword
    pub value: Expr,
}
```

#### InputDecl simplification

```rust
// Before:
struct InputDecl {
    pub name: String,
    pub array_size: Option<usize>,    // separate from type
    pub type_ann: Option<TypeAnnotation>,  // old enum
}

// After:
struct InputDecl {
    pub name: String,
    pub type_ann: Option<TypeAnnotation>,  // array_size is inside TypeAnnotation
}
```

`array_size` moves INTO `TypeAnnotation` since they're the same concept. `witness path[3]: Field` becomes `witness path: Witness Field[3]` where the `[3]` is in the type, not the name.

Wait — for `public`/`witness` STATEMENTS inside prove blocks (`prove { public x; witness y[3]; }`), the visibility is the statement keyword, not the type annotation. These remain as-is. The `type_ann` on `InputDecl` would NOT have visibility set in this context (it's redundant — the statement already specifies it).

### 4. Parser grammar changes

#### Type parsing (extended)

```
type_annotation := [visibility] base_type [array_size]
visibility      := "Public" | "Witness"
base_type       := "Field" | "Bool"
array_size      := "[" INTEGER "]"

// Valid combinations:
// Field, Bool, Field[3], Bool[2]
// Public, Witness, Public Field, Witness Bool
// Public Field[3], Witness Bool[2]
```

#### Circuit declaration

```
// Before:
circuit_decl := "circuit" IDENT "(" circuit_params ")" block
circuit_params := circuit_param ("," circuit_param)*
circuit_param := ("public" | "witness") IDENT ("[" INTEGER "]")?

// After:
circuit_decl := "circuit" IDENT "(" typed_params ")" block
typed_params := typed_param ("," typed_param)*
typed_param := IDENT [":" type_annotation]
```

Validation (compiler, not parser): circuit params must have visibility in type annotation.

#### Call expression

```
// Before:
call := expr "(" args ")"
args := expr ("," expr)*                    // positional only
     | IDENT ":" expr ("," IDENT ":" expr)*  // keyword only (LL-2)

// After:
call := expr "(" call_args ")"
call_args := call_arg ("," call_arg)*
call_arg := [IDENT ":"] expr
```

The LL-2 lookahead still detects keyword args, but now produces a `CallArg { name: Some(...), value }` instead of a separate AST node.

**Mixed args rule:** positional args must come before keyword args. `f(a: 1, 2)` is an error.

### 5. Input declarations in prove blocks

Old-style `public`/`witness` statements remain supported:

```ach
prove {
    public hash
    witness secret
    assert_eq(poseidon(secret, 0), hash)
}
```

These are unaffected — the `public`/`witness` keyword determines visibility, and `type_ann` on `InputDecl` carries only base type + array size (no visibility).

New-style `prove(public: [...])` is also unaffected — visibility is determined by list membership.

### 6. Migration path

#### Phase 1: Extend TypeAnnotation (non-breaking)
- Change `TypeAnnotation` from enum to struct
- Update all pattern matches across the codebase
- Parser accepts both old and new circuit param syntax
- Old syntax emits deprecation warning

#### Phase 2: Keyword args for functions (additive)
- Extend `Call` AST node with `CallArg`
- Parser produces keyword args for both fn and circuit calls
- Remove `CircuitCall` AST node
- Compiler validates keyword arg names against param names

#### Phase 3: Deprecate old circuit param syntax
- `circuit f(public x, witness y)` → W-code warning
- Guide: "use `circuit f(x: Public, y: Witness)` instead"

#### Phase 4: Remove old syntax (breaking, target 1.0)
- Remove `CircuitParam` struct
- Remove old circuit param parsing
- Remove `CircuitCall` AST node cleanup

## Compatibility considerations

- **`ach circuit` mode**: standalone `.ach` files use `public x` / `witness y` statements, NOT circuit param syntax. Unaffected.
- **`prove(public: [...])` blocks**: unaffected — visibility from list membership.
- **Old prove blocks**: `prove { public x; witness y; }` — unaffected.
- **Existing circuit declarations**: work during Phase 1-2 (deprecation warning), break at Phase 4.
- **Existing circuit calls with keyword args**: continue working (keyword args are preserved).

## Open questions

1. **Should `Public`/`Witness` be reserved words?** Currently `public` and `witness` are reserved. `Public` and `Witness` (capitalized) are not. Need to reserve them or handle as contextual keywords.

2. **Should visibility in non-circuit params be an error or warning?** `fn f(x: Public Field)` — doesn't make sense for functions. Error is safer.

3. **Should we allow `Public[3]` as shorthand for `Public Field[3]`?** Saves typing but could be ambiguous.

4. **Default visibility for circuit params without annotation?** Options:
   - Error (explicit is better)
   - Default to `Witness` (most params are private)
   - Default based on position (first N are public, rest witness) — bad idea

5. **Keyword arg syntax for variadic natives?** `print(x: val)` — probably just skip validation for natives.

## Files involved

- `achronyme-parser/src/ast.rs` — TypeAnnotation struct, CallArg, remove CircuitCall/CircuitParam
- `achronyme-parser/src/parser/stmts.rs` — circuit param parsing, type parsing
- `achronyme-parser/src/parser/exprs.rs` — call parsing (unified keyword args)
- `compiler/src/statements/mod.rs` — circuit declaration compilation
- `compiler/src/statements/declarations.rs` — TypeAnnotation matching
- `compiler/src/control_flow.rs` — circuit call compilation, prove compilation
- `compiler/src/functions.rs` — keyword arg validation
- `compiler/src/types.rs` — Local.type_ann matching
- `ir/src/prove_ir/compiler.rs` — TypeAnnotation usage, OuterScopeEntry
- `ir/src/prove_ir/types.rs` — ProveInputDecl, IrType mapping
- `ir/src/lower/stmts.rs` — annotation_to_ir_type, enforce_input_type_ann
- All test files with TypeAnnotation pattern matches
