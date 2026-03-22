# Design: Syntax Unification — Type Annotations, Visibility, and Keyword Arguments

## Status
**Draft** — 2026-03-22. Designing for 0.1.0-beta.15.

## Problem

The language has inconsistent syntax patterns across declarations, calls, and ZK contexts:

### Current state — 6 conflicting patterns

```ach
// 1. Function params: name: Type
fn hash(a: Field, b: Field) -> Field { poseidon(a, b) }

// 2. Circuit params: visibility name (NO types, inverted order)
circuit merkle(public root, witness path[3], witness indices[3]) { ... }

// 3. Function calls: positional only
hash(x, y)

// 4. Circuit calls: keyword args only (LL-2 hack)
merkle(root: val, path: [a,b,c], indices: [1,1,1])

// 5. Input declarations in prove blocks: visibility name[N]: Type
prove {
    public hash
    witness path[3]: Field
    ...
}

// 6. Standalone circuit files: flat visibility declarations
public root
witness path[3]: Field
merkle_verify(root, leaf, path, indices)
```

### Problems

1. **Circuit params have no type annotations** — `CircuitParam` doesn't have a `type_ann` field
2. **Circuit params use inverted order** — `public root` vs `root: Public` (inconsistent with `name: Type`)
3. **Circuit calls force keyword args** — parser needs LL-2 hack to disambiguate
4. **Functions don't support keyword args** — can't write `hash(a: x, b: y)` for readability
5. **Two different AST nodes for calls** — `Expr::Call` vs `Expr::CircuitCall`
6. **Three different prove block syntaxes** — old-style declarations, `prove(public: [...])`, standalone files
7. **`array_size` lives outside `TypeAnnotation`** — `witness path[3]: Field` has size in name, type separate

## Decisions

1. **Visibility becomes part of the type annotation** — `root: Public`, `path: Witness Field[3]`
2. **Keyword args for all callables** — functions and circuits, optional
3. **Prove blocks use param-style visibility** — `prove(hash: Public) { ... }` with auto-witness capture
4. **Old-style prove declarations deprecated** — `prove { public x; witness y; }` emits warning
5. **Standalone circuit files deprecated** — wrap in `circuit` declaration instead
6. **`prove(public: [...])` deprecated** — replaced by `prove(hash: Public)` syntax

## Proposed Design

### 1. Unified type annotations with optional visibility

`TypeAnnotation` becomes a struct carrying optional visibility:

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

// With visibility (circuit params, prove params)
circuit merkle(root: Public, leaf: Witness, path: Witness Field[3]) { ... }
prove(hash: Public) { ... }

// Visibility defaults to Field when base type omitted
circuit simple(hash: Public, secret: Witness) { ... }
//              ↑ Public Field     ↑ Witness Field
```

**Rules:**
- `Public` alone → `Public Field` (Field is the default base type)
- `Witness` alone → `Witness Field`
- `Public Bool` → public boolean input
- `Witness Field[3]` → private field array of size 3
- `Field` without visibility → no visibility (valid in fn params, let bindings)
- Visibility in non-circuit/prove contexts → compile error

### 2. Keyword arguments for all callables

Both functions and circuits support optional keyword args:

```ach
// Positional (unchanged)
hash(x, y)
merkle(root_val, leaf_val, my_path, my_idx)

// Keyword (new for functions, existing for circuits)
hash(a: x, b: y)
merkle(root: root_val, leaf: leaf_val, path: my_path, indices: my_idx)

// Mixed (positional first, then keyword)
merkle(root_val, leaf_val, path: my_path, indices: my_idx)
```

**No semantic collision with type annotations:**
- In definitions, `:` introduces a TYPE — `fn f(x: Field)` → `Field` is a type keyword
- In calls, `:` introduces a VALUE — `f(x: val)` → `val` is an expression
- The parser always knows which context it's in

**Semantics:**
- Keyword arg names must match parameter names in the declaration
- Positional args fill params left-to-right
- Keyword args can appear in any order (after all positional args)
- Positional after keyword → parse error: `f(a: 1, 2)` is invalid
- Duplicate args → compile error
- Missing args → compile error (no default values)
- Unknown keyword name → compile error with "did you mean?" suggestion

### 3. Prove blocks — param-style with auto-witness

Prove blocks adopt the same parameter syntax as circuits, listing only public inputs:

```ach
// New syntax: param-style with visibility types
prove(hash: Public) {
    assert_eq(poseidon(secret, 0), hash)
    // secret auto-captured as Witness from outer scope
}

// With explicit types
prove(root: Public Field, flag: Public Bool) {
    merkle_verify(root, poseidon(secret, 0), path, indices)
    // secret, path, indices auto-captured as Witness
}

// Named prove block
prove vote(hash: Public) {
    assert_eq(poseidon(secret, 0), hash)
}
// desugars to: let vote = prove vote(hash: Public) { ... }

// Anonymous (no public inputs — everything is witness)
prove {
    assert_eq(a, b)
}
```

**Semantic difference from circuit params:**
- `circuit`: ALL params must be declared (public + witness)
- `prove`: only public params declared; witnesses auto-captured from scope

### 4. Standalone circuit files — deprecated

Standalone `.ach` files with flat visibility declarations:
```ach
// DEPRECATED:
public root
witness path[3]
merkle_verify(root, leaf, path, indices)
```

**Replaced by:** wrapping in a `circuit` declaration:
```ach
// New format:
circuit merkle(root: Public, leaf: Witness, path: Witness Field[3], indices: Witness Bool[3]) {
    merkle_verify(root, leaf, path, indices)
}
```

`ach circuit file.ach` looks for the `circuit` declaration inside the file.
`import circuit "./file.ach" as merkle` also uses the declaration.

**Migration:** `ach circuit` emits a deprecation warning for flat-format files with guidance to wrap in `circuit`.

## AST changes

### TypeAnnotation (parser)

```rust
// Before:
enum TypeAnnotation {
    Field,
    Bool,
    FieldArray(usize),
    BoolArray(usize),
}

// After:
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeAnnotation {
    pub visibility: Option<Visibility>,
    pub base: BaseType,
    pub array_size: Option<usize>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Visibility {
    Public,
    Witness,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BaseType {
    Field,
    Bool,
}
```

Display format: `Public` → "Public", `Witness Field[3]` → "Witness Field[3]", `Bool` → "Bool", `Field` → "Field"

### CircuitParam eliminated — uses TypedParam

```rust
// Before:
pub struct CircuitParam {
    pub name: String,
    pub visibility: CircuitVisibility,
    pub array_size: Option<usize>,
}

// After: CircuitParam removed. CircuitDecl uses TypedParam.
pub struct CircuitDecl {
    pub name: String,
    pub params: Vec<TypedParam>,  // was Vec<CircuitParam>
    pub body: Block,
    pub span: Span,
}

// TypedParam unchanged — already has type_ann
pub struct TypedParam {
    pub name: String,
    pub type_ann: Option<TypeAnnotation>,  // now carries visibility
}
```

Compiler validates: every circuit param must have `type_ann.visibility` set.

### Expr::CircuitCall eliminated — unified Call

```rust
// Before:
enum Expr {
    Call { callee: Box<Expr>, args: Vec<Expr>, span: Span },
    CircuitCall { name: String, args: Vec<(String, Expr)>, span: Span },
    // ...
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

#[derive(Clone, Debug, PartialEq)]
pub struct CallArg {
    pub name: Option<String>,  // None = positional, Some("x") = keyword
    pub value: Expr,
}
```

### InputDecl simplified

```rust
// Before:
pub struct InputDecl {
    pub name: String,
    pub array_size: Option<usize>,       // separate from type
    pub type_ann: Option<TypeAnnotation>, // old enum
}

// After:
pub struct InputDecl {
    pub name: String,
    pub type_ann: Option<TypeAnnotation>, // array_size lives inside
}
```

`array_size` moves into `TypeAnnotation.array_size`. For old-style prove block declarations (`prove { witness path[3]; }`), the parser puts `[3]` into the type annotation.

### Expr::Prove updated

```rust
// Before:
Prove {
    name: Option<String>,
    body: Block,
    public_list: Option<Vec<String>>,  // just names
    span: Span,
}

// After:
Prove {
    name: Option<String>,
    body: Block,
    params: Vec<TypedParam>,  // public params with visibility types
    span: Span,
}
```

`prove(hash: Public, flag: Public Bool)` populates `params` with typed entries.
`prove { ... }` (no params) has `params: vec![]` — old-style declarations or all-witness.

## Parser grammar

### Type parsing (extended)

```
type_annotation := [visibility] base_type [array_size]
                 | visibility                              // shorthand: Public = Public Field

visibility      := "Public" | "Witness"
base_type       := "Field" | "Bool"
array_size      := "[" INTEGER "]"
```

`Public` and `Witness` are contextual keywords — only recognized after `:` in type position.

### Circuit declaration

```
// Before:
circuit_param := ("public" | "witness") IDENT ("[" INTEGER "]")?

// After (same as function params):
circuit_param := IDENT [":" type_annotation]
```

### Prove expression

```
// Before:
prove_expr := "prove" [IDENT] ["(" "public" ":" "[" ident_list "]" ")"] block

// After:
prove_expr := "prove" [IDENT] ["(" typed_params ")"] block
typed_params := typed_param ("," typed_param)*
typed_param := IDENT ":" type_annotation
```

### Call expression

```
// Before:
call_args := expr ("," expr)*                               // positional
           | IDENT ":" expr ("," IDENT ":" expr)*            // keyword (LL-2)

// After:
call_args := call_arg ("," call_arg)*
call_arg  := IDENT ":" expr                                  // keyword
           | expr                                             // positional
```

LL-2 lookahead detects keyword args (ident followed by `:`) and produces `CallArg { name: Some(...) }`. Regular expressions produce `CallArg { name: None }`.

## Deprecation warnings

| Old syntax | New syntax | Warning code |
|------------|-----------|--------------|
| `circuit f(public x, witness y)` | `circuit f(x: Public, y: Witness)` | W008 |
| `prove { public x; witness y; ... }` | `prove(x: Public) { ... }` | W009 |
| `prove(public: [x, y]) { ... }` | `prove(x: Public, y: Public) { ... }` | W010 |
| Standalone flat circuit files | Wrap in `circuit` declaration | W011 |

All deprecated syntax continues to work during beta. Removal target: 1.0.

## Migration path

### Phase 1: Extend TypeAnnotation (non-breaking)
- Change `TypeAnnotation` from enum to struct with visibility/base/array_size
- Update all pattern matches across the codebase (~50 sites)
- Parser accepts both old and new circuit param syntax
- Old syntax emits W008 deprecation warning

### Phase 2: Prove block param syntax (additive)
- Parser supports `prove(hash: Public) { ... }`
- `prove(public: [...])` emits W010 deprecation warning
- Old-style `prove { public x; ... }` emits W009 deprecation warning

### Phase 3: Keyword args for all callables (additive)
- Extend `Call` AST node with `Vec<CallArg>`
- Parser produces keyword args for both fn and circuit calls
- Remove `Expr::CircuitCall` AST node
- Compiler validates keyword arg names against param names

### Phase 4: Standalone circuit file deprecation
- `ach circuit` detects flat-format files, emits W011
- Accepts files with `circuit` declarations
- Docs migration guide

### Phase 5: Remove old syntax (breaking, target 1.0)
- Remove `CircuitParam`, `CircuitVisibility` from AST
- Remove `Expr::CircuitCall`
- Remove `public_list` from `Expr::Prove`
- Remove flat-format standalone circuit parsing

## Resolved questions

1. **`Public`/`Witness` as contextual keywords** — recognized only in type annotation position (after `:`). Not reserved as identifiers. `let Public = 42` remains valid.

2. **Visibility in non-circuit/prove params is an error** — `fn f(x: Public Field)` → compile error: "visibility annotations are only valid in circuit and prove parameters"

3. **`Public[3]` shorthand** — allowed, equivalent to `Public Field[3]`. `Witness[2]` = `Witness Field[2]`.

4. **Circuit params without visibility** — compile error: "circuit parameters require Public or Witness annotation". Explicit is better.

5. **Keyword args for variadic natives** — keyword arg validation is skipped for native functions (no declared param names to match against).

## Files involved

### Parser
- `achronyme-parser/src/ast.rs` — TypeAnnotation struct, Visibility, BaseType, CallArg, remove CircuitCall/CircuitParam/CircuitVisibility
- `achronyme-parser/src/parser/stmts.rs` — type parsing, circuit param parsing, prove parsing
- `achronyme-parser/src/parser/exprs.rs` — call parsing (unified keyword args)
- `achronyme-parser/tests/` — update all type annotation and circuit tests

### Compiler
- `compiler/src/statements/mod.rs` — circuit declaration compilation (TypedParam instead of CircuitParam)
- `compiler/src/statements/declarations.rs` — TypeAnnotation pattern matching, W006/W007
- `compiler/src/control_flow.rs` — prove compilation, circuit call → unified Call, keyword arg resolution
- `compiler/src/functions.rs` — keyword arg validation against param names
- `compiler/src/types.rs` — Local.type_ann matching
- `compiler/src/codegen.rs` — type annotation warnings

### IR
- `ir/src/prove_ir/compiler.rs` — TypeAnnotation usage, OuterScopeEntry derivation
- `ir/src/prove_ir/types.rs` — ProveInputDecl, annotation_to_ir_type
- `ir/src/lower/stmts.rs` — enforce_input_type_ann, annotation_to_ir_type

### CLI
- `cli/src/commands/circuit.rs` — detect flat-format vs declaration-format files

### Docs
- All circuit/prove documentation pages — syntax examples
- Migration guide for deprecated syntax
