# Achronyme Parser

Parses Achronyme source code into an owned AST.

## Architecture

- **grammar.pest**: PEG grammar definition (atoms, postfix, prefix, infix with precedence).
- **build_ast.rs**: Sole pest→AST conversion point. Pratt-style precedence climbing for expressions.
- **ast.rs**: Owned AST types (`Program`, `Stmt`, `Expr`, `Block`, `Span`) — independent of pest.
- **lib.rs**: Public API: `parse_program(source) -> Result<Program>`.

## Usage

```rust
use achronyme_parser::parse_program;

let program = parse_program("let x = 1 + 2").unwrap();
```

## Expression Precedence (high → low)

1. Atoms: number, identifier, string, bool, nil, list, map, if/while/for/fn, block, `(expr)`
2. Postfix: call `f(x)`, index `a[i]`
3. Prefix: negation `-`, logical NOT `!`
4. Power: `^`
5. Multiplicative: `*`, `/`, `%`
6. Additive: `+`, `-`
7. Comparison: `==`, `!=`, `<`, `<=`, `>`, `>=`
8. Logical AND: `&&`
9. Logical OR: `||`
