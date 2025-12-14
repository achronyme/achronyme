# Achronyme Parser

Wraps the PEG grammar defined in `grammar.pest` to provide easy parsing utilities.

## Usage

```rust
use achronyme_parser::parse_expression;

let pairs = parse_expression("1 + 2").unwrap();
```

## Structure

- **grammar.pest**: The exact grammar definition.
- **lib.rs**: Logic to invoke the `Pest` parser and clean up the output pairs.
