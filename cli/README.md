# Achronyme CLI

The command-line interface for the Achronyme language.

## Usage

```bash
# Run a file
ach run script.ach

# Compile to binary
ach compile script.ach --output script.achb

# Disassemble
ach disassemble script.ach
```

## Structure

- **runner.rs**: Contains logic for file processing (running, compiling, disassembly).
- **args.rs**: `clap` argument definitions.
- **repl.rs**: Read-Eval-Print-Loop (WIP).
