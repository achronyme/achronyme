# Achronyme CLI

The command-line interface for the Achronyme language.

## Commands

### `run` — Execute a program

```bash
ach run script.ach
ach run script.achb                          # Run compiled binary
ach run script.ach --stress-gc               # GC on every allocation (testing)
ach run script.ach --prove-backend plonkish  # PlonK for prove blocks
```

### `circuit` — Compile a ZK circuit

```bash
ach circuit circuit.ach --inputs "x=42,y=7"
ach circuit circuit.ach --public "out" --witness "a,b" --inputs "out=42,a=6,b=7"
ach circuit circuit.ach --backend plonkish --inputs "x=42"
ach circuit circuit.ach --inputs "x=42" --prove           # Generate proof
ach circuit circuit.ach --inputs "x=42" --solidity         # Solidity verifier
ach circuit circuit.ach --inputs "x=42" --no-optimize      # Skip IR optimization
```

### `compile` — Compile to bytecode

```bash
ach compile script.ach --output script.achb
```

### `disassemble` — Show bytecode

```bash
ach disassemble script.ach
```

## Structure

- **commands/**: `run.rs`, `compile.rs`, `circuit.rs`, `disassemble.rs`
- **groth16.rs**: Native Groth16 proving (ark-groth16), snarkjs-compatible JSON
- **halo2_proof.rs**: PlonK/KZG proving (halo2)
- **prove_handler.rs**: `DefaultProveHandler` + `VerifyHandler` for prove blocks
- **solidity.rs**: Solidity verifier contract generation
- **args.rs**: clap argument definitions
