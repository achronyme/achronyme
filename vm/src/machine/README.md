# Machine Module - VM Implementation

The machine module implements the core Virtual Machine for Achronyme, segmented into focused submodules.

## Module Structure

### Core

- **`vm.rs`**: VM struct, main interpretation loop, error location capture
- **`frame.rs`**: Call frame representation

### Execution Handlers

- **`arithmetic.rs`**: Arithmetic opcodes (Add, Sub, Mul, Div, Mod, Pow, Neg)
- **`control.rs`**: Control flow (Call, Return)
- **`globals.rs`**: Global variable opcodes (DefGlobalVar/Let, GetGlobal, SetGlobal)
- **`data.rs`**: Data structure opcodes (BuildList, BuildMap, GetIndex, SetIndex)
- **`prove.rs`**: `ProveHandler` + `VerifyHandler` traits, prove block execution

### Support

- **`stack.rs`**: Stack/register operations trait
- **`native.rs`**: Native function registration and bootstrapping (23 natives)
- **`gc.rs`**: Mark-and-sweep garbage collection
- **`promotion.rs`**: Type promotion helpers

## Architecture

- **Tagged u64 values**: No boxing overhead, i60 integers inline
- **Fixed 65,536-slot stack**: No reallocation, stable addresses
- **Trait-based dispatch**: ArithmeticOps, ControlFlowOps, GlobalOps, etc.
- **Handler injection**: `prove_handler` and `verify_handler` for pluggable proving
- **Line tracking**: `last_error_location` captures function name + line on error
