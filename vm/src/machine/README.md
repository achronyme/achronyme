# Machine Module - VM Implementation

The machine module implements the core Virtual Machine for Achronyme, segmented into focused submodules for maintainability and scalability.

## Module Structure

### Core Components

- **`vm.rs`**: Primary VM struct, initialization, and execution loop dispatcher
- **`frame.rs`**: Call frame representation

### Execution Handlers

- **`arithmetic.rs`**: Arithmetic opcodes (Add, Sub, Mul, Div, Pow, Neg, Sqrt, NewComplex)
- **`control.rs`**: Control flow opcodes (Call, Return, future Jump/JumpIf)
- **`globals.rs`**: Global variable opcodes (DefGlobalVar/Let, GetGlobal, SetGlobal)

### Support Systems

- **`stack.rs`**: Stack/register operations trait
- **`promotion.rs`**: Type promotion logic (Real ↔ Complex)
- **`native.rs`**: Native function registration and bootstrapping
- **`gc.rs`**: Garbage collection (mark & sweep)

## Design Principles

### 1. Single Responsibility
Each module handles ONE category of operations:
- Arithmetic handlers don't know about GC
- GC doesn't know about opcodes

### 2. Trait-based Architecture
Operations are defined as traits implemented on `VM`:
```rust
pub trait ArithmeticOps {
    fn handle_arithmetic(&mut self, ...) -> Result<(), RuntimeError>;
}

impl ArithmeticOps for VM { ... }
```

**Benefits:**
- Clear API contracts
- Easy to test in isolation
- Future-proof for alternative implementations

### 3. Performance-First
- Hot-path functions marked `#[inline]`
- Stack operations use trait to allow future `unsafe` optimization without API changes

## Adding New Opcodes

### Example: Adding `OpCode::Mod` (modulo)

1. **Define opcode** in [`vm/src/opcode.rs`](../opcode.rs):
   ```rust
   pub enum OpCode {
       ...
       Mod = 14,
   }
   ```

2. **Add handler** in [`machine/arithmetic.rs`](arithmetic.rs):
   ```rust
   impl ArithmeticOps for VM {
       fn handle_arithmetic(...) {
           match op {
               ...
               OpCode::Mod => {
                   let vb = self.get_reg(base, b);
                   let vc = self.get_reg(base, c);
                   let res = self.binary_op(vb, vc, |x, y| x % y, |x, y| x % y)?;
                   self.set_reg(base, a, res);
               }
           }
       }
   }
   ```

3. **Update dispatcher** in [`machine/vm.rs`](vm.rs):
   ```rust
   match op {
       Add | Sub | Mul | Div | Mod | Pow | ... => {
           self.handle_arithmetic(op, instruction, base)?;
       }
       ...
   }
   ```

## Testing Strategy

Each handler module can be tested independently:

```rust
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_numbers() {
        let mut vm = VM::new();
        // Setup test...
        vm.handle_arithmetic(OpCode::Add, ...);
        // Assert...
    }
}
```

## Future Enhancements

- [ ] Extract `dispatch()` to `machine/dispatch.rs` when adding computed GOTO
- [ ] Add `machine/locals.rs` for local variable scope management
- [ ] Add `machine/upvalues.rs` for closure support
- [ ] Performance: Inline cache in `promotion.rs` for monomorphic ops
