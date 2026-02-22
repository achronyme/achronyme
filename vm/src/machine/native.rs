use crate::globals::GlobalEntry;
use crate::native::{NativeFn, NativeObj};
use memory::Value;

/// Trait for native function registration
pub trait NativeRegistry {
    fn define_native(&mut self, name: &str, func: NativeFn, arity: isize);
    fn bootstrap_natives(&mut self);
}

impl NativeRegistry for super::vm::VM {
    fn define_native(&mut self, name: &str, func: NativeFn, arity: isize) {
        let name_string = name.to_string();

        // 1. Intern string (still needed for debugging/reflection later, but not for lookup key)
        if !self.interner.contains_key(&name_string) {
            let h = self.heap.alloc_string(name_string.clone());
            self.interner.insert(name_string.clone(), h);
        }

        // 2. Register Native Object
        let native = NativeObj {
            name: name_string,
            func,
            arity,
        };
        self.natives.push(native);
        let native_idx = (self.natives.len() - 1) as u32;

        // 3. Register in Globals (Direct Push)
        // Compiler guarantees 0=print, 1=len, etc.
        let val = Value::native(native_idx);
        self.globals.push(GlobalEntry {
            value: val,
            mutable: false, // Natives are constant
        });
    }

    fn bootstrap_natives(&mut self) {
        use crate::specs::NATIVE_TABLE;

        // Assert empty state to ensure alignment
        if !self.natives.is_empty() || !self.globals.is_empty() {
             panic!("VM must be empty before bootstrapping natives");
        }

        for meta in NATIVE_TABLE {
            // Match the name to the actual Rust function pointer
            let func_ptr = match meta.name {
                "print"  => crate::stdlib::core::native_print,
                "len"    => crate::stdlib::core::native_len,
                "typeof" => crate::stdlib::core::native_typeof,
                "assert" => crate::stdlib::core::native_assert,
                "time"   => crate::stdlib::core::native_time,
                "push"   => crate::stdlib::core::native_push,
                "pop"    => crate::stdlib::core::native_pop,
                "keys"   => crate::stdlib::core::native_keys,
                "field"  => crate::stdlib::core::native_field,
                "proof_json"   => crate::stdlib::core::native_proof_json,
                "proof_public" => crate::stdlib::core::native_proof_public,
                "proof_vkey"   => crate::stdlib::core::native_proof_vkey,
                "substring"    => crate::stdlib::core::native_substring,
                "indexOf"      => crate::stdlib::core::native_index_of,
                "split"        => crate::stdlib::core::native_split,
                "trim"         => crate::stdlib::core::native_trim,
                "replace"      => crate::stdlib::core::native_replace,
                "toUpper"      => crate::stdlib::core::native_to_upper,
                "toLower"      => crate::stdlib::core::native_to_lower,
                "chars"        => crate::stdlib::core::native_chars,
                _ => panic!("VM Implementation missing for native: {}", meta.name),
            };

            // Call internal define logic
            // IMPORTANT: This creates the GlobalEntry.
            // Since we iterate NATIVE_TABLE in order, 'print' will be pushed at index 0, matching the compiler.
            self.define_native(meta.name, func_ptr, meta.arity);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VM;
    use crate::specs::NATIVE_TABLE;

    #[test]
    fn test_native_alignment() {
        let vm = VM::new(); 
        
        // Check internal vectors match SSOT
        assert_eq!(vm.globals.len(), NATIVE_TABLE.len());
        
        // Check index 0 validity
        let first_val = vm.globals[0].value;
        assert!(first_val.is_native());
        
        // Check integrity of all natives
        for (i, _meta) in NATIVE_TABLE.iter().enumerate() {
            assert!(vm.globals[i].value.is_native());
        }
    }
}
