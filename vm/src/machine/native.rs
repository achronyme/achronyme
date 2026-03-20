use crate::globals::GlobalEntry;
use crate::module::builtin_modules;
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

        // Collect all native definitions from modules
        let modules = builtin_modules();

        // Validate module name uniqueness
        {
            let mut seen = std::collections::HashSet::new();
            for module in &modules {
                assert!(
                    seen.insert(module.name()),
                    "Duplicate builtin module name: '{}'",
                    module.name()
                );
            }
        }

        let mut all_defs = Vec::with_capacity(NATIVE_TABLE.len());
        for module in &modules {
            all_defs.extend(module.natives());
        }

        // Validate alignment with NATIVE_TABLE (compiler SSOT)
        assert_eq!(
            all_defs.len(),
            NATIVE_TABLE.len(),
            "NativeModule definitions ({}) != NATIVE_TABLE length ({})",
            all_defs.len(),
            NATIVE_TABLE.len(),
        );
        for (i, (def, meta)) in all_defs.iter().zip(NATIVE_TABLE.iter()).enumerate() {
            assert_eq!(
                def.name, meta.name,
                "Native index {i}: module says '{}' but NATIVE_TABLE says '{}'",
                def.name, meta.name,
            );
            assert_eq!(
                def.arity, meta.arity,
                "Native '{}' arity mismatch: module={} vs table={}",
                def.name, def.arity, meta.arity,
            );
        }

        // Register all natives in order
        for def in &all_defs {
            self.define_native(def.name, def.func, def.arity);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::specs::NATIVE_TABLE;
    use crate::VM;

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

    #[test]
    fn test_module_names_match_table() {
        let modules = builtin_modules();
        let mut all_names: Vec<&str> = Vec::new();
        for module in &modules {
            for def in module.natives() {
                all_names.push(def.name);
            }
        }

        assert_eq!(all_names.len(), NATIVE_TABLE.len());
        for (i, (name, meta)) in all_names.iter().zip(NATIVE_TABLE.iter()).enumerate() {
            assert_eq!(
                *name, meta.name,
                "Mismatch at index {i}: module='{}' vs table='{}'",
                name, meta.name
            );
        }
    }

    #[test]
    fn test_each_module_has_natives() {
        let modules = builtin_modules();
        assert_eq!(modules.len(), 2);
        assert_eq!(modules[0].name(), "core");
        assert_eq!(modules[1].name(), "bigint");

        // Verify each module contributes at least one native
        for module in &modules {
            assert!(
                !module.natives().is_empty(),
                "Module '{}' has no natives",
                module.name()
            );
        }
    }
}
