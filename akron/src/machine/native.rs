use crate::error::RuntimeError;
use crate::globals::GlobalEntry;
use crate::module::builtin_modules;
use crate::native::{NativeFn, NativeObj};
use memory::Value;

/// Trait for native function registration
pub trait NativeRegistry {
    fn define_native(
        &mut self,
        name: &str,
        func: NativeFn,
        arity: isize,
    ) -> Result<(), RuntimeError>;
    fn bootstrap_natives(&mut self) -> Result<(), RuntimeError>;
}

impl NativeRegistry for super::vm::VM {
    fn define_native(
        &mut self,
        name: &str,
        func: NativeFn,
        arity: isize,
    ) -> Result<(), RuntimeError> {
        let name_string = name.to_string();

        // 1. Intern string (still needed for debugging/reflection later, but not for lookup key)
        if !self.interner.contains_key(&name_string) {
            let h = self.heap.alloc_string(name_string.clone())?;
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
        Ok(())
    }

    fn bootstrap_natives(&mut self) -> Result<(), RuntimeError> {
        if !self.natives.is_empty() || !self.globals.is_empty() {
            panic!("VM must be empty before bootstrapping natives");
        }

        let modules = builtin_modules();

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

        let registry = resolve::BuiltinRegistry::default();
        let vm_entries = registry.vm_entries_by_handle();

        let mut all_defs = Vec::with_capacity(vm_entries.len());
        for module in &modules {
            all_defs.extend(module.natives());
        }

        assert_eq!(
            all_defs.len(),
            vm_entries.len(),
            "NativeModule definitions ({}) != registry VM entries ({})",
            all_defs.len(),
            vm_entries.len(),
        );
        for (i, (def, entry)) in all_defs.iter().zip(vm_entries.iter()).enumerate() {
            assert_eq!(
                def.name, entry.name,
                "Native index {i}: module says '{}' but registry says '{}'",
                def.name, entry.name,
            );
        }

        for def in &all_defs {
            self.define_native(def.name, def.func, def.arity)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::VM;

    #[test]
    fn test_native_alignment() {
        let registry = resolve::BuiltinRegistry::default();
        let native_count = registry.vm_native_count();
        let vm = VM::new();

        assert_eq!(vm.globals.len(), native_count);

        let first_val = vm.globals[0].value;
        assert!(first_val.is_native());

        for i in 0..native_count {
            assert!(vm.globals[i].value.is_native());
        }
    }

    #[test]
    fn test_module_names_match_registry() {
        let registry = resolve::BuiltinRegistry::default();
        let vm_entries = registry.vm_entries_by_handle();

        let modules = builtin_modules();
        let mut all_names: Vec<&str> = Vec::new();
        for module in &modules {
            for def in module.natives() {
                all_names.push(def.name);
            }
        }

        assert_eq!(all_names.len(), vm_entries.len());
        for (i, (name, entry)) in all_names.iter().zip(vm_entries.iter()).enumerate() {
            assert_eq!(
                *name, entry.name,
                "Mismatch at index {i}: module='{}' vs registry='{}'",
                name, entry.name
            );
        }
    }

    #[test]
    fn test_each_module_has_natives() {
        let modules = builtin_modules();
        assert_eq!(modules.len(), 2);
        assert_eq!(modules[0].name(), "core");
        assert_eq!(modules[1].name(), "bigint");

        for module in &modules {
            assert!(
                !module.natives().is_empty(),
                "Module '{}' has no natives",
                module.name()
            );
        }
    }
}
