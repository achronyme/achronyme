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

        // 1. Intern string (ensure it exists in Heap and Interner)
        let name_handle = if let Some(&h) = self.interner.get(&name_string) {
            h
        } else {
            let h = self.heap.alloc_string(name_string.clone());
            self.interner.insert(name_string.clone(), h);
            h
        };

        // 2. Register Native Object
        let native = NativeObj {
            name: name_string,
            func,
            arity,
        };
        self.natives.push(native);
        let native_idx = (self.natives.len() - 1) as u32;

        // 3. Register in Globals
        let val = Value::native(native_idx);
        self.globals.insert(
            name_handle,
            GlobalEntry {
                value: val,
                mutable: false, // Natives are constant
            },
        );
    }

    fn bootstrap_natives(&mut self) {
        // Preamble: Core Intrinsics
        self.define_native("print", crate::stdlib::core::native_print, -1);
        self.define_native("len", crate::stdlib::core::native_len, 1);
        self.define_native("typeof", crate::stdlib::core::native_typeof, 1);
        self.define_native("assert", crate::stdlib::core::native_assert, 1);
    }
}
