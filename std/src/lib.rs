//! `achronyme-std` — Standard library modules for the Achronyme VM.
//!
//! Provides additional native functions beyond the VM builtins.
//! Each module implements `akron::NativeModule` and is registered by the
//! CLI via `VM::register_module()`.

pub mod conv;
#[cfg(feature = "io")]
pub mod io;
pub mod string_ext;

use akron::module::NativeModule;
use akron::specs::NativeMeta;

/// Returns all std modules in registration order.
///
/// The order here determines global indices (continuing after builtins).
/// Both compiler (`with_extra_natives`) and VM (`register_module`) must
/// use the same order.
pub fn std_modules() -> Vec<Box<dyn NativeModule>> {
    let mut modules: Vec<Box<dyn NativeModule>> = vec![
        Box::new(conv::ConvModule),
        Box::new(string_ext::StringExtModule),
    ];

    #[cfg(feature = "io")]
    modules.push(Box::new(io::IoModule));

    modules
}

/// Returns `NativeMeta` entries for all std modules.
///
/// Pass this to `Compiler::with_extra_natives()` so the compiler
/// can resolve std function names during compilation.
pub fn std_native_table() -> Vec<NativeMeta> {
    std_modules()
        .iter()
        .flat_map(|m| {
            m.natives()
                .into_iter()
                .map(|d| NativeMeta {
                    name: d.name,
                    arity: d.arity,
                })
                .collect::<Vec<_>>()
        })
        .collect()
}
