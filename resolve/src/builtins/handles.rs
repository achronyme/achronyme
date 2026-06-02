/// Opaque handle to a VM native function implementation.
///
/// The handle is a u32 index into a backend-owned `Vec<NativeFn>`. See
/// the module docs above for why this crate holds an index and not a
/// raw function pointer — the TL;DR is "dep cycle with `vm`". The VM
/// side populates real indices as it registers natives.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct VmFnHandle(pub u32);

impl VmFnHandle {
    /// Sentinel used by tests and placeholder entries when no real
    /// implementation has been wired yet. Production code should never
    /// observe this once dispatch is live.
    pub const PLACEHOLDER: Self = VmFnHandle(0);

    /// Raw index view.
    #[inline]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}

/// Opaque handle to a ProveIR lowering callback.
///
/// Symmetric to [`VmFnHandle`]: a u32 index into a backend-owned
/// `Vec<ProveIrLowerFn>` that lives inside the `ir` crate. This
/// crate carries only the handle so `ir` never pulls in VM types
/// via `resolve`.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash)]
pub struct ProveIrLowerHandle(pub u32);

impl ProveIrLowerHandle {
    /// Sentinel used by tests and placeholder entries when no real
    /// implementation has been wired yet.
    pub const PLACEHOLDER: Self = ProveIrLowerHandle(0);

    /// Raw index view.
    #[inline]
    pub const fn as_u32(self) -> u32 {
        self.0
    }
}
