use std::fmt;

/// Errors produced by [`BuiltinRegistry::audit`] and [`BuiltinEntry::audit`].
///
/// Every variant names the offending builtin and explains the violation.
/// Downstream compilers wrap these into full diagnostics with
/// suggestions; this crate keeps them as plain enum variants.
///
/// [`BuiltinEntry::audit`]: super::BuiltinEntry::audit
/// [`BuiltinRegistry::audit`]: super::BuiltinRegistry::audit
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BuiltinAuditError {
    /// [`Availability::Both`] entry missing its VM implementation.
    ///
    /// [`Availability::Both`]: crate::symbol::Availability::Both
    BothMissingVm {
        /// Name of the offending builtin.
        name: &'static str,
    },
    /// [`Availability::Both`] entry missing its ProveIR lowering.
    ///
    /// [`Availability::Both`]: crate::symbol::Availability::Both
    BothMissingProveIr {
        /// Name of the offending builtin.
        name: &'static str,
    },
    /// [`Availability::Vm`] entry missing its VM implementation.
    ///
    /// [`Availability::Vm`]: crate::symbol::Availability::Vm
    VmMissingImpl {
        /// Name of the offending builtin.
        name: &'static str,
    },
    /// [`Availability::Vm`] entry also declares a ProveIR lowering —
    /// probably meant to be [`Availability::Both`].
    ///
    /// [`Availability::Both`]: crate::symbol::Availability::Both
    /// [`Availability::Vm`]: crate::symbol::Availability::Vm
    VmDeclaresProveIr {
        /// Name of the offending builtin.
        name: &'static str,
    },
    /// [`Availability::ProveIr`] entry missing its lowering.
    ///
    /// [`Availability::ProveIr`]: crate::symbol::Availability::ProveIr
    ProveIrMissingImpl {
        /// Name of the offending builtin.
        name: &'static str,
    },
    /// [`Availability::ProveIr`] entry also declares a VM implementation.
    ///
    /// [`Availability::ProveIr`]: crate::symbol::Availability::ProveIr
    ProveIrDeclaresVm {
        /// Name of the offending builtin.
        name: &'static str,
    },
    /// Two different entries share the same `name`.
    DuplicateName {
        /// The colliding name.
        name: &'static str,
    },
}

impl fmt::Display for BuiltinAuditError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::BothMissingVm { name } => write!(
                f,
                "builtin `{name}` declared as `Both` but missing VM implementation \
                 (`vm_fn: None`). Either provide a VM impl or change availability \
                 to `ProveIr`."
            ),
            Self::BothMissingProveIr { name } => write!(
                f,
                "builtin `{name}` declared as `Both` but missing ProveIR lowering \
                 (`prove_ir_lower: None`). Either provide a ProveIR lowering or \
                 change availability to `Vm`."
            ),
            Self::VmMissingImpl { name } => write!(
                f,
                "builtin `{name}` declared as `Vm` but has no `vm_fn` — Vm \
                 availability requires a VM implementation."
            ),
            Self::VmDeclaresProveIr { name } => write!(
                f,
                "builtin `{name}` declared as `Vm` but also declares \
                 `prove_ir_lower`. Did you mean `Availability::Both`?"
            ),
            Self::ProveIrMissingImpl { name } => write!(
                f,
                "builtin `{name}` declared as `ProveIr` but has no \
                 `prove_ir_lower` — ProveIr availability requires a lowering."
            ),
            Self::ProveIrDeclaresVm { name } => write!(
                f,
                "builtin `{name}` declared as `ProveIr` but also declares \
                 `vm_fn`. Did you mean `Availability::Both`?"
            ),
            Self::DuplicateName { name } => write!(
                f,
                "builtin `{name}` is registered more than once — every registry \
                 entry must have a unique name."
            ),
        }
    }
}

impl std::error::Error for BuiltinAuditError {}
