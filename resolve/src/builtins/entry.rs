use crate::symbol::{Arity, Availability};

use super::{BuiltinAuditError, ProveIrLowerHandle, VmFnHandle};

/// One entry in the [`BuiltinRegistry`].
///
/// Declares everything the compilers need to know about a builtin: its
/// name (for diagnostics and for the resolver pass's name lookup), its
/// arity (for early validation), its availability (for audit), and the
/// pointers to its implementation(s).
#[derive(Debug, Clone)]
pub struct BuiltinEntry {
    /// The canonical name users write in source code. `poseidon`,
    /// `assert_eq`, `mux`, etc. Unique within the registry.
    pub name: &'static str,
    /// Expected argument count. Checked by the resolver pass before
    /// dispatch; individual impls may validate further.
    pub arity: Arity,
    /// Which contexts can call this builtin. Enforced structurally by
    /// [`BuiltinRegistry::audit`].
    pub availability: Availability,
    /// VM runtime implementation handle. Required for
    /// [`Availability::Vm`] and [`Availability::Both`]; must be `None`
    /// for [`Availability::ProveIr`].
    pub vm_fn: Option<VmFnHandle>,
    /// ProveIR lowering callback handle. Required for
    /// [`Availability::ProveIr`] and [`Availability::Both`]; must be
    /// `None` for [`Availability::Vm`].
    pub prove_ir_lower: Option<ProveIrLowerHandle>,
}

impl BuiltinEntry {
    /// Audit just this entry against the four invariants documented at
    /// the module level. Returns a specific error describing the
    /// violation, or `Ok(())`.
    pub fn audit(&self) -> Result<(), BuiltinAuditError> {
        match self.availability {
            Availability::Both => {
                if self.vm_fn.is_none() {
                    return Err(BuiltinAuditError::BothMissingVm { name: self.name });
                }
                if self.prove_ir_lower.is_none() {
                    return Err(BuiltinAuditError::BothMissingProveIr { name: self.name });
                }
            }
            Availability::Vm => {
                if self.vm_fn.is_none() {
                    return Err(BuiltinAuditError::VmMissingImpl { name: self.name });
                }
                if self.prove_ir_lower.is_some() {
                    return Err(BuiltinAuditError::VmDeclaresProveIr { name: self.name });
                }
            }
            Availability::ProveIr => {
                if self.prove_ir_lower.is_none() {
                    return Err(BuiltinAuditError::ProveIrMissingImpl { name: self.name });
                }
                if self.vm_fn.is_some() {
                    return Err(BuiltinAuditError::ProveIrDeclaresVm { name: self.name });
                }
            }
        }
        Ok(())
    }
}
