//! Static members — the `Int::MAX` / `Field::ZERO` family.
//!
//! ## Status
//!
//! Empty placeholder. The current codebase has **two** parallel
//! hardcoded matches, one per compiler:
//!
//! - `compiler/src/expressions/mod.rs:compile_static_access` — six
//!   entries (`Int::MAX`, `Int::MIN`, `Field::ZERO`, `Field::ONE`,
//!   `Field::ORDER`, `BigInt::from_bits`).
//! - `ir/src/prove_ir/compiler.rs:compile_static_access` — five entries
//!   (same list minus `BigInt::from_bits`, plus errors for
//!   `Field::ORDER` and `BigInt::*` which aren't constrainable).
//!
//! A future migration will collapse both matches into this one const
//! array, keyed by `(type_name, member)` with a `StaticMemberValue`
//! payload that each backend renders in its own flavour. Until then the
//! shape is defined but the array is empty — nothing consumes it yet.

/// Declaration of a static member accessible via `Type::MEMBER` syntax.
///
/// To be populated by the future migration. The payload variants encode
/// what each backend needs to emit:
/// - VM compiler: `LoadConst` with the matching [`Value`] flavour.
/// - ProveIR compiler: `CircuitExpr::Const` for constrainable values,
///   or a [`StaticMemberValue::VmOnly`] error for values that can't
///   appear inside a circuit.
#[derive(Debug, Clone, Copy)]
pub struct StaticMemberDecl {
    /// The type name, e.g. `"Int"`, `"Field"`, `"BigInt"`.
    pub type_name: &'static str,
    /// The member name, e.g. `"MAX"`, `"ZERO"`, `"from_bits"`.
    pub member: &'static str,
    /// What value this expands to, and which backend(s) accept it.
    pub value: StaticMemberValue,
}

/// Payload for a [`StaticMemberDecl`]. Currently ships only the
/// variant tags; the future migration will add concrete data (interned
/// handles, actual [`i64`] / field values, etc.).
#[derive(Debug, Clone, Copy)]
pub enum StaticMemberValue {
    /// Integer constant with the given signed i64 value. VM and ProveIR
    /// both support this (each in their own flavour).
    Int(i64),
    /// Field constant. The future migration will wire this to an
    /// interned field handle; for now this is a placeholder `u32`.
    Field(u32),
    /// A string constant (e.g. `Field::ORDER`). Valid in VM mode only —
    /// ProveIR rejects with a clear error because strings aren't
    /// constrainable.
    VmOnlyString(&'static str),
    /// A reference to a VM native (e.g. `BigInt::from_bits`). Valid in
    /// VM mode only; ProveIR rejects.
    VmOnlyNative(&'static str),
}

/// The complete set of static members known to Achronyme. Currently
/// empty — the future migration populates it from the two hardcoded
/// matches and deletes the old code.
pub const STATIC_MEMBERS: &[StaticMemberDecl] = &[];

/// Look up a static member declaration by `(type_name, member)`. Linear
/// scan over [`STATIC_MEMBERS`] — there are a handful of entries and
/// the compilers call this once per `::` access.
pub fn lookup(type_name: &str, member: &str) -> Option<&'static StaticMemberDecl> {
    STATIC_MEMBERS
        .iter()
        .find(|d| d.type_name == type_name && d.member == member)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_is_empty() {
        assert_eq!(STATIC_MEMBERS.len(), 0);
        assert!(lookup("Int", "MAX").is_none());
    }
}
