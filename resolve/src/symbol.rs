//! Core symbol types: [`SymbolId`], [`CallableKind`], [`Availability`],
//! and [`Arity`].
//!
//! These are the shapes consumed by both compilers after the resolver pass
//! annotates the AST. See the crate-level docs for how they fit together.

use std::fmt;

/// Opaque, dense, [`u32`] identifier for a resolved symbol.
///
/// Interned by the resolver pass; stable within one compilation session.
/// Cheap to copy, compare, and hash. A [`SymbolId`] is meaningful only
/// against the [`SymbolTable`](crate::table::SymbolTable) that produced it
/// — mixing ids across tables is a logic bug the debug-assert will catch.
#[derive(Copy, Clone, Debug, Eq, PartialEq, Hash, Ord, PartialOrd)]
pub struct SymbolId(pub(crate) u32);

impl SymbolId {
    /// Raw [`u32`] view. Exposed for diagnostics and serialization. Do
    /// **not** use this to construct a [`SymbolId`] out of thin air —
    /// the resolver is the only legitimate source.
    #[inline]
    pub const fn as_u32(self) -> u32 {
        self.0
    }

    /// Sentinel used by [`CallableKind::FnAlias`] to mark an unresolved
    /// alias chain during construction. Users of the public API should
    /// never see this value — it exists to make alias-chain walking
    /// robust against partially-built tables.
    pub(crate) const UNRESOLVED: Self = SymbolId(u32::MAX);
}

impl fmt::Display for SymbolId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sym#{}", self.0)
    }
}

/// What context(s) a callable can be invoked from.
///
/// Used by [`BuiltinEntry`](crate::builtins::BuiltinEntry) to declare
/// whether a builtin has a VM implementation, a ProveIR lowering, or
/// both. User functions derive their availability from their body (see
/// Phase 4 availability inference in the RFC).
///
/// The [`BuiltinRegistry::audit`](crate::builtins::BuiltinRegistry::audit)
/// method enforces that every [`Availability::Both`] entry actually
/// carries both implementations, and that no [`Availability::Vm`] /
/// [`Availability::ProveIr`] entry over-declares itself.
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Availability {
    /// Callable only inside top-level / VM-mode code. Example: `print`,
    /// `typeof`, `gc_stats`.
    Vm,
    /// Callable only inside `prove {}` or `circuit {}` blocks. Example:
    /// `range_check`, `merkle_verify`.
    ProveIr,
    /// Callable from both contexts. Example: `poseidon`, `assert_eq`.
    Both,
}

impl Availability {
    /// Does this availability cover the VM context?
    #[inline]
    pub const fn includes_vm(self) -> bool {
        matches!(self, Self::Vm | Self::Both)
    }

    /// Does this availability cover the ProveIR context?
    #[inline]
    pub const fn includes_prove_ir(self) -> bool {
        matches!(self, Self::ProveIr | Self::Both)
    }
}

impl fmt::Display for Availability {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = match self {
            Self::Vm => "Vm",
            Self::ProveIr => "ProveIr",
            Self::Both => "Both",
        };
        f.write_str(s)
    }
}

/// How many arguments a callable accepts.
///
/// Separate from the `CallableKind` variant because user fns use
/// [`Arity::Fixed`] while some builtins use [`Arity::Range`] (assertions
/// accept an optional message) or [`Arity::Variadic`] (`print`,
/// `poseidon_many`).
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum Arity {
    /// Exact arg count.
    Fixed(u8),
    /// Inclusive range `[min, max]`. Used by assertions with an optional
    /// message parameter.
    Range(u8, u8),
    /// Any number of arguments. The callable validates at dispatch time.
    Variadic,
}

impl Arity {
    /// Does `count` satisfy this arity?
    pub const fn accepts(self, count: usize) -> bool {
        match self {
            Self::Fixed(n) => count == n as usize,
            Self::Range(min, max) => count >= min as usize && count <= max as usize,
            Self::Variadic => true,
        }
    }

    /// Human-readable summary for diagnostics.
    pub fn describe(self) -> String {
        match self {
            Self::Fixed(n) => format!("{n}"),
            Self::Range(min, max) => format!("{min}..={max}"),
            Self::Variadic => "variadic".to_string(),
        }
    }
}

/// Everything a resolved name can point at.
///
/// Produced by the resolver pass and stored in the
/// [`SymbolTable`](crate::table::SymbolTable). Both compilers dispatch on
/// the variant; nothing else in the AST needs to carry resolution data.
///
/// ## Design notes
///
/// - [`CallableKind::Builtin`] does NOT carry the impl functions directly
///   — those live in the [`BuiltinEntry`](crate::builtins::BuiltinEntry)
///   referenced by the variant. The indirection keeps
///   [`SymbolTable::get`](crate::table::SymbolTable::get) cheap and lets
///   the registry own the impls.
/// - [`CallableKind::UserFn`] holds an opaque `ast_handle` instead of the
///   AST directly, so this crate stays free of parser dependencies during
///   Phase 1. Phase 3 will plug in the real `Arc<FnDecl>` type from the
///   parser crate.
/// - [`CallableKind::FnAlias`] exists so `let a = p::fn; a()` works
///   uniformly in VM mode and prove blocks when the RHS const-resolves to
///   a known symbol (§3.7 of the RFC).
#[derive(Clone, Debug)]
pub enum CallableKind {
    /// A registered builtin. The variant carries an index into the
    /// [`BuiltinRegistry`](crate::builtins::BuiltinRegistry)'s `entries`
    /// vector. Both compilers look up the entry to discover the
    /// availability, arity, and impl function pointers.
    Builtin {
        /// Index into [`BuiltinRegistry::entries`](crate::builtins::BuiltinRegistry::entries).
        entry_index: usize,
    },

    /// A user-defined function from a `.ach` file.
    ///
    /// The `ast_handle` is an opaque token; Phase 3 replaces it with the
    /// real shared [`Arc<FnDecl>`] once the parser types are wired in.
    /// `availability` is computed during Phase 4 availability inference
    /// and defaults to [`Availability::Both`] until that pass runs.
    UserFn {
        /// Fully qualified name. `"foo"` for a top-level fn in `main.ach`,
        /// `"math::add"` for an exported fn in an imported module.
        qualified_name: String,
        /// Phase-3 placeholder: opaque handle into the module AST store.
        ast_handle: u32,
        /// Derived from the body during Phase 4 availability inference.
        availability: Availability,
    },

    /// Static alias to another callable. Created by `let a = p::function`
    /// when the RHS const-resolves at annotation time to a single
    /// [`SymbolId`] pointing at a [`CallableKind::UserFn`] or
    /// [`CallableKind::Builtin`]. Both compilers follow the alias chain.
    ///
    /// Chain depth is capped at [`FN_ALIAS_MAX_DEPTH`] to catch
    /// pathological cases; see [`Availability::includes_vm`] etc. for how
    /// availability flows through an alias.
    FnAlias {
        /// The symbol this alias points at. Follow the chain via
        /// [`SymbolTable::resolve_alias`](crate::table::SymbolTable::resolve_alias).
        target: SymbolId,
    },

    /// A Circom template imported from a `.circom` library. Dispatch is
    /// unchanged from the current path — this variant just lets the
    /// resolver know the symbol exists so `::` lookups succeed uniformly.
    ///
    /// Phase 3 will refine the payload with an `Arc<dyn CircomLibraryHandle>`
    /// once the dependency direction is finalized.
    CircomTemplate {
        /// Template name as declared in the `.circom` source.
        template_name: String,
        /// Phase-3 placeholder: opaque handle into the library registry.
        library_handle: u32,
    },

    /// A compile-time constant exported from a module: `export let PI = 3`.
    ///
    /// Phase 6 populates the `value` field with a real const
    /// representation; Phase 1 just records the qualified name and the
    /// kind of constant.
    Constant {
        /// Fully qualified name, e.g. `"math::PI"`.
        qualified_name: String,
        /// What kind of constant this is. Determines how each backend
        /// renders it.
        const_kind: ConstKind,
    },
}

/// The value category of a [`CallableKind::Constant`].
#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum ConstKind {
    /// A tagged 60-bit integer (VM `Int` / ProveIR field embedding).
    Int,
    /// A field element.
    Field,
    /// A 256-bit arbitrary-precision integer.
    BigInt,
    /// An immutable byte buffer.
    Bytes,
    /// An interned string.
    String,
}

/// Maximum depth of an [`CallableKind::FnAlias`] chain before the
/// resolver flags it as pathological. Real-world chains are length 1
/// (`a → p::fn`); anything deeper is almost certainly a mistake or a
/// cycle.
pub const FN_ALIAS_MAX_DEPTH: usize = 16;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn availability_inclusion() {
        assert!(Availability::Vm.includes_vm());
        assert!(!Availability::Vm.includes_prove_ir());
        assert!(Availability::ProveIr.includes_prove_ir());
        assert!(!Availability::ProveIr.includes_vm());
        assert!(Availability::Both.includes_vm());
        assert!(Availability::Both.includes_prove_ir());
    }

    #[test]
    fn arity_accepts() {
        assert!(Arity::Fixed(2).accepts(2));
        assert!(!Arity::Fixed(2).accepts(1));
        assert!(!Arity::Fixed(2).accepts(3));

        assert!(Arity::Range(2, 3).accepts(2));
        assert!(Arity::Range(2, 3).accepts(3));
        assert!(!Arity::Range(2, 3).accepts(1));
        assert!(!Arity::Range(2, 3).accepts(4));

        assert!(Arity::Variadic.accepts(0));
        assert!(Arity::Variadic.accepts(100));
    }

    #[test]
    fn symbol_id_display() {
        let id = SymbolId(42);
        assert_eq!(id.as_u32(), 42);
        assert_eq!(format!("{id}"), "sym#42");
    }

    #[test]
    fn availability_display() {
        assert_eq!(format!("{}", Availability::Vm), "Vm");
        assert_eq!(format!("{}", Availability::ProveIr), "ProveIr");
        assert_eq!(format!("{}", Availability::Both), "Both");
    }
}
