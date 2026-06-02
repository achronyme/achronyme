use std::collections::HashMap;

use ir_forge::types::FieldConst;

/// Inferred bit-width of a `CircuitExpr`'s runtime value.
///
/// The lattice ordering is `Exact(n) ≤ AtMost(n) ≤ AtMost(m) ≤ Field`
/// for `m ≥ n`. [`Self::join`] returns the least upper bound,
/// matching `Mux` / `if-else` branch merging. [`Self::widen`] saturates
/// toward `Field` once an arithmetic propagation crosses the 254-bit
/// BN254 limit.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BitWidth {
    /// Exact bit-width — the value is provably in `[0, 2^n)` and the
    /// width is *known* (e.g. from a `Num2Bits(n)` constraint or a
    /// numeric literal). Carries the strongest claim and is required
    /// for downstream optimisations like RangeCheck elimination
    /// (Stage 3) where a tautological check can be dropped.
    Exact(u32),
    /// Upper bound only — the value is provably in `[0, 2^n)` but the
    /// inference path was through arithmetic (`Add`, `Mul`, ...) that
    /// composes upper bounds without preserving exactness.
    AtMost(u32),
    /// 254-bit fallback (BN254 field-width). Unconstrained witnesses,
    /// modular subtractions, and any expression involving signals
    /// without provenance default here. Always sound.
    Field,
}

/// Field-width fallback constant. Matches `DEFAULT_MAX_BITS` at the
/// lowering layer (`circom/src/lowering/expressions/mod.rs`). Both
/// must change together if/when the prime field changes.
pub const FIELD_BITS: u32 = 254;

impl BitWidth {
    /// Concrete bit-count for downstream consumers (Decompose,
    /// RangeCheck, …). Always returns ≥ the actual range — sound to
    /// substitute for `DEFAULT_MAX_BITS`.
    pub fn to_num_bits(self) -> u32 {
        match self {
            Self::Exact(n) => n,
            Self::AtMost(n) => n,
            Self::Field => FIELD_BITS,
        }
    }

    /// Saturate-to-`Field` constructor. Use whenever an arithmetic
    /// rule could produce a width ≥ `FIELD_BITS`. Without this guard,
    /// `u32` arithmetic would wrap and we'd silently miscompile.
    pub fn widen(n: u32) -> Self {
        if n >= FIELD_BITS {
            Self::Field
        } else {
            Self::AtMost(n)
        }
    }

    /// Least-upper-bound merge for branch joins (`Mux`, `if-else`).
    ///
    /// `join(Exact(a), Exact(b)) = Exact(max(a, b))` only when `a == b`
    /// — the post-join width is no longer "exactly that bit-count" if
    /// the branches differ. Otherwise widens to `AtMost` or `Field`.
    pub fn join(self, other: Self) -> Self {
        match (self, other) {
            (Self::Field, _) | (_, Self::Field) => Self::Field,
            (Self::Exact(a), Self::Exact(b)) if a == b => Self::Exact(a),
            (Self::Exact(a), Self::Exact(b))
            | (Self::Exact(a), Self::AtMost(b))
            | (Self::AtMost(a), Self::Exact(b))
            | (Self::AtMost(a), Self::AtMost(b)) => Self::widen(a.max(b)),
        }
    }
}

/// Side-table of signal-name → known [`BitWidth`]. Populated by the
/// lowering pipeline (e.g., `wiring.rs::PendingComponent::inline_into`)
/// when it instantiates a library template with a constraint-driving
/// signature like `Num2Bits(n)`. Lookups for `CircuitExpr::Input(name)`
/// and `Var(name)` consult this table before falling back to `Field`.
pub type SignalWidths = HashMap<String, BitWidth>;

/// Inference context carried through `infer_expr`. Stage 2 adds the
/// `signal_widths` table for constrained-signal lookups; Stage 1
/// only used `param_values` + `known_constants`.
#[derive(Debug, Clone, Default)]
pub struct InferenceCtx<'a> {
    /// Captures bound to compile-time `FieldConst`s. Mirrors
    /// `LoweringContext::param_values` — passed in directly to avoid a
    /// circular dep between `circom::lowering` and this module.
    pub param_values: Option<&'a HashMap<String, FieldConst>>,
    /// Known constants from the `LoweringEnv` (signals whose value the
    /// const-fold pass has resolved). Read the same way as
    /// `param_values` — both yield exact bit-widths.
    pub known_constants: Option<&'a HashMap<String, FieldConst>>,
    /// Stage 2: signal names whose bit-width is provably bounded via
    /// constraint context (e.g., outputs of `Num2Bits(n)` are
    /// `Exact(1)`). Lookups consulted by `Input` / `Var` before the
    /// `Field` fallback.
    pub signal_widths: Option<&'a SignalWidths>,
}

impl<'a> InferenceCtx<'a> {
    /// Build a context with all three maps. Convenience for call sites
    /// that have access to `LoweringContext`, `LoweringEnv`, and the
    /// signal-widths side-table.
    pub fn new(
        param_values: &'a HashMap<String, FieldConst>,
        known_constants: &'a HashMap<String, FieldConst>,
        signal_widths: &'a SignalWidths,
    ) -> Self {
        Self {
            param_values: Some(param_values),
            known_constants: Some(known_constants),
            signal_widths: Some(signal_widths),
        }
    }

    pub(super) fn lookup(&self, name: &str) -> Option<FieldConst> {
        if let Some(map) = self.param_values {
            if let Some(v) = map.get(name) {
                return Some(*v);
            }
        }
        if let Some(map) = self.known_constants {
            if let Some(v) = map.get(name) {
                return Some(*v);
            }
        }
        None
    }

    pub(super) fn lookup_signal_width(&self, name: &str) -> Option<BitWidth> {
        self.signal_widths.and_then(|map| map.get(name).copied())
    }
}
