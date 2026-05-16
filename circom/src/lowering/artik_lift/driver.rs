//! Callee registry for lifting a circom function and its
//! transitively-called functions into a multi-subprogram Artik
//! program.
//!
//! The function being lifted is the entry subprogram — builder
//! subprogram 0, which reads its inputs via `ReadSignal` and writes
//! its outputs via `WriteWitness`, so it has an empty `Call`
//! parameter and return signature. Every transitively-called circom
//! function becomes a callee subprogram, reserved once per distinct
//! array-dimension specialization and invoked with a real Artik
//! `Call`. Callee bodies are drained from the pending queue and
//! lifted after their ids are reserved, so a call to a function
//! defined later in source — or shared between several call sites —
//! resolves to one subprogram.
//!
//! The builder itself is owned by the lift state, not the registry:
//! every lift method emits into one shared builder, and a callee body
//! is lifted as an additional pass over that builder via
//! `begin_subprogram` / `end_subprogram`. The registry only tracks
//! which specializations have been reserved and which still need a
//! body.

use std::collections::{HashMap, VecDeque};

use artik::{ProgramBuilder, RegType};

use super::ConstInt;

/// The structural signature of one callee parameter at a call site.
/// Two call sites may share a subprogram only when their full
/// parameter signatures are identical: a different compile-time scalar
/// value, a runtime-vs-constant scalar, or a different array shape all
/// change what the body compiles to (loop unrolling, `1 << n` folding,
/// per-element array work), so each distinct signature gets its own
/// subprogram. A body-dimension signature alone is too coarse — it
/// misses scalar args that drive structure without appearing in a
/// `var X[..]` declaration.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(super) enum ParamSig {
    /// Scalar argument with a known compile-time value.
    ScalarConst(ConstInt),
    /// Scalar argument whose value is only known at witness time.
    ScalarRuntime,
    /// 1D array argument of the given element count.
    Array1D(u32),
    /// 2D array argument of the given row/column counts.
    Array2D(u32, u32),
}

/// A callee whose subprogram id is reserved but whose body has not yet
/// been lifted. Reserving the id up front lets a `Call` be emitted at
/// the point the callee is discovered; the body is filled in
/// afterwards. `param_sig` lets the body lift reconstruct the
/// parameter bindings (parameter `i` is the callee subprogram's
/// pre-allocated register `i`; its shape and any compile-time value
/// come from the signature).
pub(super) struct PendingCallee {
    pub func_id: u32,
    pub name: String,
    pub param_sig: Vec<ParamSig>,
}

/// Callee registry shared across every subprogram of one lift. One
/// instance lives for the duration of lifting a single entry
/// function.
#[derive(Default)]
pub(super) struct LiftDriver {
    /// `(function name, parameter signature) -> subprogram id`. One
    /// subprogram per distinct specialization; call sites with an
    /// identical parameter signature share it.
    registry: HashMap<(String, Vec<ParamSig>), u32>,
    /// Callees reserved but not yet lifted, drained in reservation
    /// order so each body is lifted exactly once.
    pending: VecDeque<PendingCallee>,
}

impl LiftDriver {
    pub fn new() -> Self {
        Self::default()
    }

    /// Resolve a callee to its subprogram id. The first time a given
    /// `(name, param_sig)` specialization is seen, its subprogram is
    /// reserved on `builder` with the supplied `Call` signature and
    /// queued for a later body lift; later sightings of the same
    /// specialization return the same id without re-reserving, so
    /// call sites with an identical parameter signature share one
    /// subprogram.
    pub fn lookup_or_reserve_callee(
        &mut self,
        builder: &mut ProgramBuilder,
        name: &str,
        param_sig: &[ParamSig],
        params: Vec<RegType>,
        returns: Vec<RegType>,
    ) -> u32 {
        let key = (name.to_owned(), param_sig.to_vec());
        if let Some(&id) = self.registry.get(&key) {
            return id;
        }
        let id = builder.reserve_subprogram(params, returns);
        self.registry.insert(key, id);
        self.pending.push_back(PendingCallee {
            func_id: id,
            name: name.to_owned(),
            param_sig: param_sig.to_vec(),
        });
        id
    }

    /// Take the next reserved-but-unlifted callee, or `None` once every
    /// reserved callee body has been drained.
    pub fn next_pending(&mut self) -> Option<PendingCallee> {
        self.pending.pop_front()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use artik::ElemT;
    use memory::FieldFamily;

    fn builder() -> ProgramBuilder {
        ProgramBuilder::new(FieldFamily::BnLike256)
    }

    #[test]
    fn first_reserved_callee_is_subprogram_one() {
        let mut b = builder();
        let mut driver = LiftDriver::new();
        // Subprogram 0 is the implicit entry seeded by the builder, so
        // the first reserved callee is subprogram 1.
        let id = driver.lookup_or_reserve_callee(
            &mut b,
            "f",
            &[ParamSig::ScalarRuntime],
            vec![RegType::Field],
            vec![RegType::Field],
        );
        assert_eq!(id, 1);
    }

    #[test]
    fn same_specialization_dedups_to_one_subprogram() {
        let mut b = builder();
        let mut driver = LiftDriver::new();
        let sig = [ParamSig::ScalarConst(8)];
        let a = driver.lookup_or_reserve_callee(
            &mut b,
            "f",
            &sig,
            vec![RegType::Field],
            vec![RegType::Field],
        );
        let c = driver.lookup_or_reserve_callee(
            &mut b,
            "f",
            &sig,
            vec![RegType::Field],
            vec![RegType::Field],
        );
        assert_eq!(a, c);
        // One pending entry queued for the shared subprogram, no more.
        assert!(driver.next_pending().is_some());
        assert!(driver.next_pending().is_none());
    }

    #[test]
    fn distinct_specializations_get_distinct_subprograms() {
        let mut b = builder();
        let mut driver = LiftDriver::new();
        let p = || vec![RegType::Field];
        let a = driver.lookup_or_reserve_callee(&mut b, "f", &[ParamSig::ScalarConst(8)], p(), p());
        let b2 =
            driver.lookup_or_reserve_callee(&mut b, "f", &[ParamSig::ScalarConst(16)], p(), p());
        let c = driver.lookup_or_reserve_callee(&mut b, "g", &[ParamSig::ScalarConst(8)], p(), p());
        assert_ne!(a, b2);
        assert_ne!(a, c);
        assert_ne!(b2, c);
    }

    #[test]
    fn param_signature_separates_const_runtime_and_array_shapes() {
        let mut b = builder();
        let mut driver = LiftDriver::new();
        let p = || vec![RegType::Field];
        // Distinct compile-time scalar values must not share a body.
        let c8 =
            driver.lookup_or_reserve_callee(&mut b, "f", &[ParamSig::ScalarConst(8)], p(), p());
        let c16 =
            driver.lookup_or_reserve_callee(&mut b, "f", &[ParamSig::ScalarConst(16)], p(), p());
        assert_ne!(c8, c16);
        // A runtime scalar is its own specialization, shared across
        // sites that both pass runtime.
        let r1 = driver.lookup_or_reserve_callee(&mut b, "f", &[ParamSig::ScalarRuntime], p(), p());
        let r2 = driver.lookup_or_reserve_callee(&mut b, "f", &[ParamSig::ScalarRuntime], p(), p());
        assert_eq!(r1, r2);
        assert_ne!(r1, c8);
        // Array shapes separate too.
        let ap = || vec![RegType::Array(ElemT::Field)];
        let a4 = driver.lookup_or_reserve_callee(&mut b, "g", &[ParamSig::Array1D(4)], ap(), ap());
        let a8 = driver.lookup_or_reserve_callee(&mut b, "g", &[ParamSig::Array1D(8)], ap(), ap());
        let a23 =
            driver.lookup_or_reserve_callee(&mut b, "g", &[ParamSig::Array2D(2, 3)], ap(), ap());
        assert_ne!(a4, a8);
        assert_ne!(a4, a23);
    }

    #[test]
    fn pending_drains_in_reservation_order_once_each() {
        let mut b = builder();
        let mut driver = LiftDriver::new();
        let f_sig = [ParamSig::ScalarConst(1)];
        let g_sig = [ParamSig::Array1D(2)];
        driver.lookup_or_reserve_callee(
            &mut b,
            "f",
            &f_sig,
            vec![RegType::Field],
            vec![RegType::Field],
        );
        driver.lookup_or_reserve_callee(
            &mut b,
            "g",
            &g_sig,
            vec![RegType::Array(ElemT::Field)],
            vec![RegType::Array(ElemT::Field)],
        );
        // Re-sighting f must not re-queue it.
        driver.lookup_or_reserve_callee(
            &mut b,
            "f",
            &f_sig,
            vec![RegType::Field],
            vec![RegType::Field],
        );

        let first = driver.next_pending().expect("f pending");
        assert_eq!(
            (first.name.as_str(), first.param_sig.as_slice()),
            ("f", &f_sig[..])
        );
        let second = driver.next_pending().expect("g pending");
        assert_eq!(
            (second.name.as_str(), second.param_sig.as_slice()),
            ("g", &g_sig[..])
        );
        assert!(driver.next_pending().is_none());
        assert_ne!(first.func_id, second.func_id);
    }
}
