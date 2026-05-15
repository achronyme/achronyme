//! Orchestration state for lifting a circom function and its
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

use std::collections::{HashMap, VecDeque};

use artik::{ProgramBuilder, RegType};
use memory::FieldFamily;

/// A callee whose subprogram id is reserved but whose body has not yet
/// been lifted. Reserving the id up front lets a `Call` be emitted at
/// the point the callee is discovered; the body is filled in
/// afterwards.
pub(super) struct PendingCallee {
    pub func_id: u32,
    pub name: String,
    pub dim_sig: Vec<u32>,
}

/// Builder + callee registry shared across every subprogram of one
/// lift. A single instance lives for the duration of lifting one
/// entry function; each subprogram body (entry or callee) is emitted
/// into the shared [`ProgramBuilder`].
pub(super) struct LiftDriver {
    /// Shared builder. Subprogram 0 is the entry; callee subprograms
    /// are appended by [`LiftDriver::lookup_or_reserve_callee`].
    pub builder: ProgramBuilder,
    /// `(function name, dimension signature) -> subprogram id`. One
    /// subprogram per distinct specialization; instantiations whose
    /// array dimensions fold to the same values share it.
    registry: HashMap<(String, Vec<u32>), u32>,
    /// Callees reserved but not yet lifted, drained in reservation
    /// order so each body is lifted exactly once.
    pending: VecDeque<PendingCallee>,
}

impl LiftDriver {
    /// Build a driver whose entry subprogram (builder subprogram 0,
    /// empty `Call` signature — it communicates through signals and
    /// witness slots, not call arguments) is ready to receive the
    /// function body.
    pub fn new() -> Self {
        Self {
            builder: ProgramBuilder::new(FieldFamily::BnLike256),
            registry: HashMap::new(),
            pending: VecDeque::new(),
        }
    }

    /// Resolve a callee to its subprogram id. The first time a given
    /// `(name, dim_sig)` specialization is seen, its subprogram is
    /// reserved with the supplied `Call` signature and queued for a
    /// later body lift; later sightings of the same specialization
    /// return the same id without re-reserving, so identical
    /// specializations share one subprogram.
    pub fn lookup_or_reserve_callee(
        &mut self,
        name: &str,
        dim_sig: &[u32],
        params: Vec<RegType>,
        returns: Vec<RegType>,
    ) -> u32 {
        let key = (name.to_owned(), dim_sig.to_vec());
        if let Some(&id) = self.registry.get(&key) {
            return id;
        }
        let id = self.builder.reserve_subprogram(params, returns);
        self.registry.insert(key, id);
        self.pending.push_back(PendingCallee {
            func_id: id,
            name: name.to_owned(),
            dim_sig: dim_sig.to_vec(),
        });
        id
    }

    /// Take the next reserved-but-unlifted callee, or `None` once every
    /// reserved callee body has been drained.
    pub fn next_pending(&mut self) -> Option<PendingCallee> {
        self.pending.pop_front()
    }
}

impl Default for LiftDriver {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use artik::ElemT;

    #[test]
    fn first_reserved_callee_is_subprogram_one() {
        let mut driver = LiftDriver::new();
        // Subprogram 0 is the implicit entry seeded by the builder, so
        // the first reserved callee is subprogram 1.
        let id = driver.lookup_or_reserve_callee("f", &[], vec![], vec![RegType::Field]);
        assert_eq!(id, 1);
    }

    #[test]
    fn same_specialization_dedups_to_one_subprogram() {
        let mut driver = LiftDriver::new();
        let a = driver.lookup_or_reserve_callee("f", &[8], vec![], vec![RegType::Field]);
        let b = driver.lookup_or_reserve_callee("f", &[8], vec![], vec![RegType::Field]);
        assert_eq!(a, b);
        // One pending entry queued for the shared subprogram, no more.
        assert!(driver.next_pending().is_some());
        assert!(driver.next_pending().is_none());
    }

    #[test]
    fn distinct_specializations_get_distinct_subprograms() {
        let mut driver = LiftDriver::new();
        let a = driver.lookup_or_reserve_callee("f", &[8], vec![], vec![RegType::Field]);
        let b = driver.lookup_or_reserve_callee("f", &[16], vec![], vec![RegType::Field]);
        let c = driver.lookup_or_reserve_callee("g", &[8], vec![], vec![RegType::Field]);
        assert_ne!(a, b);
        assert_ne!(a, c);
        assert_ne!(b, c);
    }

    #[test]
    fn pending_drains_in_reservation_order_once_each() {
        let mut driver = LiftDriver::new();
        driver.lookup_or_reserve_callee("f", &[1], vec![], vec![RegType::Field]);
        driver.lookup_or_reserve_callee(
            "g",
            &[2],
            vec![RegType::Array(ElemT::Field)],
            vec![RegType::Array(ElemT::Field)],
        );
        // Re-sighting f must not re-queue it.
        driver.lookup_or_reserve_callee("f", &[1], vec![], vec![RegType::Field]);

        let first = driver.next_pending().expect("f pending");
        assert_eq!(
            (first.name.as_str(), first.dim_sig.as_slice()),
            ("f", &[1][..])
        );
        let second = driver.next_pending().expect("g pending");
        assert_eq!(
            (second.name.as_str(), second.dim_sig.as_slice()),
            ("g", &[2][..])
        );
        assert!(driver.next_pending().is_none());
        assert_ne!(first.func_id, second.func_id);
    }
}
