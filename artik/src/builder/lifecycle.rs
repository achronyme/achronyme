use memory::FieldFamily;

use crate::ir::{Instr, Reg, RegType};
use crate::program::FieldConstEntry;

use super::{BuilderSnapshot, ProgramBuilder, SubInProgress};

impl ProgramBuilder {
    /// Start a new builder for the given field family. The builder has
    /// one subprogram — the entry (id 0), with no parameters or
    /// returns — and zero registers, signals, slots, constants, or
    /// instructions. Allocate them as you go.
    pub fn new(family: FieldFamily) -> Self {
        Self {
            family,
            const_pool: Vec::new(),
            next_signal: 0,
            next_slot: 0,
            subs: vec![SubInProgress::new(Vec::new(), Vec::new())],
            active: 0,
        }
    }

    #[inline]
    pub(super) fn cur(&self) -> &SubInProgress {
        // `active` is 0 on construction and only ever set to an index
        // returned by `reserve_subprogram` (always in range), so this
        // index is an internal invariant, not caller-controlled.
        &self.subs[self.active]
    }

    #[inline]
    pub(super) fn cur_mut(&mut self) -> &mut SubInProgress {
        &mut self.subs[self.active]
    }

    // ── Subprogram management ─────────────────────────────────────────

    /// Reserve a callable subprogram id with the given signature
    /// without building its body yet. The id can be used as the
    /// `func_id` of a [`Self::call`] emitted from any subprogram —
    /// including one built *before* this subprogram's body — so the
    /// lift can emit a call at the point it discovers the callee and
    /// fill in the callee body afterwards. Does not change the active
    /// subprogram.
    pub fn reserve_subprogram(&mut self, params: Vec<RegType>, returns: Vec<RegType>) -> u32 {
        let id = self.subs.len() as u32;
        self.subs.push(SubInProgress::new(params, returns));
        id
    }

    /// Make `id` the active subprogram, returning the previously active
    /// id so the caller can restore it with [`Self::end_subprogram`].
    /// `id` must come from [`Self::reserve_subprogram`] (or be 0, the
    /// entry).
    pub fn begin_subprogram(&mut self, id: u32) -> u32 {
        let prev = self.active as u32;
        debug_assert!((id as usize) < self.subs.len());
        self.active = id as usize;
        prev
    }

    /// Restore the active subprogram to `prev` (the value returned by
    /// the matching [`Self::begin_subprogram`]).
    pub fn end_subprogram(&mut self, prev: u32) {
        debug_assert!((prev as usize) < self.subs.len());
        self.active = prev as usize;
    }

    /// The currently active subprogram id. Subprogram 0 is the entry;
    /// any other id is a reserved callee whose body is being built.
    pub fn active_subprogram(&self) -> u32 {
        self.active as u32
    }

    // ── Namespace allocation ──────────────────────────────────────────

    /// Allocate a fresh register in the active subprogram. Returns a
    /// monotonically increasing index; the subprogram's frame size
    /// grows automatically.
    pub fn alloc_reg(&mut self) -> Reg {
        let r = self.cur().next_reg;
        self.cur_mut().next_reg += 1;
        r
    }

    /// Current register count of the active subprogram — same as its
    /// `next_reg`. The lift uses this as a frame-size proxy when
    /// deciding whether to bail out of a partial unroll attempt.
    pub fn next_reg(&self) -> u32 {
        self.cur().next_reg
    }

    /// Snapshot the active subprogram's emission state so a speculative
    /// attempt (e.g. unrolling a loop) can be rolled back on failure
    /// without leaving partial instructions or register allocations
    /// behind. Restore via [`Self::restore`].
    pub fn snapshot(&self) -> BuilderSnapshot {
        let s = self.cur();
        BuilderSnapshot {
            active: self.active,
            body_len: s.body.len(),
            const_pool_len: self.const_pool.len(),
            next_reg: s.next_reg,
            next_signal: self.next_signal,
            next_slot: self.next_slot,
            label_positions_len: s.label_positions.len(),
            pending_jumps_len: s.pending_jumps.len(),
        }
    }

    /// Roll back to a previously-captured [`BuilderSnapshot`]. All
    /// instructions, constants, labels, and pending jumps emitted
    /// since the snapshot are discarded; id counters revert. The
    /// snapshot must have been taken with the same subprogram active.
    pub fn restore(&mut self, snapshot: BuilderSnapshot) {
        debug_assert_eq!(
            snapshot.active, self.active,
            "snapshot taken under a different active subprogram"
        );
        self.const_pool.truncate(snapshot.const_pool_len);
        self.next_signal = snapshot.next_signal;
        self.next_slot = snapshot.next_slot;
        let s = self.cur_mut();
        s.body.truncate(snapshot.body_len);
        s.next_reg = snapshot.next_reg;
        s.label_positions.truncate(snapshot.label_positions_len);
        s.pending_jumps.truncate(snapshot.pending_jumps_len);
    }

    /// Allocate a fresh input signal id. Signals are only meaningful in
    /// the entry subprogram (the validator rejects signal access
    /// elsewhere). The caller supplies these as the
    /// `signals: &[FieldElement<F>]` slice when invoking the executor.
    pub fn alloc_signal(&mut self) -> u32 {
        let s = self.next_signal;
        self.next_signal += 1;
        s
    }

    /// Allocate a fresh witness slot id. Witness slots are only
    /// meaningful in the entry subprogram. The caller provides a
    /// `witness_slots: &mut [FieldElement<F>]` slice of at least
    /// `slot + 1` elements when invoking the executor.
    pub fn alloc_witness_slot(&mut self) -> u32 {
        let s = self.next_slot;
        self.next_slot += 1;
        s
    }

    /// Intern a constant into the program-global pool and return its
    /// id. `bytes` is little-endian canonical encoding (up to the
    /// field family's max). Smaller values are zero-padded on decode.
    pub fn intern_const(&mut self, bytes: Vec<u8>) -> u32 {
        let id = self.const_pool.len() as u32;
        self.const_pool.push(FieldConstEntry { bytes });
        id
    }

    // ── Raw emission ──────────────────────────────────────────────────

    /// Append a raw instruction to the active subprogram. Prefer the
    /// typed helpers below for common patterns.
    pub fn emit(&mut self, instr: Instr) {
        self.cur_mut().body.push(instr);
    }
}
