//! Frame-register allocation for a single template body (RFC §6.2).
//!
//! Lysis templates live in a fixed-size register file — the
//! `frame_size` field of a `DefineTemplate` opcode is a `u8`, so at
//! most 255 slots exist per instantiation. The lifter emits
//! instructions that reference those slots by [`RegId`]; this module
//! hands out fresh slot ids as the walker descends through the body.
//!
//! ## Strategy
//!
//! The current implementation is a **bump allocator** — every
//! [`RegAllocator::alloc`] returns the next monotonically-increasing
//! id and bumps the high water mark. Registers are never reused
//! within a body.
//!
//! This is conservative: the true minimum frame size (maximum
//! simultaneous live registers) is always ≤ the bump count. The
//! downside is slightly larger frame_size values than a liveness-
//! aware allocator would produce. A future linear-scan pass can
//! tighten the result; the `release` hook is here so the switch-over
//! is API-compatible.
//!
//! ## Dep-direction note
//!
//! This module stays `ir`-free on purpose: `lysis` is the leaf crate,
//! and the lift bridge runs in the `ir → lysis` direction. The
//! companion `compute_frame_size` that walks an
//! `ir::ExtendedInstruction` body lives under
//! `ir/src/prove_ir/lysis_lower/` with the rest of the lifter.

use crate::lower::env::RegId;

/// Maximum number of slots a single Lysis frame can declare.
///
/// `Template.frame_size` is a `u8` field, so the largest encodable
/// count is 255 — a template with `frame_size = 255` addresses
/// registers `r0..=r254`. Register id 255 is never usable inside a
/// template body because no frame can be that large; the allocator
/// rejects requests for it.
pub const MAX_FRAME_SIZE: u32 = 255;

/// Errors raised by [`RegAllocator`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllocError {
    /// The allocator was asked to produce a register past the last
    /// addressable slot. `requested` is the 0-based slot id that
    /// would have exceeded the limit, so callers can report "body
    /// needs {requested + 1} registers, max {MAX_FRAME_SIZE}".
    FrameOverflow { requested: u32 },
}

impl std::fmt::Display for AllocError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FrameOverflow { requested } => write!(
                f,
                "frame overflow: register slot {requested} exceeds max frame size {MAX_FRAME_SIZE}"
            ),
        }
    }
}

impl std::error::Error for AllocError {}

/// Hands out fresh register ids within a single frame.
///
/// One allocator per template body. When the walker finishes emitting
/// the body, [`RegAllocator::frame_size`] reports the final size to
/// stamp on `DefineTemplate`. The struct does NOT cross frame
/// boundaries — each `TemplateBody` gets a new allocator.
#[derive(Debug, Clone, Default)]
pub struct RegAllocator {
    /// Next slot to hand out (monotonic under bump allocation).
    next: u32,
    /// High water mark — the largest `next` value ever reached. Equal
    /// to `next` under pure bump allocation; kept separate so a
    /// future liveness-aware reuse pass doesn't lose the peak.
    max_used: u32,
}

impl RegAllocator {
    /// Start with the frame empty. The first `alloc` hands out `r0`.
    pub fn new() -> Self {
        Self::default()
    }

    /// Start with the first `n` slots already reserved — the
    /// convention used for captures: `LoadCapture r0, 0`, ...,
    /// `LoadCapture r{n-1}, {n-1}`. Subsequent `alloc` calls hand
    /// out `r{n}` and up.
    pub fn new_after_captures(n: u8) -> Self {
        Self {
            next: u32::from(n),
            max_used: u32::from(n),
        }
    }

    /// Hand out a fresh register. Fails when the body would exceed
    /// the frame limit.
    pub fn alloc(&mut self) -> Result<RegId, AllocError> {
        if self.next >= MAX_FRAME_SIZE {
            return Err(AllocError::FrameOverflow {
                requested: self.next,
            });
        }
        let reg = self.next as RegId;
        self.next += 1;
        if self.next > self.max_used {
            self.max_used = self.next;
        }
        Ok(reg)
    }

    /// Allocate `n` contiguous registers and return them in order.
    /// Convenience for patterns like `Decompose` where the lifter
    /// needs a run of bit-result slots.
    pub fn alloc_many(&mut self, n: usize) -> Result<Vec<RegId>, AllocError> {
        let mut out = Vec::with_capacity(n);
        for _ in 0..n {
            out.push(self.alloc()?);
        }
        Ok(out)
    }

    /// Release a register so a future `alloc` can reuse it.
    ///
    /// **Currently a no-op.** The hook exists so a future
    /// liveness-aware allocator can slot in without rewriting call
    /// sites. Today the allocator grows monotonically; release makes
    /// no observable change.
    pub fn release(&mut self, _reg: RegId) {
        // Intentionally empty — see module docs.
    }

    /// Drop all state and restart at `r0`. Used when the same
    /// allocator instance is reused across template bodies.
    pub fn reset(&mut self) {
        self.next = 0;
        self.max_used = 0;
    }

    /// Number of slots needed by the frame — the value to stamp on
    /// `DefineTemplate.frame_size`. The `alloc` guard prevents
    /// `max_used` from exceeding [`MAX_FRAME_SIZE`] so the `u8`
    /// cast is lossless.
    pub fn frame_size(&self) -> u8 {
        debug_assert!(self.max_used <= MAX_FRAME_SIZE);
        self.max_used as u8
    }

    /// Count of live bumps without regard to reuse.
    pub fn next_slot(&self) -> u32 {
        self.next
    }

    /// Snapshot the current bump counter so a later
    /// [`Self::restore_to`] can rewind back to this point. The
    /// high-water mark (`max_used`) is *not* part of the snapshot —
    /// it keeps tracking the peak across rewinds, so the final
    /// [`Self::frame_size`] reports the true maximum the body ever
    /// needed even if intermediate scopes restored.
    ///
    /// Used by the walker's per-iteration unrolling: each iteration
    /// restores to the pre-body checkpoint, re-emits with fresh
    /// bindings, and lets the same body-internal slots be reused
    /// across iterations rather than ballooning the frame past the
    /// 255-slot cap.
    pub fn checkpoint(&self) -> u32 {
        self.next
    }

    /// Restore the bump counter to a [`Self::checkpoint`] result.
    /// Callers must ensure no live binding still references a slot
    /// being rolled back — restoring is conceptually equivalent to a
    /// bulk [`Self::release`] on every reg above `checkpoint`.
    pub fn restore_to(&mut self, checkpoint: u32) {
        debug_assert!(
            checkpoint <= self.next,
            "restore_to: checkpoint {checkpoint} ahead of next {}",
            self.next
        );
        self.next = checkpoint;
        // Intentionally leave max_used alone — see method docs.
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_allocator_hands_out_r0_first() {
        let mut a = RegAllocator::new();
        assert_eq!(a.alloc().unwrap(), 0);
        assert_eq!(a.alloc().unwrap(), 1);
        assert_eq!(a.frame_size(), 2);
    }

    #[test]
    fn new_after_captures_skips_reserved() {
        let mut a = RegAllocator::new_after_captures(3);
        assert_eq!(a.alloc().unwrap(), 3);
        assert_eq!(a.alloc().unwrap(), 4);
        assert_eq!(a.frame_size(), 5);
    }

    #[test]
    fn new_after_captures_zero_matches_new() {
        let a0 = RegAllocator::new_after_captures(0);
        let a1 = RegAllocator::new();
        assert_eq!(a0.frame_size(), a1.frame_size());
        assert_eq!(a0.next_slot(), a1.next_slot());
    }

    #[test]
    fn alloc_many_returns_contiguous_run() {
        let mut a = RegAllocator::new();
        let run = a.alloc_many(4).unwrap();
        assert_eq!(run, vec![0, 1, 2, 3]);
        assert_eq!(a.frame_size(), 4);
    }

    #[test]
    fn alloc_past_limit_errors() {
        let mut a = RegAllocator::new_after_captures(254);
        assert_eq!(a.alloc().unwrap(), 254);
        // next slot would be 255 — one past the last addressable.
        assert_eq!(
            a.alloc().unwrap_err(),
            AllocError::FrameOverflow { requested: 255 }
        );
    }

    #[test]
    fn alloc_many_partial_failure_reports_overflow() {
        let mut a = RegAllocator::new_after_captures(253);
        // 253, 254 succeed; the third push would be r255 → overflow.
        let err = a.alloc_many(3).unwrap_err();
        assert!(matches!(err, AllocError::FrameOverflow { .. }));
    }

    #[test]
    fn release_is_a_noop_under_bump_alloc() {
        let mut a = RegAllocator::new();
        let r = a.alloc().unwrap();
        a.release(r);
        // Still bumping monotonically.
        assert_eq!(a.alloc().unwrap(), 1);
        assert_eq!(a.frame_size(), 2);
    }

    #[test]
    fn reset_starts_over_at_r0() {
        let mut a = RegAllocator::new();
        a.alloc_many(10).unwrap();
        a.reset();
        assert_eq!(a.alloc().unwrap(), 0);
        assert_eq!(a.frame_size(), 1);
    }

    #[test]
    fn checkpoint_and_restore_keep_max_used() {
        let mut a = RegAllocator::new();
        let _ = a.alloc().unwrap(); // r0
        let _ = a.alloc().unwrap(); // r1
        let ckpt = a.checkpoint();
        let _ = a.alloc().unwrap(); // r2
        let _ = a.alloc().unwrap(); // r3
        assert_eq!(a.next_slot(), 4);
        assert_eq!(a.frame_size(), 4);

        // Restore — bump counter goes back, max_used stays at peak.
        a.restore_to(ckpt);
        assert_eq!(a.next_slot(), 2);
        assert_eq!(a.frame_size(), 4, "max_used preserved across restore");

        // Subsequent allocation reuses the rolled-back slots.
        assert_eq!(a.alloc().unwrap(), 2);
        assert_eq!(a.frame_size(), 4);
    }

    #[test]
    fn frame_size_max_is_255() {
        // Bump from an empty allocator until overflow fires, then
        // check the frame size reported.
        let mut a = RegAllocator::new();
        let mut handed_out = 0u32;
        for _ in 0..1000 {
            match a.alloc() {
                Ok(_) => handed_out += 1,
                Err(_) => break,
            }
        }
        assert_eq!(handed_out, MAX_FRAME_SIZE);
        assert_eq!(a.frame_size(), MAX_FRAME_SIZE as u8);
    }
}
