//! `ChunkDrainingSink<'a, F>` — an [`IrSink`] that wraps an
//! [`InterningSink`] in chunked-streaming mode and hands each sealed
//! chunk to a caller-supplied closure the moment it fills, instead of
//! letting chunks accumulate in the underlying interner.
//!
//! Why: under chunked streaming the interner keeps each filled chunk
//! alive in `streaming_chunks` until something else drains it. On
//! circuits whose emission stream is large enough that all sealed
//! chunks coexist with the still-emitting executor, the chunk Vec is
//! the dominant accumulator. Draining at chunk-seal time keeps the
//! resident chunk count at one (the currently-filling tail), so peak
//! resident footprint becomes
//! `interner dedup state + 1 chunk + downstream consumer state`
//! instead of `interner dedup state + all-emitted chunks`.
//!
//! Single-threaded, synchronous. The wrapper exists at the
//! `IrSink` boundary so the executor itself does not need to know
//! anything about the drain — it still calls `intern_pure` /
//! `emit_effect` / `fresh_id` normally.
//!
//! Error propagation: the consumer closure is infallible. Callers
//! that need to abort on a consumer error track the error in a
//! side-channel they own (e.g. a `Cell<Option<E>>` captured by the
//! closure) and check it after [`Self::finalize`] returns. The
//! executor keeps running through any error the consumer would have
//! raised — for the boss-fight context this is acceptable because the
//! consumer is `R1CSCompiler::compile_instructions` and a mid-stream
//! failure is a logic bug worth surfacing at the end of the run, not
//! a recoverable condition that should short-circuit emission.

use memory::FieldBackend;

use crate::execute::{InterningSink, IrSink};
use crate::intern::{InstructionKind, NodeId};

/// `IrSink` wrapper that drains the underlying chunked
/// [`InterningSink`]'s sealed chunks through a caller-supplied
/// closure at chunk-seal time.
pub struct ChunkDrainingSink<'a, F: FieldBackend> {
    inner: InterningSink<F>,
    consumer: &'a mut dyn FnMut(Vec<InstructionKind<F>>),
}

impl<'a, F: FieldBackend> ChunkDrainingSink<'a, F> {
    /// Build a chunk-draining sink backed by an
    /// [`InterningSink::with_streaming_window_chunked`] interner. The
    /// `consumer` closure is invoked once per sealed chunk, in
    /// emission order, as soon as the chunk fills its capacity.
    pub fn with_streaming_window_chunked(
        window_size: usize,
        consumer: &'a mut dyn FnMut(Vec<InstructionKind<F>>),
    ) -> Self {
        Self {
            inner: InterningSink::with_streaming_window_chunked(window_size),
            consumer,
        }
    }

    /// Borrow the underlying interning sink — diagnostics only.
    pub fn inner(&self) -> &InterningSink<F> {
        &self.inner
    }

    fn drain_sealed(&mut self) {
        // Fast path: most emissions don't seal a chunk. The check is
        // a single `streaming_chunks.len() <= 1` comparison inside
        // `take_sealed_chunks`.
        for chunk in self.inner.take_sealed_chunks() {
            (self.consumer)(chunk);
        }
    }

    /// Drain every remaining chunk — sealed AND the trailing partial
    /// chunk — through the consumer, then return the (now-empty
    /// emission-buffer) underlying interning sink for any post-execute
    /// inspection of dedup state.
    pub fn finalize(mut self) -> InterningSink<F> {
        for chunk in self.inner.drain_all_chunks() {
            (self.consumer)(chunk);
        }
        self.inner
    }
}

impl<'a, F: FieldBackend> IrSink<F> for ChunkDrainingSink<'a, F> {
    fn fresh_id(&mut self) -> NodeId {
        self.inner.fresh_id()
    }

    fn emit(&mut self, kind: InstructionKind<F>) {
        self.inner.emit(kind);
        self.drain_sealed();
    }

    fn intern_pure(&mut self, kind: InstructionKind<F>) -> NodeId {
        let id = self.inner.intern_pure(kind);
        self.drain_sealed();
        id
    }

    fn emit_effect(&mut self, kind: InstructionKind<F>) {
        self.inner.emit_effect(kind);
        self.drain_sealed();
    }

    fn count(&self) -> usize {
        self.inner.count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use memory::{Bn254Fr, FieldElement};

    use std::cell::RefCell;

    use crate::intern::Visibility;

    type F = Bn254Fr;

    fn fe(n: u64) -> FieldElement<F> {
        FieldElement::from_canonical([n, 0, 0, 0])
    }

    #[test]
    fn small_emission_stays_in_partial_chunk_until_finalize() {
        // Fewer items than one chunk's capacity — consumer must not
        // see anything until finalize drains the partial tail.
        let received: RefCell<Vec<Vec<InstructionKind<F>>>> = RefCell::new(Vec::new());
        let mut consumer = |chunk: Vec<InstructionKind<F>>| {
            received.borrow_mut().push(chunk);
        };
        let mut sink = ChunkDrainingSink::<F>::with_streaming_window_chunked(8, &mut consumer);
        let v = sink.intern_pure(InstructionKind::Const {
            result: NodeId::from_zero_based(0),
            value: fe(1),
        });
        assert!(received.borrow().is_empty(), "no seal yet");
        let _ = sink.intern_pure(InstructionKind::Add {
            result: NodeId::from_zero_based(0),
            lhs: v,
            rhs: v,
        });
        assert!(received.borrow().is_empty(), "still no seal");
        sink.finalize();
        let r = received.borrow();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].len(), 2);
    }

    #[test]
    fn finalize_drains_partial_tail_chunk() {
        let received: RefCell<Vec<Vec<InstructionKind<F>>>> = RefCell::new(Vec::new());
        let mut consumer = |chunk: Vec<InstructionKind<F>>| {
            received.borrow_mut().push(chunk);
        };
        let mut sink = ChunkDrainingSink::<F>::with_streaming_window_chunked(1, &mut consumer);
        let v = sink.fresh_id();
        sink.emit_effect(InstructionKind::Input {
            result: v,
            name: "x".into(),
            visibility: Visibility::Public,
        });
        sink.finalize();
        let r = received.borrow();
        assert_eq!(r.len(), 1);
        assert_eq!(r[0].len(), 1);
    }

    #[test]
    fn finalize_returns_drained_inner_sink() {
        let received: RefCell<Vec<Vec<InstructionKind<F>>>> = RefCell::new(Vec::new());
        let mut consumer = |chunk: Vec<InstructionKind<F>>| {
            received.borrow_mut().push(chunk);
        };
        let mut sink = ChunkDrainingSink::<F>::with_streaming_window_chunked(8, &mut consumer);
        let v = sink.intern_pure(InstructionKind::Const {
            result: NodeId::from_zero_based(0),
            value: fe(1),
        });
        let _ = v;
        let inner = sink.finalize();
        let r = received.borrow();
        assert_eq!(r.len(), 1);
        // Pure dedup state survives the chunk drain.
        assert_eq!(inner.pure_len(), 1);
    }
}
