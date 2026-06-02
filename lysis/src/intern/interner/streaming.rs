use super::*;

impl<F: FieldBackend> NodeInterner<F> {
    /// Empty interner in **streaming mode**: the `nodes` IndexMap is
    /// capped at `window_size` entries with FIFO eviction by insertion
    /// order. Materialized output is built incrementally as fresh
    /// pure inserts + effects flow through. The `timeline` channel is
    /// not used. Const dedup is preserved across eviction by the
    /// eternal Const-value table; `Mul(Const, Const)` dedup likewise
    /// via the eternal value-pair table. Other long-range dedup hits
    /// past the window are forfeited — the materialized Vec is
    /// **functionally equivalent** (same post-O1 constraint count)
    /// but not byte-identical to the eager path.
    ///
    /// Spans are not populated; the trusted-replay opt-out is implicit.
    /// `window_size` of 0 is treated as "minimum useful window of 1"
    /// to avoid degenerate eviction-on-insert.
    pub fn with_streaming_window(window_size: usize) -> Self {
        let window_size = window_size.max(1);
        Self {
            record_spans: false,
            window_size: Some(window_size),
            ..Self::new()
        }
    }

    /// Streaming mode with chunked output storage. Same dedup contract
    /// as [`Self::with_streaming_window`] (Tier 1/2 eternal tables, Tier
    /// 3 windowed `nodes`, FIFO eviction). Differs only in the layout of
    /// the materialized emission buffer: instead of a single doubling
    /// Vec, each fresh push lands in the current chunk; when that chunk
    /// fills its capacity the interner allocates a fresh one. Worst-case
    /// single allocation is one chunk, eliminating multi-gigabyte Vec
    /// realloc transients on circuits with very high instruction counts.
    ///
    /// The materialized stream remains observable as a single
    /// `Vec<InstructionKind<F>>` via [`Self::materialize`] (which
    /// flattens chunks at the boundary), or via
    /// [`Self::into_chunked_iter`] which drains chunks lazily without
    /// the boundary Vec.
    pub fn with_streaming_window_chunked(window_size: usize) -> Self {
        Self::with_streaming_window_chunked_capacity(window_size, STREAMING_CHUNK_CAPACITY)
    }

    /// Chunked-streaming constructor with the per-chunk capacity
    /// overridable. The production path uses
    /// [`STREAMING_CHUNK_CAPACITY`] (~72 MB per chunk on `Bn254Fr`);
    /// tests dial it down to exercise the chunk-seal pop/allocate
    /// boundary without emitting a million instructions.
    pub fn with_streaming_window_chunked_capacity(
        window_size: usize,
        chunk_capacity: usize,
    ) -> Self {
        let window_size = window_size.max(1);
        let chunk_capacity = chunk_capacity.max(1);
        let mut me = Self::with_streaming_window(window_size);
        me.chunked = true;
        me.chunk_capacity = chunk_capacity;
        me.streaming_chunks.push(Vec::with_capacity(chunk_capacity));
        me
    }

    /// Push a freshly-emitted `InstructionKind<F>` into the streaming
    /// output. Chooses between the eager `Vec` and the chunked layout
    /// based on `self.chunked`. Caller has already verified
    /// `window_size.is_some()`.
    #[inline]
    pub(crate) fn push_streaming(&mut self, inst: InstructionKind<F>) {
        if self.chunked {
            // Allocate a fresh chunk if the current one is full or the
            // chunk vector is empty (defensive — the constructor seeds
            // the first chunk, but `Self::new()`-then-`chunked=true`
            // patches would not).
            if self
                .streaming_chunks
                .last()
                .map(|c| c.len() == c.capacity())
                .unwrap_or(true)
            {
                self.streaming_chunks
                    .push(Vec::with_capacity(self.chunk_capacity));
            }
            self.streaming_chunks
                .last_mut()
                .expect("last chunk seeded above")
                .push(inst);
        } else {
            self.streaming_output.push(inst);
        }
    }

    /// Pop and return every chunk that has filled to capacity. The
    /// currently-filling tail chunk (the last one in
    /// [`Self::streaming_chunks`]) stays behind so subsequent
    /// [`Self::push_streaming`] calls have somewhere to land. Caller
    /// drains each returned chunk and drops it, releasing its backing
    /// region to the OS.
    ///
    /// Returns an empty Vec when chunked streaming is not active, when
    /// no chunks exist yet, or when only the partially-filled tail
    /// chunk is present. Safe to call after every emission — the
    /// no-sealed-chunks fast path costs one len comparison.
    pub fn take_sealed_chunks(&mut self) -> Vec<Vec<InstructionKind<F>>> {
        if !self.chunked || self.streaming_chunks.len() <= 1 {
            return Vec::new();
        }
        let tail = self.streaming_chunks.pop().expect("len > 1 just verified");
        let sealed = std::mem::take(&mut self.streaming_chunks);
        self.streaming_chunks.push(tail);
        sealed
    }

    /// Drain every remaining chunk — sealed AND partial — leaving
    /// [`Self::streaming_chunks`] empty. Called once at end of
    /// execution to capture the final partial chunk before the
    /// interner is discarded.
    ///
    /// Returns an empty Vec when chunked streaming is not active.
    pub fn drain_all_chunks(&mut self) -> Vec<Vec<InstructionKind<F>>> {
        if !self.chunked {
            return Vec::new();
        }
        std::mem::take(&mut self.streaming_chunks)
    }
}
