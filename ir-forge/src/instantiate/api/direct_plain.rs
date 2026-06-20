use lysis::{ChunkDrainingSink, InstructionKind};
use memory::FieldBackend;

use crate::extended::ExtendedInstruction;
use crate::lysis_roundtrip::RoundTripError;

use super::direct_core::DirectInternState;
use super::errors::LysisInstantiateError;

pub(super) fn direct_plain_drain_enabled() -> bool {
    std::env::var("ACH_LYSIS_DIRECT_PLAIN_DRAIN")
        .map(|v| v == "1" || v.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

/// Chunk-draining variant of the direct interning path. Drives
/// [`DirectInternState::feed_plain`] — the shared per-form mirror of
/// the Walker → bytecode → executor cable — over a
/// [`ChunkDrainingSink`], so an all-Plain body is interned without
/// building the walker's bytecode and executor state. Each filled
/// chunk is handed to `chunk_consumer` at seal time; the partial tail
/// drains at `finalize`. Sharing `feed_plain` is what keeps this path
/// byte-identical to the walker (and to the non-draining direct sink):
/// the desugarings (`Not`, `And`, `Or`, `IsNeq`, `IsLe`,
/// `IsLeBounded`, `Assert`) and u8 bit-width guards live in one place.
///
/// Returns the number of Plain instructions fed, or the first
/// [`WalkError`] surfaced through `feed_plain` (an undefined SSA
/// reference or an out-of-range bit width).
///
/// [`WalkError`]: crate::lysis_lift::WalkError
pub(super) fn drain_plain_extended_chunks_interned<F: FieldBackend>(
    body: Vec<ExtendedInstruction<F>>,
    window: usize,
    chunk_capacity: usize,
    chunk_consumer: &mut dyn FnMut(Vec<InstructionKind<F>>),
) -> Result<usize, LysisInstantiateError> {
    let mut sink = ChunkDrainingSink::<F>::with_streaming_window_chunked_capacity(
        window,
        chunk_capacity,
        chunk_consumer,
    );
    let mut state = DirectInternState::new();
    let mut total = 0usize;

    for ext in body {
        let ExtendedInstruction::Plain(inst) = ext else {
            unreachable!("non-plain body rejected before draining");
        };
        total += 1;
        state.feed_plain(&mut sink, inst);
    }

    // Surface a sticky walk error before draining the partial tail: on
    // the error path the chunks already handed to the consumer are
    // discarded by the caller along with the returned bundle.
    if let Some(err) = state.take_error() {
        return Err(LysisInstantiateError::from(RoundTripError::Walk(err)));
    }

    sink.finalize();
    Ok(total)
}
