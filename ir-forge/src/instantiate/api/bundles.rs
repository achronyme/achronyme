use std::collections::HashMap;

use lysis::InterningSink;
use memory::FieldBackend;

use ir_core::SsaVar;

/// Side-data carried alongside a populated [`InterningSink<F>`] when
/// the lifter splits the pipeline at the post-execute boundary. The
/// `IrProgram` reassembly path consumes this together with the
/// materialized instruction stream; the streaming path discards it.
///
/// The metadata maps (`var_names`, `var_types`, `var_spans`,
/// `input_spans`) are populated only on the reassembly path. The
/// streaming entry points ([`ProveIR::instantiate_lysis_sink`] and
/// [`ProveIR::instantiate_lysis_sink_with_outputs`]) leave them empty
/// — the streaming consumer drains the sink iterator into a
/// constraint backend that does not consume semantic metadata, so
/// keeping the maps alive across the executor run would waste peak
/// resident footprint on multi-million-variable circuits.
pub struct LysisSinkBundle<F: FieldBackend> {
    pub sink: InterningSink<F>,
    pub next_var: u64,
    pub var_names: HashMap<SsaVar, String>,
    pub var_types: HashMap<SsaVar, ir_core::IrType>,
    pub var_spans: HashMap<SsaVar, diagnostics::SpanRange>,
    pub input_spans: HashMap<String, diagnostics::SpanRange>,
}

/// Output of the chunk-draining entry point
/// ([`ProveIR::instantiate_lysis_drain_with_outputs`]). The emission
/// stream has already been delivered to the caller's consumer
/// closure; this bundle carries post-execute bookkeeping the caller
/// still needs after the chunks are gone — the `next_var` watermark
/// for any further SSA allocation, plus the underlying interning
/// sink whose dedup tier state (eternal Const table, sliding window,
/// node id counter) is preserved for diagnostics. The sink's
/// emission buffer is empty.
pub struct LysisDrainBundle<F: FieldBackend> {
    pub residual_sink: InterningSink<F>,
    pub next_var: u64,
}
