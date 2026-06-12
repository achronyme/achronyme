//! The [`InstrSink`] adapter and entry point for the direct interning
//! path. The per-instruction mirror lives in [`super::direct_core`];
//! this module owns the walk-facing surface: the sink that feeds
//! Plain instructions into the interner (and poisons itself on
//! symbolic emission), and the entry the lean `instantiate_lysis_*`
//! family calls before falling back to the extended-body cable.

use std::collections::{HashMap, HashSet};

use diagnostics::SpanRange;
use lysis::InterningSink;
use memory::{FieldBackend, FieldElement};

use ir_core::{Instruction, IrProgram, IrType, SsaVar};

use crate::extended::{IndexedEffectKind, ShiftDirection};
use crate::lysis_materialize::materialize_interning_sink;
use crate::lysis_roundtrip::RoundTripError;
use crate::types::ProveIR;

use super::super::InstrSink;
use super::direct_core::DirectInternState;
use super::errors::LysisInstantiateError;
use super::lowering::ssa_watermark;
use super::walk::run_walk;

/// [`InstrSink`] that feeds the instantiate walk straight into an
/// interner. Borrows entry-owned state (the `ExtendedSink` pattern)
/// so the entry function inspects poison/error after `run_walk`
/// consumed the box.
pub(super) struct InterningDirectSink<'a, F: FieldBackend> {
    state: &'a mut DirectInternState,
    interner: &'a mut InterningSink<F>,
    next_var: &'a mut u64,
    poisoned: &'a mut bool,
    /// Dense transient type table — same lean behavior as
    /// `ExtendedSink::new_lean`, so the ternary type-propagation in
    /// the emitters reads identical answers and the walk emits the
    /// identical instruction stream. Stays live after poisoning for
    /// the same reason.
    lean_types: Vec<Option<IrType>>,
}

impl<'a, F: FieldBackend> InterningDirectSink<'a, F> {
    pub(super) fn new(
        state: &'a mut DirectInternState,
        interner: &'a mut InterningSink<F>,
        next_var: &'a mut u64,
        poisoned: &'a mut bool,
    ) -> Self {
        Self {
            state,
            interner,
            next_var,
            poisoned,
            lean_types: Vec::new(),
        }
    }

    fn poison(&mut self) {
        *self.poisoned = true;
    }
}

impl<'a, F: FieldBackend> InstrSink<F> for InterningDirectSink<'a, F> {
    fn fresh_var(&mut self) -> SsaVar {
        let v = SsaVar(*self.next_var);
        *self.next_var += 1;
        v
    }

    fn push_inst(&mut self, inst: Instruction<F>, _span: Option<&SpanRange>) -> SsaVar {
        let var = inst.result_var();
        if !*self.poisoned {
            self.state.feed_plain(self.interner, inst);
        }
        var
    }

    fn set_name(&mut self, _var: SsaVar, _name: String) {}

    fn keeps_metadata(&self) -> bool {
        false
    }

    fn set_type(&mut self, var: SsaVar, ty: IrType) {
        let idx = var.0 as usize;
        if idx >= self.lean_types.len() {
            self.lean_types.resize(idx + 1, None);
        }
        self.lean_types[idx] = Some(ty);
    }

    fn get_type(&self, var: SsaVar) -> Option<IrType> {
        self.lean_types.get(var.0 as usize).copied().flatten()
    }

    fn set_input_span(&mut self, _name: String, _span: SpanRange) {}

    fn next_var(&self) -> u64 {
        *self.next_var
    }

    fn begin_symbolic_loop(&mut self) {
        self.poison();
    }

    fn finish_symbolic_loop(&mut self, _iter_var: SsaVar, _start: i64, _end: i64) {
        self.poison();
    }

    fn push_symbolic_indexed_effect(
        &mut self,
        _kind: IndexedEffectKind,
        _array_slots: Vec<SsaVar>,
        _index_var: SsaVar,
        _value_var: Option<SsaVar>,
        _span: Option<SpanRange>,
    ) {
        self.poison();
    }

    fn push_symbolic_array_read(
        &mut self,
        _result_var: SsaVar,
        _array_slots: Vec<SsaVar>,
        _index_var: SsaVar,
        _span: Option<SpanRange>,
    ) {
        self.poison();
    }

    fn push_symbolic_shift(
        &mut self,
        _result_var: SsaVar,
        _operand_var: SsaVar,
        _shift_var: SsaVar,
        _num_bits: u32,
        _direction: ShiftDirection,
        _span: Option<SpanRange>,
    ) {
        self.poison();
    }
}

/// Run the instantiate walk straight into an eager interner and
/// materialize once. Returns `Ok(None)` when the walk emitted a
/// symbolic node (rolled loop / dynamic shift / indexed effect) —
/// the caller falls back to the extended-body cable by re-running
/// the walk; the partial interner state is discarded.
pub(super) fn instantiate_direct_lean<F: FieldBackend>(
    prove_ir: &ProveIR,
    captures: &HashMap<String, FieldElement<F>>,
    output_names: Option<&HashSet<String>>,
) -> Result<Option<IrProgram<F>>, LysisInstantiateError> {
    let mut interner = InterningSink::<F>::without_span_tracking();
    let mut state = DirectInternState::new();
    let mut next_var = 0u64;
    let mut poisoned = false;
    {
        let sink =
            InterningDirectSink::new(&mut state, &mut interner, &mut next_var, &mut poisoned);
        run_walk::<F>(prove_ir, captures, Box::new(sink), output_names)?;
    }
    if poisoned {
        return Ok(None);
    }
    if let Some(err) = state.take_error() {
        return Err(LysisInstantiateError::from(RoundTripError::Walk(err)));
    }
    let instructions = materialize_interning_sink(interner);
    let final_next_var = ssa_watermark(&instructions).max(next_var);
    let mut out = IrProgram::<F>::new();
    out.set_instructions(instructions);
    out.set_next_var(final_next_var);
    Ok(Some(out))
}
