use memory::{FieldBackend, FieldElement};

use super::super::{InstEnvValue, Instantiator};
use crate::error::ProveIrError;
use crate::types::CircuitExpr;
use ir_core::SsaVar;

impl<'a, F: FieldBackend> Instantiator<'a, F> {
    pub(super) fn emit_array_index(
        &mut self,
        array: &str,
        index: &CircuitExpr,
    ) -> Result<SsaVar, ProveIrError> {
        // Fast path 1: index is a pure compile-time constant.
        // `eval_const_expr` is side-effect-free, so trying it first costs
        // nothing and avoids polluting the IR stream with an emission we'd
        // then discard.
        if let Some(idx) = self.eval_const_expr(index).ok().and_then(|fe| {
            let limbs = fe.to_canonical();
            if limbs[1] == 0 && limbs[2] == 0 && limbs[3] == 0 {
                usize::try_from(limbs[0]).ok()
            } else {
                None
            }
        }) {
            return self.resolve_array_at(array, idx);
        }

        // Fast path 2: emit the index expression, then check whether the
        // emitted SsaVar reduces to a literal via `extract_const_index`
        // (handles linearised forms like `i*2+j` after loop unroll).
        // Match the original surface error if `emit_expr` itself errors so
        // callers see a consistent "must be compile-time constant" hit.
        let idx_var = match self.emit_expr(index) {
            Ok(v) => v,
            Err(_) => {
                return Err(ProveIrError::UnsupportedOperation {
                    description: format!(
                        "array index into `{array}` must be a compile-time constant"
                    ),
                    span: None,
                });
            }
        };

        if let Some(idx) = self.extract_const_index(idx_var) {
            return self.resolve_array_at(array, idx);
        }

        // Truly symbolic index: emit a SymbolicArrayRead that the walker
        // resolves per-iteration to `array_slots[idx]`.
        self.emit_array_index_symbolic(array, idx_var)
    }

    pub(super) fn emit_array_len(&mut self, name: &str) -> Result<SsaVar, ProveIrError> {
        let len = match self.env.get(name) {
            Some(InstEnvValue::Array(elems)) => elems.len(),
            _ => {
                return Err(ProveIrError::UnsupportedOperation {
                    description: format!("`{name}` is not an array"),
                    span: None,
                });
            }
        };
        Ok(self.emit_const(FieldElement::<F>::from_u64(len as u64)))
    }

    /// Resolve `array[idx]` with bounds + array-shape checking. Both
    /// const-fold paths in [`Self::emit_expr`]'s `ArrayIndex` arm route
    /// through this so the env lookup, type assertion, and bounds error stay
    /// byte-identical.
    fn resolve_array_at(&self, array: &str, idx: usize) -> Result<SsaVar, ProveIrError> {
        match self.env.get(array) {
            Some(InstEnvValue::Array(elems)) => {
                if idx >= elems.len() {
                    return Err(ProveIrError::IndexOutOfBounds {
                        name: array.to_string(),
                        index: idx,
                        length: elems.len(),
                        span: None,
                    });
                }
                Ok(elems[idx])
            }
            _ => Err(ProveIrError::UnsupportedOperation {
                description: format!("`{array}` is not an array"),
                span: None,
            }),
        }
    }

    /// Symbolic-index `ArrayIndex` — emits one
    /// [`crate::ExtendedInstruction::SymbolicArrayRead`] carrying the
    /// resolved `array_slots` snapshot for the walker. Mints a fresh
    /// `result_var` to hand back to the caller; the walker rebinds it to
    /// `array_slots[idx]`'s register per iteration. Mirror of
    /// `emit_let_indexed_symbolic` on the write side.
    fn emit_array_index_symbolic(
        &mut self,
        array: &str,
        index_var: SsaVar,
    ) -> Result<SsaVar, ProveIrError> {
        let array_slots = self.snapshot_array_slots(array)?;
        let result_var = self.fresh_var();
        let span = self.current_span.clone();
        self.sink
            .push_symbolic_array_read(result_var, array_slots, index_var, span);
        Ok(result_var)
    }
}
