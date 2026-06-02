use memory::FieldBackend;

use super::super::{InstEnvValue, Instantiator};
use crate::error::ProveIrError;
use crate::extended::IndexedEffectKind;
use crate::types::*;
use ir_core::{Instruction, SsaVar, Visibility};

impl<'a, F: FieldBackend> Instantiator<'a, F> {
    /// Const-index `LetIndexed` handler. Mirrors the pre-Gap 1
    /// behaviour byte-for-byte: outputs go through AssertEq against
    /// the public wire; non-outputs lazily allocate the slot and
    /// shadow the env entry.
    pub(super) fn emit_let_indexed_const(
        &mut self,
        array: &str,
        idx: usize,
        value: &CircuitExpr,
    ) -> Result<(), ProveIrError> {
        let elem_name = format!("{array}_{idx}");

        if let Some(&pub_var) = self.output_pub_vars.get(&elem_name) {
            let v = self.emit_expr(value)?;
            let result = self.fresh_var();
            self.push_inst(Instruction::AssertEq {
                result,
                lhs: pub_var,
                rhs: v,
                message: None,
            });
        } else {
            let v = self.emit_expr(value)?;
            if self.keeps_metadata() {
                self.set_name(v, elem_name.clone());
            }
            self.env.insert(elem_name, InstEnvValue::Scalar(v));
            self.ensure_array_slot(array, idx, v);
        }
        Ok(())
    }

    /// Const-index `WitnessHintIndexed` handler.
    pub(super) fn emit_witness_hint_indexed_const(
        &mut self,
        array: &str,
        idx: usize,
    ) -> Result<(), ProveIrError> {
        let elem_name = format!("{array}_{idx}");
        if self.output_pub_vars.contains_key(&elem_name) {
            // env already has the public wire — nothing to do.
        } else {
            let v = self.fresh_var();
            if self.keeps_metadata() {
                self.set_name(v, elem_name.clone());
            }
            self.push_inst(Instruction::Input {
                result: v,
                name: elem_name.clone(),
                visibility: Visibility::Witness,
            });
            self.env.insert(elem_name, InstEnvValue::Scalar(v));
            self.ensure_array_slot(array, idx, v);
        }
        Ok(())
    }

    /// Symbolic-index `LetIndexed` — emits one
    /// [`ExtendedInstruction::SymbolicIndexedEffect`] carrying the
    /// resolved `array_slots` snapshot for the walker. Requires the
    /// surrounding `array` to be declared (so its slots are
    /// pre-allocated in env); errors if the array doesn't exist or
    /// is a scalar.
    pub(super) fn emit_let_indexed_symbolic(
        &mut self,
        array: &str,
        index_var: SsaVar,
        value: &CircuitExpr,
    ) -> Result<(), ProveIrError> {
        let array_slots = self.snapshot_array_slots(array)?;
        let value_var = self.emit_expr(value)?;
        let span = self.current_span.clone();
        self.sink.push_symbolic_indexed_effect(
            IndexedEffectKind::Let,
            array_slots,
            index_var,
            Some(value_var),
            span,
        );
        Ok(())
    }

    /// Symbolic-index `WitnessHintIndexed`. Same shape as
    /// [`emit_let_indexed_symbolic`] but with no value side.
    pub(super) fn emit_witness_hint_indexed_symbolic(
        &mut self,
        array: &str,
        index_var: SsaVar,
    ) -> Result<(), ProveIrError> {
        let array_slots = self.snapshot_array_slots(array)?;
        let span = self.current_span.clone();
        self.sink.push_symbolic_indexed_effect(
            IndexedEffectKind::WitnessHint,
            array_slots,
            index_var,
            None,
            span,
        );
        Ok(())
    }

    /// Snapshot the `Vec<SsaVar>` of slot wires for a declared array.
    /// Returns an error if `array` is missing or bound to a scalar.
    pub(in crate::instantiate) fn snapshot_array_slots(
        &self,
        array: &str,
    ) -> Result<Vec<SsaVar>, ProveIrError> {
        match self.env.get(array) {
            Some(InstEnvValue::Array(elems)) => Ok(elems.clone()),
            Some(InstEnvValue::Scalar(_)) => Err(ProveIrError::UnsupportedOperation {
                description: format!(
                    "symbolic indexed write into `{array}` but `{array}` is a scalar"
                ),
                span: None,
            }),
            None => Err(ProveIrError::UnsupportedOperation {
                description: format!(
                    "symbolic indexed write into `{array}` but the array is not declared in this scope"
                ),
                span: None,
            }),
        }
    }
}
