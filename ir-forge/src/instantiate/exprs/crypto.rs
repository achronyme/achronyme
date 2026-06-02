use memory::{FieldBackend, FieldElement};

use super::super::{InstEnvValue, Instantiator};
use crate::error::ProveIrError;
use crate::types::CircuitExpr;
use ir_core::{Instruction, IrType, SsaVar};

impl<'a, F: FieldBackend> Instantiator<'a, F> {
    pub(super) fn emit_poseidon_pair(
        &mut self,
        left: &CircuitExpr,
        right: &CircuitExpr,
    ) -> Result<SsaVar, ProveIrError> {
        let l = self.emit_expr(left)?;
        let r = self.emit_expr(right)?;
        let v = self.fresh_var();
        self.push_inst(Instruction::PoseidonHash {
            result: v,
            left: l,
            right: r,
        });
        self.set_type(v, IrType::Field);
        Ok(v)
    }

    pub(super) fn emit_poseidon_many(
        &mut self,
        args: &[CircuitExpr],
    ) -> Result<SsaVar, ProveIrError> {
        if args.is_empty() {
            return Err(ProveIrError::UnsupportedOperation {
                description: "poseidon_many requires at least 2 arguments".into(),
                span: None,
            });
        }

        let compiled: Vec<SsaVar> = args
            .iter()
            .map(|a| self.emit_expr(a))
            .collect::<Result<_, _>>()?;

        if compiled.len() == 1 {
            // Match IrLowering semantics: single arg → poseidon(arg, ZERO)
            let zero = self.emit_const(FieldElement::<F>::zero());
            let v = self.fresh_var();
            self.push_inst(Instruction::PoseidonHash {
                result: v,
                left: compiled[0],
                right: zero,
            });
            return Ok(v);
        }

        // Left-fold: poseidon(poseidon(a0, a1), a2), ...
        let mut iter = compiled.into_iter();
        let mut acc = iter.next().expect("checked non-empty above");
        for next in iter {
            let v = self.fresh_var();
            self.push_inst(Instruction::PoseidonHash {
                result: v,
                left: acc,
                right: next,
            });
            acc = v;
        }
        Ok(acc)
    }

    pub(super) fn emit_range_check(
        &mut self,
        value: &CircuitExpr,
        bits: u32,
    ) -> Result<SsaVar, ProveIrError> {
        let operand = self.emit_expr(value)?;
        let v = self.fresh_var();
        self.push_inst(Instruction::RangeCheck {
            result: v,
            operand,
            bits,
        });
        Ok(v)
    }

    pub(super) fn emit_merkle_verify(
        &mut self,
        root: &CircuitExpr,
        leaf: &CircuitExpr,
        path: &str,
        indices: &str,
    ) -> Result<SsaVar, ProveIrError> {
        // Merkle verification: hash leaf up the tree using path and indices.
        // path and indices are arrays in env.
        let root_var = self.emit_expr(root)?;
        let leaf_var = self.emit_expr(leaf)?;

        let path_elems = match self.env.get(path) {
            Some(InstEnvValue::Array(elems)) => elems.clone(),
            _ => {
                return Err(ProveIrError::UnsupportedOperation {
                    description: format!("merkle_verify path `{path}` is not an array"),
                    span: None,
                });
            }
        };
        let idx_elems = match self.env.get(indices) {
            Some(InstEnvValue::Array(elems)) => elems.clone(),
            _ => {
                return Err(ProveIrError::UnsupportedOperation {
                    description: format!("merkle_verify indices `{indices}` is not an array"),
                    span: None,
                });
            }
        };

        if path_elems.len() != idx_elems.len() {
            return Err(ProveIrError::ArrayLengthMismatch {
                expected: path_elems.len(),
                got: idx_elems.len(),
                span: None,
            });
        }

        // Walk up the tree: conditional swap + single hash per level.
        // idx=0 → current is left child:  poseidon(current, sibling)
        // idx=1 → current is right child: poseidon(sibling, current)
        // Cost: 2 Mux + 1 Poseidon (365) instead of 2 Poseidon + 1 Mux (724).
        let mut current = leaf_var;
        for (sibling, idx) in path_elems.iter().zip(idx_elems.iter()) {
            let left = self.fresh_var();
            self.push_inst(Instruction::Mux {
                result: left,
                cond: *idx,
                if_true: *sibling,
                if_false: current,
            });
            let right = self.fresh_var();
            self.push_inst(Instruction::Mux {
                result: right,
                cond: *idx,
                if_true: current,
                if_false: *sibling,
            });
            let v = self.fresh_var();
            self.push_inst(Instruction::PoseidonHash {
                result: v,
                left,
                right,
            });
            current = v;
        }

        // Assert computed root == expected root
        let v = self.fresh_var();
        self.push_inst(Instruction::AssertEq {
            result: v,
            lhs: current,
            rhs: root_var,
            message: None,
        });
        Ok(v)
    }
}
