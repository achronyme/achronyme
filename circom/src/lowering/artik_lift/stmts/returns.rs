use artik::ElemT;

use crate::ast::Expr;

use super::super::{ArrayShape, LiftState, ReturnShape};

impl<'f> LiftState<'f> {
    pub(super) fn lift_return(&mut self, value: &Expr) -> Option<()> {
        // A callee subprogram returns by value: one `Return`
        // instruction carrying a single register. The entry
        // subprogram (active id 0) keeps the witness-slot ABI
        // below.
        if self.builder.active_subprogram() != 0 {
            return self.emit_callee_return(value);
        }
        // Array-return for the entry function: expose each
        // element as its own witness slot so the caller can
        // re-bundle them into a `CircuitNode::LetArray`. 2D
        // arrays return their flattened row-major layout
        // (`rows * cols` slots).
        if let Expr::Ident { name, .. } = value {
            if let Some(&shape) = self.arrays.get(name) {
                let len = shape.total_len();
                let arr_reg = shape.handle();
                let slots = match self.output_array_slots.as_ref() {
                    Some(s) if s.len() == len as usize => s.clone(),
                    Some(_) => return None,
                    None => {
                        let s: Vec<u32> = (0..len)
                            .map(|_| self.builder.alloc_witness_slot())
                            .collect();
                        self.output_array_slots = Some(s.clone());
                        s
                    }
                };
                for (i, slot) in slots.iter().copied().enumerate() {
                    let idx_reg = self.push_int_const(i as u64)?;
                    let val_reg = self.builder.load_arr(arr_reg, idx_reg);
                    self.builder.write_witness(slot, val_reg);
                }
                self.builder.ret();
                self.halted = true;
                self.return_shape = ReturnShape::Array(len);
                return Some(());
            }
        }

        // Row-slice return: `return arr2d[row_idx];` where the
        // local is a Flat2D and the row index const-folds.
        // Materialize the row as a fresh Flat1D and fall
        // through to the 1D array-return path (per-cell witness
        // slots or `NestedResult::Array`). Shape lookup happens
        // on the syntactic base name; a chained `arr2d[r][c]`
        // would shape-match the inner index and fall through to
        // the scalar path further down, which is the correct
        // behaviour for a fully-indexed read.
        if let Expr::Index { object, index, .. } = value {
            if let Expr::Ident { name, .. } = object.as_ref() {
                if let Some(ArrayShape::Flat2D {
                    handle: src_handle,
                    rows,
                    cols,
                }) = self.arrays.get(name).copied()
                {
                    let row_shape = self.materialize_row_slice(src_handle, rows, cols, index)?;
                    let (dst_handle, len) = match row_shape {
                        ArrayShape::Flat1D { handle, len } => (handle, len),
                        ArrayShape::Flat2D { .. } => return None,
                    };
                    let slots = match self.output_array_slots.as_ref() {
                        Some(s) if s.len() == len as usize => s.clone(),
                        Some(_) => return None,
                        None => {
                            let s: Vec<u32> = (0..len)
                                .map(|_| self.builder.alloc_witness_slot())
                                .collect();
                            self.output_array_slots = Some(s.clone());
                            s
                        }
                    };
                    for (i, slot) in slots.iter().copied().enumerate() {
                        let idx_reg = self.push_int_const(i as u64)?;
                        let val_reg = self.builder.load_arr(dst_handle, idx_reg);
                        self.builder.write_witness(slot, val_reg);
                    }
                    self.builder.ret();
                    self.halted = true;
                    self.return_shape = ReturnShape::Array(len);
                    return Some(());
                }
            }
        }

        // Array-literal return: `return [e0, e1, ..., eN];`.
        // Allocate a fresh 1D field array, lift each element
        // into a register, store at index `i`. From there the
        // path is identical to a named-array return — outer
        // functions emit per-cell witness slots. Nested calls
        // take a shorter route: the destination is the
        // pre-allocated `nested_array_return_slot` so every
        // return in the body writes into the same heap array
        // and jumps to the shared end-label, leaving the
        // caller observing whichever return actually fired
        // at runtime.
        if let Expr::ArrayLit { elements, .. } = value {
            let len_usize = elements.len();
            let len = u32::try_from(len_usize).ok()?;
            let handle = self.builder.alloc_array(len, ElemT::Field);
            for (i, elem) in elements.iter().enumerate() {
                let val_reg = self.lift_expr(elem)?;
                let idx_reg = self.push_int_const(i as u64)?;
                self.builder.store_arr(handle, idx_reg, val_reg);
            }
            let slots = match self.output_array_slots.as_ref() {
                Some(s) if s.len() == len as usize => s.clone(),
                Some(_) => return None,
                None => {
                    let s: Vec<u32> = (0..len)
                        .map(|_| self.builder.alloc_witness_slot())
                        .collect();
                    self.output_array_slots = Some(s.clone());
                    s
                }
            };
            for (i, slot) in slots.iter().copied().enumerate() {
                let idx_reg = self.push_int_const(i as u64)?;
                let val_reg = self.builder.load_arr(handle, idx_reg);
                self.builder.write_witness(slot, val_reg);
            }
            self.builder.ret();
            self.halted = true;
            self.return_shape = ReturnShape::Array(len);
            return Some(());
        }

        // Scalar return.
        let r = self.lift_expr(value)?;
        let slot = match self.output_slot {
            Some(s) => s,
            None => {
                let s = self.builder.alloc_witness_slot();
                self.output_slot = Some(s);
                s
            }
        };
        self.builder.write_witness(slot, r);
        self.builder.ret();
        self.halted = true;
        self.return_shape = ReturnShape::Scalar;
        Some(())
    }
}
