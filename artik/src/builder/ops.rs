use crate::ir::{ElemT, Instr, IntBinOp, IntW, Reg, RegType};

use super::ProgramBuilder;

impl ProgramBuilder {
    // ── High-level emission helpers ───────────────────────────────────

    /// Emit `ReadSignal` and return the destination register. Only
    /// valid in the entry subprogram.
    pub fn read_signal(&mut self, signal_id: u32) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::ReadSignal { dst, signal_id });
        dst
    }

    /// Emit `PushConst` and return the destination register.
    pub fn push_const(&mut self, const_id: u32) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::PushConst { dst, const_id });
        dst
    }

    /// Emit `WriteWitness`. No register is returned (it is a sink).
    /// Only valid in the entry subprogram.
    pub fn write_witness(&mut self, slot_id: u32, src: Reg) {
        self.emit(Instr::WriteWitness { slot_id, src });
    }

    /// Emit a `Return` with no return values (the entry subprogram, or
    /// a callee that communicates only through arrays).
    pub fn ret(&mut self) {
        self.emit(Instr::Return { srcs: Vec::new() });
    }

    /// Emit a `Return` carrying the given source registers. The count
    /// and categories must match the active subprogram's declared
    /// return list.
    pub fn ret_vals(&mut self, srcs: &[Reg]) {
        self.emit(Instr::Return {
            srcs: srcs.to_vec(),
        });
    }

    /// Emit a `Call` to subprogram `func_id` with `args` (registers in
    /// the active subprogram). One destination register is allocated
    /// per entry in `ret_types`; the destinations are returned in
    /// order. `func_id` is typically a [`Self::reserve_subprogram`]
    /// result.
    pub fn call(&mut self, func_id: u32, args: &[Reg], ret_types: &[RegType]) -> Vec<Reg> {
        let rets: Vec<Reg> = (0..ret_types.len()).map(|_| self.alloc_reg()).collect();
        self.emit(Instr::Call {
            func_id,
            args: args.to_vec(),
            rets: rets.clone(),
        });
        rets
    }

    /// Emit `Trap { code }`. No register is returned.
    pub fn trap(&mut self, code: u16) {
        self.emit(Instr::Trap { code });
    }

    // ── Field ops ────────────────────────────────────────────────────

    pub fn fadd(&mut self, a: Reg, b: Reg) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::FAdd { dst, a, b });
        dst
    }

    pub fn fsub(&mut self, a: Reg, b: Reg) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::FSub { dst, a, b });
        dst
    }

    pub fn fmul(&mut self, a: Reg, b: Reg) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::FMul { dst, a, b });
        dst
    }

    pub fn fdiv(&mut self, a: Reg, b: Reg) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::FDiv { dst, a, b });
        dst
    }

    pub fn finv(&mut self, src: Reg) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::FInv { dst, src });
        dst
    }

    pub fn feq(&mut self, a: Reg, b: Reg) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::FEq { dst, a, b });
        dst
    }

    /// `dst (Int U8) = 1 if a < b else 0`, comparing canonical
    /// representatives as unsigned integers in `[0, p)` — field
    /// precision, no fixed-width truncation.
    pub fn fcmplt(&mut self, a: Reg, b: Reg) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::FCmpLt { dst, a, b });
        dst
    }

    /// Truncated unsigned division on the canonical representative.
    /// Both operands are field cells; result is a field cell carrying
    /// `floor(a / b)`. Traps at execute time on `b == 0`.
    pub fn fidiv(&mut self, a: Reg, b: Reg) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::FIDiv { dst, a, b });
        dst
    }

    /// Unsigned remainder on the canonical representative.
    pub fn firem(&mut self, a: Reg, b: Reg) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::FIRem { dst, a, b });
        dst
    }

    /// Right-shift the canonical representative by a compile-time
    /// constant amount (≤ 253).
    pub fn fshr(&mut self, src: Reg, amount: u32) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::FShr { dst, src, amount });
        dst
    }

    /// `2 ^ amount` in the field — the field-precision lowering of
    /// circom's `1 << amount`. `amount` is a runtime Field register;
    /// the result is a correct residue for the active backend prime.
    pub fn fpow2(&mut self, amount: Reg) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::FPow2 { dst, amount });
        dst
    }

    /// AND the canonical representative with a const-pool mask.
    pub fn fand(&mut self, src: Reg, mask_const_id: u32) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::FAnd {
            dst,
            src,
            mask_const_id,
        });
        dst
    }

    // ── Integer ops ──────────────────────────────────────────────────

    pub fn ibin(&mut self, op: IntBinOp, w: IntW, a: Reg, b: Reg) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::IBin { op, w, dst, a, b });
        dst
    }

    pub fn inot(&mut self, w: IntW, src: Reg) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::INot { w, dst, src });
        dst
    }

    pub fn rotl32(&mut self, src: Reg, n: Reg) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::Rotl32 { dst, src, n });
        dst
    }

    pub fn rotr32(&mut self, src: Reg, n: Reg) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::Rotr32 { dst, src, n });
        dst
    }

    pub fn rotl8(&mut self, src: Reg, n: Reg) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::Rotl8 { dst, src, n });
        dst
    }

    // ── Conversions ─────────────────────────────────────────────────

    pub fn int_from_field(&mut self, w: IntW, src: Reg) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::IntFromField { w, dst, src });
        dst
    }

    pub fn field_from_int(&mut self, src: Reg, w: IntW) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::FieldFromInt { dst, src, w });
        dst
    }

    // ── Arrays ──────────────────────────────────────────────────────

    pub fn alloc_array(&mut self, len: u32, elem: ElemT) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::AllocArray { dst, len, elem });
        dst
    }

    pub fn load_arr(&mut self, arr: Reg, idx: Reg) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::LoadArr { dst, arr, idx });
        dst
    }

    pub fn store_arr(&mut self, arr: Reg, idx: Reg, val: Reg) {
        self.emit(Instr::StoreArr { arr, idx, val });
    }

    /// Read the array handle in `arr` as a U32 int so it can be
    /// stashed in a heap slot across a branch and reconstructed with
    /// [`Self::array_from_id`].
    pub fn array_id(&mut self, arr: Reg) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::ArrayId { dst, arr });
        dst
    }

    /// Reconstruct an array handle from a U32 int produced by
    /// [`Self::array_id`]. `elem` must match the original array's
    /// element category.
    pub fn array_from_id(&mut self, id: Reg, elem: ElemT) -> Reg {
        let dst = self.alloc_reg();
        self.emit(Instr::ArrayFromId { dst, id, elem });
        dst
    }
}
