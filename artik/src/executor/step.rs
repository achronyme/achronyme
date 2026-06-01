use super::{
    arrays::{load_array, store_array},
    canonical::{
        canonical_rep_and, canonical_rep_div, canonical_rep_from_bytes, canonical_rep_rem,
        canonical_rep_shr, decode_const_fe,
    },
    int_ops::apply_bin,
    state::{ArrayBuf, Cell, Flow, State},
    *,
};

pub(super) fn step<F: FieldBackend>(
    instr: &Instr,
    state: &mut State<F>,
    ctx: &mut ArtikContext<'_, F>,
    prog: &Program,
) -> Result<Flow, ArtikError> {
    match instr {
        // ── Control flow ────────────────────────────────────────────
        Instr::Return { srcs } => Ok(Flow::Return { srcs: srcs.clone() }),
        Instr::Call {
            func_id,
            args,
            rets,
        } => Ok(Flow::Call {
            func_id: *func_id,
            args: args.clone(),
            rets: rets.clone(),
        }),
        Instr::Trap { code } => Err(ArtikError::ExecTrap { code: *code }),
        Instr::Jump { target } => Ok(Flow::JumpTo(state.resolve_jump(*target)?)),
        Instr::JumpIf { cond, target } => {
            // Any non-zero in the low byte of the int cell is truthy,
            // matching the `FEq`/`CmpLt`/`CmpEq` encoding of 0 or 1.
            let c = state.read_int(*cond)?;
            if c != 0 {
                Ok(Flow::JumpTo(state.resolve_jump(*target)?))
            } else {
                Ok(Flow::Next)
            }
        }

        // ── Constants & signals ────────────────────────────────────
        Instr::PushConst { dst, const_id } => {
            let entry =
                prog.const_pool
                    .get(*const_id as usize)
                    .ok_or(ArtikError::InvalidConstId {
                        const_id: *const_id,
                    })?;
            let fe = decode_const_fe::<F>(&entry.bytes).ok_or(ArtikError::BadConstBytes {
                const_id: *const_id,
            })?;
            state.write(*dst, Cell::Field(fe))?;
            Ok(Flow::Next)
        }
        Instr::ReadSignal { dst, signal_id } => {
            let fe = ctx.signals.get(*signal_id as usize).copied().ok_or(
                ArtikError::SignalOutOfBounds {
                    signal_id: *signal_id,
                    len: ctx.signals.len() as u32,
                },
            )?;
            state.write(*dst, Cell::Field(fe))?;
            Ok(Flow::Next)
        }
        Instr::WriteWitness { slot_id, src } => {
            let fe = *state.read_field(*src)?;
            let slots_len = ctx.witness_slots.len() as u32;
            let slot = ctx.witness_slots.get_mut(*slot_id as usize).ok_or(
                ArtikError::WitnessSlotOutOfBounds {
                    slot_id: *slot_id,
                    len: slots_len,
                },
            )?;
            *slot = fe;
            Ok(Flow::Next)
        }

        // ── Field ops ──────────────────────────────────────────────
        Instr::FAdd { dst, a, b } => {
            let a = *state.read_field(*a)?;
            let b = *state.read_field(*b)?;
            state.write(*dst, Cell::Field(a.add(&b)))?;
            Ok(Flow::Next)
        }
        Instr::FSub { dst, a, b } => {
            let a = *state.read_field(*a)?;
            let b = *state.read_field(*b)?;
            state.write(*dst, Cell::Field(a.sub(&b)))?;
            Ok(Flow::Next)
        }
        Instr::FMul { dst, a, b } => {
            let a = *state.read_field(*a)?;
            let b = *state.read_field(*b)?;
            state.write(*dst, Cell::Field(a.mul(&b)))?;
            Ok(Flow::Next)
        }
        Instr::FDiv { dst, a, b } => {
            let a = *state.read_field(*a)?;
            let b = *state.read_field(*b)?;
            let v = a.div(&b).ok_or(ArtikError::FieldDivByZero)?;
            state.write(*dst, Cell::Field(v))?;
            Ok(Flow::Next)
        }
        Instr::FInv { dst, src } => {
            let s = *state.read_field(*src)?;
            let v = s.inv().ok_or(ArtikError::FieldDivByZero)?;
            state.write(*dst, Cell::Field(v))?;
            Ok(Flow::Next)
        }
        Instr::FPow2 { dst, amount } => {
            // `2 ^ amount` in the active field — the field-precision
            // lowering of circom's `1 << amount`. Square-and-multiply
            // over the canonical representative of `amount` keeps the
            // result a correct residue for whatever backend prime is
            // in effect (no modulus constant here) and bounds the work
            // to the representative's bit width regardless of how large
            // `amount` is.
            let exp = (*state.read_field(*amount)?).to_canonical();
            let mut result = FieldElement::<F>::from_u64(1);
            let mut base = FieldElement::<F>::from_u64(2);
            for limb in exp {
                let mut bits = limb;
                for _ in 0..64 {
                    if bits & 1 == 1 {
                        result = result.mul(&base);
                    }
                    base = base.mul(&base);
                    bits >>= 1;
                }
            }
            state.write(*dst, Cell::Field(result))?;
            Ok(Flow::Next)
        }
        Instr::FEq { dst, a, b } => {
            let a = *state.read_field(*a)?;
            let b = *state.read_field(*b)?;
            let out: u64 = if a == b { 1 } else { 0 };
            state.write(*dst, Cell::Int(out))?;
            Ok(Flow::Next)
        }
        Instr::FCmpLt { dst, a, b } => {
            // Compare the canonical representatives as unsigned 256-bit
            // integers in `[0, p)`, high limb first. Exact at every
            // width — unlike the fixed-width `IBin { CmpLt }`, this does
            // not truncate operands that reach `2^64` (e.g. the
            // `b[i] + borrow` right-hand side of circomlib's bigint
            // `long_sub` at n=64).
            let al = state.read_field(*a)?.to_canonical();
            let bl = state.read_field(*b)?.to_canonical();
            let mut out: u64 = 0;
            for i in (0..4).rev() {
                if al[i] != bl[i] {
                    out = u64::from(al[i] < bl[i]);
                    break;
                }
            }
            state.write(*dst, Cell::Int(out))?;
            Ok(Flow::Next)
        }
        Instr::FIDiv { dst, a, b } => {
            let av = *state.read_field(*a)?;
            let bv = *state.read_field(*b)?;
            if bv.is_zero() {
                return Err(ArtikError::FieldDivByZero);
            }
            let q = canonical_rep_div(av.to_canonical(), bv.to_canonical());
            state.write(*dst, Cell::Field(FieldElement::<F>::from_canonical(q)))?;
            Ok(Flow::Next)
        }
        Instr::FIRem { dst, a, b } => {
            let av = *state.read_field(*a)?;
            let bv = *state.read_field(*b)?;
            if bv.is_zero() {
                return Err(ArtikError::FieldDivByZero);
            }
            let r = canonical_rep_rem(av.to_canonical(), bv.to_canonical());
            state.write(*dst, Cell::Field(FieldElement::<F>::from_canonical(r)))?;
            Ok(Flow::Next)
        }
        Instr::FShr { dst, src, amount } => {
            let s = *state.read_field(*src)?;
            let shifted = canonical_rep_shr(s.to_canonical(), *amount);
            state.write(
                *dst,
                Cell::Field(FieldElement::<F>::from_canonical(shifted)),
            )?;
            Ok(Flow::Next)
        }
        Instr::FAnd {
            dst,
            src,
            mask_const_id,
        } => {
            let s = *state.read_field(*src)?;
            let entry =
                prog.const_pool
                    .get(*mask_const_id as usize)
                    .ok_or(ArtikError::InvalidConstId {
                        const_id: *mask_const_id,
                    })?;
            let mask = canonical_rep_from_bytes(&entry.bytes);
            let r = canonical_rep_and(s.to_canonical(), mask);
            state.write(*dst, Cell::Field(FieldElement::<F>::from_canonical(r)))?;
            Ok(Flow::Next)
        }

        // ── Integer ops ────────────────────────────────────────────
        Instr::IBin { op, w, dst, a, b } => {
            let av = state.read_int(*a)?;
            let bv = state.read_int(*b)?;
            let out = apply_bin(*op, *w, av, bv);
            state.write(*dst, Cell::Int(out))?;
            Ok(Flow::Next)
        }
        Instr::INot { w, dst, src } => {
            let v = state.read_int(*src)?;
            let mask = w.mask();
            state.write(*dst, Cell::Int((!v) & mask))?;
            Ok(Flow::Next)
        }
        Instr::Rotl32 { dst, src, n } => {
            let v = state.read_int(*src)? as u32;
            let shift = (state.read_int(*n)? & 31) as u32;
            state.write(*dst, Cell::Int(v.rotate_left(shift) as u64))?;
            Ok(Flow::Next)
        }
        Instr::Rotr32 { dst, src, n } => {
            let v = state.read_int(*src)? as u32;
            let shift = (state.read_int(*n)? & 31) as u32;
            state.write(*dst, Cell::Int(v.rotate_right(shift) as u64))?;
            Ok(Flow::Next)
        }
        Instr::Rotl8 { dst, src, n } => {
            let v = state.read_int(*src)? as u8;
            let shift = (state.read_int(*n)? & 7) as u32;
            state.write(*dst, Cell::Int(v.rotate_left(shift) as u64))?;
            Ok(Flow::Next)
        }

        // ── Conversions ───────────────────────────────────────────
        // `IntFromField` is an unsigned truncation to `width` bits —
        // we take the low 64-bit limb of the canonical representation
        // and mask. For values that fit in `width` bits (typical for
        // SHA-256 u32 signals) this is exact; for full 256-bit field
        // elements it is truncation. Signed interpretation of an I64
        // conversion is the caller's responsibility.
        Instr::IntFromField { w, dst, src } => {
            let fe = *state.read_field(*src)?;
            let limbs = fe.to_canonical();
            state.write(*dst, Cell::Int(limbs[0] & w.mask()))?;
            Ok(Flow::Next)
        }
        // `FieldFromInt` with `I64` treats the raw u64 as a two's
        // complement signed value and maps negative inputs to
        // `p - |v|` via `from_i64`. All other widths zero-extend.
        Instr::FieldFromInt { dst, src, w } => {
            let v = state.read_int(*src)?;
            let fe = match w {
                IntW::I64 => FieldElement::<F>::from_i64(v as i64),
                _ => FieldElement::<F>::from_u64(v & w.mask()),
            };
            state.write(*dst, Cell::Field(fe))?;
            Ok(Flow::Next)
        }

        // ── Arrays ─────────────────────────────────────────────────
        Instr::AllocArray { dst, len, elem } => {
            // Cumulative runtime check: the validator caps each
            // individual `len`, but a loop that allocates many arrays
            // can still add up. Reject the whole execution cleanly.
            let prospective = state.array_cells_used.saturating_add(*len as u64);
            if prospective > MAX_ARRAY_MEMORY_CELLS {
                return Err(ArtikError::ArrayMemoryExceeded {
                    cells: prospective,
                    max: MAX_ARRAY_MEMORY_CELLS,
                });
            }
            state.array_cells_used = prospective;

            let handle = state.arrays.len() as u32;
            let buf = match elem {
                ElemT::Field => ArrayBuf::Field(vec![FieldElement::<F>::zero(); *len as usize]),
                ElemT::IntU8 => ArrayBuf::Int {
                    w: IntW::U8,
                    data: vec![0; *len as usize],
                },
                ElemT::IntU32 => ArrayBuf::Int {
                    w: IntW::U32,
                    data: vec![0; *len as usize],
                },
                ElemT::IntU64 => ArrayBuf::Int {
                    w: IntW::U64,
                    data: vec![0; *len as usize],
                },
                ElemT::IntI64 => ArrayBuf::Int {
                    w: IntW::I64,
                    data: vec![0; *len as usize],
                },
            };
            state.arrays.push(buf);
            state.write(*dst, Cell::Array(handle))?;
            Ok(Flow::Next)
        }
        Instr::LoadArr { dst, arr, idx } => {
            let handle = state.read_array(*arr)?;
            let idx_v = state.read_int(*idx)?;
            let buf = state
                .arrays
                .get(handle as usize)
                .ok_or(ArtikError::WrongCellKind { reg: *arr })?;
            let cell = load_array(buf, idx_v)?;
            state.write(*dst, cell)?;
            Ok(Flow::Next)
        }
        Instr::StoreArr { arr, idx, val } => {
            let handle = state.read_array(*arr)?;
            let idx_v = state.read_int(*idx)?;
            // Defensive lookup: clone the source cell rather than hold
            // a borrow across the `arrays` mutation so the executor
            // stays non-panicking even if a caller hands it a Program
            // that skipped `decode` / `validate`.
            let src = state.read_cell_clone(*val)?;
            let buf = state
                .arrays
                .get_mut(handle as usize)
                .ok_or(ArtikError::WrongCellKind { reg: *arr })?;
            store_array(buf, idx_v, src, *val)?;
            Ok(Flow::Next)
        }
        Instr::ArrayId { dst, arr } => {
            let handle = state.read_array(*arr)?;
            state.write(*dst, Cell::Int(u64::from(handle)))?;
            Ok(Flow::Next)
        }
        Instr::ArrayFromId { dst, id, elem: _ } => {
            let raw = state.read_int(*id)?;
            let len = state.arrays.len() as u64;
            if raw >= len {
                return Err(ArtikError::ArrayIndexOutOfBounds {
                    idx: raw,
                    len: state.arrays.len() as u32,
                });
            }
            state.write(*dst, Cell::Array(raw as u32))?;
            Ok(Flow::Next)
        }
    }
}
