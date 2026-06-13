//! Pass-1 forward scan over the interner's emission events.
//!
//! One walk computes, against the *post-constant-fold* view of the
//! stream, everything the later stages need: fold decisions (mirror
//! of `const_fold`), per-variable use counts taken after the
//! tautological-`AssertEq` filter (mirror of `dce`'s counting),
//! defining-event indices, `RangeCheck` bounds, the ordered
//! comparison list for bound inference, and the SSA watermark of the
//! unoptimized stream.
//!
//! MIRROR CONTRACT: every fold arm here must match the corresponding
//! arm in `crate::passes::const_fold` exactly; any semantic change to
//! that pass must land here too, plus a differential case in the
//! fused parity tests. The same contract binds `facts.rs` (bool_prop
//! / bit_pattern / bound_inference mirrors) and `dce.rs` (liveness).

use lysis::intern::{EmissionEventRef, NodeInterner, NodeKey, SideEffect};
use memory::{FieldBackend, FieldElement};
use rustc_hash::{FxHashMap, FxHashSet};

pub(super) const NO_EVENT: u32 = u32::MAX;

/// Why the fast path refused the stream. The caller falls back to
/// materialize + `optimize()`, which handles these shapes verbatim.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum ScanPoison {
    /// A variable has more than one defining instruction (the
    /// reference DCE switches to its round-based fallback there).
    DuplicateDef,
    /// `Decompose` aliases its operand as the result, which makes the
    /// stream non-SSA by construction; the constant-operand expansion
    /// also only exists on the materialized pass.
    Decompose,
    /// Stream too large for the u32 event indices.
    TooManyEvents,
}

/// A surviving `IsLt`/`IsLe` candidate for bound inference, in
/// instruction order.
pub(super) struct CmpSite {
    pub event: u32,
    pub result: u64,
    pub lhs: u64,
    pub rhs: u64,
    pub is_le: bool,
}

pub(super) struct Scan<F: FieldBackend> {
    pub event_count: usize,
    /// event index → folded constant value (post-fold instruction is
    /// `Const { original result var, value }`).
    pub folded: FxHashMap<u32, FieldElement<F>>,
    /// event index → tautological `AssertEq(x, x)`; removed before
    /// use counting, exactly like the reference pre-pass.
    pub taut: Vec<bool>,
    pub taut_count: usize,
    /// Use counts over the post-fold, taut-filtered stream, indexed
    /// by zero-based id.
    pub counts: Vec<u32>,
    /// Defining event per zero-based id (`result_var` defs only —
    /// extra results stay absent, mirroring the reference def maps).
    pub def_event: Vec<u32>,
    /// `max(def id) + 1` over the UNOPTIMIZED stream, mirroring
    /// `ssa_watermark` on the materialized instructions.
    pub watermark: u64,
    /// Tightest `RangeCheck` bound per operand id.
    pub range_bounds: FxHashMap<u64, u32>,
    /// Post-fold `IsLt`/`IsLe` sites in instruction order.
    pub cmps: Vec<CmpSite>,
    /// Surviving pre-existing bounded compares, keyed exactly like
    /// the reference CSE key: (is_le, lhs, rhs, bitwidth). A bound
    /// rewrite that lands on one of these keys makes the reference
    /// pipeline CSE the duplicate — the fused driver must hand such
    /// streams to the reference path.
    pub bounded_keys: FxHashSet<(bool, u64, u64, u32)>,
}

impl<F: FieldBackend> Scan<F> {
    fn grow(&mut self, id: usize) {
        if id >= self.counts.len() {
            self.counts.resize(id + 1, 0);
            self.def_event.resize(id + 1, NO_EVENT);
        }
    }

    fn define(&mut self, id: u64, event: u32) -> Result<(), ScanPoison> {
        let idx = id as usize;
        self.grow(idx);
        if self.def_event[idx] != NO_EVENT {
            return Err(ScanPoison::DuplicateDef);
        }
        self.def_event[idx] = event;
        self.watermark = self.watermark.max(id + 1);
        Ok(())
    }

    /// Watermark-only bump for extra results (`WitnessCall` secondary
    /// outputs), which the reference def maps do not index.
    fn bump_watermark(&mut self, id: u64) {
        self.watermark = self.watermark.max(id + 1);
    }

    fn count_use(&mut self, id: u64) {
        let idx = id as usize;
        if idx >= self.counts.len() {
            self.counts.resize(idx + 1, 0);
        }
        self.counts[idx] += 1;
    }
}

fn idx(id: lysis::intern::NodeId) -> u64 {
    id.index() as u64
}

/// Mirror of `const_fold`'s "constant value fits in `bits`" check on
/// the `RangeCheck` propagation arm.
fn fits_in_bits<F: FieldBackend>(val: &FieldElement<F>, bits: u32) -> bool {
    let limbs = val.to_canonical();
    if bits >= 64 {
        let full_limbs_needed = (bits / 64) as usize;
        let remaining_bits = bits % 64;
        let mut ok = true;
        for limb in limbs.iter().skip(full_limbs_needed + 1) {
            if *limb != 0 {
                ok = false;
            }
        }
        if ok && full_limbs_needed < 4 && remaining_bits > 0 {
            ok = limbs[full_limbs_needed] < (1u64 << remaining_bits);
        }
        ok
    } else {
        limbs[0] < (1u64 << bits) && limbs[1] == 0 && limbs[2] == 0 && limbs[3] == 0
    }
}

fn limb_lex_lt<F: FieldBackend>(a: &FieldElement<F>, b: &FieldElement<F>) -> bool {
    let la = a.to_canonical();
    let lb = b.to_canonical();
    (la[3], la[2], la[1], la[0]) < (lb[3], lb[2], lb[1], lb[0])
}

fn limb_lex_le<F: FieldBackend>(a: &FieldElement<F>, b: &FieldElement<F>) -> bool {
    let la = a.to_canonical();
    let lb = b.to_canonical();
    (la[3], la[2], la[1], la[0]) <= (lb[3], lb[2], lb[1], lb[0])
}

/// Fold decision for one pure node — mirror of the `const_fold` arms
/// over the in-flight `constants` map. Returns the folded value when
/// the post-fold instruction is `Const { result, value }`.
#[allow(clippy::too_many_lines)]
fn fold_pure<F: FieldBackend>(
    key: &NodeKey<F>,
    constants: &FxHashMap<u64, FieldElement<F>>,
) -> Option<FieldElement<F>> {
    let get = |v: &lysis::intern::NodeId| constants.get(&idx(*v)).copied();
    let one = FieldElement::<F>::one();
    let zero = FieldElement::<F>::zero();
    let is_bool = |v: FieldElement<F>| v.is_zero() || v == one;
    match key {
        NodeKey::Const(_) => None,
        NodeKey::Neg(operand) => get(operand).map(|v| v.neg()),
        NodeKey::Add(lhs, rhs) => {
            let lhs_val = get(lhs);
            let rhs_val = get(rhs);
            if lhs_val.is_some_and(|v| v.is_zero()) {
                rhs_val
            } else if rhs_val.is_some_and(|v| v.is_zero()) {
                lhs_val
            } else if let (Some(a), Some(b)) = (lhs_val, rhs_val) {
                Some(a.add(&b))
            } else {
                None
            }
        }
        NodeKey::Sub(lhs, rhs) => {
            if lhs == rhs {
                return Some(zero);
            }
            let lhs_val = get(lhs);
            let rhs_val = get(rhs);
            if rhs_val.is_some_and(|v| v.is_zero()) {
                lhs_val
            } else if let (Some(a), Some(b)) = (lhs_val, rhs_val) {
                Some(a.sub(&b))
            } else {
                None
            }
        }
        NodeKey::Mul(lhs, rhs) => {
            let lhs_val = get(lhs);
            let rhs_val = get(rhs);
            if lhs_val.is_some_and(|v| v.is_zero()) || rhs_val.is_some_and(|v| v.is_zero()) {
                Some(zero)
            } else if lhs_val == Some(one) {
                rhs_val
            } else if rhs_val == Some(one) {
                lhs_val
            } else if let (Some(a), Some(b)) = (lhs_val, rhs_val) {
                Some(a.mul(&b))
            } else {
                None
            }
        }
        NodeKey::Div(lhs, rhs) => {
            if lhs == rhs {
                if let Some(val) = get(lhs) {
                    if !val.is_zero() {
                        return Some(one);
                    }
                }
            }
            let lhs_val = get(lhs);
            let rhs_val = get(rhs);
            let lhs_zero = lhs_val.is_some_and(|v| v.is_zero());
            let rhs_zero = rhs_val.is_some_and(|v| v.is_zero());
            if lhs_zero && !rhs_zero {
                Some(zero)
            } else if rhs_val == Some(one) {
                lhs_val
            } else if let (Some(a), Some(b)) = (lhs_val, rhs_val) {
                b.inv().map(|inv| a.mul(&inv))
            } else {
                None
            }
        }
        NodeKey::Mux {
            cond,
            if_true,
            if_false,
        } => {
            let cond_val = get(cond);
            let true_val = get(if_true);
            let false_val = get(if_false);
            if let (Some(t), Some(f)) = (true_val, false_val) {
                if t == f {
                    Some(t)
                } else {
                    cond_val.map(|c| if c.is_zero() { f } else { t })
                }
            } else if let Some(c) = cond_val {
                if c.is_zero() {
                    false_val
                } else if c == one {
                    true_val
                } else {
                    None
                }
            } else {
                None
            }
        }
        NodeKey::Not(operand) => get(operand).and_then(|v| {
            if v.is_zero() || v == one {
                Some(if v.is_zero() { one } else { zero })
            } else {
                None
            }
        }),
        NodeKey::And(lhs, rhs) => {
            let lhs_val = get(lhs);
            let rhs_val = get(rhs);
            if lhs_val.is_some_and(|v| v.is_zero()) || rhs_val.is_some_and(|v| v.is_zero()) {
                Some(zero)
            } else if let (Some(a), Some(b)) = (lhs_val, rhs_val) {
                (is_bool(a) && is_bool(b)).then(|| a.mul(&b))
            } else {
                None
            }
        }
        NodeKey::Or(lhs, rhs) => {
            let lhs_val = get(lhs);
            let rhs_val = get(rhs);
            if lhs_val == Some(one) || rhs_val == Some(one) {
                Some(one)
            } else if let (Some(a), Some(b)) = (lhs_val, rhs_val) {
                (is_bool(a) && is_bool(b)).then(|| a.add(&b).sub(&a.mul(&b)))
            } else {
                None
            }
        }
        NodeKey::IsEq(lhs, rhs) => match (get(lhs), get(rhs)) {
            (Some(a), Some(b)) => Some(if a == b { one } else { zero }),
            _ => None,
        },
        NodeKey::IsNeq(lhs, rhs) => match (get(lhs), get(rhs)) {
            (Some(a), Some(b)) => Some(if a != b { one } else { zero }),
            _ => None,
        },
        NodeKey::IsLt(lhs, rhs) | NodeKey::IsLtBounded { lhs, rhs, .. } => {
            match (get(lhs), get(rhs)) {
                (Some(a), Some(b)) => Some(if limb_lex_lt(&a, &b) { one } else { zero }),
                _ => None,
            }
        }
        NodeKey::IsLe(lhs, rhs) | NodeKey::IsLeBounded { lhs, rhs, .. } => {
            match (get(lhs), get(rhs)) {
                (Some(a), Some(b)) => Some(if limb_lex_le(&a, &b) { one } else { zero }),
                _ => None,
            }
        }
        // PoseidonHash / IntDiv / IntMod never fold (reference wildcard).
        NodeKey::PoseidonHash { .. } | NodeKey::IntDiv { .. } | NodeKey::IntMod { .. } => None,
    }
}

/// Visit the operands of a pure node key, mirroring
/// `Instruction::for_each_operand` on the corresponding variant.
pub(super) fn for_each_key_operand<F: FieldBackend>(key: &NodeKey<F>, mut f: impl FnMut(u64)) {
    match key {
        NodeKey::Const(_) => {}
        NodeKey::Add(l, r)
        | NodeKey::Sub(l, r)
        | NodeKey::Mul(l, r)
        | NodeKey::Div(l, r)
        | NodeKey::And(l, r)
        | NodeKey::Or(l, r)
        | NodeKey::IsEq(l, r)
        | NodeKey::IsNeq(l, r)
        | NodeKey::IsLt(l, r)
        | NodeKey::IsLe(l, r) => {
            f(idx(*l));
            f(idx(*r));
        }
        NodeKey::IsLtBounded { lhs, rhs, .. }
        | NodeKey::IsLeBounded { lhs, rhs, .. }
        | NodeKey::IntDiv { lhs, rhs, .. }
        | NodeKey::IntMod { lhs, rhs, .. } => {
            f(idx(*lhs));
            f(idx(*rhs));
        }
        NodeKey::Neg(o) | NodeKey::Not(o) => f(idx(*o)),
        NodeKey::Mux {
            cond,
            if_true,
            if_false,
        } => {
            f(idx(*cond));
            f(idx(*if_true));
            f(idx(*if_false));
        }
        NodeKey::PoseidonHash { left, right } => {
            f(idx(*left));
            f(idx(*right));
        }
    }
}

pub(super) fn scan<F: FieldBackend>(interner: &NodeInterner<F>) -> Result<Scan<F>, ScanPoison> {
    let events = interner
        .emission_events()
        .expect("scan is only called on eager interners");
    let mut out = Scan {
        event_count: 0,
        folded: FxHashMap::default(),
        taut: Vec::new(),
        taut_count: 0,
        counts: Vec::new(),
        def_event: Vec::new(),
        watermark: 0,
        range_bounds: FxHashMap::default(),
        cmps: Vec::new(),
        bounded_keys: FxHashSet::default(),
    };
    // In-flight constant values, exactly the reference fold pass's
    // `constants` map (includes `RangeCheck` propagation, which the
    // post-fold const-def view in `facts.rs` must NOT report).
    let mut constants: FxHashMap<u64, FieldElement<F>> = FxHashMap::default();

    for (e, event) in events.enumerate() {
        if e as u64 >= NO_EVENT as u64 {
            return Err(ScanPoison::TooManyEvents);
        }
        let e32 = e as u32;
        out.taut.push(false);
        match event {
            EmissionEventRef::Pure { id, key } => {
                let r = idx(id);
                out.define(r, e32)?;
                if let NodeKey::Const(value) = key {
                    constants.insert(r, *value);
                } else if let Some(val) = fold_pure(key, &constants) {
                    constants.insert(r, val);
                    out.folded.insert(e32, val);
                } else {
                    for_each_key_operand(key, |op| out.count_use(op));
                    match key {
                        NodeKey::IsLt(l, rh) => out.cmps.push(CmpSite {
                            event: e32,
                            result: r,
                            lhs: idx(*l),
                            rhs: idx(*rh),
                            is_le: false,
                        }),
                        NodeKey::IsLe(l, rh) => out.cmps.push(CmpSite {
                            event: e32,
                            result: r,
                            lhs: idx(*l),
                            rhs: idx(*rh),
                            is_le: true,
                        }),
                        NodeKey::IsLtBounded { lhs, rhs, bitwidth } => {
                            out.bounded_keys
                                .insert((false, idx(*lhs), idx(*rhs), *bitwidth));
                        }
                        NodeKey::IsLeBounded { lhs, rhs, bitwidth } => {
                            out.bounded_keys
                                .insert((true, idx(*lhs), idx(*rhs), *bitwidth));
                        }
                        _ => {}
                    }
                }
            }
            EmissionEventRef::Effect(eff) => match eff {
                SideEffect::Decompose { .. } => return Err(ScanPoison::Decompose),
                SideEffect::Input { output, .. } => {
                    out.define(idx(*output), e32)?;
                }
                SideEffect::AssertEq {
                    result, lhs, rhs, ..
                } => {
                    if lhs == rhs {
                        // Tautological: removed before def/use
                        // accounting, mirroring the reference retain —
                        // but the SSA watermark is taken on the
                        // UNOPTIMIZED stream, so the result still
                        // raises it.
                        out.taut[e] = true;
                        out.taut_count += 1;
                        out.bump_watermark(idx(*result));
                    } else {
                        out.define(idx(*result), e32)?;
                        out.count_use(idx(*lhs));
                        out.count_use(idx(*rhs));
                    }
                }
                SideEffect::Assert {
                    result, operand, ..
                } => {
                    out.define(idx(*result), e32)?;
                    out.count_use(idx(*operand));
                }
                SideEffect::RangeCheck {
                    result,
                    operand,
                    bits,
                } => {
                    out.define(idx(*result), e32)?;
                    out.count_use(idx(*operand));
                    let op = idx(*operand);
                    // Constant propagation through a satisfied check
                    // (the instruction itself stays in the stream).
                    if let Some(val) = constants.get(&op).copied() {
                        if fits_in_bits(&val, *bits) {
                            constants.insert(idx(*result), val);
                        }
                    }
                    // Bound collection for bound_inference (tightest).
                    let entry = out.range_bounds.entry(op).or_insert(*bits);
                    if *bits < *entry {
                        *entry = *bits;
                    }
                }
                SideEffect::WitnessCall {
                    outputs, inputs, ..
                } => {
                    let mut first = true;
                    for o in outputs {
                        if first {
                            out.define(idx(*o), e32)?;
                            first = false;
                        } else {
                            out.bump_watermark(idx(*o));
                        }
                    }
                    for i in inputs {
                        out.count_use(idx(*i));
                    }
                }
            },
        }
        out.event_count = e + 1;
    }
    Ok(out)
}
