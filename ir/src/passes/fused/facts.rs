//! Pass-1 analyses over the post-fold virtual stream: boolean
//! propagation, bit-pattern bound detection, and bound-inference
//! decisions. Mirrors of `bool_prop::proven_boolean_dense`,
//! `bit_pattern::detect_bit_patterns_with` and
//! `bound_inference::bound_inference` — same MIRROR CONTRACT as
//! `scan.rs`: arms must track the reference passes exactly, and the
//! fused parity tests pin the equality.
//!
//! Def/const lookups resolve through `Scan::def_event` plus the fold
//! overlay, reproducing the reference `DefIndex` (result-var defs
//! only, unique by scan poisoning) and `ConstIndex` (value only when
//! the post-fold defining instruction is itself a `Const` — NOT the
//! fold pass's in-flight map, which also carries `RangeCheck`
//! propagations).

use std::collections::{HashMap, HashSet};

use lysis::intern::{EmissionEventRef, NodeInterner, NodeKey, SideEffect};
use memory::{FieldBackend, FieldElement};
use rustc_hash::FxHashMap;

use crate::passes::bound_inference::BoundInferenceResult;
use crate::passes::dense::DenseVarSet;
use crate::types::{IrType, SsaVar};

use super::scan::{Scan, NO_EVENT};

/// Outputs of the fused analyses.
pub(super) struct Facts {
    pub booleans_detected: usize,
    pub bit_bounds: usize,
    /// event index → bitwidth for the `IsLt`/`IsLe` → bounded rewrite.
    pub rewrites: FxHashMap<u32, u32>,
    pub bound_inference: BoundInferenceResult,
}

/// Post-fold defining-instruction view, restricted to the shapes the
/// detection helpers pattern-match on. Everything else (effects,
/// other pure ops) behaves like the reference `_` arms.
enum DefView<F: FieldBackend> {
    Absent,
    Add(u64, u64),
    Sub(u64, u64),
    Mul(u64, u64),
    Const(FieldElement<F>),
    Other,
}

struct Resolver<'a, F: FieldBackend> {
    interner: &'a NodeInterner<F>,
    scan: &'a Scan<F>,
}

impl<'a, F: FieldBackend> Resolver<'a, F> {
    fn def_view(&self, v: u64) -> DefView<F> {
        let Some(&e) = self.scan.def_event.get(v as usize) else {
            return DefView::Absent;
        };
        if e == NO_EVENT {
            return DefView::Absent;
        }
        if let Some(val) = self.scan.folded.get(&e) {
            return DefView::Const(*val);
        }
        match self.interner.emission_event_at(e as usize) {
            Some(EmissionEventRef::Pure { key, .. }) => match key {
                NodeKey::Const(value) => DefView::Const(*value),
                NodeKey::Add(l, r) => DefView::Add(l.index() as u64, r.index() as u64),
                NodeKey::Sub(l, r) => DefView::Sub(l.index() as u64, r.index() as u64),
                NodeKey::Mul(l, r) => DefView::Mul(l.index() as u64, r.index() as u64),
                _ => DefView::Other,
            },
            Some(EmissionEventRef::Effect(_)) => DefView::Other,
            None => DefView::Absent,
        }
    }

    fn const_of(&self, v: u64) -> Option<FieldElement<F>> {
        match self.def_view(v) {
            DefView::Const(val) => Some(val),
            _ => None,
        }
    }

    /// Mirror of `try_detect_boolean_enforcement`:
    /// `AssertEq(Mul(v, Sub(v, 1)), 0)` (or symmetric) proves `v`
    /// boolean.
    fn detect_boolean_enforcement(&self, mul_side: u64, zero_side: u64) -> Option<u64> {
        let zero_val = self.const_of(zero_side)?;
        if !zero_val.is_zero() {
            return None;
        }
        let DefView::Mul(a, b) = self.def_view(mul_side) else {
            return None;
        };
        if self.is_sub_one(b, a) {
            return Some(a);
        }
        if self.is_sub_one(a, b) {
            return Some(b);
        }
        None
    }

    fn is_sub_one(&self, var: u64, expected_base: u64) -> bool {
        let DefView::Sub(lhs, rhs) = self.def_view(var) else {
            return false;
        };
        if lhs != expected_base {
            return false;
        }
        self.const_of(rhs) == Some(FieldElement::<F>::one())
    }

    /// Mirror of `bit_pattern::sum::decompose_sum`.
    fn decompose_sum(&self, var: u64, booleans: &DenseVarSet) -> Option<Vec<(u64, u32)>> {
        match self.def_view(var) {
            DefView::Absent => {
                if booleans.contains(SsaVar(var)) {
                    Some(vec![(var, 0)])
                } else {
                    None
                }
            }
            DefView::Add(lhs, rhs) => {
                let mut left = self.decompose_sum(lhs, booleans)?;
                let right = self.decompose_sum(rhs, booleans)?;
                left.extend(right);
                Some(left)
            }
            DefView::Mul(lhs, rhs) => {
                if booleans.contains(SsaVar(lhs)) {
                    if let Some(val) = self.const_of(rhs) {
                        if let Some(exp) = is_power_of_two(&val) {
                            return Some(vec![(lhs, exp)]);
                        }
                    }
                }
                if booleans.contains(SsaVar(rhs)) {
                    if let Some(val) = self.const_of(lhs) {
                        if let Some(exp) = is_power_of_two(&val) {
                            return Some(vec![(rhs, exp)]);
                        }
                    }
                }
                None
            }
            DefView::Const(value) => {
                if value.is_zero() {
                    Some(vec![])
                } else {
                    None
                }
            }
            DefView::Sub(..) | DefView::Other => {
                if booleans.contains(SsaVar(var)) {
                    Some(vec![(var, 0)])
                } else {
                    None
                }
            }
        }
    }

    /// Mirror of `bit_pattern::sum::try_extract_weighted_sum`.
    fn extract_weighted_sum(&self, var: u64, booleans: &DenseVarSet) -> Option<u32> {
        let terms = self.decompose_sum(var, booleans)?;
        if terms.is_empty() {
            return None;
        }
        let mut positions: HashSet<u32> = HashSet::new();
        for &(_, pos) in &terms {
            if !positions.insert(pos) {
                return None;
            }
        }
        let n = terms.len() as u32;
        let max_pos = positions.iter().copied().max().unwrap_or(0);
        if max_pos != n - 1 {
            return None;
        }
        let min_pos = positions.iter().copied().min().unwrap_or(1);
        if min_pos != 0 {
            return None;
        }
        Some(n)
    }
}

/// Mirror of `bit_pattern::sum::is_power_of_two`.
fn is_power_of_two<F: FieldBackend>(val: &FieldElement<F>) -> Option<u32> {
    if val.is_zero() {
        return None;
    }
    let limbs = val.to_canonical();
    for (limb_idx, &limb) in limbs.iter().enumerate() {
        if limb != 0 {
            if limbs[limb_idx + 1..].iter().all(|&l| l == 0) && limb.is_power_of_two() {
                return Some(limb_idx as u32 * 64 + limb.trailing_zeros());
            }
            return None;
        }
    }
    None
}

/// Run the bool_prop → bit_pattern → bound_inference mirror chain.
/// `var_types` is the (lean: empty) type-annotation map the reference
/// seeds proven booleans from.
pub(super) fn analyze<F: FieldBackend>(
    interner: &NodeInterner<F>,
    scan: &Scan<F>,
    var_types: &HashMap<SsaVar, IrType>,
) -> Facts {
    let r = Resolver { interner, scan };
    let one = FieldElement::<F>::one();

    // ---- bool_prop mirror (proven_boolean_dense) ----
    let mut booleans = DenseVarSet::with_capacity(scan.watermark as usize);
    for (var, ty) in var_types {
        if *ty == IrType::Bool {
            booleans.insert(*var);
        }
    }
    let events = interner
        .emission_events()
        .expect("analyze is only called on eager interners");
    for (e, event) in events.enumerate() {
        match event {
            EmissionEventRef::Pure { id, key } => {
                let result = SsaVar(id.index() as u64);
                if let Some(val) = scan.folded.get(&(e as u32)) {
                    // Post-fold view: Const { result, value }.
                    if val.is_zero() || *val == one {
                        booleans.insert(result);
                    }
                    continue;
                }
                match key {
                    NodeKey::Const(value) => {
                        if value.is_zero() || *value == one {
                            booleans.insert(result);
                        }
                    }
                    NodeKey::IsEq(..)
                    | NodeKey::IsNeq(..)
                    | NodeKey::IsLt(..)
                    | NodeKey::IsLe(..)
                    | NodeKey::IsLtBounded { .. }
                    | NodeKey::IsLeBounded { .. } => {
                        booleans.insert(result);
                    }
                    NodeKey::Not(operand) => {
                        if booleans.contains(SsaVar(operand.index() as u64)) {
                            booleans.insert(result);
                        }
                    }
                    NodeKey::And(lhs, rhs) | NodeKey::Or(lhs, rhs) => {
                        if booleans.contains(SsaVar(lhs.index() as u64))
                            && booleans.contains(SsaVar(rhs.index() as u64))
                        {
                            booleans.insert(result);
                        }
                    }
                    NodeKey::Mux {
                        if_true, if_false, ..
                    } if booleans.contains(SsaVar(if_true.index() as u64))
                        && booleans.contains(SsaVar(if_false.index() as u64)) =>
                    {
                        booleans.insert(result);
                    }
                    _ => {}
                }
            }
            EmissionEventRef::Effect(eff) => match eff {
                SideEffect::RangeCheck { result, bits, .. } => {
                    if *bits == 1 {
                        booleans.insert(SsaVar(result.index() as u64));
                    }
                }
                SideEffect::Assert {
                    result, operand, ..
                } => {
                    booleans.insert(SsaVar(operand.index() as u64));
                    booleans.insert(SsaVar(result.index() as u64));
                }
                SideEffect::AssertEq { lhs, rhs, .. } => {
                    let l = lhs.index() as u64;
                    let rh = rhs.index() as u64;
                    if let Some(var) = r.detect_boolean_enforcement(l, rh) {
                        booleans.insert(SsaVar(var));
                    }
                    if let Some(var) = r.detect_boolean_enforcement(rh, l) {
                        booleans.insert(SsaVar(var));
                    }
                }
                // Decompose is unreachable here (scan poisons it);
                // Input / WitnessCall have no boolean arm.
                _ => {}
            },
        }
    }

    // ---- bit_pattern mirror (detect_bit_patterns_with) ----
    // Step 1: augment the proven set with v*(v-1)=0 enforcements.
    let mut augmented = booleans.clone();
    let mut booleans_detected = 0usize;
    let for_each_asserteq = |f: &mut dyn FnMut(u64, u64)| {
        let events = interner
            .emission_events()
            .expect("analyze is only called on eager interners");
        for event in events {
            if let EmissionEventRef::Effect(SideEffect::AssertEq { lhs, rhs, .. }) = event {
                f(lhs.index() as u64, rhs.index() as u64);
            }
        }
    };
    for_each_asserteq(&mut |l, rh| {
        if let Some(var) = r.detect_boolean_enforcement(l, rh) {
            if augmented.insert(SsaVar(var)) {
                booleans_detected += 1;
            }
        }
        if let Some(var) = r.detect_boolean_enforcement(rh, l) {
            if augmented.insert(SsaVar(var)) {
                booleans_detected += 1;
            }
        }
    });
    // Step 2: weighted boolean sums → bitwidth bounds (tightest).
    let mut bit_bounds: HashMap<u64, u32> = HashMap::new();
    let merge_bound = |bounds: &mut HashMap<u64, u32>, var: u64, bits: u32| {
        let entry = bounds.entry(var).or_insert(bits);
        if bits < *entry {
            *entry = bits;
        }
    };
    for_each_asserteq(&mut |l, rh| {
        if let Some(n) = r.extract_weighted_sum(l, &augmented) {
            merge_bound(&mut bit_bounds, rh, n);
        }
        if let Some(n) = r.extract_weighted_sum(rh, &augmented) {
            merge_bound(&mut bit_bounds, l, n);
        }
    });

    // ---- bound_inference mirror ----
    // RangeCheck bounds (collected by the scan) merged with the
    // bit-pattern bounds, tightest wins; then per-comparison decide.
    let mut bounds = scan.range_bounds.clone();
    for (&var, &bits) in &bit_bounds {
        let entry = bounds.entry(var).or_insert(bits);
        if bits < *entry {
            *entry = bits;
        }
    }
    let mut rewrites: FxHashMap<u32, u32> = FxHashMap::default();
    let mut rewritten = 0usize;
    let mut unbounded = Vec::new();
    for site in &scan.cmps {
        match (bounds.get(&site.lhs), bounds.get(&site.rhs)) {
            (Some(&ba), Some(&bb)) => {
                rewrites.insert(site.event, ba.max(bb));
                rewritten += 1;
            }
            _ => unbounded.push((SsaVar(site.result), SsaVar(site.lhs), SsaVar(site.rhs))),
        }
    }

    Facts {
        booleans_detected,
        bit_bounds: bit_bounds.len(),
        rewrites,
        bound_inference: BoundInferenceResult {
            rewritten,
            unbounded,
        },
    }
}
