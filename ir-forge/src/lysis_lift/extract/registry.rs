use std::collections::BTreeSet;

use rustc_hash::FxHashMap as HashMap;

use memory::FieldBackend;

use super::super::symbolic::{SlotId, SymbolicTree};
use super::error::ExtractError;
use super::layout::{build_capture_layout, compute_frame_size, CaptureLayout};
use crate::TemplateId;

/// Metadata for one registered template. The walker later walks the
/// `skeleton` to emit the actual bytecode body when assembling the
/// final `Program`.
#[derive(Debug, Clone)]
pub struct TemplateSpec<F: FieldBackend> {
    pub id: TemplateId,
    pub frame_size: u8,
    pub layout: CaptureLayout,
    pub skeleton: SymbolicTree<F>,
}

impl<F: FieldBackend> TemplateSpec<F> {
    pub fn n_params(&self) -> u8 {
        self.layout.n_params()
    }
}

/// Registry that hands out fresh [`TemplateId`]s and stores the
/// skeleton + metadata for each.
///
/// The current pass has no structural dedup — every
/// `extract_template` call allocates a fresh id. A future pass will
/// add canonical-bytecode dedup as an optimization (see module docs).
#[derive(Debug, Clone)]
pub struct TemplateRegistry<F: FieldBackend> {
    specs: HashMap<TemplateId, TemplateSpec<F>>,
    next_id: u32,
}

impl<F: FieldBackend> Default for TemplateRegistry<F> {
    fn default() -> Self {
        Self {
            specs: HashMap::default(),
            next_id: 0,
        }
    }
}

impl<F: FieldBackend> TemplateRegistry<F> {
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of templates registered so far.
    pub fn len(&self) -> usize {
        self.specs.len()
    }

    /// `true` when nothing has been registered.
    pub fn is_empty(&self) -> bool {
        self.specs.is_empty()
    }

    /// Look up a registered template by id.
    pub fn get(&self, id: TemplateId) -> Option<&TemplateSpec<F>> {
        self.specs.get(&id)
    }

    /// Iterate templates in id order. Deterministic: the walker uses
    /// this to emit `DefineTemplate` in a stable order.
    pub fn iter(&self) -> impl Iterator<Item = (&TemplateId, &TemplateSpec<F>)> {
        let mut pairs: Vec<_> = self.specs.iter().collect();
        pairs.sort_by_key(|(id, _)| id.0);
        pairs.into_iter()
    }

    pub(super) fn allocate_fresh(&mut self) -> Result<TemplateId, ExtractError> {
        if self.next_id > u32::from(u16::MAX) {
            return Err(ExtractError::TemplateSpaceExhausted);
        }
        let id = TemplateId(self.next_id as u16);
        self.next_id += 1;
        Ok(id)
    }

    /// Insert a fully-built [`TemplateSpec`] keyed by its id.
    /// `pub(super)` so the [`lift_uniform_loops`] helper can attach a
    /// spec without going through [`extract_template`] — the lift's
    /// `Option B` lowering keeps the iter_var local to the template
    /// frame, so the synthesised spec carries an `OuterRef`-only
    /// layout that doesn't match what `extract_template` would build.
    pub(super) fn insert(&mut self, spec: TemplateSpec<F>) {
        self.specs.insert(spec.id, spec);
    }
}

/// Register a new template from a BTA-classified uniform skeleton.
///
/// Returns the allocated [`TemplateSpec`]; the registry retains a
/// copy keyed by `id`.
pub fn extract_template<F: FieldBackend>(
    skeleton: &SymbolicTree<F>,
    slot_captures: &BTreeSet<SlotId>,
    registry: &mut TemplateRegistry<F>,
) -> Result<TemplateSpec<F>, ExtractError> {
    let layout = build_capture_layout(skeleton, slot_captures);
    let frame_size = compute_frame_size(skeleton, &layout)?;
    let id = registry.allocate_fresh()?;
    let spec = TemplateSpec {
        id,
        frame_size,
        layout,
        skeleton: skeleton.clone(),
    };
    registry.specs.insert(id, spec.clone());
    Ok(spec)
}
