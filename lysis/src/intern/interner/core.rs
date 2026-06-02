use super::*;

impl<F: FieldBackend> NodeInterner<F> {
    /// Intern a pure node. If an equivalent key is already present,
    /// the existing `NodeId` is returned and `span` is appended to
    /// its span list (subject to the [`crate::intern::span::SPAN_LIST_CAP`]).
    ///
    /// `node_spans[i]` is kept parallel to the `nodes` IndexMap, so
    /// the insertion index is the right cursor for both structures
    /// — not `NodeId.index()`, since opaque reservations between
    /// pure inserts would leave gaps in the latter.
    pub fn intern_pure(&mut self, key: NodeKey<F>, span: SpanRange) -> NodeId {
        // Tier 3 (hot path): IndexMap lookup. Same as the historical
        // eager path; under streaming, hits also include all in-window
        // entries.
        if let Some((insertion_idx, _, meta)) = self.nodes.get_full(&key) {
            let id = meta.id;
            if let Some(list) = self.node_spans.get_mut(insertion_idx) {
                list.push_capped(span);
            }
            return id;
        }

        // Tier 1 (eternal Const): catches Const dedup after the entry
        // would have been evicted from `nodes`. The const_table itself
        // never evicts, so this is the long-range Const rescue.
        if let NodeKey::Const(v) = &key {
            if let Some(&id) = self.const_table.get(v) {
                return id;
            }
        }

        // Tier 2 (eternal Mul(Const, Const)): symmetric-normalized
        // value-pair lookup. Catches the dominant long-range Mul
        // dedup cohort once the original Mul entry has been evicted.
        // Both operand NodeIds must be in the eternal const_nodes set.
        if let NodeKey::Mul(a, b) = &key {
            if self.const_nodes.contains(a) && self.const_nodes.contains(b) {
                let pair = if a.index() <= b.index() {
                    (*a, *b)
                } else {
                    (*b, *a)
                };
                if let Some(&id) = self.mul_cc_table.get(&pair) {
                    return id;
                }
            }
        }

        // All tiers missed — fresh insert.
        let id = self.fresh_node_id();
        let hash = deterministic_hash(&key);
        let insertion_idx = self.nodes.len();

        // Populate eternal tiers BEFORE inserting into `nodes`, so a
        // future eviction of the Tier-3 entry still preserves the
        // long-range dedup path.
        match &key {
            NodeKey::Const(v) => {
                self.const_table.insert(*v, id);
                self.const_nodes.insert(id);
            }
            NodeKey::Mul(a, b) if self.const_nodes.contains(a) && self.const_nodes.contains(b) => {
                let pair = if a.index() <= b.index() {
                    (*a, *b)
                } else {
                    (*b, *a)
                };
                self.mul_cc_table.insert(pair, id);
                assert!(
                    self.mul_cc_table.len() <= MUL_CC_TIER_CAP,
                    "Mul(Const, Const) eternal tier exceeded the {} entry cap — \
                     re-measure cardinality (Stage-1 probe baseline = 10 distinct slots) \
                     before raising the cap",
                    MUL_CC_TIER_CAP,
                );
            }
            _ => {}
        }

        if let Some(cap) = self.window_size {
            // Streaming path: emit to output immediately, then insert
            // into `nodes`, then maybe evict the oldest entry.
            self.push_streaming(key.clone().into_instruction(id));
            self.eviction_queue.push_back(key.clone());
            self.nodes.insert(key, NodeMeta { id, hash });
            // record_spans is conventionally false in streaming mode,
            // but if a caller flips it we still mirror eager semantics.
            if self.record_spans {
                self.node_spans.push(SpanList::with_span(span));
            }
            while self.nodes.len() > cap {
                if let Some(old_key) = self.eviction_queue.pop_front() {
                    // Don't evict eternal-tier-tracked entries; they
                    // remain reachable via Tier 1/2 lookup but their
                    // hot-path Tier-3 slot is reclaimed.
                    let _removed = self.nodes.swap_remove(&old_key);
                    if !self.node_spans.is_empty() {
                        // node_spans is parallel to historical insertion
                        // order; under streaming we don't preserve that
                        // ordering once eviction starts, so this is a
                        // best-effort drop that keeps the Vec from
                        // growing unbounded when record_spans is set.
                        self.node_spans.pop();
                    }
                } else {
                    break;
                }
            }
        } else {
            // Eager path: byte-for-byte the historical behaviour.
            self.nodes.insert(key, NodeMeta { id, hash });
            if self.record_spans {
                debug_assert_eq!(self.node_spans.len(), insertion_idx);
                self.node_spans.push(SpanList::with_span(span));
            }
            self.timeline.push(Emission::Pure(insertion_idx));
        }

        id
    }

    /// Append a side-effect in emission order. `EffectId`s are
    /// assigned in insertion order starting from zero. Side-effects
    /// that define wires downstream pure nodes consume (e.g.
    /// [`SideEffect::Decompose`], [`SideEffect::Input`]) rely on the
    /// emission order being preserved through materialize — that's
    /// what the `timeline` log guarantees.
    pub fn emit_effect(&mut self, effect: SideEffect, span: SpanRange) -> EffectId {
        let eff_idx = self.effects.len();
        let eff_id = EffectId::from_zero_based(eff_idx);
        if let Some(_cap) = self.window_size {
            // Streaming path: emit directly to output. The `effects`
            // Vec stays empty — the materialized output Vec already
            // carries every effect, no external consumer reads
            // `effects` field outside this crate (verified via grep),
            // and `effect_len()` returning 0 is fine for the streaming
            // path's contract (caller uses the output Vec). Skipping
            // the push releases the dominant non-node accumulator
            // (~1.1 GB on the boss-fight).
            self.push_streaming(SideEffect::into_instruction::<F>(effect));
        } else {
            self.effects.push(effect);
            if self.record_spans {
                self.effect_spans.push(SpanList::with_span(span));
            }
            self.timeline.push(Emission::Effect(eff_idx));
        }
        eff_id
    }

    /// Hand out a fresh `NodeId` that is not interned. Used for
    /// side-effect outputs (e.g., `Input`'s new wire, `Decompose`'s
    /// per-bit results, `WitnessCall`'s outputs). These ids live in
    /// the same monotonic sequence as pure ids but have no entry in
    /// `nodes`, which is the signal to materialization that they
    /// were produced by an effect.
    pub fn reserve_opaque_id(&mut self) -> NodeId {
        // No span list for opaque ids — spans for side-effects live
        // in `effect_spans` instead, keyed by EffectId.
        self.fresh_node_id()
    }

    fn fresh_node_id(&mut self) -> NodeId {
        let id = NodeId::from_zero_based(self.next_node_id as usize);
        self.next_node_id = self
            .next_node_id
            .checked_add(1)
            .expect("NodeId counter overflows u64");
        id
    }

    /// Total unique pure nodes interned.
    #[inline]
    pub fn pure_len(&self) -> usize {
        self.nodes.len()
    }

    /// Total side-effects emitted.
    #[inline]
    pub fn effect_len(&self) -> usize {
        self.effects.len()
    }

    /// Total opaque NodeIds allocated (pure nodes + opaque reservations).
    #[inline]
    pub fn total_node_ids(&self) -> u64 {
        self.next_node_id
    }

    /// Look up the structural key for a pure `NodeId`. Returns `None`
    /// for opaque (side-effect-output) ids and for unknown ids.
    pub fn key_of(&self, id: NodeId) -> Option<&NodeKey<F>> {
        // Linear but nodes are insertion-ordered: the id is assigned
        // at insertion time, so iterating is O(n). Good enough for
        // diagnostics / post-hoc inspection; not on the hot path.
        self.nodes
            .iter()
            .find(|(_, meta)| meta.id == id)
            .map(|(k, _)| k)
    }

    /// Look up the cached hash for a pure node.
    pub fn hash_of(&self, id: NodeId) -> Option<u64> {
        self.nodes
            .iter()
            .find(|(_, meta)| meta.id == id)
            .map(|(_, meta)| meta.hash)
    }

    /// Span list attached to a pure `NodeId`. `None` for opaque ids.
    /// Linear scan — `O(pure_len)` — since we don't maintain a
    /// reverse id→insertion-index index. Off the hot path (used by
    /// diagnostics / materialize).
    pub fn node_spans(&self, id: NodeId) -> Option<&SpanList> {
        let idx = self.nodes.values().position(|m| m.id == id)?;
        self.node_spans.get(idx)
    }

    /// Span list attached to a side-effect.
    pub fn effect_spans(&self, eff: EffectId) -> Option<&SpanList> {
        self.effect_spans.get(eff.index())
    }

    /// Iterate pure nodes in insertion (= topological) order, yielding
    /// `(NodeId, &NodeKey, &NodeMeta)`. This is what
    /// [`crate::intern::materialize`] walks.
    pub fn iter_pure(&self) -> impl Iterator<Item = (NodeId, &NodeKey<F>, &NodeMeta)> {
        self.nodes.iter().map(|(key, meta)| (meta.id, key, meta))
    }

    /// Iterate side-effects in emission order.
    pub fn iter_effects(&self) -> impl Iterator<Item = (EffectId, &SideEffect)> {
        self.effects
            .iter()
            .enumerate()
            .map(|(i, eff)| (EffectId::from_zero_based(i), eff))
    }
}
