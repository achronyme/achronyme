//! Timeline-ordered emission-event iterators over an eager
//! [`NodeInterner`].
//!
//! [`NodeInterner::materialize`] flattens the emission timeline into a
//! `Vec<InstructionKind<F>>`. The iterators here expose the *same
//! sequence* without building that Vec, so a consumer can analyze or
//! re-emit the stream against the interner's own storage:
//!
//! - [`NodeInterner::emission_events`] borrows the interner and yields
//!   one [`EmissionEventRef`] per timeline entry.
//! - [`NodeInterner::into_emission_events`] consumes the interner and
//!   yields owned [`EmissionEvent`]s by walking `nodes` / `effects` in
//!   lockstep with the timeline.
//!
//! The lockstep walk is exact because, in eager mode, the k-th
//! `Emission::Pure` entry was recorded with insertion index k (dedup
//! hits append nothing and nothing is ever removed from `nodes`), and
//! likewise the k-th `Emission::Effect` entry refers to `effects[k]`.
//! Both iterators are **eager-mode only**: the windowed/streaming
//! strategies do not maintain a timeline, so the constructors hand the
//! interner back instead of yielding a wrong (empty) sequence.

use memory::field::FieldBackend;

use crate::intern::interner::Emission;
use crate::intern::{NodeId, NodeInterner, NodeKey, SideEffect};

/// One borrowed emission-timeline entry.
#[derive(Debug)]
pub enum EmissionEventRef<'a, F: FieldBackend> {
    /// A fresh pure-node insertion: the node's canonical id plus its
    /// structural key.
    Pure { id: NodeId, key: &'a NodeKey<F> },
    /// A side-effect emission.
    Effect(&'a SideEffect),
}

/// One owned emission-timeline entry (consuming counterpart of
/// [`EmissionEventRef`]).
#[derive(Debug)]
pub enum EmissionEvent<F: FieldBackend> {
    Pure { id: NodeId, key: NodeKey<F> },
    Effect(SideEffect),
}

impl<F: FieldBackend> NodeInterner<F> {
    /// `true` when this interner uses the eager strategy (no streaming
    /// window), i.e. its timeline + node table describe the complete
    /// emission stream.
    pub fn is_eager(&self) -> bool {
        self.window_size.is_none()
    }

    /// Borrowed timeline-ordered iteration over the emission stream.
    /// Returns `None` when the interner is not eager (the streaming
    /// strategies keep no timeline).
    pub fn emission_events(&self) -> Option<impl Iterator<Item = EmissionEventRef<'_, F>> + '_> {
        if !self.is_eager() {
            return None;
        }
        Some(self.timeline.iter().map(move |event| {
            match *event {
                Emission::Pure(idx) => {
                    let (key, meta) = self
                        .nodes
                        .get_index(idx)
                        .expect("eager timeline Pure index always in-bounds");
                    EmissionEventRef::Pure { id: meta.id, key }
                }
                Emission::Effect(idx) => EmissionEventRef::Effect(
                    self.effects
                        .get(idx)
                        .expect("eager timeline Effect index always in-bounds"),
                ),
            }
        }))
    }

    /// Random access into the emission timeline (eager mode only):
    /// the event at position `idx` of the sequence
    /// [`Self::emission_events`] yields. `None` when out of range or
    /// when the interner is not eager.
    pub fn emission_event_at(&self, idx: usize) -> Option<EmissionEventRef<'_, F>> {
        if !self.is_eager() {
            return None;
        }
        Some(match *self.timeline.get(idx)? {
            Emission::Pure(i) => {
                let (key, meta) = self
                    .nodes
                    .get_index(i)
                    .expect("eager timeline Pure index always in-bounds");
                EmissionEventRef::Pure { id: meta.id, key }
            }
            Emission::Effect(i) => EmissionEventRef::Effect(
                self.effects
                    .get(i)
                    .expect("eager timeline Effect index always in-bounds"),
            ),
        })
    }

    /// Consuming timeline-ordered iteration over the emission stream.
    /// Yields the same sequence as [`Self::materialize`] (before its
    /// `InstructionKind` conversion), without building the flat Vec.
    /// Returns the interner back via `Err` when it is not eager.
    pub fn into_emission_events(self) -> Result<IntoEmissionEvents<F>, Box<Self>> {
        if !self.is_eager() {
            return Err(Box::new(self));
        }
        debug_assert_eq!(
            self.timeline
                .iter()
                .filter(|e| matches!(e, Emission::Pure(_)))
                .count(),
            self.nodes.len(),
            "every eager node insertion records exactly one Pure event"
        );
        debug_assert_eq!(
            self.timeline
                .iter()
                .filter(|e| matches!(e, Emission::Effect(_)))
                .count(),
            self.effects.len(),
            "every effect emission records exactly one Effect event"
        );
        Ok(IntoEmissionEvents {
            timeline: self.timeline.into_iter(),
            nodes: self.nodes.into_iter(),
            effects: self.effects.into_iter(),
        })
    }
}

/// Consuming iterator returned by [`NodeInterner::into_emission_events`].
pub struct IntoEmissionEvents<F: FieldBackend> {
    timeline: std::vec::IntoIter<Emission>,
    nodes: indexmap::map::IntoIter<NodeKey<F>, crate::intern::NodeMeta>,
    effects: std::vec::IntoIter<SideEffect>,
}

impl<F: FieldBackend> Iterator for IntoEmissionEvents<F> {
    type Item = EmissionEvent<F>;

    fn next(&mut self) -> Option<Self::Item> {
        match self.timeline.next()? {
            Emission::Pure(_) => {
                let (key, meta) = self
                    .nodes
                    .next()
                    .expect("timeline Pure count equals node count");
                Some(EmissionEvent::Pure { id: meta.id, key })
            }
            Emission::Effect(_) => Some(EmissionEvent::Effect(
                self.effects
                    .next()
                    .expect("timeline Effect count equals effect count"),
            )),
        }
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.timeline.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use memory::field::Bn254Fr;
    use memory::FieldElement;

    use super::*;
    use crate::intern::{InstructionKind, SpanRange, Visibility};

    type F = Bn254Fr;

    fn fe(n: u64) -> FieldElement<F> {
        FieldElement::from_u64(n)
    }

    fn sample_interner() -> NodeInterner<F> {
        let mut interner = NodeInterner::<F>::without_span_tracking();
        let a = interner.intern_pure(NodeKey::Const(fe(1)), SpanRange::UNKNOWN);
        let inp = interner.reserve_opaque_id();
        interner.emit_effect(
            SideEffect::Input {
                output: inp,
                name: "x".into(),
                visibility: Visibility::Witness,
            },
            SpanRange::UNKNOWN,
        );
        let s = interner.intern_pure(NodeKey::Add(a, inp), SpanRange::UNKNOWN);
        // Dedup hit: must not add a timeline entry.
        let s2 = interner.intern_pure(NodeKey::Add(a, inp), SpanRange::UNKNOWN);
        assert_eq!(s, s2);
        let r = interner.reserve_opaque_id();
        interner.emit_effect(
            SideEffect::AssertEq {
                result: r,
                lhs: s,
                rhs: a,
                message: None,
            },
            SpanRange::UNKNOWN,
        );
        interner
    }

    /// Both iterators must reproduce materialize()'s sequence exactly.
    /// `InstructionKind` has no `PartialEq`; per-element Debug equality
    /// is the established comparison idiom for stream parity.
    #[test]
    fn events_match_materialize_order() {
        let interner = sample_interner();
        let expected: Vec<String> = interner
            .clone()
            .materialize()
            .iter()
            .map(|k: &InstructionKind<F>| format!("{k:?}"))
            .collect();

        let borrowed: Vec<String> = interner
            .emission_events()
            .expect("eager interner has events")
            .map(|e| match e {
                EmissionEventRef::Pure { id, key } => format!("{:?}", key.into_instruction(id)),
                EmissionEventRef::Effect(eff) => {
                    format!("{:?}", eff.clone().into_instruction::<F>())
                }
            })
            .collect();
        assert_eq!(borrowed, expected);

        let owned: Vec<String> = interner
            .into_emission_events()
            .expect("eager interner converts")
            .map(|e| match e {
                EmissionEvent::Pure { id, key } => format!("{:?}", key.into_instruction(id)),
                EmissionEvent::Effect(eff) => format!("{:?}", eff.into_instruction::<F>()),
            })
            .collect();
        assert_eq!(owned, expected);
    }

    #[test]
    fn windowed_interner_yields_no_events() {
        let mut interner = NodeInterner::<F>::with_streaming_window(4);
        interner.intern_pure(NodeKey::Const(fe(1)), SpanRange::UNKNOWN);
        assert!(!interner.is_eager());
        assert!(interner.emission_events().is_none());
        assert!(interner.into_emission_events().is_err());
    }
}
