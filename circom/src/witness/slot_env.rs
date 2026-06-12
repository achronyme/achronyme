//! Slot-addressed value store for the witness-hints replay.
//!
//! The replay resolves a qualified signal name to a `u32` slot once
//! and then reads/writes a dense `Vec` — the `String` key is hashed
//! only at resolution (and at most once more when the final map is
//! materialized), instead of on every access. Keys are built in a
//! caller-owned scratch buffer; an owned `String` is allocated only
//! when a name is interned for the first time.

use std::collections::HashMap;

use memory::{FieldBackend, FieldElement};
use rustc_hash::FxHashMap;

pub(super) struct SlotEnv<F: FieldBackend> {
    slots: FxHashMap<String, u32>,
    values: Vec<Option<FieldElement<F>>>,
}

impl<F: FieldBackend> SlotEnv<F> {
    pub fn new() -> Self {
        Self {
            slots: FxHashMap::default(),
            values: Vec::new(),
        }
    }

    /// Slot for `name`, interned on first sight.
    pub fn slot(&mut self, name: &str) -> u32 {
        if let Some(&s) = self.slots.get(name) {
            return s;
        }
        let s = self.values.len() as u32;
        self.values.push(None);
        self.slots.insert(name.to_string(), s);
        s
    }

    /// Read-only lookup: the value under `name`, without interning.
    /// Mirrors a plain `HashMap::get` on the reference env — a miss
    /// leaves no trace.
    pub fn lookup(&self, name: &str) -> Option<FieldElement<F>> {
        self.slots.get(name).and_then(|&s| self.values[s as usize])
    }

    pub fn get(&self, slot: u32) -> Option<FieldElement<F>> {
        self.values[slot as usize]
    }

    pub fn set(&mut self, slot: u32, val: FieldElement<F>) {
        self.values[slot as usize] = Some(val);
    }

    /// Write `val` under `name`, interning if needed.
    pub fn write(&mut self, name: &str, val: FieldElement<F>) {
        let s = self.slot(name);
        self.set(s, val);
    }

    /// Flatten into the walk's public result shape. Interned names
    /// that never received a value (reads of absent signals, loops
    /// that ran zero iterations) are dropped — the reference env never
    /// contained them either.
    pub fn materialize(self) -> HashMap<String, FieldElement<F>> {
        let mut out = HashMap::with_capacity(self.values.len());
        let values = self.values;
        for (name, slot) in self.slots {
            if let Some(val) = values[slot as usize] {
                out.insert(name, val);
            }
        }
        out
    }
}
