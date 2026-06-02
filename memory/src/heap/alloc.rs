use super::{
    objects::circom_handle_cost, CircomHandle, Closure, Function, Heap, IteratorObj, ProofObject,
    Upvalue,
};
use crate::bigint::BigInt;
use crate::field::FieldElement;
use crate::Value;
use std::collections::HashMap;

impl Heap {
    pub fn alloc_upvalue(&mut self, val: Upvalue) -> Result<u32, crate::arena::ArenaError> {
        self.bytes_allocated += std::mem::size_of::<Upvalue>();
        self.check_gc();
        self.upvalues.alloc(val)
    }

    pub fn get_upvalue(&self, index: u32) -> Option<&Upvalue> {
        self.upvalues.get(index)
    }

    pub fn get_upvalue_mut(&mut self, index: u32) -> Option<&mut Upvalue> {
        self.upvalues.get_mut(index)
    }

    pub fn alloc_closure(&mut self, c: Closure) -> Result<u32, crate::arena::ArenaError> {
        self.bytes_allocated += std::mem::size_of::<Closure>() + c.upvalues.len() * 4;
        self.check_gc();
        self.closures.alloc(c)
    }

    pub fn get_closure(&self, index: u32) -> Option<&Closure> {
        self.closures.get(index)
    }

    /// # Safety
    /// `index` must refer to a live (GC-rooted) closure.
    #[inline(always)]
    pub unsafe fn get_closure_unchecked(&self, index: u32) -> &Closure {
        self.closures.get_unchecked_live(index)
    }

    pub fn get_closure_mut(&mut self, index: u32) -> Option<&mut Closure> {
        self.closures.get_mut(index)
    }

    pub fn alloc_string(&mut self, s: String) -> Result<u32, crate::arena::ArenaError> {
        self.bytes_allocated += s.capacity();
        self.check_gc();
        self.strings.alloc(s)
    }

    pub fn alloc_list(&mut self, l: Vec<Value>) -> Result<u32, crate::arena::ArenaError> {
        self.bytes_allocated += l.capacity() * std::mem::size_of::<Value>();
        self.check_gc();
        self.lists.alloc(l)
    }

    pub fn alloc_map(
        &mut self,
        m: HashMap<String, Value>,
    ) -> Result<u32, crate::arena::ArenaError> {
        self.bytes_allocated += m.capacity() * Self::map_entry_size();
        self.check_gc();
        self.maps.alloc(m)
    }

    pub fn get_map(&self, index: u32) -> Option<&HashMap<String, Value>> {
        self.maps.get(index)
    }

    pub fn get_map_mut(&mut self, index: u32) -> Option<&mut HashMap<String, Value>> {
        self.maps.get_mut(index)
    }

    /// Push a value onto a heap-allocated list, tracking capacity growth.
    pub fn list_push(&mut self, index: u32, value: Value) -> Option<()> {
        let list = self.lists.get_mut(index)?;
        let old_cap = list.capacity();
        list.push(value);
        let new_cap = list.capacity();
        if new_cap > old_cap {
            self.bytes_allocated += (new_cap - old_cap) * std::mem::size_of::<Value>();
            self.check_gc();
        }
        Some(())
    }

    /// Insert a key-value pair into a heap-allocated map, tracking capacity growth.
    pub fn map_insert(&mut self, index: u32, key: String, value: Value) -> Option<()> {
        let map = self.maps.get_mut(index)?;
        let old_cap = map.capacity();
        map.insert(key, value);
        let new_cap = map.capacity();
        if new_cap > old_cap {
            self.bytes_allocated += (new_cap - old_cap) * Self::map_entry_size();
            self.check_gc();
        }
        Some(())
    }

    /// Estimated cost per map entry (key + value + hash overhead).
    /// Used by both `alloc_map` and `recount_live_bytes` for consistency.
    pub(super) fn map_entry_size() -> usize {
        std::mem::size_of::<String>() + std::mem::size_of::<Value>() + std::mem::size_of::<u64>()
    }

    pub fn get_string(&self, index: u32) -> Option<&String> {
        self.strings.get(index)
    }

    pub fn get_list(&self, index: u32) -> Option<&Vec<Value>> {
        self.lists.get(index)
    }

    pub fn get_list_mut(&mut self, index: u32) -> Option<&mut Vec<Value>> {
        self.lists.get_mut(index)
    }

    pub fn alloc_function(&mut self, f: Function) -> Result<u32, crate::arena::ArenaError> {
        self.bytes_allocated +=
            f.chunk.len() * 4 + f.constants.len() * std::mem::size_of::<Value>();
        self.check_gc();
        self.functions.alloc(f)
    }

    pub fn get_function(&self, index: u32) -> Option<&Function> {
        self.functions.get(index)
    }

    /// # Safety
    /// `index` must refer to a live (GC-reachable) function.
    #[inline(always)]
    pub unsafe fn get_function_unchecked(&self, index: u32) -> &Function {
        self.functions.get_unchecked_live(index)
    }

    /// Replace the string arena wholesale with compiler output.
    ///
    /// # Safety invariant
    ///
    /// This invalidates **all** existing string handles. It must only be
    /// called during VM initialization, before `interpret()`. Any external
    /// string-handle caches (e.g. the VM's interner) must be cleared after
    /// this call.
    ///
    /// # Panics
    ///
    /// Panics if the string arena's free list is non-empty, which indicates
    /// that GC has already swept the arena (i.e. execution has started).
    pub fn import_strings(&mut self, strings: Vec<String>) {
        assert!(
            self.strings.free_indices.is_empty(),
            "import_strings called after execution started (string arena has freed slots)"
        );
        let cost: usize = strings.iter().map(|s| s.capacity()).sum();
        self.strings.data = strings;
        self.strings.clear_free();
        self.bytes_allocated += cost;
        self.check_gc();
    }

    pub fn alloc_iterator(&mut self, iter: IteratorObj) -> Result<u32, crate::arena::ArenaError> {
        self.bytes_allocated += std::mem::size_of::<IteratorObj>();
        self.check_gc();
        self.iterators.alloc(iter)
    }

    pub fn get_iterator(&self, index: u32) -> Option<&IteratorObj> {
        self.iterators.get(index)
    }

    pub fn get_iterator_mut(&mut self, index: u32) -> Option<&mut IteratorObj> {
        self.iterators.get_mut(index)
    }

    pub fn import_fields(
        &mut self,
        fields: Vec<FieldElement>,
    ) -> Result<Vec<u32>, crate::arena::ArenaError> {
        fields.into_iter().map(|fe| self.alloc_field(fe)).collect()
    }

    pub fn alloc_field(&mut self, fe: FieldElement) -> Result<u32, crate::arena::ArenaError> {
        self.bytes_allocated += std::mem::size_of::<FieldElement>();
        self.check_gc();
        self.fields.alloc(fe)
    }

    pub fn get_field(&self, index: u32) -> Option<&FieldElement> {
        self.fields.get(index)
    }

    pub fn alloc_proof(&mut self, p: ProofObject) -> Result<u32, crate::arena::ArenaError> {
        self.bytes_allocated += std::mem::size_of::<ProofObject>()
            + p.proof_json.capacity()
            + p.public_json.capacity()
            + p.vkey_json.capacity();
        self.check_gc();
        self.proofs.alloc(p)
    }

    pub fn get_proof(&self, index: u32) -> Option<&ProofObject> {
        self.proofs.get(index)
    }

    pub fn alloc_bigint(&mut self, bi: BigInt) -> Result<u32, crate::arena::ArenaError> {
        self.bytes_allocated += std::mem::size_of::<BigInt>() + std::mem::size_of_val(bi.limbs());
        self.check_gc();
        self.bigints.alloc(bi)
    }

    pub fn get_bigint(&self, index: u32) -> Option<&BigInt> {
        self.bigints.get(index)
    }

    pub fn get_bigint_mut(&mut self, index: u32) -> Option<&mut BigInt> {
        self.bigints.get_mut(index)
    }

    pub fn import_bigints(
        &mut self,
        bigints: Vec<BigInt>,
    ) -> Result<Vec<u32>, crate::arena::ArenaError> {
        bigints
            .into_iter()
            .map(|bi| self.alloc_bigint(bi))
            .collect()
    }

    pub fn alloc_bytes(&mut self, data: Vec<u8>) -> Result<u32, crate::arena::ArenaError> {
        self.bytes_allocated += data.capacity();
        self.check_gc();
        self.bytes.alloc(data)
    }

    pub fn get_bytes(&self, index: u32) -> Option<&Vec<u8>> {
        self.bytes.get(index)
    }

    /// Bulk-import byte blobs from the compiler (same pattern as import_strings).
    pub fn import_bytes(&mut self, blobs: Vec<Vec<u8>>) {
        assert!(
            self.bytes.free_indices.is_empty(),
            "import_bytes called after execution started (bytes arena has freed slots)"
        );
        let cost: usize = blobs.iter().map(|b| b.capacity()).sum();
        self.bytes.data = blobs;
        self.bytes.clear_free();
        self.bytes_allocated += cost;
        self.check_gc();
    }

    pub fn alloc_circom_handle(
        &mut self,
        handle: CircomHandle,
    ) -> Result<u32, crate::arena::ArenaError> {
        self.bytes_allocated += circom_handle_cost(&handle);
        self.check_gc();
        self.circom_handles.alloc(handle)
    }

    pub fn get_circom_handle(&self, index: u32) -> Option<&CircomHandle> {
        self.circom_handles.get(index)
    }

    /// Bulk-import circom handles from the compiler's handle table
    /// (same pattern as `import_bytes`). Called by the VM's bytecode
    /// loader at program-load time so every `Value::circom_handle(i)`
    /// constant resolves against the same arena slot the compiler
    /// allocated at compile time.
    pub fn import_circom_handles(&mut self, handles: Vec<CircomHandle>) {
        assert!(
            self.circom_handles.free_indices.is_empty(),
            "import_circom_handles called after execution started \
             (circom_handles arena has freed slots)"
        );
        let cost: usize = handles.iter().map(circom_handle_cost).sum();
        self.circom_handles.data = handles;
        self.circom_handles.clear_free();
        self.bytes_allocated += cost;
        self.check_gc();
    }
}
