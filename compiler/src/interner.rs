use std::collections::HashMap;
use std::sync::Arc;

use memory::{BigInt, CircomHandle, FieldElement};

pub struct FieldInterner {
    pub fields: Vec<FieldElement>,
    cache: HashMap<[u64; 4], u32>,
}

impl Default for FieldInterner {
    fn default() -> Self {
        Self::new()
    }
}

impl FieldInterner {
    pub fn new() -> Self {
        Self {
            fields: Vec::new(),
            cache: HashMap::new(),
        }
    }

    pub fn intern(&mut self, fe: FieldElement) -> u32 {
        let key = fe.to_canonical();
        if let Some(&handle) = self.cache.get(&key) {
            return handle;
        }
        let handle = self.fields.len() as u32;
        self.fields.push(fe);
        self.cache.insert(key, handle);
        handle
    }
}

pub struct BigIntInterner {
    pub bigints: Vec<BigInt>,
    cache: HashMap<Vec<u64>, u32>,
}

impl Default for BigIntInterner {
    fn default() -> Self {
        Self::new()
    }
}

impl BigIntInterner {
    pub fn new() -> Self {
        Self {
            bigints: Vec::new(),
            cache: HashMap::new(),
        }
    }

    pub fn intern(&mut self, bi: BigInt) -> u32 {
        let key = bi.limbs().to_vec();
        if let Some(&handle) = self.cache.get(&key) {
            return handle;
        }
        let handle = self.bigints.len() as u32;
        self.cache.insert(key, handle);
        self.bigints.push(bi);
        handle
    }
}

/// Append-only registry of circom handle descriptors.
///
/// Each `intern(handle)` appends a [`CircomHandle`] and returns its
/// index, which the compiler then wraps into a `Value::circom_handle`
/// constant. At VM load time the bytecode loader bulk-imports the
/// descriptors into the heap's `circom_handles` arena so every
/// constant resolves against the same slot the compiler created.
///
/// No deduplication: each template call site gets its own handle,
/// even when two call sites share (library_id, template_name,
/// template_args), because deduplication would require reading the
/// handle back for comparison and the performance win is negligible.
pub struct CircomHandleInterner {
    pub handles: Vec<CircomHandle>,
}

impl Default for CircomHandleInterner {
    fn default() -> Self {
        Self::new()
    }
}

impl CircomHandleInterner {
    pub fn new() -> Self {
        Self {
            handles: Vec::new(),
        }
    }

    pub fn intern(&mut self, handle: CircomHandle) -> u32 {
        let idx = self.handles.len() as u32;
        self.handles.push(handle);
        idx
    }
}

/// Append-only registry of `Arc<CircomLibrary>` entries used at
/// runtime by the VM's circom handler. The compiler inserts a
/// library the first time it sees a circom template call and
/// records the returned `library_id` in every `CircomHandle` that
/// dispatches to that library. The CLI hands this registry over to
/// the handler at program-run time via `register_libraries`.
///
/// Lives next to the other interners so it shares the compiler's
/// ownership of compile-time-only state.
pub struct CircomLibraryRegistry {
    libraries: Vec<Arc<circom::CircomLibrary>>,
    by_path: HashMap<std::path::PathBuf, u32>,
}

impl Default for CircomLibraryRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl CircomLibraryRegistry {
    pub fn new() -> Self {
        Self {
            libraries: Vec::new(),
            by_path: HashMap::new(),
        }
    }

    /// Insert a library if not already present and return its id.
    /// Looked up by canonicalized source path so the same `.circom`
    /// file imported as both a namespace and a selective alias gets
    /// the same id (and therefore the same runtime instance).
    pub fn intern(&mut self, lib: Arc<circom::CircomLibrary>) -> u32 {
        let key = lib.source_path.clone();
        if let Some(&id) = self.by_path.get(&key) {
            return id;
        }
        let id = self.libraries.len() as u32;
        self.by_path.insert(key, id);
        self.libraries.push(lib);
        id
    }

    /// Materialize the flat library list in id order. Consumed by
    /// the CLI when building the runtime circom handler.
    pub fn into_libraries(self) -> Vec<Arc<circom::CircomLibrary>> {
        self.libraries
    }

    /// Drain the libraries out of the registry, leaving it empty.
    /// Preferred over `into_libraries` when the caller still needs
    /// the rest of the `Compiler` alive (e.g. to read debug
    /// symbols or prototypes).
    pub fn take_libraries(&mut self) -> Vec<Arc<circom::CircomLibrary>> {
        std::mem::take(&mut self.by_path);
        std::mem::take(&mut self.libraries)
    }

    /// Borrow the current registry (used by tests and by the CLI
    /// when it needs to copy without consuming the compiler).
    pub fn libraries(&self) -> &[Arc<circom::CircomLibrary>] {
        &self.libraries
    }
}

/// Append-only storage for binary blobs (e.g. serialized ProveIR).
/// No deduplication cache — each blob is typically unique.
pub struct BytesInterner {
    pub blobs: Vec<Vec<u8>>,
}

impl Default for BytesInterner {
    fn default() -> Self {
        Self::new()
    }
}

impl BytesInterner {
    pub fn new() -> Self {
        Self { blobs: Vec::new() }
    }

    pub fn intern(&mut self, data: Vec<u8>) -> u32 {
        let handle = self.blobs.len() as u32;
        self.blobs.push(data);
        handle
    }
}

pub struct StringInterner {
    pub strings: Vec<String>,
    pub cache: HashMap<String, u32>,
}

impl Default for StringInterner {
    fn default() -> Self {
        Self::new()
    }
}

impl StringInterner {
    pub fn new() -> Self {
        Self {
            strings: Vec::new(),
            cache: HashMap::new(),
        }
    }

    pub fn intern(&mut self, s: &str) -> u32 {
        if let Some(&handle) = self.cache.get(s) {
            return handle;
        }

        let handle = self.strings.len() as u32;
        self.strings.push(s.to_string());
        self.cache.insert(s.to_string(), handle);
        handle
    }
}
