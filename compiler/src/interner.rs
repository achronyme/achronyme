use std::collections::HashMap;

use memory::{BigInt, FieldElement};

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
