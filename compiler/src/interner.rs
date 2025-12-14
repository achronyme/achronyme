use std::collections::HashMap;

pub struct StringInterner {
    pub strings: Vec<String>,
    pub cache: HashMap<String, u32>,
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
