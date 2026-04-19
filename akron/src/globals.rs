use memory::Value;

#[derive(Clone, Debug)]
pub struct GlobalEntry {
    pub value: Value,
    pub mutable: bool,
}

impl GlobalEntry {
    pub fn new(value: Value, mutable: bool) -> Self {
        Self { value, mutable }
    }
}
