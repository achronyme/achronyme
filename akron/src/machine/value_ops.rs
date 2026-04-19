use memory::Value;

/// Trait for value display and deep equality operations
pub trait ValueOps {
    fn val_to_string(&self, val: &Value) -> String;
    fn values_equal(&self, v1: Value, v2: Value) -> bool;
}

impl ValueOps for super::vm::VM {
    /// Helper to format values for display (Clean UX)
    fn val_to_string(&self, val: &Value) -> String {
        match val {
            v if v.is_string() => {
                let Some(handle) = v.as_handle() else {
                    return "<bad string>".into();
                };
                self.heap
                    .get_string(handle)
                    .cloned()
                    .unwrap_or("<bad string>".into())
            }
            v if v.is_int() => format!("{}", v.as_int().unwrap_or(0)),
            v if v.is_bool() => format!("{}", v.as_bool().unwrap_or(false)),
            v if v.is_nil() => "nil".to_string(),
            v if v.is_field() => {
                let Some(handle) = v.as_handle() else {
                    return "<bad field>".into();
                };
                match self.heap.get_field(handle) {
                    Some(fe) => format!("Field({})", fe.to_decimal_string()),
                    None => "<bad field>".into(),
                }
            }
            v if v.is_bigint() => {
                let Some(handle) = v.as_handle() else {
                    return "<bad bigint>".into();
                };
                match self.heap.get_bigint(handle) {
                    Some(bi) => format!("{}", bi),
                    None => "<bad bigint>".into(),
                }
            }
            v if v.is_proof() => "<Proof>".to_string(),
            v if v.is_list() => {
                let Some(handle) = v.as_handle() else {
                    return "<bad list>".into();
                };
                let Some(elements) = self.heap.get_list(handle) else {
                    return "<bad list>".into();
                };
                let parts: Vec<String> = elements.iter().map(|e| self.val_to_string(e)).collect();
                format!("[{}]", parts.join(", "))
            }
            v if v.is_map() => {
                let Some(handle) = v.as_handle() else {
                    return "<bad map>".into();
                };
                let Some(map) = self.heap.get_map(handle) else {
                    return "<bad map>".into();
                };
                let mut parts: Vec<String> = map
                    .iter()
                    .map(|(k, v)| format!("{}: {}", k, self.val_to_string(v)))
                    .collect();
                parts.sort(); // deterministic output
                format!("{{{}}}", parts.join(", "))
            }
            _ => format!("{:?}", val), // Fallback
        }
    }

    /// Deep equality check for runtime values
    fn values_equal(&self, v1: Value, v2: Value) -> bool {
        if v1 == v2 {
            return true; // Same identity (or primitive value)
        }

        if v1.is_string() && v2.is_string() {
            let (Some(h1), Some(h2)) = (v1.as_handle(), v2.as_handle()) else {
                return false;
            };
            let s1 = self.heap.get_string(h1);
            let s2 = self.heap.get_string(h2);
            match (s1, s2) {
                (Some(str1), Some(str2)) => str1 == str2,
                _ => false,
            }
        } else if v1.is_field() && v2.is_field() {
            let (Some(h1), Some(h2)) = (v1.as_handle(), v2.as_handle()) else {
                return false;
            };
            match (self.heap.get_field(h1), self.heap.get_field(h2)) {
                (Some(f1), Some(f2)) => f1 == f2,
                _ => false,
            }
        } else if v1.is_bigint() && v2.is_bigint() {
            let (Some(h1), Some(h2)) = (v1.as_handle(), v2.as_handle()) else {
                return false;
            };
            match (self.heap.get_bigint(h1), self.heap.get_bigint(h2)) {
                (Some(b1), Some(b2)) => b1 == b2,
                _ => false,
            }
        } else if v1.is_proof() && v2.is_proof() {
            // Proof equality is structural: two proofs are equal iff all three
            // JSON components match byte-for-byte. This is intentional — Groth16
            // proofs include randomness, so different proofs for the same circuit
            // and inputs will not compare equal. This matches the semantics of
            // "same proof object" rather than "same statement proven".
            let (Some(h1), Some(h2)) = (v1.as_handle(), v2.as_handle()) else {
                return false;
            };
            match (self.heap.get_proof(h1), self.heap.get_proof(h2)) {
                (Some(p1), Some(p2)) => {
                    p1.proof_json == p2.proof_json
                        && p1.public_json == p2.public_json
                        && p1.vkey_json == p2.vkey_json
                }
                _ => false,
            }
        } else {
            false
        }
    }
}
