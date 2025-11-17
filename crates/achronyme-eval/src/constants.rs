use std::collections::HashMap;
use std::f64::consts;

/// Mathematical constants
pub const PI: f64 = consts::PI;
pub const E: f64 = consts::E;
pub const PHI: f64 = 1.618033988749895; // Golden ratio
pub const SQRT2: f64 = consts::SQRT_2;
pub const SQRT3: f64 = 1.7320508075688772;
pub const LN2: f64 = consts::LN_2;
pub const LN10: f64 = consts::LN_10;

/// IEEE 754 special values
pub const INFINITY: f64 = f64::INFINITY;
pub const NEG_INFINITY: f64 = f64::NEG_INFINITY;
pub const NAN: f64 = f64::NAN;

/// Registry for mathematical constants
///
/// Provides case-insensitive lookup of mathematical constants.
///
/// # Example
/// ```
/// use achronyme_eval::constants::ConstantsRegistry;
///
/// let registry = ConstantsRegistry::new();
/// let pi = registry.get("PI").unwrap();
/// assert_eq!(pi, std::f64::consts::PI);
/// ```
#[derive(Debug, Clone)]
pub struct ConstantsRegistry {
    constants: HashMap<String, f64>,
}

impl ConstantsRegistry {
    /// Create a new constants registry with all standard constants
    pub fn new() -> Self {
        let mut constants = HashMap::new();

        // Register all constants (lowercase keys for case-insensitive lookup)
        constants.insert("pi".to_string(), PI);
        constants.insert("e".to_string(), E);
        constants.insert("phi".to_string(), PHI);
        constants.insert("sqrt2".to_string(), SQRT2);
        constants.insert("sqrt3".to_string(), SQRT3);
        constants.insert("ln2".to_string(), LN2);
        constants.insert("ln10".to_string(), LN10);

        // Common aliases
        constants.insert("goldenratio".to_string(), PHI);

        // IEEE 754 special values
        constants.insert("infinity".to_string(), INFINITY);
        constants.insert("nan".to_string(), NAN);

        Self { constants }
    }

    /// Check if a constant is defined
    ///
    /// # Arguments
    /// * `name` - Constant name (case-insensitive)
    ///
    /// # Returns
    /// true if constant exists
    pub fn has(&self, name: &str) -> bool {
        let lower_name = name.to_lowercase();
        self.constants.contains_key(&lower_name)
    }

    /// Get a constant value
    ///
    /// # Arguments
    /// * `name` - Constant name (case-insensitive)
    ///
    /// # Returns
    /// Constant value if found
    ///
    /// # Errors
    /// Returns error if constant not found
    pub fn get(&self, name: &str) -> Result<f64, String> {
        let lower_name = name.to_lowercase();
        self.constants
            .get(&lower_name)
            .copied()
            .ok_or_else(|| format!("Unknown constant: {}", name))
    }

    /// Get all constant names
    pub fn names(&self) -> Vec<String> {
        self.constants.keys().cloned().collect()
    }
}

impl Default for ConstantsRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_get_pi() {
        let registry = ConstantsRegistry::new();
        let pi = registry.get("PI").unwrap();
        assert_eq!(pi, std::f64::consts::PI);
    }

    #[test]
    fn test_case_insensitive() {
        let registry = ConstantsRegistry::new();
        assert_eq!(registry.get("PI").unwrap(), registry.get("pi").unwrap());
        assert_eq!(registry.get("Pi").unwrap(), registry.get("pI").unwrap());
    }

    #[test]
    fn test_has() {
        let registry = ConstantsRegistry::new();
        assert!(registry.has("PI"));
        assert!(registry.has("pi"));
        assert!(registry.has("E"));
        assert!(!registry.has("UNKNOWN"));
    }

    #[test]
    fn test_golden_ratio() {
        let registry = ConstantsRegistry::new();
        assert_eq!(registry.get("PHI").unwrap(), PHI);
        assert_eq!(registry.get("goldenratio").unwrap(), PHI);
    }

    #[test]
    fn test_unknown_constant() {
        let registry = ConstantsRegistry::new();
        let result = registry.get("UNKNOWN");
        assert!(result.is_err());
    }

    #[test]
    fn test_infinity() {
        let registry = ConstantsRegistry::new();
        let inf = registry.get("Infinity").unwrap();
        assert!(inf.is_infinite() && inf.is_sign_positive());
    }

    #[test]
    fn test_nan() {
        let registry = ConstantsRegistry::new();
        let nan = registry.get("NaN").unwrap();
        assert!(nan.is_nan());
    }
}
