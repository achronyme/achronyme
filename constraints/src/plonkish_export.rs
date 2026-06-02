/// JSON export for Plonkish constraint systems (achronyme-plonkish-v1 format).
///
/// Produces a self-contained JSON file with gates, copy constraints, lookups,
/// and assignments so external tools can inspect/verify the circuit.
mod serialization;
mod validation;

pub use serialization::write_plonkish_json;
pub use validation::validate_plonkish_json;

#[cfg(test)]
mod tests;
