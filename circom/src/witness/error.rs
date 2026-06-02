/// Error during witness computation.
#[derive(Debug)]
pub struct WitnessError {
    pub message: String,
}

impl std::fmt::Display for WitnessError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.message)
    }
}

impl std::error::Error for WitnessError {}
