use crate::error::ProveIrError;
use crate::lysis_roundtrip::RoundTripError;

/// Errors raised by the `instantiate_lysis*` family. Bridges
/// [`ProveIrError`] (instantiate side) and [`RoundTripError`] (Lysis
/// pipeline side) into one variant the caller can match against.
#[derive(Debug)]
pub enum LysisInstantiateError {
    /// Instantiate-side error: invalid captures, oversize loop range,
    /// missing array element, etc.
    Instantiate(ProveIrError),
    /// Lysis-side error: Walker rejection (unsupported variant),
    /// bytecode validation failure, executor abort.
    Lysis(RoundTripError),
}

impl std::fmt::Display for LysisInstantiateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Instantiate(e) => write!(f, "instantiate_lysis: instantiate-side error: {e}"),
            Self::Lysis(e) => write!(f, "instantiate_lysis: lysis-side error: {e}"),
        }
    }
}

impl std::error::Error for LysisInstantiateError {}

impl From<ProveIrError> for LysisInstantiateError {
    fn from(e: ProveIrError) -> Self {
        Self::Instantiate(e)
    }
}

impl From<RoundTripError> for LysisInstantiateError {
    fn from(e: RoundTripError) -> Self {
        Self::Lysis(e)
    }
}
