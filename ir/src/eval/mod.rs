mod error;
mod int;
mod lenient;
mod strict;
mod witness;

#[cfg(test)]
mod tests;

pub use error::EvalError;
pub use lenient::evaluate_lenient;
pub use strict::evaluate;
