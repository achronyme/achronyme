/// Prime Field Element — generic over `FieldBackend`.
///
/// `FieldElement<F>` wraps `F::Repr` and delegates all operations to the
/// backend. The default type parameter `Bn254Fr` means bare `FieldElement`
/// in type position resolves to `FieldElement<Bn254Fr>`, preserving backward
/// compatibility across the workspace.
pub(crate) mod arithmetic;
mod backend;
pub mod bls12_381;
pub mod bn254;
mod element;
mod family;
pub mod goldilocks;
mod prime_id;
pub mod profile;
mod simd;

pub use arithmetic::MODULUS;
pub use backend::FieldBackend;
pub use bls12_381::Bls12_381Fr;
pub use bn254::Bn254Fr;
pub use element::FieldElement;
pub use family::FieldFamily;
pub use goldilocks::GoldilocksFr;
pub use prime_id::PrimeId;

#[cfg(test)]
mod tests;
