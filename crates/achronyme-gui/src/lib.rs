pub mod bridge;
pub mod components;
pub mod runner;
pub mod style;

// We expose these modules so the VM adapter can use them.
// No registration logic here to avoid circular deps.
