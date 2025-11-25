//! Unified synchronization types to facilitate migration and provide thread-safety.
//!
//! We use parking_lot because:
//! - It has no poisoning (more ergonomic).
//! - Better performance in cases without contention.
//! - API compatible with std (mostly).

pub use parking_lot::{Mutex, MutexGuard, RwLock, RwLockReadGuard, RwLockWriteGuard};
pub use std::sync::Arc;

/// Alias for the common pattern Arc<RwLock<T>>
pub type Shared<T> = Arc<RwLock<T>>;

/// Helper to create Shared<T> easily
pub fn shared<T>(value: T) -> Shared<T> {
    Arc::new(RwLock::new(value))
}
