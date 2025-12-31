//! LogMate Modules
//!
//! Processing modules for the LogMate observability engine.
//! Each module is feature-gated and can be enabled/disabled at compile time.

#[cfg(feature = "pattern")]
pub mod pattern;

// Re-export the core Module trait for convenience
pub use logmate_core::{Module, PassthroughModule};

// Re-export module implementations
#[cfg(feature = "pattern")]
pub use pattern::PatternDetectionModule;
