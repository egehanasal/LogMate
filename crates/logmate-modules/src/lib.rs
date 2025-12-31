//! LogMate Modules
//!
//! Processing modules for the LogMate observability engine.
//! Each module is feature-gated and can be enabled/disabled at compile time.

// Re-export the core Module trait for convenience
pub use logmate_core::{Module, PassthroughModule};

// Module implementations will be added here:
// #[cfg(feature = "pattern")]
// pub mod pattern;
//
// #[cfg(feature = "parser")]
// pub mod parser;
//
// #[cfg(feature = "metrics")]
// pub mod metrics;
//
// #[cfg(feature = "security")]
// pub mod security;
