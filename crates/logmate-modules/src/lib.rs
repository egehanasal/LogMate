//! LogMate Modules
//!
//! Processing modules for the LogMate observability engine.
//! Each module is feature-gated and can be enabled/disabled at compile time.

#[cfg(feature = "pattern")]
pub mod pattern;

#[cfg(feature = "parser")]
pub mod parser;

#[cfg(feature = "metrics")]
pub mod performance;

#[cfg(feature = "security")]
pub mod security;

// Re-export the core Module trait for convenience
pub use logmate_core::{Module, PassthroughModule};

// Re-export module implementations
#[cfg(feature = "pattern")]
pub use pattern::PatternDetectionModule;

#[cfg(feature = "parser")]
pub use parser::StructuralParserModule;

#[cfg(feature = "metrics")]
pub use performance::PerformanceMetricsModule;

#[cfg(feature = "security")]
pub use security::SecurityModule;
