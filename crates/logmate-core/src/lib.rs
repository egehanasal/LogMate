//! LogMate Core
//!
//! Core types, traits, and utilities for the LogMate observability engine.

pub mod config;
pub mod error;
pub mod log_entry;
pub mod traits;

// Re-export commonly used types
pub use config::Config;
pub use error::{IngestionError, LogMateError, OutputError, Result};
pub use log_entry::{EnrichedEntry, LogEntry, LogLevel, LogSource, SecurityFlag};
pub use traits::{Module, PassthroughModule};
