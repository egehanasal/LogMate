//! LogMate Ingestion
//!
//! Input sources for the LogMate observability engine.
//! Supports stdin, TCP, UDP, and file watching.

pub mod stdin;

pub use stdin::StdinReader;

use logmate_core::LogEntry;
use tokio::sync::mpsc;

/// Default channel buffer size for log entries
pub const DEFAULT_CHANNEL_SIZE: usize = 10_000;

/// Create a new channel for log entries
pub fn create_log_channel(buffer_size: usize) -> (mpsc::Sender<LogEntry>, mpsc::Receiver<LogEntry>) {
    mpsc::channel(buffer_size)
}
