//! LogMate Ingestion
//!
//! Input sources for the LogMate observability engine.
//! Supports stdin, TCP, UDP, and file watching.

pub mod file;
pub mod manager;
pub mod stdin;
pub mod tcp;
pub mod udp;

pub use file::FileIngestion;
pub use manager::IngestionManager;
pub use stdin::StdinReader;
pub use tcp::TcpIngestion;
pub use udp::UdpIngestion;

use logmate_core::LogEntry;
use tokio::sync::mpsc;

/// Default channel buffer size for log entries
pub const DEFAULT_CHANNEL_SIZE: usize = 10_000;

/// Create a new channel for log entries
pub fn create_log_channel(buffer_size: usize) -> (mpsc::Sender<LogEntry>, mpsc::Receiver<LogEntry>) {
    mpsc::channel(buffer_size)
}
