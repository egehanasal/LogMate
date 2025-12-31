use logmate_core::{IngestionError, LogEntry};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

/// Reads log lines from stdin and sends them through a channel
pub struct StdinReader {
    #[allow(dead_code)] // Will be used when we add buffered reading
    buffer_size: usize,
}

impl StdinReader {
    /// Create a new stdin reader with default buffer size
    pub fn new() -> Self {
        Self { buffer_size: 1024 }
    }

    /// Create a new stdin reader with custom buffer size
    pub fn with_buffer_size(buffer_size: usize) -> Self {
        Self { buffer_size }
    }

    /// Start reading from stdin and send entries through the provided sender
    ///
    /// This will read until EOF is reached or the channel is closed.
    /// Returns the number of lines read.
    pub async fn run(
        self,
        sender: mpsc::Sender<LogEntry>,
    ) -> Result<usize, IngestionError> {
        let stdin = tokio::io::stdin();
        let reader = BufReader::new(stdin);
        let mut lines = reader.lines();
        let mut count = 0;

        info!("Starting stdin ingestion");

        loop {
            match lines.next_line().await {
                Ok(Some(line)) => {
                    if line.is_empty() {
                        continue;
                    }

                    let entry = LogEntry::from_stdin(line);
                    debug!(content = %entry.content, "Received log line from stdin");

                    if sender.send(entry).await.is_err() {
                        warn!("Channel closed, stopping stdin reader");
                        return Err(IngestionError::ChannelClosed);
                    }
                    count += 1;
                }
                Ok(None) => {
                    // EOF reached
                    info!(lines_read = count, "Stdin EOF reached");
                    break;
                }
                Err(e) => {
                    warn!(error = %e, "Error reading from stdin");
                    return Err(IngestionError::Stdin(e.to_string()));
                }
            }
        }

        Ok(count)
    }
}

impl Default for StdinReader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_stdin_reader_creation() {
        let reader = StdinReader::new();
        assert_eq!(reader.buffer_size, 1024);

        let reader = StdinReader::with_buffer_size(4096);
        assert_eq!(reader.buffer_size, 4096);
    }
}
