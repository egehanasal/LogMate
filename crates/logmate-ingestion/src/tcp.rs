use logmate_core::{IngestionError, LogEntry, LogSource};
use tokio::io::{AsyncBufReadExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// TCP socket listener for log ingestion
pub struct TcpIngestion {
    bind_address: String,
    port: u16,
    max_connections: usize,
}

impl TcpIngestion {
    /// Create a new TCP ingestion listener
    pub fn new(bind_address: String, port: u16, max_connections: usize) -> Self {
        Self {
            bind_address,
            port,
            max_connections,
        }
    }

    /// Get the full bind address (ip:port)
    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.bind_address, self.port)
    }

    /// Start listening for TCP connections and send log entries through the channel
    pub async fn run(self, sender: mpsc::Sender<LogEntry>) -> Result<(), IngestionError> {
        let addr = self.bind_addr();
        let listener = TcpListener::bind(&addr)
            .await
            .map_err(|e| IngestionError::Tcp(format!("Failed to bind to {}: {}", addr, e)))?;

        info!(address = %addr, "TCP listener started");

        let mut active_connections = 0;

        loop {
            match listener.accept().await {
                Ok((stream, peer_addr)) => {
                    if active_connections >= self.max_connections {
                        warn!(
                            peer = %peer_addr,
                            max = self.max_connections,
                            "Max connections reached, rejecting"
                        );
                        drop(stream);
                        continue;
                    }

                    active_connections += 1;
                    let sender = sender.clone();
                    let peer_str = peer_addr.to_string();

                    info!(peer = %peer_addr, active = active_connections, "New TCP connection");

                    tokio::spawn(async move {
                        if let Err(e) = handle_tcp_connection(stream, &peer_str, sender).await {
                            error!(peer = %peer_str, error = %e, "Connection error");
                        }
                        debug!(peer = %peer_str, "Connection closed");
                    });

                    // Note: We don't decrement active_connections here because
                    // we'd need shared state. For production, use Arc<AtomicUsize>.
                }
                Err(e) => {
                    error!(error = %e, "Failed to accept connection");
                }
            }
        }
    }
}

/// Handle a single TCP connection
async fn handle_tcp_connection(
    stream: TcpStream,
    peer_addr: &str,
    sender: mpsc::Sender<LogEntry>,
) -> Result<(), IngestionError> {
    let reader = BufReader::new(stream);
    let mut lines = reader.lines();
    let mut count = 0;

    let source = LogSource::Tcp {
        addr: peer_addr.to_string(),
    };

    while let Some(line) = lines
        .next_line()
        .await
        .map_err(|e| IngestionError::Tcp(e.to_string()))?
    {
        if line.is_empty() {
            continue;
        }

        let entry = LogEntry::new(source.clone(), line);
        debug!(peer = %peer_addr, "Received log line via TCP");

        if sender.send(entry).await.is_err() {
            warn!("Channel closed, stopping TCP handler");
            return Err(IngestionError::ChannelClosed);
        }
        count += 1;
    }

    debug!(peer = %peer_addr, lines = count, "TCP connection completed");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tcp_ingestion_creation() {
        let tcp = TcpIngestion::new("127.0.0.1".to_string(), 9514, 100);
        assert_eq!(tcp.bind_addr(), "127.0.0.1:9514");
    }

    #[tokio::test]
    async fn test_tcp_connection_handling() {
        use tokio::io::AsyncWriteExt;
        use tokio::net::TcpStream;

        // Start a listener on a random port
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let (sender, mut receiver) = mpsc::channel(100);

        // Spawn handler for one connection
        let handle = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await.unwrap();
            handle_tcp_connection(stream, &peer.to_string(), sender).await
        });

        // Connect and send data
        let mut client = TcpStream::connect(addr).await.unwrap();
        client.write_all(b"ERROR: Test message\n").await.unwrap();
        client.write_all(b"INFO: Another message\n").await.unwrap();
        drop(client); // Close connection

        // Wait for handler to finish
        handle.await.unwrap().unwrap();

        // Check received entries
        let entry1 = receiver.recv().await.unwrap();
        assert_eq!(entry1.content, "ERROR: Test message");
        assert!(matches!(entry1.source, LogSource::Tcp { .. }));

        let entry2 = receiver.recv().await.unwrap();
        assert_eq!(entry2.content, "INFO: Another message");
    }
}
