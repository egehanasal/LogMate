use logmate_core::{IngestionError, LogEntry, LogSource};
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// UDP socket listener for log ingestion (syslog-compatible)
pub struct UdpIngestion {
    bind_address: String,
    port: u16,
    max_packet_size: usize,
}

impl UdpIngestion {
    /// Create a new UDP ingestion listener
    pub fn new(bind_address: String, port: u16) -> Self {
        Self {
            bind_address,
            port,
            max_packet_size: 65535, // Max UDP packet size
        }
    }

    /// Create with custom max packet size
    pub fn with_max_packet_size(mut self, size: usize) -> Self {
        self.max_packet_size = size;
        self
    }

    /// Get the full bind address (ip:port)
    pub fn bind_addr(&self) -> String {
        format!("{}:{}", self.bind_address, self.port)
    }

    /// Start listening for UDP packets and send log entries through the channel
    pub async fn run(self, sender: mpsc::Sender<LogEntry>) -> Result<(), IngestionError> {
        let addr = self.bind_addr();
        let socket = UdpSocket::bind(&addr)
            .await
            .map_err(|e| IngestionError::Udp(format!("Failed to bind to {}: {}", addr, e)))?;

        info!(address = %addr, "UDP listener started");

        let mut buf = vec![0u8; self.max_packet_size];
        let mut count: u64 = 0;

        loop {
            match socket.recv_from(&mut buf).await {
                Ok((len, peer_addr)) => {
                    // Parse the received data as UTF-8
                    let data = match std::str::from_utf8(&buf[..len]) {
                        Ok(s) => s.trim().to_string(),
                        Err(e) => {
                            warn!(peer = %peer_addr, error = %e, "Invalid UTF-8 in UDP packet");
                            continue;
                        }
                    };

                    if data.is_empty() {
                        continue;
                    }

                    // Handle multiple lines in a single packet
                    for line in data.lines() {
                        if line.is_empty() {
                            continue;
                        }

                        let source = LogSource::Udp {
                            addr: peer_addr.to_string(),
                        };
                        let entry = LogEntry::new(source, line.to_string());

                        debug!(peer = %peer_addr, "Received log line via UDP");

                        if sender.send(entry).await.is_err() {
                            warn!("Channel closed, stopping UDP listener");
                            return Err(IngestionError::ChannelClosed);
                        }
                        count += 1;
                    }

                    if count % 10000 == 0 && count > 0 {
                        debug!(total = count, "UDP packets processed");
                    }
                }
                Err(e) => {
                    error!(error = %e, "Failed to receive UDP packet");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_ingestion_creation() {
        let udp = UdpIngestion::new("127.0.0.1".to_string(), 9515);
        assert_eq!(udp.bind_addr(), "127.0.0.1:9515");
        assert_eq!(udp.max_packet_size, 65535);
    }

    #[test]
    fn test_udp_custom_packet_size() {
        let udp = UdpIngestion::new("127.0.0.1".to_string(), 9515)
            .with_max_packet_size(8192);
        assert_eq!(udp.max_packet_size, 8192);
    }

    #[tokio::test]
    async fn test_udp_receive() {
        use tokio::net::UdpSocket;

        // Bind server on random port
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_addr = server.local_addr().unwrap();

        let (sender, mut receiver) = mpsc::channel(100);

        // Spawn UDP listener
        let handle = tokio::spawn(async move {
            let mut buf = vec![0u8; 1024];

            // Receive one packet
            let (len, peer) = server.recv_from(&mut buf).await.unwrap();
            let data = std::str::from_utf8(&buf[..len]).unwrap().trim().to_string();

            let entry = LogEntry::new(
                LogSource::Udp { addr: peer.to_string() },
                data,
            );
            sender.send(entry).await.unwrap();
        });

        // Send data
        let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        client.send_to(b"ERROR: Test UDP message\n", server_addr).await.unwrap();

        // Wait for handler
        handle.await.unwrap();

        // Check received entry
        let entry = receiver.recv().await.unwrap();
        assert_eq!(entry.content, "ERROR: Test UDP message");
        assert!(matches!(entry.source, LogSource::Udp { .. }));
    }
}
