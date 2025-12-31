use crate::{FileIngestion, StdinReader, TcpIngestion, UdpIngestion};
use logmate_core::config::IngestionConfig;
use logmate_core::LogEntry;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tracing::info;

/// Manages multiple ingestion sources running concurrently
pub struct IngestionManager {
    config: IngestionConfig,
    sender: Option<mpsc::Sender<LogEntry>>,
    handles: Vec<JoinHandle<()>>,
}

impl IngestionManager {
    /// Create a new ingestion manager
    pub fn new(config: IngestionConfig, sender: mpsc::Sender<LogEntry>) -> Self {
        Self {
            config,
            sender: Some(sender),
            handles: Vec::new(),
        }
    }

    /// Start all enabled ingestion sources
    ///
    /// Returns the number of sources started
    pub fn start(&mut self) -> usize {
        let mut count = 0;

        let sender = match self.sender.as_ref() {
            Some(s) => s,
            None => return 0, // Already started
        };

        // Start stdin ingestion
        if self.config.stdin.enabled {
            let sender = sender.clone();
            let handle = tokio::spawn(async move {
                let reader = StdinReader::new();
                if let Err(e) = reader.run(sender).await {
                    tracing::error!(error = %e, "Stdin ingestion error");
                }
            });
            self.handles.push(handle);
            count += 1;
            info!("Started stdin ingestion");
        }

        // Start TCP ingestion
        if self.config.tcp.enabled {
            let sender = sender.clone();
            let tcp = TcpIngestion::new(
                self.config.tcp.bind_address.clone(),
                self.config.tcp.port,
                self.config.tcp.max_connections,
            );
            let handle = tokio::spawn(async move {
                if let Err(e) = tcp.run(sender).await {
                    tracing::error!(error = %e, "TCP ingestion error");
                }
            });
            self.handles.push(handle);
            count += 1;
            info!(
                address = %self.config.tcp.bind_address,
                port = self.config.tcp.port,
                "Started TCP ingestion"
            );
        }

        // Start UDP ingestion
        if self.config.udp.enabled {
            let sender = sender.clone();
            let udp = UdpIngestion::new(
                self.config.udp.bind_address.clone(),
                self.config.udp.port,
            );
            let handle = tokio::spawn(async move {
                if let Err(e) = udp.run(sender).await {
                    tracing::error!(error = %e, "UDP ingestion error");
                }
            });
            self.handles.push(handle);
            count += 1;
            info!(
                address = %self.config.udp.bind_address,
                port = self.config.udp.port,
                "Started UDP ingestion"
            );
        }

        // Start file ingestion
        if self.config.file.enabled && !self.config.file.paths.is_empty() {
            let sender = sender.clone();
            let file_watcher = FileIngestion::new(
                self.config.file.paths.clone(),
                self.config.file.tail,
            );
            let handle = tokio::spawn(async move {
                if let Err(e) = file_watcher.run(sender).await {
                    tracing::error!(error = %e, "File ingestion error");
                }
            });
            self.handles.push(handle);
            count += 1;
            info!(
                paths = ?self.config.file.paths,
                tail = self.config.file.tail,
                "Started file ingestion"
            );
        }

        // Drop the original sender so the channel closes when all sources are done
        // For stdin-only mode, this allows the receiver to close when stdin ends
        // For network/file modes, those run forever anyway
        self.sender = None;

        count
    }

    /// Wait for all ingestion sources to complete
    ///
    /// Note: TCP and UDP sources run forever, so this will only return
    /// if they encounter an error or are cancelled.
    pub async fn wait(self) {
        for handle in self.handles {
            let _ = handle.await;
        }
    }

    /// Get the number of active ingestion sources
    pub fn active_count(&self) -> usize {
        self.handles.len()
    }

    /// Check if stdin ingestion is enabled
    pub fn has_stdin(&self) -> bool {
        self.config.stdin.enabled
    }

    /// Check if any network ingestion is enabled
    pub fn has_network(&self) -> bool {
        self.config.tcp.enabled || self.config.udp.enabled
    }

    /// Check if file ingestion is enabled
    pub fn has_file(&self) -> bool {
        self.config.file.enabled && !self.config.file.paths.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use logmate_core::config::{StdinConfig, TcpConfig, UdpConfig};

    fn create_config(stdin: bool, tcp: bool, udp: bool) -> IngestionConfig {
        IngestionConfig {
            stdin: StdinConfig { enabled: stdin },
            tcp: TcpConfig {
                enabled: tcp,
                bind_address: "127.0.0.1".to_string(),
                port: 0, // Random port
                max_connections: 10,
            },
            udp: UdpConfig {
                enabled: udp,
                bind_address: "127.0.0.1".to_string(),
                port: 0, // Random port
            },
            ..Default::default()
        }
    }

    #[test]
    fn test_manager_creation() {
        let config = create_config(true, false, false);
        let (sender, _receiver) = mpsc::channel(100);
        let manager = IngestionManager::new(config, sender);

        assert!(manager.has_stdin());
        assert!(!manager.has_network());
    }

    #[test]
    fn test_manager_network_detection() {
        let config = create_config(false, true, true);
        let (sender, _receiver) = mpsc::channel(100);
        let manager = IngestionManager::new(config, sender);

        assert!(!manager.has_stdin());
        assert!(manager.has_network());
    }
}
