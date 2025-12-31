//! Loki integration for pushing logs to Grafana Loki
//!
//! This module provides a client for pushing log entries to Loki's HTTP API.

use logmate_core::config::LokiConfig;
use logmate_core::{EnrichedEntry, OutputError};
use reqwest::Client;
use serde::Serialize;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{debug, error, info, warn};

/// Loki push API request format
#[derive(Debug, Serialize)]
struct LokiPushRequest {
    streams: Vec<LokiStream>,
}

/// A stream of log entries with labels
#[derive(Debug, Serialize)]
struct LokiStream {
    stream: HashMap<String, String>,
    values: Vec<[String; 2]>,
}

/// Client for pushing logs to Loki
pub struct LokiClient {
    config: LokiConfig,
    client: Client,
    buffer: Arc<Mutex<Vec<EnrichedEntry>>>,
    last_flush: Arc<Mutex<Instant>>,
}

impl LokiClient {
    /// Create a new Loki client
    pub fn new(config: LokiConfig) -> Result<Self, OutputError> {
        let client = Client::builder()
            .timeout(Duration::from_secs(config.timeout_seconds as u64))
            .build()
            .map_err(|e| OutputError::Network(format!("Failed to create HTTP client: {}", e)))?;

        info!(
            endpoint = %config.endpoint,
            batch_size = config.batch_size,
            "Loki client initialized"
        );

        Ok(Self {
            config,
            client,
            buffer: Arc::new(Mutex::new(Vec::new())),
            last_flush: Arc::new(Mutex::new(Instant::now())),
        })
    }

    /// Push a log entry to Loki (buffered)
    pub async fn push(&self, entry: &EnrichedEntry) -> Result<(), OutputError> {
        let mut buffer = self.buffer.lock().await;
        buffer.push(entry.clone());

        let should_flush = buffer.len() >= self.config.batch_size;
        let time_since_flush = {
            let last = self.last_flush.lock().await;
            last.elapsed()
        };
        let timeout_flush = time_since_flush >= Duration::from_secs(self.config.flush_interval_seconds as u64);

        if should_flush || timeout_flush {
            let entries: Vec<EnrichedEntry> = buffer.drain(..).collect();
            drop(buffer); // Release lock before network call

            if !entries.is_empty() {
                self.flush_entries(&entries).await?;
                let mut last = self.last_flush.lock().await;
                *last = Instant::now();
            }
        }

        Ok(())
    }

    /// Force flush all buffered entries
    pub async fn flush(&self) -> Result<(), OutputError> {
        let mut buffer = self.buffer.lock().await;
        let entries: Vec<EnrichedEntry> = buffer.drain(..).collect();
        drop(buffer);

        if !entries.is_empty() {
            self.flush_entries(&entries).await?;
            let mut last = self.last_flush.lock().await;
            *last = Instant::now();
        }

        Ok(())
    }

    /// Flush entries to Loki
    async fn flush_entries(&self, entries: &[EnrichedEntry]) -> Result<(), OutputError> {
        let request = self.build_request(entries);

        debug!(
            streams = request.streams.len(),
            entries = entries.len(),
            "Pushing entries to Loki"
        );

        let response = self
            .client
            .post(&self.config.endpoint)
            .header("Content-Type", "application/json")
            .json(&request)
            .send()
            .await
            .map_err(|e| OutputError::Network(format!("Failed to push to Loki: {}", e)))?;

        if !response.status().is_success() {
            let status = response.status();
            let body: String = response.text().await.unwrap_or_default();
            error!(
                status = %status,
                body = %body,
                "Loki push failed"
            );
            return Err(OutputError::Network(format!(
                "Loki returned error {}: {}",
                status, body
            )));
        }

        debug!(entries = entries.len(), "Successfully pushed entries to Loki");
        Ok(())
    }

    /// Build a Loki push request from entries
    fn build_request(&self, entries: &[EnrichedEntry]) -> LokiPushRequest {
        // Group entries by their labels
        let mut streams: HashMap<String, Vec<[String; 2]>> = HashMap::new();

        for entry in entries {
            let labels = self.extract_labels(entry);
            let label_key = self.labels_to_key(&labels);

            // Loki expects timestamp in nanoseconds as string
            let timestamp_ns = entry
                .raw
                .received_at
                .timestamp_nanos_opt()
                .unwrap_or(0)
                .to_string();

            // Build log line
            let log_line = self.format_log_line(entry);

            streams
                .entry(label_key)
                .or_default()
                .push([timestamp_ns, log_line]);
        }

        // Convert to Loki format
        let streams: Vec<LokiStream> = streams
            .into_iter()
            .map(|(label_key, values)| {
                let labels = self.key_to_labels(&label_key);
                LokiStream {
                    stream: labels,
                    values,
                }
            })
            .collect();

        LokiPushRequest { streams }
    }

    /// Extract labels from an entry
    fn extract_labels(&self, entry: &EnrichedEntry) -> HashMap<String, String> {
        let mut labels = HashMap::new();

        // Add configured static labels
        for (key, value) in &self.config.labels {
            labels.insert(key.clone(), value.clone());
        }

        // Add source as label
        labels.insert("source".to_string(), entry.raw.source.to_string());

        // Add level if present
        if let Some(ref level) = entry.level {
            labels.insert("level".to_string(), level.to_string());
        }

        // Add job label (common Loki convention)
        if !labels.contains_key("job") {
            labels.insert("job".to_string(), "logmate".to_string());
        }

        labels
    }

    /// Convert labels to a stable string key for grouping
    fn labels_to_key(&self, labels: &HashMap<String, String>) -> String {
        let mut pairs: Vec<_> = labels.iter().collect();
        pairs.sort_by(|a, b| a.0.cmp(b.0));
        pairs
            .into_iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<_>>()
            .join(",")
    }

    /// Convert label key back to HashMap
    fn key_to_labels(&self, key: &str) -> HashMap<String, String> {
        key.split(',')
            .filter_map(|pair| {
                let mut parts = pair.splitn(2, '=');
                match (parts.next(), parts.next()) {
                    (Some(k), Some(v)) => Some((k.to_string(), v.to_string())),
                    _ => None,
                }
            })
            .collect()
    }

    /// Format log line for Loki
    fn format_log_line(&self, entry: &EnrichedEntry) -> String {
        // Include structured data if present
        if entry.structured.is_some() || !entry.security_flags.is_empty() || entry.latency_ms.is_some() {
            serde_json::to_string(entry).unwrap_or_else(|_| entry.raw.content.clone())
        } else {
            entry.raw.content.clone()
        }
    }

    /// Get the number of buffered entries
    pub async fn buffered_count(&self) -> usize {
        self.buffer.lock().await.len()
    }
}

impl Drop for LokiClient {
    fn drop(&mut self) {
        // Note: Can't do async flush in drop, but the buffer will be cleared
        // In production, call flush() explicitly before dropping
        let buffer = self.buffer.clone();
        let count = {
            if let Ok(guard) = buffer.try_lock() {
                guard.len()
            } else {
                0
            }
        };
        if count > 0 {
            warn!(
                entries = count,
                "Loki client dropped with buffered entries"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use logmate_core::LogEntry;

    fn create_test_config() -> LokiConfig {
        LokiConfig {
            enabled: true,
            endpoint: "http://localhost:3100/loki/api/v1/push".to_string(),
            batch_size: 100,
            flush_interval_seconds: 5,
            timeout_seconds: 30,
            labels: {
                let mut labels = HashMap::new();
                labels.insert("app".to_string(), "test".to_string());
                labels
            },
        }
    }

    fn create_test_entry(content: &str, level: Option<logmate_core::LogLevel>) -> EnrichedEntry {
        EnrichedEntry {
            raw: LogEntry {
                received_at: Utc::now(),
                source: logmate_core::LogSource::Stdin,
                content: content.to_string(),
                metadata: HashMap::new(),
            },
            level,
            error_code: None,
            structured: None,
            security_flags: Vec::new(),
            latency_ms: None,
            tags: HashMap::new(),
        }
    }

    #[test]
    fn test_extract_labels() {
        let config = create_test_config();
        let client = LokiClient::new(config).unwrap();

        let entry = create_test_entry("test", Some(logmate_core::LogLevel::Error));
        let labels = client.extract_labels(&entry);

        assert_eq!(labels.get("app"), Some(&"test".to_string()));
        assert_eq!(labels.get("source"), Some(&"stdin".to_string()));
        assert_eq!(labels.get("level"), Some(&"ERROR".to_string()));
        assert_eq!(labels.get("job"), Some(&"logmate".to_string()));
    }

    #[test]
    fn test_labels_to_key() {
        let config = create_test_config();
        let client = LokiClient::new(config).unwrap();

        let mut labels = HashMap::new();
        labels.insert("a".to_string(), "1".to_string());
        labels.insert("b".to_string(), "2".to_string());

        let key = client.labels_to_key(&labels);
        assert_eq!(key, "a=1,b=2");
    }

    #[test]
    fn test_key_to_labels() {
        let config = create_test_config();
        let client = LokiClient::new(config).unwrap();

        let key = "a=1,b=2";
        let labels = client.key_to_labels(key);

        assert_eq!(labels.get("a"), Some(&"1".to_string()));
        assert_eq!(labels.get("b"), Some(&"2".to_string()));
    }

    #[test]
    fn test_build_request() {
        let config = create_test_config();
        let client = LokiClient::new(config).unwrap();

        let entries = vec![
            create_test_entry("error message", Some(logmate_core::LogLevel::Error)),
            create_test_entry("info message", Some(logmate_core::LogLevel::Info)),
        ];

        let request = client.build_request(&entries);

        // Should have 2 streams (different levels)
        assert_eq!(request.streams.len(), 2);
    }

    #[test]
    fn test_format_log_line_simple() {
        let config = create_test_config();
        let client = LokiClient::new(config).unwrap();

        let entry = create_test_entry("simple message", None);
        let line = client.format_log_line(&entry);

        assert_eq!(line, "simple message");
    }

    #[test]
    fn test_format_log_line_with_structured() {
        let config = create_test_config();
        let client = LokiClient::new(config).unwrap();

        let mut entry = create_test_entry("structured message", None);
        entry.structured = Some(serde_json::json!({"key": "value"}));

        let line = client.format_log_line(&entry);

        // Should be JSON
        assert!(line.contains("structured"));
        assert!(line.contains("key"));
    }
}
