//! Prometheus metrics integration
//!
//! This module provides metrics collection and an HTTP endpoint for Prometheus scraping.

use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use logmate_core::config::PrometheusConfig;
use logmate_core::OutputError;
use prometheus::{
    Counter, CounterVec, Encoder, Gauge, Histogram, HistogramOpts, Opts, Registry, TextEncoder,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{debug, error, info};

/// Metrics collector for LogMate
pub struct MetricsCollector {
    registry: Registry,

    // Core metrics
    logs_received_total: Counter,
    logs_processed_total: Counter,
    logs_by_level: CounterVec,
    logs_by_source: CounterVec,

    // Processing metrics
    processing_duration_seconds: Histogram,
    processing_errors_total: Counter,

    // Security metrics
    security_flags_total: CounterVec,

    // Performance metrics
    latency_extracted_total: Counter,
    latency_histogram: Histogram,

    // Output metrics
    output_bytes_total: CounterVec,
    output_errors_total: CounterVec,

    // Buffer metrics
    buffer_size: Gauge,
    loki_buffer_size: Gauge,
}

impl MetricsCollector {
    /// Create a new metrics collector
    pub fn new() -> Result<Self, OutputError> {
        let registry = Registry::new();

        // Core metrics
        let logs_received_total = Counter::new(
            "logmate_logs_received_total",
            "Total number of log entries received",
        )
        .map_err(|e| OutputError::Grafana(format!("Failed to create metric: {}", e)))?;

        let logs_processed_total = Counter::new(
            "logmate_logs_processed_total",
            "Total number of log entries processed",
        )
        .map_err(|e| OutputError::Grafana(format!("Failed to create metric: {}", e)))?;

        let logs_by_level = CounterVec::new(
            Opts::new("logmate_logs_by_level_total", "Log entries by level"),
            &["level"],
        )
        .map_err(|e| OutputError::Grafana(format!("Failed to create metric: {}", e)))?;

        let logs_by_source = CounterVec::new(
            Opts::new("logmate_logs_by_source_total", "Log entries by source"),
            &["source"],
        )
        .map_err(|e| OutputError::Grafana(format!("Failed to create metric: {}", e)))?;

        // Processing metrics
        let processing_duration_seconds = Histogram::with_opts(HistogramOpts::new(
            "logmate_processing_duration_seconds",
            "Time spent processing log entries",
        ))
        .map_err(|e| OutputError::Grafana(format!("Failed to create metric: {}", e)))?;

        let processing_errors_total = Counter::new(
            "logmate_processing_errors_total",
            "Total number of processing errors",
        )
        .map_err(|e| OutputError::Grafana(format!("Failed to create metric: {}", e)))?;

        // Security metrics
        let security_flags_total = CounterVec::new(
            Opts::new(
                "logmate_security_flags_total",
                "Security flags detected in logs",
            ),
            &["flag"],
        )
        .map_err(|e| OutputError::Grafana(format!("Failed to create metric: {}", e)))?;

        // Performance metrics
        let latency_extracted_total = Counter::new(
            "logmate_latency_extracted_total",
            "Total number of latency values extracted",
        )
        .map_err(|e| OutputError::Grafana(format!("Failed to create metric: {}", e)))?;

        let latency_histogram = Histogram::with_opts(
            HistogramOpts::new(
                "logmate_extracted_latency_ms",
                "Distribution of extracted latency values",
            )
            .buckets(vec![1.0, 5.0, 10.0, 25.0, 50.0, 100.0, 250.0, 500.0, 1000.0, 5000.0]),
        )
        .map_err(|e| OutputError::Grafana(format!("Failed to create metric: {}", e)))?;

        // Output metrics
        let output_bytes_total = CounterVec::new(
            Opts::new(
                "logmate_output_bytes_total",
                "Total bytes written to outputs",
            ),
            &["output"],
        )
        .map_err(|e| OutputError::Grafana(format!("Failed to create metric: {}", e)))?;

        let output_errors_total = CounterVec::new(
            Opts::new(
                "logmate_output_errors_total",
                "Total errors writing to outputs",
            ),
            &["output"],
        )
        .map_err(|e| OutputError::Grafana(format!("Failed to create metric: {}", e)))?;

        // Buffer metrics
        let buffer_size = Gauge::new(
            "logmate_buffer_size",
            "Current size of the processing buffer",
        )
        .map_err(|e| OutputError::Grafana(format!("Failed to create metric: {}", e)))?;

        let loki_buffer_size =
            Gauge::new("logmate_loki_buffer_size", "Current size of the Loki buffer")
                .map_err(|e| OutputError::Grafana(format!("Failed to create metric: {}", e)))?;

        // Register all metrics
        registry
            .register(Box::new(logs_received_total.clone()))
            .map_err(|e| OutputError::Grafana(format!("Failed to register metric: {}", e)))?;
        registry
            .register(Box::new(logs_processed_total.clone()))
            .map_err(|e| OutputError::Grafana(format!("Failed to register metric: {}", e)))?;
        registry
            .register(Box::new(logs_by_level.clone()))
            .map_err(|e| OutputError::Grafana(format!("Failed to register metric: {}", e)))?;
        registry
            .register(Box::new(logs_by_source.clone()))
            .map_err(|e| OutputError::Grafana(format!("Failed to register metric: {}", e)))?;
        registry
            .register(Box::new(processing_duration_seconds.clone()))
            .map_err(|e| OutputError::Grafana(format!("Failed to register metric: {}", e)))?;
        registry
            .register(Box::new(processing_errors_total.clone()))
            .map_err(|e| OutputError::Grafana(format!("Failed to register metric: {}", e)))?;
        registry
            .register(Box::new(security_flags_total.clone()))
            .map_err(|e| OutputError::Grafana(format!("Failed to register metric: {}", e)))?;
        registry
            .register(Box::new(latency_extracted_total.clone()))
            .map_err(|e| OutputError::Grafana(format!("Failed to register metric: {}", e)))?;
        registry
            .register(Box::new(latency_histogram.clone()))
            .map_err(|e| OutputError::Grafana(format!("Failed to register metric: {}", e)))?;
        registry
            .register(Box::new(output_bytes_total.clone()))
            .map_err(|e| OutputError::Grafana(format!("Failed to register metric: {}", e)))?;
        registry
            .register(Box::new(output_errors_total.clone()))
            .map_err(|e| OutputError::Grafana(format!("Failed to register metric: {}", e)))?;
        registry
            .register(Box::new(buffer_size.clone()))
            .map_err(|e| OutputError::Grafana(format!("Failed to register metric: {}", e)))?;
        registry
            .register(Box::new(loki_buffer_size.clone()))
            .map_err(|e| OutputError::Grafana(format!("Failed to register metric: {}", e)))?;

        Ok(Self {
            registry,
            logs_received_total,
            logs_processed_total,
            logs_by_level,
            logs_by_source,
            processing_duration_seconds,
            processing_errors_total,
            security_flags_total,
            latency_extracted_total,
            latency_histogram,
            output_bytes_total,
            output_errors_total,
            buffer_size,
            loki_buffer_size,
        })
    }

    /// Record a received log entry
    pub fn record_received(&self) {
        self.logs_received_total.inc();
    }

    /// Record a processed log entry
    pub fn record_processed(&self, level: Option<&str>, source: &str) {
        self.logs_processed_total.inc();

        if let Some(level) = level {
            self.logs_by_level.with_label_values(&[level]).inc();
        }

        // Normalize source for metrics (remove IP/port details)
        let normalized_source = if source.starts_with("tcp://") {
            "tcp"
        } else if source.starts_with("udp://") {
            "udp"
        } else if source.starts_with("file://") {
            "file"
        } else if source == "stdin" {
            "stdin"
        } else {
            "unknown"
        };

        self.logs_by_source
            .with_label_values(&[normalized_source])
            .inc();
    }

    /// Record processing duration
    pub fn record_processing_duration(&self, seconds: f64) {
        self.processing_duration_seconds.observe(seconds);
    }

    /// Record a processing error
    pub fn record_processing_error(&self) {
        self.processing_errors_total.inc();
    }

    /// Record a security flag detection
    pub fn record_security_flag(&self, flag: &str) {
        self.security_flags_total.with_label_values(&[flag]).inc();
    }

    /// Record extracted latency
    pub fn record_latency(&self, latency_ms: f64) {
        self.latency_extracted_total.inc();
        self.latency_histogram.observe(latency_ms);
    }

    /// Record bytes written to an output
    pub fn record_output_bytes(&self, output: &str, bytes: u64) {
        self.output_bytes_total
            .with_label_values(&[output])
            .inc_by(bytes as f64);
    }

    /// Record an output error
    pub fn record_output_error(&self, output: &str) {
        self.output_errors_total.with_label_values(&[output]).inc();
    }

    /// Update buffer size
    pub fn set_buffer_size(&self, size: usize) {
        self.buffer_size.set(size as f64);
    }

    /// Update Loki buffer size
    pub fn set_loki_buffer_size(&self, size: usize) {
        self.loki_buffer_size.set(size as f64);
    }

    /// Get metrics in Prometheus text format
    pub fn gather(&self) -> String {
        let encoder = TextEncoder::new();
        let metric_families = self.registry.gather();
        let mut buffer = Vec::new();
        encoder.encode(&metric_families, &mut buffer).unwrap();
        String::from_utf8(buffer).unwrap()
    }
}

impl Default for MetricsCollector {
    fn default() -> Self {
        Self::new().expect("Failed to create default metrics collector")
    }
}

/// HTTP server for serving Prometheus metrics
pub struct MetricsServer {
    config: PrometheusConfig,
    collector: Arc<MetricsCollector>,
}

impl MetricsServer {
    /// Create a new metrics server
    pub fn new(config: PrometheusConfig, collector: Arc<MetricsCollector>) -> Self {
        Self { config, collector }
    }

    /// Start the metrics server
    pub async fn run(&self) -> Result<(), OutputError> {
        let addr: SocketAddr = format!("{}:{}", self.config.bind_address, self.config.port)
            .parse()
            .map_err(|e| OutputError::Grafana(format!("Invalid address: {}", e)))?;

        let listener = TcpListener::bind(addr)
            .await
            .map_err(|e| OutputError::Grafana(format!("Failed to bind: {}", e)))?;

        info!(
            address = %addr,
            path = %self.config.path,
            "Prometheus metrics server started"
        );

        let collector = self.collector.clone();
        let path = self.config.path.clone();

        loop {
            let (stream, _) = listener
                .accept()
                .await
                .map_err(|e| OutputError::Grafana(format!("Accept failed: {}", e)))?;

            let io = TokioIo::new(stream);
            let collector = collector.clone();
            let path = path.clone();

            tokio::spawn(async move {
                let service = service_fn(|req: Request<hyper::body::Incoming>| {
                    let collector = collector.clone();
                    let path = path.clone();
                    async move { handle_request(req, &collector, &path) }
                });

                if let Err(err) = http1::Builder::new().serve_connection(io, service).await {
                    error!(error = %err, "Error serving connection");
                }
            });
        }
    }
}

/// Handle an HTTP request
fn handle_request(
    req: Request<hyper::body::Incoming>,
    collector: &MetricsCollector,
    metrics_path: &str,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path();

    debug!(path = %path, "Metrics request");

    if path == metrics_path {
        let metrics = collector.gather();
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/plain; charset=utf-8")
            .body(Full::new(Bytes::from(metrics)))
            .unwrap())
    } else if path == "/health" || path == "/healthz" {
        Ok(Response::builder()
            .status(StatusCode::OK)
            .header("Content-Type", "text/plain")
            .body(Full::new(Bytes::from("OK")))
            .unwrap())
    } else {
        Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from("Not Found")))
            .unwrap())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_metrics_collector_creation() {
        let collector = MetricsCollector::new().unwrap();
        assert!(collector.gather().len() > 0);
    }

    #[test]
    fn test_record_received() {
        let collector = MetricsCollector::new().unwrap();
        collector.record_received();
        collector.record_received();

        let metrics = collector.gather();
        assert!(metrics.contains("logmate_logs_received_total 2"));
    }

    #[test]
    fn test_record_processed() {
        let collector = MetricsCollector::new().unwrap();
        collector.record_processed(Some("ERROR"), "stdin");
        collector.record_processed(Some("INFO"), "tcp://127.0.0.1:1234");
        collector.record_processed(None, "file:///var/log/test.log");

        let metrics = collector.gather();
        assert!(metrics.contains("logmate_logs_processed_total 3"));
        assert!(metrics.contains(r#"logmate_logs_by_level_total{level="ERROR"} 1"#));
        assert!(metrics.contains(r#"logmate_logs_by_level_total{level="INFO"} 1"#));
        assert!(metrics.contains(r#"logmate_logs_by_source_total{source="stdin"} 1"#));
        assert!(metrics.contains(r#"logmate_logs_by_source_total{source="tcp"} 1"#));
        assert!(metrics.contains(r#"logmate_logs_by_source_total{source="file"} 1"#));
    }

    #[test]
    fn test_record_security_flag() {
        let collector = MetricsCollector::new().unwrap();
        collector.record_security_flag("sql_injection");
        collector.record_security_flag("sql_injection");
        collector.record_security_flag("xss");

        let metrics = collector.gather();
        assert!(metrics.contains(r#"logmate_security_flags_total{flag="sql_injection"} 2"#));
        assert!(metrics.contains(r#"logmate_security_flags_total{flag="xss"} 1"#));
    }

    #[test]
    fn test_record_latency() {
        let collector = MetricsCollector::new().unwrap();
        collector.record_latency(50.0);
        collector.record_latency(150.0);
        collector.record_latency(500.0);

        let metrics = collector.gather();
        assert!(metrics.contains("logmate_latency_extracted_total 3"));
        assert!(metrics.contains("logmate_extracted_latency_ms_bucket"));
    }

    #[test]
    fn test_record_output_bytes() {
        let collector = MetricsCollector::new().unwrap();
        collector.record_output_bytes("stdout", 100);
        collector.record_output_bytes("file", 500);

        let metrics = collector.gather();
        assert!(metrics.contains(r#"logmate_output_bytes_total{output="stdout"} 100"#));
        assert!(metrics.contains(r#"logmate_output_bytes_total{output="file"} 500"#));
    }

    #[test]
    fn test_buffer_size() {
        let collector = MetricsCollector::new().unwrap();
        collector.set_buffer_size(42);

        let metrics = collector.gather();
        assert!(metrics.contains("logmate_buffer_size 42"));
    }
}
