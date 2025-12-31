use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use crate::error::LogMateError;

/// Main configuration for LogMate
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    /// General settings
    pub general: GeneralConfig,

    /// Ingestion sources configuration
    pub ingestion: IngestionConfig,

    /// Processing modules configuration
    pub modules: ModulesConfig,

    /// Output targets configuration
    pub output: OutputConfig,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            general: GeneralConfig::default(),
            ingestion: IngestionConfig::default(),
            modules: ModulesConfig::default(),
            output: OutputConfig::default(),
        }
    }
}

impl Config {
    /// Load configuration from a TOML file
    pub fn from_file(path: &PathBuf) -> Result<Self, LogMateError> {
        let content = std::fs::read_to_string(path)
            .map_err(|e| LogMateError::Config(format!("Failed to read config file: {}", e)))?;
        Self::from_str(&content)
    }

    /// Parse configuration from a TOML string
    pub fn from_str(content: &str) -> Result<Self, LogMateError> {
        toml::from_str(content)
            .map_err(|e| LogMateError::Config(format!("Failed to parse config: {}", e)))
    }

    /// Serialize configuration to TOML string
    pub fn to_toml(&self) -> Result<String, LogMateError> {
        toml::to_string_pretty(self)
            .map_err(|e| LogMateError::Config(format!("Failed to serialize config: {}", e)))
    }
}

/// General settings
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GeneralConfig {
    /// Instance name for identification
    pub instance_name: String,

    /// Internal log level: trace, debug, info, warn, error
    pub log_level: String,

    /// Buffer size for backpressure handling
    pub buffer_size: usize,
}

impl Default for GeneralConfig {
    fn default() -> Self {
        Self {
            instance_name: "logmate".to_string(),
            log_level: "warn".to_string(),
            buffer_size: 10_000,
        }
    }
}

/// Ingestion sources configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IngestionConfig {
    /// Stdin ingestion
    pub stdin: StdinConfig,

    /// TCP socket ingestion
    pub tcp: TcpConfig,

    /// UDP socket ingestion
    pub udp: UdpConfig,

    /// File watching ingestion
    pub file: FileConfig,
}

impl Default for IngestionConfig {
    fn default() -> Self {
        Self {
            stdin: StdinConfig::default(),
            tcp: TcpConfig::default(),
            udp: UdpConfig::default(),
            file: FileConfig::default(),
        }
    }
}

/// Stdin ingestion configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StdinConfig {
    pub enabled: bool,
}

impl Default for StdinConfig {
    fn default() -> Self {
        Self { enabled: true }
    }
}

/// TCP ingestion configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct TcpConfig {
    pub enabled: bool,
    pub bind_address: String,
    pub port: u16,
    pub max_connections: usize,
}

impl Default for TcpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: "127.0.0.1".to_string(),
            port: 9514,
            max_connections: 100,
        }
    }
}

/// UDP ingestion configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct UdpConfig {
    pub enabled: bool,
    pub bind_address: String,
    pub port: u16,
}

impl Default for UdpConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: "127.0.0.1".to_string(),
            port: 9515,
        }
    }
}

/// File watching configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FileConfig {
    pub enabled: bool,
    /// Paths or glob patterns to watch
    pub paths: Vec<String>,
    /// Start from end of file (tail mode)
    pub tail: bool,
}

impl Default for FileConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            paths: Vec::new(),
            tail: true,
        }
    }
}

/// Processing modules configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ModulesConfig {
    /// Pattern detection module
    pub pattern_detection: PatternDetectionConfig,

    /// Performance metrics module
    pub performance_metrics: PerformanceMetricsConfig,

    /// Security and anomaly detection module
    pub security: SecurityConfig,

    /// Structural parser module
    pub structural_parser: StructuralParserConfig,
}

impl Default for ModulesConfig {
    fn default() -> Self {
        Self {
            pattern_detection: PatternDetectionConfig::default(),
            performance_metrics: PerformanceMetricsConfig::default(),
            security: SecurityConfig::default(),
            structural_parser: StructuralParserConfig::default(),
        }
    }
}

/// Pattern detection module configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PatternDetectionConfig {
    pub enabled: bool,
    /// Detect log levels (ERROR, WARN, INFO, etc.)
    pub detect_levels: bool,
    /// Detect error codes
    pub detect_error_codes: bool,
    /// Custom regex patterns with named capture groups
    pub custom_patterns: Vec<CustomPattern>,
}

impl Default for PatternDetectionConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            detect_levels: true,
            detect_error_codes: true,
            custom_patterns: Vec::new(),
        }
    }
}

/// Custom pattern definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomPattern {
    pub name: String,
    pub pattern: String,
}

/// Performance metrics module configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PerformanceMetricsConfig {
    pub enabled: bool,
    /// Patterns to extract latency values
    pub latency_patterns: Vec<String>,
    /// Rolling window durations (e.g., "1m", "5m", "15m")
    pub windows: Vec<String>,
    /// Percentiles to calculate
    pub percentiles: Vec<u8>,
}

impl Default for PerformanceMetricsConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            latency_patterns: vec![
                r"took (?P<duration>\d+)(?P<unit>ms|s|us)".to_string(),
                r"latency[=:]\s*(?P<duration>\d+\.?\d*)(?P<unit>ms|s)?".to_string(),
            ],
            windows: vec!["1m".to_string(), "5m".to_string(), "15m".to_string()],
            percentiles: vec![50, 90, 95, 99],
        }
    }
}

/// Security module configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct SecurityConfig {
    pub enabled: bool,
    pub detect_sql_injection: bool,
    pub detect_xss: bool,
    pub detect_path_traversal: bool,
    pub detect_auth_failures: bool,
    /// Custom sensitive data patterns
    pub sensitive_patterns: Vec<CustomPattern>,
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            detect_sql_injection: true,
            detect_xss: true,
            detect_path_traversal: true,
            detect_auth_failures: true,
            sensitive_patterns: Vec::new(),
        }
    }
}

/// Structural parser module configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StructuralParserConfig {
    pub enabled: bool,
    /// Auto-detect log format
    pub auto_detect: bool,
    /// Explicit format: apache_combined, nginx, syslog, json, kv
    pub format: Option<String>,
}

impl Default for StructuralParserConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            auto_detect: true,
            format: None,
        }
    }
}

/// Output targets configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OutputConfig {
    /// Stdout output
    pub stdout: StdoutConfig,

    /// File output
    pub file: FileOutputConfig,

    /// Grafana integration
    pub grafana: GrafanaConfig,
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            stdout: StdoutConfig::default(),
            file: FileOutputConfig::default(),
            grafana: GrafanaConfig::default(),
        }
    }
}

/// Stdout output configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct StdoutConfig {
    pub enabled: bool,
    /// Format: pretty, json, raw
    pub format: String,
    /// Enable colored output
    pub color: bool,
}

impl Default for StdoutConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            format: "pretty".to_string(),
            color: true,
        }
    }
}

/// File output configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct FileOutputConfig {
    pub enabled: bool,
    /// Output file path
    pub path: String,
    /// Format: jsonl, json, text
    pub format: String,
    /// Rotation: daily, hourly, size
    pub rotation: String,
    /// Max file size for size-based rotation (e.g., "100MB")
    pub max_size: String,
    /// Number of rotated files to keep
    pub max_files: usize,
    /// Compress rotated files
    pub compress: bool,
}

impl Default for FileOutputConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            path: "logmate.jsonl".to_string(),
            format: "jsonl".to_string(),
            rotation: "daily".to_string(),
            max_size: "100MB".to_string(),
            max_files: 7,
            compress: true,
        }
    }
}

/// Grafana integration configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct GrafanaConfig {
    /// Loki integration
    pub loki: LokiConfig,

    /// Prometheus metrics
    pub prometheus: PrometheusConfig,
}

impl Default for GrafanaConfig {
    fn default() -> Self {
        Self {
            loki: LokiConfig::default(),
            prometheus: PrometheusConfig::default(),
        }
    }
}

/// Loki output configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct LokiConfig {
    pub enabled: bool,
    /// Loki push API endpoint
    pub endpoint: String,
    /// Batch size for log entries
    pub batch_size: usize,
    /// Batch timeout (e.g., "5s")
    pub batch_timeout: String,
}

impl Default for LokiConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: "http://localhost:3100/loki/api/v1/push".to_string(),
            batch_size: 100,
            batch_timeout: "5s".to_string(),
        }
    }
}

/// Prometheus metrics configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct PrometheusConfig {
    pub enabled: bool,
    /// Bind address for metrics endpoint
    pub bind_address: String,
    /// Port for metrics endpoint
    pub port: u16,
    /// Path for metrics endpoint
    pub path: String,
}

impl Default for PrometheusConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            bind_address: "0.0.0.0".to_string(),
            port: 9090,
            path: "/metrics".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.general.instance_name, "logmate");
        assert_eq!(config.general.buffer_size, 10_000);
        assert!(config.ingestion.stdin.enabled);
        assert!(!config.ingestion.tcp.enabled);
        assert!(config.modules.pattern_detection.enabled);
        assert!(config.output.stdout.enabled);
    }

    #[test]
    fn test_parse_minimal_toml() {
        let toml = r#"
[general]
instance_name = "my-logmate"
"#;
        let config = Config::from_str(toml).unwrap();
        assert_eq!(config.general.instance_name, "my-logmate");
        // Defaults should be applied
        assert_eq!(config.general.buffer_size, 10_000);
    }

    #[test]
    fn test_parse_full_toml() {
        let toml = r#"
[general]
instance_name = "prod-logmate"
log_level = "debug"
buffer_size = 50000

[ingestion.tcp]
enabled = true
port = 9999

[modules.pattern_detection]
enabled = true
detect_levels = true
custom_patterns = [
    { name = "request_id", pattern = "req_id=([a-f0-9]+)" }
]

[output.stdout]
format = "json"
color = false
"#;
        let config = Config::from_str(toml).unwrap();
        assert_eq!(config.general.instance_name, "prod-logmate");
        assert_eq!(config.general.buffer_size, 50_000);
        assert!(config.ingestion.tcp.enabled);
        assert_eq!(config.ingestion.tcp.port, 9999);
        assert_eq!(config.output.stdout.format, "json");
        assert!(!config.output.stdout.color);
        assert_eq!(config.modules.pattern_detection.custom_patterns.len(), 1);
    }

    #[test]
    fn test_serialize_to_toml() {
        let config = Config::default();
        let toml = config.to_toml().unwrap();
        assert!(toml.contains("[general]"));
        assert!(toml.contains("instance_name"));
    }
}
