use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Log level classification
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum LogLevel {
    Trace,
    Debug,
    Info,
    Warn,
    Error,
    Fatal,
}

impl std::fmt::Display for LogLevel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogLevel::Trace => write!(f, "TRACE"),
            LogLevel::Debug => write!(f, "DEBUG"),
            LogLevel::Info => write!(f, "INFO"),
            LogLevel::Warn => write!(f, "WARN"),
            LogLevel::Error => write!(f, "ERROR"),
            LogLevel::Fatal => write!(f, "FATAL"),
        }
    }
}

/// Source of the log entry
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LogSource {
    Stdin,
    Tcp { addr: String },
    Udp { addr: String },
    File { path: String },
}

impl std::fmt::Display for LogSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            LogSource::Stdin => write!(f, "stdin"),
            LogSource::Tcp { addr } => write!(f, "tcp://{}", addr),
            LogSource::Udp { addr } => write!(f, "udp://{}", addr),
            LogSource::File { path } => write!(f, "file://{}", path),
        }
    }
}

/// Raw log entry as received from ingestion
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogEntry {
    /// Timestamp when the log was received
    pub received_at: DateTime<Utc>,

    /// Source of the log entry
    pub source: LogSource,

    /// Raw log content (the original line)
    pub content: String,

    /// Optional metadata from the source
    #[serde(default)]
    pub metadata: HashMap<String, String>,
}

impl LogEntry {
    /// Create a new log entry from stdin
    pub fn from_stdin(content: String) -> Self {
        Self {
            received_at: Utc::now(),
            source: LogSource::Stdin,
            content,
            metadata: HashMap::new(),
        }
    }

    /// Create a new log entry with a specific source
    pub fn new(source: LogSource, content: String) -> Self {
        Self {
            received_at: Utc::now(),
            source,
            content,
            metadata: HashMap::new(),
        }
    }

    /// Add metadata to the log entry
    pub fn with_metadata(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.metadata.insert(key.into(), value.into());
        self
    }
}

/// Security flag detected in a log entry
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SecurityFlag {
    SqlInjection,
    Xss,
    PathTraversal,
    AuthFailure,
    SensitiveData { pattern_name: String },
}

/// Enriched log entry after processing through modules
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichedEntry {
    /// Original log entry
    #[serde(flatten)]
    pub raw: LogEntry,

    /// Detected log level (from Pattern Detection module)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<LogLevel>,

    /// Extracted error code (from Pattern Detection module)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_code: Option<String>,

    /// Extracted latency in milliseconds (from Performance Metrics module)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<f64>,

    /// Security flags detected (from Security module)
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub security_flags: Vec<SecurityFlag>,

    /// Structured fields parsed from the log (from Structural Parser module)
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub structured: Option<serde_json::Value>,

    /// Additional tags added during processing
    #[serde(default, skip_serializing_if = "HashMap::is_empty")]
    pub tags: HashMap<String, String>,
}

impl From<LogEntry> for EnrichedEntry {
    fn from(entry: LogEntry) -> Self {
        Self {
            raw: entry,
            level: None,
            error_code: None,
            latency_ms: None,
            security_flags: Vec::new(),
            structured: None,
            tags: HashMap::new(),
        }
    }
}

impl EnrichedEntry {
    /// Create from a log entry
    pub fn new(entry: LogEntry) -> Self {
        Self::from(entry)
    }

    /// Set the detected log level
    pub fn with_level(mut self, level: LogLevel) -> Self {
        self.level = Some(level);
        self
    }

    /// Set the extracted error code
    pub fn with_error_code(mut self, code: impl Into<String>) -> Self {
        self.error_code = Some(code.into());
        self
    }

    /// Set the extracted latency
    pub fn with_latency_ms(mut self, latency: f64) -> Self {
        self.latency_ms = Some(latency);
        self
    }

    /// Add a security flag
    pub fn with_security_flag(mut self, flag: SecurityFlag) -> Self {
        self.security_flags.push(flag);
        self
    }

    /// Set structured data
    pub fn with_structured(mut self, data: serde_json::Value) -> Self {
        self.structured = Some(data);
        self
    }

    /// Add a tag
    pub fn with_tag(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.tags.insert(key.into(), value.into());
        self
    }
}
