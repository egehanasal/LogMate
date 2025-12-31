use logmate_core::config::StructuralParserConfig;
use logmate_core::{EnrichedEntry, Module, Result};
use regex::Regex;
use serde_json::{json, Map, Value};
use std::sync::OnceLock;
use tracing::debug;

/// Structural Parser Module
///
/// Parses unstructured log lines into structured JSON data.
/// Supports multiple formats: JSON, key=value, Apache/Nginx combined, Syslog.
pub struct StructuralParserModule {
    config: StructuralParserConfig,
}

/// Detected or configured log format
#[derive(Debug, Clone, PartialEq)]
pub enum LogFormat {
    /// JSON formatted logs
    Json,
    /// Key=value pairs (e.g., "user=john status=200")
    KeyValue,
    /// Apache/Nginx combined log format
    ApacheCombined,
    /// Syslog RFC 3164 format
    Syslog,
    /// Unknown/unstructured format
    Unknown,
}

// Pre-compiled regex patterns
static KV_REGEX: OnceLock<Regex> = OnceLock::new();
static APACHE_COMBINED_REGEX: OnceLock<Regex> = OnceLock::new();
static SYSLOG_REGEX: OnceLock<Regex> = OnceLock::new();

fn get_kv_regex() -> &'static Regex {
    KV_REGEX.get_or_init(|| {
        // Matches: key=value, key="quoted value", key='quoted value'
        Regex::new(r#"(\w+)=(?:"([^"]*)"|'([^']*)'|(\S+))"#).unwrap()
    })
}

fn get_apache_combined_regex() -> &'static Regex {
    APACHE_COMBINED_REGEX.get_or_init(|| {
        // Apache/Nginx Combined Log Format:
        // 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://www.example.com/start.html" "Mozilla/4.08"
        Regex::new(
            r#"^(?P<ip>\S+)\s+(?P<ident>\S+)\s+(?P<user>\S+)\s+\[(?P<timestamp>[^\]]+)\]\s+"(?P<method>\S+)\s+(?P<path>\S+)\s*(?P<protocol>[^"]*)"\s+(?P<status>\d+)\s+(?P<bytes>\S+)(?:\s+"(?P<referrer>[^"]*)"\s+"(?P<user_agent>[^"]*)")?"#
        ).unwrap()
    })
}

fn get_syslog_regex() -> &'static Regex {
    SYSLOG_REGEX.get_or_init(|| {
        // Syslog RFC 3164 format:
        // <priority>timestamp hostname process[pid]: message
        // Or without priority: Jan  1 00:00:00 hostname process[pid]: message
        Regex::new(
            r#"^(?:<(?P<priority>\d+)>)?(?P<timestamp>\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})\s+(?P<hostname>\S+)\s+(?P<process>[^\[:]+)(?:\[(?P<pid>\d+)\])?:\s*(?P<message>.*)$"#
        ).unwrap()
    })
}

impl StructuralParserModule {
    /// Create a new structural parser module with the given configuration
    pub fn new(config: StructuralParserConfig) -> Self {
        Self { config }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(StructuralParserConfig::default())
    }

    /// Detect the format of a log line
    fn detect_format(&self, content: &str) -> LogFormat {
        let trimmed = content.trim();

        // Check for JSON (starts with { or [)
        if (trimmed.starts_with('{') && trimmed.ends_with('}'))
            || (trimmed.starts_with('[') && trimmed.ends_with(']'))
        {
            // Verify it's valid JSON
            if serde_json::from_str::<Value>(trimmed).is_ok() {
                return LogFormat::Json;
            }
        }

        // Check for Apache/Nginx combined format
        if get_apache_combined_regex().is_match(trimmed) {
            return LogFormat::ApacheCombined;
        }

        // Check for Syslog format
        if get_syslog_regex().is_match(trimmed) {
            return LogFormat::Syslog;
        }

        // Check for key=value format (at least 2 key=value pairs)
        let kv_matches: Vec<_> = get_kv_regex().find_iter(trimmed).collect();
        if kv_matches.len() >= 2 {
            return LogFormat::KeyValue;
        }

        LogFormat::Unknown
    }

    /// Get the configured format or auto-detect
    fn get_format(&self, content: &str) -> LogFormat {
        if !self.config.auto_detect {
            // Use explicit format from config
            return match self.config.format.as_deref() {
                Some("json") => LogFormat::Json,
                Some("kv") | Some("key_value") => LogFormat::KeyValue,
                Some("apache") | Some("apache_combined") | Some("nginx") => LogFormat::ApacheCombined,
                Some("syslog") => LogFormat::Syslog,
                _ => LogFormat::Unknown,
            };
        }

        self.detect_format(content)
    }

    /// Parse JSON formatted log
    fn parse_json(&self, content: &str) -> Option<Value> {
        serde_json::from_str(content.trim()).ok()
    }

    /// Parse key=value formatted log
    fn parse_key_value(&self, content: &str) -> Option<Value> {
        let regex = get_kv_regex();
        let mut map = Map::new();

        for caps in regex.captures_iter(content) {
            let key = caps.get(1)?.as_str().to_string();
            // Value is in group 2 (double quoted), 3 (single quoted), or 4 (unquoted)
            let value = caps.get(2)
                .or_else(|| caps.get(3))
                .or_else(|| caps.get(4))?
                .as_str();

            // Try to parse as number or boolean
            let parsed_value = if let Ok(n) = value.parse::<i64>() {
                Value::Number(n.into())
            } else if let Ok(f) = value.parse::<f64>() {
                Value::Number(serde_json::Number::from_f64(f).unwrap_or_else(|| 0.into()))
            } else if value == "true" {
                Value::Bool(true)
            } else if value == "false" {
                Value::Bool(false)
            } else {
                Value::String(value.to_string())
            };

            map.insert(key, parsed_value);
        }

        if map.is_empty() {
            None
        } else {
            Some(Value::Object(map))
        }
    }

    /// Parse Apache/Nginx combined log format
    fn parse_apache_combined(&self, content: &str) -> Option<Value> {
        let regex = get_apache_combined_regex();
        let caps = regex.captures(content.trim())?;

        let mut map = Map::new();

        // Extract named groups
        if let Some(m) = caps.name("ip") {
            map.insert("client_ip".to_string(), json!(m.as_str()));
        }
        if let Some(m) = caps.name("ident") {
            if m.as_str() != "-" {
                map.insert("ident".to_string(), json!(m.as_str()));
            }
        }
        if let Some(m) = caps.name("user") {
            if m.as_str() != "-" {
                map.insert("user".to_string(), json!(m.as_str()));
            }
        }
        if let Some(m) = caps.name("timestamp") {
            map.insert("timestamp".to_string(), json!(m.as_str()));
        }
        if let Some(m) = caps.name("method") {
            map.insert("method".to_string(), json!(m.as_str()));
        }
        if let Some(m) = caps.name("path") {
            map.insert("path".to_string(), json!(m.as_str()));
        }
        if let Some(m) = caps.name("protocol") {
            let proto = m.as_str().trim();
            if !proto.is_empty() {
                map.insert("protocol".to_string(), json!(proto));
            }
        }
        if let Some(m) = caps.name("status") {
            if let Ok(status) = m.as_str().parse::<u16>() {
                map.insert("status".to_string(), json!(status));
            }
        }
        if let Some(m) = caps.name("bytes") {
            let bytes_str = m.as_str();
            if bytes_str != "-" {
                if let Ok(bytes) = bytes_str.parse::<u64>() {
                    map.insert("bytes".to_string(), json!(bytes));
                }
            }
        }
        if let Some(m) = caps.name("referrer") {
            if m.as_str() != "-" {
                map.insert("referrer".to_string(), json!(m.as_str()));
            }
        }
        if let Some(m) = caps.name("user_agent") {
            map.insert("user_agent".to_string(), json!(m.as_str()));
        }

        map.insert("_format".to_string(), json!("apache_combined"));

        Some(Value::Object(map))
    }

    /// Parse Syslog RFC 3164 format
    fn parse_syslog(&self, content: &str) -> Option<Value> {
        let regex = get_syslog_regex();
        let caps = regex.captures(content.trim())?;

        let mut map = Map::new();

        if let Some(m) = caps.name("priority") {
            if let Ok(pri) = m.as_str().parse::<u8>() {
                map.insert("priority".to_string(), json!(pri));
                // Calculate facility and severity from priority
                let facility = pri / 8;
                let severity = pri % 8;
                map.insert("facility".to_string(), json!(facility));
                map.insert("severity".to_string(), json!(severity));
            }
        }
        if let Some(m) = caps.name("timestamp") {
            map.insert("timestamp".to_string(), json!(m.as_str()));
        }
        if let Some(m) = caps.name("hostname") {
            map.insert("hostname".to_string(), json!(m.as_str()));
        }
        if let Some(m) = caps.name("process") {
            map.insert("process".to_string(), json!(m.as_str().trim()));
        }
        if let Some(m) = caps.name("pid") {
            if let Ok(pid) = m.as_str().parse::<u32>() {
                map.insert("pid".to_string(), json!(pid));
            }
        }
        if let Some(m) = caps.name("message") {
            map.insert("message".to_string(), json!(m.as_str()));
        }

        map.insert("_format".to_string(), json!("syslog"));

        Some(Value::Object(map))
    }

    /// Parse content based on detected or configured format
    fn parse(&self, content: &str) -> Option<Value> {
        let format = self.get_format(content);

        debug!(format = ?format, "Parsing log with format");

        match format {
            LogFormat::Json => self.parse_json(content),
            LogFormat::KeyValue => self.parse_key_value(content),
            LogFormat::ApacheCombined => self.parse_apache_combined(content),
            LogFormat::Syslog => self.parse_syslog(content),
            LogFormat::Unknown => None,
        }
    }
}

impl Module for StructuralParserModule {
    fn name(&self) -> &'static str {
        "structural_parser"
    }

    fn process(&self, mut entry: EnrichedEntry) -> Result<EnrichedEntry> {
        let content = entry.raw.content.clone();

        if let Some(structured) = self.parse(&content) {
            debug!("Parsed log into structured data");
            entry.structured = Some(structured);
        }

        Ok(entry)
    }

    fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use logmate_core::{LogEntry, LogSource};

    fn create_entry(content: &str) -> EnrichedEntry {
        EnrichedEntry::from(LogEntry::new(LogSource::Stdin, content.to_string()))
    }

    fn enabled_config() -> StructuralParserConfig {
        StructuralParserConfig {
            enabled: true,
            auto_detect: true,
            format: None,
        }
    }

    // JSON parsing tests
    #[test]
    fn test_parse_json_object() {
        let module = StructuralParserModule::new(enabled_config());
        let entry = create_entry(r#"{"level": "error", "message": "Connection failed", "code": 500}"#);
        let result = module.process(entry).unwrap();

        let structured = result.structured.unwrap();
        assert_eq!(structured["level"], "error");
        assert_eq!(structured["message"], "Connection failed");
        assert_eq!(structured["code"], 500);
    }

    #[test]
    fn test_parse_json_with_whitespace() {
        let module = StructuralParserModule::new(enabled_config());
        let entry = create_entry(r#"  {"key": "value"}  "#);
        let result = module.process(entry).unwrap();

        assert!(result.structured.is_some());
        assert_eq!(result.structured.unwrap()["key"], "value");
    }

    // Key=value parsing tests
    #[test]
    fn test_parse_key_value() {
        let module = StructuralParserModule::new(enabled_config());
        let entry = create_entry("user=john status=200 duration=150ms");
        let result = module.process(entry).unwrap();

        let structured = result.structured.unwrap();
        assert_eq!(structured["user"], "john");
        assert_eq!(structured["status"], 200);
        assert_eq!(structured["duration"], "150ms");
    }

    #[test]
    fn test_parse_key_value_quoted() {
        let module = StructuralParserModule::new(enabled_config());
        let entry = create_entry(r#"message="Hello World" user='john doe' count=42"#);
        let result = module.process(entry).unwrap();

        let structured = result.structured.unwrap();
        assert_eq!(structured["message"], "Hello World");
        assert_eq!(structured["user"], "john doe");
        assert_eq!(structured["count"], 42);
    }

    #[test]
    fn test_parse_key_value_booleans() {
        let module = StructuralParserModule::new(enabled_config());
        let entry = create_entry("enabled=true disabled=false count=10");
        let result = module.process(entry).unwrap();

        let structured = result.structured.unwrap();
        assert_eq!(structured["enabled"], true);
        assert_eq!(structured["disabled"], false);
        assert_eq!(structured["count"], 10);
    }

    // Apache combined log format tests
    #[test]
    fn test_parse_apache_combined() {
        let module = StructuralParserModule::new(enabled_config());
        let entry = create_entry(
            r#"192.168.1.1 - john [10/Oct/2024:13:55:36 -0700] "GET /api/users HTTP/1.1" 200 1234 "https://example.com" "Mozilla/5.0""#
        );
        let result = module.process(entry).unwrap();

        let structured = result.structured.unwrap();
        assert_eq!(structured["client_ip"], "192.168.1.1");
        assert_eq!(structured["user"], "john");
        assert_eq!(structured["method"], "GET");
        assert_eq!(structured["path"], "/api/users");
        assert_eq!(structured["protocol"], "HTTP/1.1");
        assert_eq!(structured["status"], 200);
        assert_eq!(structured["bytes"], 1234);
        assert_eq!(structured["referrer"], "https://example.com");
        assert_eq!(structured["user_agent"], "Mozilla/5.0");
        assert_eq!(structured["_format"], "apache_combined");
    }

    #[test]
    fn test_parse_apache_combined_minimal() {
        let module = StructuralParserModule::new(enabled_config());
        let entry = create_entry(
            r#"127.0.0.1 - - [01/Jan/2024:00:00:00 +0000] "POST /login HTTP/1.1" 302 0"#
        );
        let result = module.process(entry).unwrap();

        let structured = result.structured.unwrap();
        assert_eq!(structured["client_ip"], "127.0.0.1");
        assert_eq!(structured["method"], "POST");
        assert_eq!(structured["path"], "/login");
        assert_eq!(structured["status"], 302);
    }

    // Syslog parsing tests
    #[test]
    fn test_parse_syslog() {
        let module = StructuralParserModule::new(enabled_config());
        let entry = create_entry("Jan  5 14:32:01 myhost sshd[12345]: Connection from 192.168.1.100");
        let result = module.process(entry).unwrap();

        let structured = result.structured.unwrap();
        assert_eq!(structured["timestamp"], "Jan  5 14:32:01");
        assert_eq!(structured["hostname"], "myhost");
        assert_eq!(structured["process"], "sshd");
        assert_eq!(structured["pid"], 12345);
        assert_eq!(structured["message"], "Connection from 192.168.1.100");
        assert_eq!(structured["_format"], "syslog");
    }

    #[test]
    fn test_parse_syslog_with_priority() {
        let module = StructuralParserModule::new(enabled_config());
        let entry = create_entry("<34>Oct 11 22:14:15 mymachine su: 'su root' failed");
        let result = module.process(entry).unwrap();

        let structured = result.structured.unwrap();
        assert_eq!(structured["priority"], 34);
        assert_eq!(structured["facility"], 4);  // 34 / 8 = 4 (auth)
        assert_eq!(structured["severity"], 2);  // 34 % 8 = 2 (critical)
        assert_eq!(structured["hostname"], "mymachine");
        assert_eq!(structured["process"], "su");
    }

    #[test]
    fn test_parse_syslog_no_pid() {
        let module = StructuralParserModule::new(enabled_config());
        let entry = create_entry("Dec 25 08:00:00 server kernel: CPU0: Temperature above threshold");
        let result = module.process(entry).unwrap();

        let structured = result.structured.unwrap();
        assert_eq!(structured["process"], "kernel");
        assert!(structured.get("pid").is_none());
        assert_eq!(structured["message"], "CPU0: Temperature above threshold");
    }

    // Format detection tests
    #[test]
    fn test_detect_json_format() {
        let module = StructuralParserModule::new(enabled_config());
        assert_eq!(module.detect_format(r#"{"key": "value"}"#), LogFormat::Json);
        assert_eq!(module.detect_format(r#"[1, 2, 3]"#), LogFormat::Json);
    }

    #[test]
    fn test_detect_kv_format() {
        let module = StructuralParserModule::new(enabled_config());
        assert_eq!(module.detect_format("key1=value1 key2=value2"), LogFormat::KeyValue);
    }

    #[test]
    fn test_detect_apache_format() {
        let module = StructuralParserModule::new(enabled_config());
        let log = r#"192.168.1.1 - - [10/Oct/2024:13:55:36 -0700] "GET / HTTP/1.1" 200 1234"#;
        assert_eq!(module.detect_format(log), LogFormat::ApacheCombined);
    }

    #[test]
    fn test_detect_syslog_format() {
        let module = StructuralParserModule::new(enabled_config());
        assert_eq!(
            module.detect_format("Jan  1 00:00:00 host process[123]: message"),
            LogFormat::Syslog
        );
    }

    #[test]
    fn test_detect_unknown_format() {
        let module = StructuralParserModule::new(enabled_config());
        assert_eq!(module.detect_format("Just a plain text message"), LogFormat::Unknown);
    }

    // Explicit format config tests
    #[test]
    fn test_explicit_format_json() {
        let config = StructuralParserConfig {
            enabled: true,
            auto_detect: false,
            format: Some("json".to_string()),
        };
        let module = StructuralParserModule::new(config);

        // Even if it looks like key=value, use JSON parser
        let entry = create_entry(r#"{"a": 1}"#);
        let result = module.process(entry).unwrap();
        assert!(result.structured.is_some());
    }

    #[test]
    fn test_explicit_format_kv() {
        let config = StructuralParserConfig {
            enabled: true,
            auto_detect: false,
            format: Some("kv".to_string()),
        };
        let module = StructuralParserModule::new(config);

        let entry = create_entry("key=value other=123");
        let result = module.process(entry).unwrap();
        assert!(result.structured.is_some());
    }

    // Module trait tests
    #[test]
    fn test_module_name() {
        let module = StructuralParserModule::with_defaults();
        assert_eq!(module.name(), "structural_parser");
    }

    #[test]
    fn test_module_disabled() {
        let config = StructuralParserConfig {
            enabled: false,
            ..Default::default()
        };
        let module = StructuralParserModule::new(config);
        assert!(!module.is_enabled());
    }

    #[test]
    fn test_unstructured_log_no_parsing() {
        let module = StructuralParserModule::new(enabled_config());
        let entry = create_entry("This is just a plain text log message");
        let result = module.process(entry).unwrap();

        assert!(result.structured.is_none());
    }
}
