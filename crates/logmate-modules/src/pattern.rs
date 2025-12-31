use logmate_core::config::PatternDetectionConfig;
use logmate_core::{EnrichedEntry, LogLevel, Module, Result};
use regex::Regex;
use std::sync::OnceLock;
use tracing::debug;

/// Pattern Detection Module
///
/// Detects log levels (ERROR, WARN, INFO, etc.) and error codes in log entries.
pub struct PatternDetectionModule {
    config: PatternDetectionConfig,
    custom_patterns: Vec<CompiledPattern>,
}

struct CompiledPattern {
    name: String,
    regex: Regex,
}

// Pre-compiled regex patterns for log level detection
static LEVEL_REGEX: OnceLock<Regex> = OnceLock::new();
static ERROR_CODE_REGEX: OnceLock<Regex> = OnceLock::new();

fn get_level_regex() -> &'static Regex {
    LEVEL_REGEX.get_or_init(|| {
        // Matches common log level formats:
        // - [ERROR], [WARN], [INFO], etc.
        // - ERROR:, WARN:, INFO:, etc.
        // - level=ERROR, level=WARN, etc.
        // - Just ERROR, WARN, INFO as standalone words
        Regex::new(r"(?i)\b(TRACE|DEBUG|INFO|WARN(?:ING)?|ERROR|FATAL|CRITICAL|SEVERE)\b").unwrap()
    })
}

fn get_error_code_regex() -> &'static Regex {
    ERROR_CODE_REGEX.get_or_init(|| {
        // Matches common error code formats:
        // - E0001, ERR-001, ERROR_CODE_123
        // - error_code=123, code: 500, status=404
        // - HTTP status codes in context
        Regex::new(r"(?i)(?:error[_-]?code|err(?:or)?|code|status)[=:\s]*([A-Z]*\d+[A-Z0-9_-]*)|\b([A-Z]{1,3}[-_]?\d{3,5})\b").unwrap()
    })
}

impl PatternDetectionModule {
    /// Create a new pattern detection module with the given configuration
    pub fn new(config: PatternDetectionConfig) -> Self {
        let custom_patterns = config
            .custom_patterns
            .iter()
            .filter_map(|p| {
                match Regex::new(&p.pattern) {
                    Ok(regex) => Some(CompiledPattern {
                        name: p.name.clone(),
                        regex,
                    }),
                    Err(e) => {
                        tracing::warn!(
                            pattern_name = %p.name,
                            error = %e,
                            "Failed to compile custom pattern, skipping"
                        );
                        None
                    }
                }
            })
            .collect();

        Self {
            config,
            custom_patterns,
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(PatternDetectionConfig::default())
    }

    /// Detect log level from content
    fn detect_level(&self, content: &str) -> Option<LogLevel> {
        if !self.config.detect_levels {
            return None;
        }

        let regex = get_level_regex();
        regex.find(content).and_then(|m| {
            match m.as_str().to_uppercase().as_str() {
                "TRACE" => Some(LogLevel::Trace),
                "DEBUG" => Some(LogLevel::Debug),
                "INFO" => Some(LogLevel::Info),
                "WARN" | "WARNING" => Some(LogLevel::Warn),
                "ERROR" | "SEVERE" => Some(LogLevel::Error),
                "FATAL" | "CRITICAL" => Some(LogLevel::Fatal),
                _ => None,
            }
        })
    }

    /// Extract error code from content
    fn extract_error_code(&self, content: &str) -> Option<String> {
        if !self.config.detect_error_codes {
            return None;
        }

        let regex = get_error_code_regex();
        regex.captures(content).and_then(|caps| {
            // Try capture group 1 first (from error_code=X pattern)
            // Then try capture group 2 (from standalone E001 pattern)
            caps.get(1)
                .or_else(|| caps.get(2))
                .map(|m| m.as_str().to_string())
        })
    }

    /// Apply custom patterns and add matches to tags
    fn apply_custom_patterns(&self, content: &str, entry: &mut EnrichedEntry) {
        for pattern in &self.custom_patterns {
            if let Some(caps) = pattern.regex.captures(content) {
                // If there are named capture groups, add each as a tag
                for name in pattern.regex.capture_names().flatten() {
                    if let Some(m) = caps.name(name) {
                        entry.tags.insert(
                            format!("{}_{}", pattern.name, name),
                            m.as_str().to_string(),
                        );
                    }
                }
                // If no named groups but there's a match, add the whole match
                if pattern.regex.capture_names().flatten().count() == 0 {
                    if let Some(m) = caps.get(1).or_else(|| caps.get(0)) {
                        entry.tags.insert(pattern.name.clone(), m.as_str().to_string());
                    }
                }
            }
        }
    }
}

impl Module for PatternDetectionModule {
    fn name(&self) -> &'static str {
        "pattern_detection"
    }

    fn process(&self, mut entry: EnrichedEntry) -> Result<EnrichedEntry> {
        // Clone content to avoid borrow issues
        let content = entry.raw.content.clone();

        // Detect log level
        if let Some(level) = self.detect_level(&content) {
            debug!(level = ?level, "Detected log level");
            entry.level = Some(level);
        }

        // Extract error code
        if let Some(code) = self.extract_error_code(&content) {
            debug!(code = %code, "Extracted error code");
            entry.error_code = Some(code);
        }

        // Apply custom patterns
        self.apply_custom_patterns(&content, &mut entry);

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

    #[test]
    fn test_detect_error_level() {
        let module = PatternDetectionModule::with_defaults();

        let entry = create_entry("2024-01-15 10:23:45 ERROR: Database connection failed");
        let result = module.process(entry).unwrap();
        assert_eq!(result.level, Some(LogLevel::Error));
    }

    #[test]
    fn test_detect_warn_level() {
        let module = PatternDetectionModule::with_defaults();

        let entry = create_entry("[WARN] Low memory warning");
        let result = module.process(entry).unwrap();
        assert_eq!(result.level, Some(LogLevel::Warn));
    }

    #[test]
    fn test_detect_warning_level() {
        let module = PatternDetectionModule::with_defaults();

        let entry = create_entry("WARNING: Disk space low");
        let result = module.process(entry).unwrap();
        assert_eq!(result.level, Some(LogLevel::Warn));
    }

    #[test]
    fn test_detect_info_level() {
        let module = PatternDetectionModule::with_defaults();

        let entry = create_entry("INFO - Server started successfully");
        let result = module.process(entry).unwrap();
        assert_eq!(result.level, Some(LogLevel::Info));
    }

    #[test]
    fn test_detect_debug_level() {
        let module = PatternDetectionModule::with_defaults();

        let entry = create_entry("[DEBUG] Loading configuration file");
        let result = module.process(entry).unwrap();
        assert_eq!(result.level, Some(LogLevel::Debug));
    }

    #[test]
    fn test_detect_fatal_level() {
        let module = PatternDetectionModule::with_defaults();

        let entry = create_entry("FATAL: System shutdown imminent");
        let result = module.process(entry).unwrap();
        assert_eq!(result.level, Some(LogLevel::Fatal));
    }

    #[test]
    fn test_detect_critical_as_fatal() {
        let module = PatternDetectionModule::with_defaults();

        let entry = create_entry("CRITICAL: Out of memory");
        let result = module.process(entry).unwrap();
        assert_eq!(result.level, Some(LogLevel::Fatal));
    }

    #[test]
    fn test_case_insensitive() {
        let module = PatternDetectionModule::with_defaults();

        let entry = create_entry("error: something went wrong");
        let result = module.process(entry).unwrap();
        assert_eq!(result.level, Some(LogLevel::Error));
    }

    #[test]
    fn test_extract_error_code_format1() {
        let module = PatternDetectionModule::with_defaults();

        let entry = create_entry("Error code: E001 - Invalid input");
        let result = module.process(entry).unwrap();
        assert_eq!(result.error_code, Some("E001".to_string()));
    }

    #[test]
    fn test_extract_error_code_format2() {
        let module = PatternDetectionModule::with_defaults();

        let entry = create_entry("Request failed with status=404");
        let result = module.process(entry).unwrap();
        assert_eq!(result.error_code, Some("404".to_string()));
    }

    #[test]
    fn test_extract_error_code_format3() {
        let module = PatternDetectionModule::with_defaults();

        let entry = create_entry("ERR-500: Internal server error");
        let result = module.process(entry).unwrap();
        assert_eq!(result.error_code, Some("ERR-500".to_string()));
    }

    #[test]
    fn test_no_level_detected() {
        let module = PatternDetectionModule::with_defaults();

        let entry = create_entry("Just a regular log message");
        let result = module.process(entry).unwrap();
        assert_eq!(result.level, None);
    }

    #[test]
    fn test_disabled_level_detection() {
        let config = PatternDetectionConfig {
            enabled: true,
            detect_levels: false,
            detect_error_codes: true,
            custom_patterns: vec![],
        };
        let module = PatternDetectionModule::new(config);

        let entry = create_entry("ERROR: This should not be detected");
        let result = module.process(entry).unwrap();
        assert_eq!(result.level, None);
    }

    #[test]
    fn test_disabled_error_code_detection() {
        let config = PatternDetectionConfig {
            enabled: true,
            detect_levels: true,
            detect_error_codes: false,
            custom_patterns: vec![],
        };
        let module = PatternDetectionModule::new(config);

        let entry = create_entry("Error code: E001");
        let result = module.process(entry).unwrap();
        assert_eq!(result.error_code, None);
    }

    #[test]
    fn test_custom_pattern() {
        use logmate_core::config::CustomPattern;

        let config = PatternDetectionConfig {
            enabled: true,
            detect_levels: true,
            detect_error_codes: true,
            custom_patterns: vec![
                CustomPattern {
                    name: "request_id".to_string(),
                    pattern: r"req_id=(?P<id>[a-f0-9-]+)".to_string(),
                },
            ],
        };
        let module = PatternDetectionModule::new(config);

        let entry = create_entry("INFO req_id=abc-123-def Processing request");
        let result = module.process(entry).unwrap();
        assert_eq!(result.tags.get("request_id_id"), Some(&"abc-123-def".to_string()));
    }

    #[test]
    fn test_module_name() {
        let module = PatternDetectionModule::with_defaults();
        assert_eq!(module.name(), "pattern_detection");
    }

    #[test]
    fn test_module_is_enabled() {
        let module = PatternDetectionModule::with_defaults();
        assert!(module.is_enabled());

        let config = PatternDetectionConfig {
            enabled: false,
            ..Default::default()
        };
        let disabled_module = PatternDetectionModule::new(config);
        assert!(!disabled_module.is_enabled());
    }
}
