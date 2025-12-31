use aho_corasick::AhoCorasick;
use logmate_core::config::SecurityConfig;
use logmate_core::{EnrichedEntry, Module, Result, SecurityFlag};
use regex::Regex;
use std::sync::OnceLock;
use tracing::{debug, warn};

/// Security and Anomaly Detection Module
///
/// Detects security issues in log entries including:
/// - SQL injection attempts
/// - Cross-site scripting (XSS) patterns
/// - Path traversal attacks
/// - Authentication failures
/// - Sensitive data exposure (PII, credentials)
pub struct SecurityModule {
    config: SecurityConfig,
    sql_injection_detector: AhoCorasick,
    xss_detector: AhoCorasick,
    path_traversal_detector: AhoCorasick,
    auth_failure_regex: Regex,
    sensitive_patterns: Vec<CompiledSensitivePattern>,
}

struct CompiledSensitivePattern {
    name: String,
    regex: Regex,
}

// SQL injection patterns - common attack signatures
const SQL_INJECTION_PATTERNS: &[&str] = &[
    // Union-based injection
    "union select",
    "union all select",
    // Comment-based injection
    "' --",
    "' #",
    "'; --",
    // Boolean-based injection
    "' or '1'='1",
    "' or 1=1",
    "' or ''='",
    "or 1=1--",
    "' or 'a'='a",
    // Tautology attacks
    "1=1",
    "1' or '1'='1",
    // Stacked queries
    "; drop table",
    "; delete from",
    "; insert into",
    "; update ",
    // Information schema probing
    "information_schema",
    "table_name",
    "column_name",
    // MySQL specific
    "load_file(",
    "into outfile",
    "into dumpfile",
    // SQL functions used in attacks
    "char(",
    "concat(",
    "benchmark(",
    "sleep(",
    "waitfor delay",
    // Common bypass attempts
    "/**/",
    "%27",  // URL encoded '
    "%22",  // URL encoded "
];

// XSS patterns - common attack signatures
const XSS_PATTERNS: &[&str] = &[
    // Script tags
    "<script",
    "</script>",
    "javascript:",
    "vbscript:",
    // Event handlers
    "onerror=",
    "onload=",
    "onclick=",
    "onmouseover=",
    "onfocus=",
    "onblur=",
    "onchange=",
    "onsubmit=",
    "onkeyup=",
    "onkeydown=",
    // Data URIs
    "data:text/html",
    "data:application/javascript",
    // Expression/eval
    "expression(",
    "eval(",
    // Other injection vectors
    "<iframe",
    "<object",
    "<embed",
    "<img src=",
    "<svg",
    "document.cookie",
    "document.location",
    "document.write",
    "window.location",
    ".innerHTML",
    // Encoded variants
    "&#x3c;script",  // < encoded
    "&#60;script",   // < encoded decimal
    "%3cscript",     // URL encoded
    "\\x3cscript",   // JS hex encoded
];

// Path traversal patterns
const PATH_TRAVERSAL_PATTERNS: &[&str] = &[
    // Basic traversal
    "../",
    "..\\",
    "..\\/",
    // Double encoding
    "..%2f",
    "..%5c",
    "%2e%2e/",
    "%2e%2e\\",
    // Unicode/overlong encoding
    "..%c0%af",
    "..%c1%9c",
    // Common targets
    "/etc/passwd",
    "/etc/shadow",
    "/etc/hosts",
    "/proc/self",
    "/var/log",
    "\\windows\\system32",
    "\\boot.ini",
    "\\win.ini",
    "web.config",
    ".htaccess",
    ".htpasswd",
    // Null byte injection (legacy)
    "%00",
    "\x00",
];

// Pre-compiled auth failure regex
static AUTH_FAILURE_REGEX: OnceLock<Regex> = OnceLock::new();

fn get_auth_failure_regex() -> &'static Regex {
    AUTH_FAILURE_REGEX.get_or_init(|| {
        Regex::new(
            r"(?i)(authentication\s+fail|auth\s+fail|login\s+fail|invalid\s+(password|credential|token|api.?key)|unauthorized|access\s+denied|permission\s+denied|forbidden|401\s+unauthorized|403\s+forbidden|invalid\s+user|unknown\s+user|bad\s+password|wrong\s+password|incorrect\s+password|password\s+incorrect|failed\s+login|login\s+attempt|brute\s*force|too\s+many\s+attempts|account\s+locked|session\s+expired|token\s+expired|jwt\s+expired)"
        ).unwrap()
    })
}

impl SecurityModule {
    /// Create a new security module with the given configuration
    pub fn new(config: SecurityConfig) -> Self {
        // Build SQL injection detector
        let sql_injection_detector = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(SQL_INJECTION_PATTERNS)
            .unwrap();

        // Build XSS detector
        let xss_detector = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(XSS_PATTERNS)
            .unwrap();

        // Build path traversal detector
        let path_traversal_detector = AhoCorasick::builder()
            .ascii_case_insensitive(true)
            .build(PATH_TRAVERSAL_PATTERNS)
            .unwrap();

        // Compile custom sensitive patterns
        let sensitive_patterns: Vec<CompiledSensitivePattern> = config
            .sensitive_patterns
            .iter()
            .filter_map(|p| {
                match Regex::new(&p.pattern) {
                    Ok(regex) => Some(CompiledSensitivePattern {
                        name: p.name.clone(),
                        regex,
                    }),
                    Err(e) => {
                        warn!(
                            pattern_name = %p.name,
                            error = %e,
                            "Failed to compile sensitive pattern, skipping"
                        );
                        None
                    }
                }
            })
            .collect();

        Self {
            config,
            sql_injection_detector,
            xss_detector,
            path_traversal_detector,
            auth_failure_regex: get_auth_failure_regex().clone(),
            sensitive_patterns,
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(SecurityConfig::default())
    }

    /// Check for SQL injection patterns
    fn detect_sql_injection(&self, content: &str) -> bool {
        if !self.config.detect_sql_injection {
            return false;
        }
        self.sql_injection_detector.is_match(content)
    }

    /// Check for XSS patterns
    fn detect_xss(&self, content: &str) -> bool {
        if !self.config.detect_xss {
            return false;
        }
        self.xss_detector.is_match(content)
    }

    /// Check for path traversal patterns
    fn detect_path_traversal(&self, content: &str) -> bool {
        if !self.config.detect_path_traversal {
            return false;
        }
        self.path_traversal_detector.is_match(content)
    }

    /// Check for authentication failure patterns
    fn detect_auth_failure(&self, content: &str) -> bool {
        if !self.config.detect_auth_failures {
            return false;
        }
        self.auth_failure_regex.is_match(content)
    }

    /// Check for sensitive data patterns
    fn detect_sensitive_data(&self, content: &str) -> Vec<String> {
        let mut found = Vec::new();

        // Check built-in PII patterns
        if self.check_builtin_pii(content) {
            found.push("pii".to_string());
        }

        // Check custom patterns
        for pattern in &self.sensitive_patterns {
            if pattern.regex.is_match(content) {
                found.push(pattern.name.clone());
            }
        }

        found
    }

    /// Check for built-in PII patterns (credit cards, SSN, emails in suspicious contexts)
    fn check_builtin_pii(&self, content: &str) -> bool {
        // Credit card patterns (basic check - 13-19 digits with common separators)
        static CC_REGEX: OnceLock<Regex> = OnceLock::new();
        let cc_regex = CC_REGEX.get_or_init(|| {
            Regex::new(r"\b(?:\d{4}[-\s]?){3}\d{1,4}\b").unwrap()
        });

        // SSN pattern (XXX-XX-XXXX)
        static SSN_REGEX: OnceLock<Regex> = OnceLock::new();
        let ssn_regex = SSN_REGEX.get_or_init(|| {
            Regex::new(r"\b\d{3}-\d{2}-\d{4}\b").unwrap()
        });

        // API key / secret patterns
        static SECRET_REGEX: OnceLock<Regex> = OnceLock::new();
        let secret_regex = SECRET_REGEX.get_or_init(|| {
            Regex::new(r#"(?i)(api[_-]?key|api[_-]?secret|access[_-]?token|auth[_-]?token|bearer|private[_-]?key|secret[_-]?key)\s*[=:]\s*['"]?([a-zA-Z0-9_-]{20,})['"]?"#).unwrap()
        });

        // Password in logs (common mistake)
        static PASSWORD_REGEX: OnceLock<Regex> = OnceLock::new();
        let password_regex = PASSWORD_REGEX.get_or_init(|| {
            Regex::new(r#"(?i)(password|passwd|pwd)\s*[=:]\s*['"]?([^\s'"]+)['"]?"#).unwrap()
        });

        cc_regex.is_match(content)
            || ssn_regex.is_match(content)
            || secret_regex.is_match(content)
            || password_regex.is_match(content)
    }
}

impl Module for SecurityModule {
    fn name(&self) -> &'static str {
        "security"
    }

    fn process(&self, mut entry: EnrichedEntry) -> Result<EnrichedEntry> {
        let content = entry.raw.content.clone();

        // Check for SQL injection
        if self.detect_sql_injection(&content) {
            debug!("Detected SQL injection attempt");
            entry.security_flags.push(SecurityFlag::SqlInjection);
        }

        // Check for XSS
        if self.detect_xss(&content) {
            debug!("Detected XSS attempt");
            entry.security_flags.push(SecurityFlag::Xss);
        }

        // Check for path traversal
        if self.detect_path_traversal(&content) {
            debug!("Detected path traversal attempt");
            entry.security_flags.push(SecurityFlag::PathTraversal);
        }

        // Check for auth failures
        if self.detect_auth_failure(&content) {
            debug!("Detected authentication failure");
            entry.security_flags.push(SecurityFlag::AuthFailure);
        }

        // Check for sensitive data
        for pattern_name in self.detect_sensitive_data(&content) {
            debug!(pattern = %pattern_name, "Detected sensitive data");
            entry.security_flags.push(SecurityFlag::SensitiveData {
                pattern_name,
            });
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

    fn enabled_config() -> SecurityConfig {
        SecurityConfig {
            enabled: true,
            detect_sql_injection: true,
            detect_xss: true,
            detect_path_traversal: true,
            detect_auth_failures: true,
            sensitive_patterns: vec![],
        }
    }

    // SQL Injection tests
    #[test]
    fn test_detect_sql_injection_union() {
        let module = SecurityModule::new(enabled_config());
        let entry = create_entry("SELECT * FROM users WHERE id=1 UNION SELECT password FROM admin");
        let result = module.process(entry).unwrap();
        assert!(result.security_flags.contains(&SecurityFlag::SqlInjection));
    }

    #[test]
    fn test_detect_sql_injection_or_1_1() {
        let module = SecurityModule::new(enabled_config());
        let entry = create_entry("User input: ' or 1=1--");
        let result = module.process(entry).unwrap();
        assert!(result.security_flags.contains(&SecurityFlag::SqlInjection));
    }

    #[test]
    fn test_detect_sql_injection_drop_table() {
        let module = SecurityModule::new(enabled_config());
        let entry = create_entry("Query: SELECT * FROM users; DROP TABLE users;");
        let result = module.process(entry).unwrap();
        assert!(result.security_flags.contains(&SecurityFlag::SqlInjection));
    }

    #[test]
    fn test_detect_sql_injection_sleep() {
        let module = SecurityModule::new(enabled_config());
        let entry = create_entry("Query took long: SELECT * FROM users WHERE id=1 AND SLEEP(5)");
        let result = module.process(entry).unwrap();
        assert!(result.security_flags.contains(&SecurityFlag::SqlInjection));
    }

    #[test]
    fn test_no_sql_injection_normal_query() {
        let module = SecurityModule::new(enabled_config());
        let entry = create_entry("SELECT name, email FROM users WHERE active = true");
        let result = module.process(entry).unwrap();
        assert!(!result.security_flags.contains(&SecurityFlag::SqlInjection));
    }

    // XSS tests
    #[test]
    fn test_detect_xss_script_tag() {
        let module = SecurityModule::new(enabled_config());
        let entry = create_entry("User input: <script>alert('xss')</script>");
        let result = module.process(entry).unwrap();
        assert!(result.security_flags.contains(&SecurityFlag::Xss));
    }

    #[test]
    fn test_detect_xss_event_handler() {
        let module = SecurityModule::new(enabled_config());
        let entry = create_entry("Image tag with onerror=alert(1)");
        let result = module.process(entry).unwrap();
        assert!(result.security_flags.contains(&SecurityFlag::Xss));
    }

    #[test]
    fn test_detect_xss_javascript_uri() {
        let module = SecurityModule::new(enabled_config());
        let entry = create_entry("Link clicked: javascript:document.cookie");
        let result = module.process(entry).unwrap();
        assert!(result.security_flags.contains(&SecurityFlag::Xss));
    }

    #[test]
    fn test_detect_xss_iframe() {
        let module = SecurityModule::new(enabled_config());
        let entry = create_entry("Content: <iframe src='http://evil.com'>");
        let result = module.process(entry).unwrap();
        assert!(result.security_flags.contains(&SecurityFlag::Xss));
    }

    #[test]
    fn test_no_xss_normal_html() {
        let module = SecurityModule::new(enabled_config());
        let entry = create_entry("Rendering page with <div> and <span> elements");
        let result = module.process(entry).unwrap();
        assert!(!result.security_flags.contains(&SecurityFlag::Xss));
    }

    // Path traversal tests
    #[test]
    fn test_detect_path_traversal_dotdot() {
        let module = SecurityModule::new(enabled_config());
        let entry = create_entry("File access: ../../etc/passwd");
        let result = module.process(entry).unwrap();
        assert!(result.security_flags.contains(&SecurityFlag::PathTraversal));
    }

    #[test]
    fn test_detect_path_traversal_encoded() {
        let module = SecurityModule::new(enabled_config());
        let entry = create_entry("Path: ..%2f..%2fetc%2fpasswd");
        let result = module.process(entry).unwrap();
        assert!(result.security_flags.contains(&SecurityFlag::PathTraversal));
    }

    #[test]
    fn test_detect_path_traversal_windows() {
        let module = SecurityModule::new(enabled_config());
        let entry = create_entry("Path: ..\\..\\windows\\system32\\config\\sam");
        let result = module.process(entry).unwrap();
        assert!(result.security_flags.contains(&SecurityFlag::PathTraversal));
    }

    #[test]
    fn test_detect_path_traversal_etc_shadow() {
        let module = SecurityModule::new(enabled_config());
        let entry = create_entry("Attempted to read /etc/shadow");
        let result = module.process(entry).unwrap();
        assert!(result.security_flags.contains(&SecurityFlag::PathTraversal));
    }

    // Auth failure tests
    #[test]
    fn test_detect_auth_failure_login() {
        let module = SecurityModule::new(enabled_config());
        let entry = create_entry("Login failed for user admin from 192.168.1.1");
        let result = module.process(entry).unwrap();
        assert!(result.security_flags.contains(&SecurityFlag::AuthFailure));
    }

    #[test]
    fn test_detect_auth_failure_invalid_password() {
        let module = SecurityModule::new(enabled_config());
        let entry = create_entry("Invalid password for user john@example.com");
        let result = module.process(entry).unwrap();
        assert!(result.security_flags.contains(&SecurityFlag::AuthFailure));
    }

    #[test]
    fn test_detect_auth_failure_unauthorized() {
        let module = SecurityModule::new(enabled_config());
        let entry = create_entry("401 Unauthorized - API request rejected");
        let result = module.process(entry).unwrap();
        assert!(result.security_flags.contains(&SecurityFlag::AuthFailure));
    }

    #[test]
    fn test_detect_auth_failure_forbidden() {
        let module = SecurityModule::new(enabled_config());
        let entry = create_entry("403 Forbidden - Access denied to resource");
        let result = module.process(entry).unwrap();
        assert!(result.security_flags.contains(&SecurityFlag::AuthFailure));
    }

    #[test]
    fn test_detect_auth_failure_token_expired() {
        let module = SecurityModule::new(enabled_config());
        let entry = create_entry("JWT expired for user session");
        let result = module.process(entry).unwrap();
        assert!(result.security_flags.contains(&SecurityFlag::AuthFailure));
    }

    // Sensitive data tests
    #[test]
    fn test_detect_credit_card() {
        let module = SecurityModule::new(enabled_config());
        let entry = create_entry("Payment with card 4111-1111-1111-1111");
        let result = module.process(entry).unwrap();
        assert!(result.security_flags.iter().any(|f| matches!(f, SecurityFlag::SensitiveData { .. })));
    }

    #[test]
    fn test_detect_ssn() {
        let module = SecurityModule::new(enabled_config());
        let entry = create_entry("User SSN: 123-45-6789");
        let result = module.process(entry).unwrap();
        assert!(result.security_flags.iter().any(|f| matches!(f, SecurityFlag::SensitiveData { .. })));
    }

    #[test]
    fn test_detect_api_key() {
        let module = SecurityModule::new(enabled_config());
        let entry = create_entry("Config: api_key=sk_live_abcdefghijklmnopqrstuvwxyz");
        let result = module.process(entry).unwrap();
        assert!(result.security_flags.iter().any(|f| matches!(f, SecurityFlag::SensitiveData { .. })));
    }

    #[test]
    fn test_detect_password_in_log() {
        let module = SecurityModule::new(enabled_config());
        let entry = create_entry("User login attempt: username=admin password=secret123");
        let result = module.process(entry).unwrap();
        assert!(result.security_flags.iter().any(|f| matches!(f, SecurityFlag::SensitiveData { .. })));
    }

    // Custom sensitive pattern tests
    #[test]
    fn test_custom_sensitive_pattern() {
        use logmate_core::config::CustomPattern;

        let config = SecurityConfig {
            enabled: true,
            sensitive_patterns: vec![
                CustomPattern {
                    name: "internal_id".to_string(),
                    pattern: r"INTERNAL-\d{8}".to_string(),
                },
            ],
            ..enabled_config()
        };
        let module = SecurityModule::new(config);

        let entry = create_entry("Processing request for INTERNAL-12345678");
        let result = module.process(entry).unwrap();
        assert!(result.security_flags.iter().any(|f| {
            matches!(f, SecurityFlag::SensitiveData { pattern_name } if pattern_name == "internal_id")
        }));
    }

    // Module config tests
    #[test]
    fn test_module_name() {
        let module = SecurityModule::with_defaults();
        assert_eq!(module.name(), "security");
    }

    #[test]
    fn test_module_disabled_by_default() {
        let module = SecurityModule::with_defaults();
        assert!(!module.is_enabled());
    }

    #[test]
    fn test_disabled_sql_injection_detection() {
        let config = SecurityConfig {
            enabled: true,
            detect_sql_injection: false,
            ..enabled_config()
        };
        let module = SecurityModule::new(config);

        let entry = create_entry("Query: ' OR 1=1--");
        let result = module.process(entry).unwrap();
        assert!(!result.security_flags.contains(&SecurityFlag::SqlInjection));
    }

    #[test]
    fn test_multiple_flags_detected() {
        let module = SecurityModule::new(enabled_config());
        // This log has both SQL injection AND auth failure
        let entry = create_entry("Login failed with input: ' OR 1=1--");
        let result = module.process(entry).unwrap();
        assert!(result.security_flags.contains(&SecurityFlag::SqlInjection));
        assert!(result.security_flags.contains(&SecurityFlag::AuthFailure));
    }

    #[test]
    fn test_no_false_positive_normal_log() {
        let module = SecurityModule::new(enabled_config());
        let entry = create_entry("INFO: User john logged in successfully from 192.168.1.100");
        let result = module.process(entry).unwrap();
        assert!(result.security_flags.is_empty());
    }
}
