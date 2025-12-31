use logmate_core::{EnrichedEntry, OutputError};
use tokio::io::{AsyncWriteExt, Stdout};
use tracing::debug;

/// Output format for stdout
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    /// Pretty-printed, human-readable format
    Pretty,
    /// Compact JSON (one line per entry)
    Json,
    /// Raw content only (original log line)
    Raw,
}

impl Default for OutputFormat {
    fn default() -> Self {
        Self::Pretty
    }
}

/// Writes enriched log entries to stdout
pub struct StdoutWriter {
    format: OutputFormat,
    stdout: Stdout,
}

impl StdoutWriter {
    /// Create a new stdout writer with default format
    pub fn new() -> Self {
        Self {
            format: OutputFormat::default(),
            stdout: tokio::io::stdout(),
        }
    }

    /// Create a new stdout writer with a specific format
    pub fn with_format(format: OutputFormat) -> Self {
        Self {
            format,
            stdout: tokio::io::stdout(),
        }
    }

    /// Write a single enriched entry to stdout
    pub async fn write(&mut self, entry: &EnrichedEntry) -> Result<(), OutputError> {
        let output = self.format_entry(entry)?;

        self.stdout
            .write_all(output.as_bytes())
            .await
            .map_err(|e| OutputError::Stdout(e.to_string()))?;

        self.stdout
            .write_all(b"\n")
            .await
            .map_err(|e| OutputError::Stdout(e.to_string()))?;

        self.stdout
            .flush()
            .await
            .map_err(|e| OutputError::Stdout(e.to_string()))?;

        debug!(format = ?self.format, "Wrote entry to stdout");
        Ok(())
    }

    /// Format an entry according to the output format
    fn format_entry(&self, entry: &EnrichedEntry) -> Result<String, OutputError> {
        match self.format {
            OutputFormat::Pretty => Ok(self.format_pretty(entry)),
            OutputFormat::Json => serde_json::to_string(entry)
                .map_err(|e| OutputError::Serialization(e.to_string())),
            OutputFormat::Raw => Ok(entry.raw.content.clone()),
        }
    }

    /// Format an entry in a human-readable way
    fn format_pretty(&self, entry: &EnrichedEntry) -> String {
        let mut parts = Vec::new();

        // Timestamp
        parts.push(format!("[{}]", entry.raw.received_at.format("%Y-%m-%d %H:%M:%S%.3f")));

        // Source
        parts.push(format!("[{}]", entry.raw.source));

        // Level (if detected)
        if let Some(ref level) = entry.level {
            parts.push(format!("[{}]", level));
        }

        // Error code (if detected)
        if let Some(ref code) = entry.error_code {
            parts.push(format!("[code:{}]", code));
        }

        // Latency (if detected)
        if let Some(latency) = entry.latency_ms {
            parts.push(format!("[{:.2}ms]", latency));
        }

        // Security flags
        if !entry.security_flags.is_empty() {
            let flags: Vec<String> = entry
                .security_flags
                .iter()
                .map(|f| format!("{:?}", f))
                .collect();
            parts.push(format!("[SECURITY:{}]", flags.join(",")));
        }

        // Content
        parts.push(entry.raw.content.clone());

        parts.join(" ")
    }
}

impl Default for StdoutWriter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use logmate_core::{LogEntry, LogLevel, LogSource};

    #[test]
    fn test_format_pretty() {
        let writer = StdoutWriter::new();
        let entry = LogEntry::new(LogSource::Stdin, "Test message".to_string());
        let mut enriched = EnrichedEntry::from(entry);
        enriched.level = Some(LogLevel::Error);

        let output = writer.format_pretty(&enriched);
        assert!(output.contains("[stdin]"));
        assert!(output.contains("[ERROR]"));
        assert!(output.contains("Test message"));
    }

    #[test]
    fn test_format_json() {
        let writer = StdoutWriter::with_format(OutputFormat::Json);
        let entry = LogEntry::new(LogSource::Stdin, "Test message".to_string());
        let enriched = EnrichedEntry::from(entry);

        let output = writer.format_entry(&enriched).unwrap();
        assert!(output.contains("\"content\":\"Test message\""));
    }
}
