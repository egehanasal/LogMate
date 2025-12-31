use chrono::{DateTime, Local};
use flate2::write::GzEncoder;
use flate2::Compression;
use logmate_core::config::FileOutputConfig;
use logmate_core::{EnrichedEntry, OutputError};
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use tracing::{debug, info, warn};

/// File output format
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileFormat {
    /// JSON Lines - one JSON object per line
    JsonLines,
    /// Pretty JSON array (note: requires buffering all entries)
    Json,
    /// Plain text - just the formatted log content
    Text,
}

impl FileFormat {
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "json" => Self::Json,
            "text" | "txt" | "plain" => Self::Text,
            _ => Self::JsonLines, // Default to JSONL
        }
    }
}

/// Rotation strategy for log files
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RotationStrategy {
    /// Rotate daily at midnight
    Daily,
    /// Rotate hourly
    Hourly,
    /// Rotate when file exceeds size (in bytes)
    Size(u64),
    /// No rotation
    None,
}

impl RotationStrategy {
    pub fn from_config(rotation: &str, max_size: &str) -> Self {
        match rotation.to_lowercase().as_str() {
            "daily" => Self::Daily,
            "hourly" => Self::Hourly,
            "size" => Self::Size(parse_size(max_size)),
            "none" | "disabled" => Self::None,
            _ => Self::Daily, // Default to daily
        }
    }
}

/// Parse size string like "100MB", "1GB", "500KB" to bytes
fn parse_size(s: &str) -> u64 {
    let s = s.trim().to_uppercase();

    if let Some(num_str) = s.strip_suffix("GB") {
        num_str.trim().parse::<u64>().unwrap_or(100) * 1024 * 1024 * 1024
    } else if let Some(num_str) = s.strip_suffix("MB") {
        num_str.trim().parse::<u64>().unwrap_or(100) * 1024 * 1024
    } else if let Some(num_str) = s.strip_suffix("KB") {
        num_str.trim().parse::<u64>().unwrap_or(100) * 1024
    } else if let Some(num_str) = s.strip_suffix('B') {
        num_str.trim().parse::<u64>().unwrap_or(100 * 1024 * 1024)
    } else {
        // Assume MB if no suffix
        s.parse::<u64>().unwrap_or(100) * 1024 * 1024
    }
}

/// Writes enriched log entries to files with rotation support
pub struct FileWriter {
    config: FileOutputConfig,
    format: FileFormat,
    rotation: RotationStrategy,
    current_file: Option<BufWriter<File>>,
    current_path: PathBuf,
    current_size: u64,
    last_rotation_time: DateTime<Local>,
    entries_written: u64,
}

impl FileWriter {
    /// Create a new file writer from configuration
    pub fn new(config: FileOutputConfig) -> Result<Self, OutputError> {
        let format = FileFormat::from_str(&config.format);
        let rotation = RotationStrategy::from_config(&config.rotation, &config.max_size);
        let base_path = PathBuf::from(&config.path);

        // Create parent directory if it doesn't exist
        if let Some(parent) = base_path.parent() {
            if !parent.as_os_str().is_empty() && !parent.exists() {
                fs::create_dir_all(parent)
                    .map_err(|e| OutputError::File(format!("Failed to create directory: {}", e)))?;
            }
        }

        let mut writer = Self {
            config,
            format,
            rotation,
            current_file: None,
            current_path: base_path,
            current_size: 0,
            last_rotation_time: Local::now(),
            entries_written: 0,
        };

        // Open the initial file
        writer.open_file()?;

        Ok(writer)
    }

    /// Open or create the current log file
    fn open_file(&mut self) -> Result<(), OutputError> {
        let path = self.get_current_path();

        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(|e| OutputError::File(format!("Failed to open file {:?}: {}", path, e)))?;

        // Get current file size
        self.current_size = file.metadata()
            .map(|m| m.len())
            .unwrap_or(0);

        self.current_path = path.clone();
        self.current_file = Some(BufWriter::new(file));

        info!(path = %path.display(), "Opened log file for writing");

        Ok(())
    }

    /// Get the path for the current log file (with timestamp if rotating)
    fn get_current_path(&self) -> PathBuf {
        let base = PathBuf::from(&self.config.path);

        match self.rotation {
            RotationStrategy::Daily => {
                let date = Local::now().format("%Y-%m-%d");
                insert_date_into_path(&base, &date.to_string())
            }
            RotationStrategy::Hourly => {
                let datetime = Local::now().format("%Y-%m-%d-%H");
                insert_date_into_path(&base, &datetime.to_string())
            }
            _ => base,
        }
    }

    /// Check if rotation is needed and perform it
    fn check_rotation(&mut self) -> Result<bool, OutputError> {
        let needs_rotation = match &self.rotation {
            RotationStrategy::Daily => {
                let now = Local::now();
                now.date_naive() != self.last_rotation_time.date_naive()
            }
            RotationStrategy::Hourly => {
                let now = Local::now();
                now.hour() != self.last_rotation_time.hour()
                    || now.date_naive() != self.last_rotation_time.date_naive()
            }
            RotationStrategy::Size(max_size) => {
                self.current_size >= *max_size
            }
            RotationStrategy::None => false,
        };

        if needs_rotation {
            self.rotate()?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    /// Rotate the current log file
    fn rotate(&mut self) -> Result<(), OutputError> {
        // Flush and close current file
        if let Some(ref mut file) = self.current_file {
            file.flush()
                .map_err(|e| OutputError::File(format!("Failed to flush file: {}", e)))?;
        }
        self.current_file = None;

        // For size-based rotation, rename the current file
        if matches!(self.rotation, RotationStrategy::Size(_)) {
            let rotated_path = self.get_rotated_path();
            if self.current_path.exists() {
                fs::rename(&self.current_path, &rotated_path)
                    .map_err(|e| OutputError::File(format!("Failed to rotate file: {}", e)))?;

                info!(
                    from = %self.current_path.display(),
                    to = %rotated_path.display(),
                    "Rotated log file"
                );

                // Compress if enabled
                if self.config.compress {
                    self.compress_file(&rotated_path)?;
                }
            }
        } else {
            // For time-based rotation, compress the old file if it exists
            if self.config.compress && self.current_path.exists() {
                let old_path = self.current_path.clone();
                // Compress in background (or synchronously for simplicity)
                if let Err(e) = self.compress_file(&old_path) {
                    warn!(error = %e, "Failed to compress rotated file");
                }
            }
        }

        // Clean up old files
        self.cleanup_old_files()?;

        // Update rotation time
        self.last_rotation_time = Local::now();
        self.current_size = 0;

        // Open new file
        self.open_file()?;

        Ok(())
    }

    /// Get path for a rotated file (for size-based rotation)
    fn get_rotated_path(&self) -> PathBuf {
        let timestamp = Local::now().format("%Y%m%d-%H%M%S");
        let base = &self.current_path;

        if let Some(stem) = base.file_stem() {
            if let Some(ext) = base.extension() {
                let new_name = format!("{}-{}.{}", stem.to_string_lossy(), timestamp, ext.to_string_lossy());
                base.with_file_name(new_name)
            } else {
                let new_name = format!("{}-{}", stem.to_string_lossy(), timestamp);
                base.with_file_name(new_name)
            }
        } else {
            base.with_extension(format!("{}", timestamp))
        }
    }

    /// Compress a file with gzip
    fn compress_file(&self, path: &Path) -> Result<(), OutputError> {
        let gz_path = path.with_extension(
            format!("{}.gz", path.extension().unwrap_or_default().to_string_lossy())
        );

        let input = fs::read(path)
            .map_err(|e| OutputError::File(format!("Failed to read file for compression: {}", e)))?;

        let output_file = File::create(&gz_path)
            .map_err(|e| OutputError::File(format!("Failed to create compressed file: {}", e)))?;

        let mut encoder = GzEncoder::new(output_file, Compression::default());
        encoder.write_all(&input)
            .map_err(|e| OutputError::File(format!("Failed to write compressed data: {}", e)))?;
        encoder.finish()
            .map_err(|e| OutputError::File(format!("Failed to finish compression: {}", e)))?;

        // Remove original file
        fs::remove_file(path)
            .map_err(|e| OutputError::File(format!("Failed to remove original file: {}", e)))?;

        info!(
            original = %path.display(),
            compressed = %gz_path.display(),
            "Compressed rotated log file"
        );

        Ok(())
    }

    /// Clean up old rotated files beyond max_files limit
    fn cleanup_old_files(&self) -> Result<(), OutputError> {
        let base_path = PathBuf::from(&self.config.path);
        let parent = base_path.parent().unwrap_or(Path::new("."));
        let stem = base_path.file_stem()
            .map(|s| s.to_string_lossy().to_string())
            .unwrap_or_default();

        if !parent.exists() {
            return Ok(());
        }

        // Find all related log files
        let mut log_files: Vec<(PathBuf, std::time::SystemTime)> = fs::read_dir(parent)
            .map_err(|e| OutputError::File(format!("Failed to read directory: {}", e)))?
            .filter_map(|entry| entry.ok())
            .filter(|entry| {
                let name = entry.file_name().to_string_lossy().to_string();
                name.starts_with(&stem) && (name.ends_with(".log") || name.ends_with(".jsonl") || name.ends_with(".gz"))
            })
            .filter_map(|entry| {
                entry.metadata().ok().and_then(|m| {
                    m.modified().ok().map(|time| (entry.path(), time))
                })
            })
            .collect();

        // Sort by modification time (oldest first)
        log_files.sort_by(|a, b| a.1.cmp(&b.1));

        // Remove files beyond max_files
        let to_remove = log_files.len().saturating_sub(self.config.max_files);
        for (path, _) in log_files.into_iter().take(to_remove) {
            if let Err(e) = fs::remove_file(&path) {
                warn!(path = %path.display(), error = %e, "Failed to remove old log file");
            } else {
                debug!(path = %path.display(), "Removed old log file");
            }
        }

        Ok(())
    }

    /// Write an entry to the file
    pub fn write(&mut self, entry: &EnrichedEntry) -> Result<(), OutputError> {
        // Check if rotation is needed
        self.check_rotation()?;

        // Format entry first (before borrowing file mutably)
        let output = self.format_entry(entry)?;
        let bytes = output.as_bytes();
        let bytes_len = bytes.len() as u64;

        let file = self.current_file.as_mut()
            .ok_or_else(|| OutputError::File("File not open".to_string()))?;

        file.write_all(bytes)
            .map_err(|e| OutputError::File(format!("Failed to write to file: {}", e)))?;

        file.write_all(b"\n")
            .map_err(|e| OutputError::File(format!("Failed to write newline: {}", e)))?;

        self.current_size += bytes_len + 1;
        self.entries_written += 1;

        // Flush periodically (every 100 entries)
        if self.entries_written % 100 == 0 {
            if let Some(ref mut f) = self.current_file {
                f.flush()
                    .map_err(|e| OutputError::File(format!("Failed to flush file: {}", e)))?;
            }
        }

        debug!(format = ?self.format, "Wrote entry to file");

        Ok(())
    }

    /// Format an entry according to the output format
    fn format_entry(&self, entry: &EnrichedEntry) -> Result<String, OutputError> {
        match self.format {
            FileFormat::JsonLines | FileFormat::Json => {
                serde_json::to_string(entry)
                    .map_err(|e| OutputError::Serialization(e.to_string()))
            }
            FileFormat::Text => {
                Ok(self.format_text(entry))
            }
        }
    }

    /// Format entry as plain text
    fn format_text(&self, entry: &EnrichedEntry) -> String {
        let mut parts = Vec::new();

        // Timestamp
        parts.push(format!("[{}]", entry.raw.received_at.format("%Y-%m-%d %H:%M:%S%.3f")));

        // Source
        parts.push(format!("[{}]", entry.raw.source));

        // Level
        if let Some(ref level) = entry.level {
            parts.push(format!("[{}]", level));
        }

        // Latency
        if let Some(latency) = entry.latency_ms {
            parts.push(format!("[{:.2}ms]", latency));
        }

        // Security flags
        if !entry.security_flags.is_empty() {
            let flags: Vec<String> = entry.security_flags
                .iter()
                .map(|f| format!("{:?}", f))
                .collect();
            parts.push(format!("[SECURITY:{}]", flags.join(",")));
        }

        // Content
        parts.push(entry.raw.content.clone());

        parts.join(" ")
    }

    /// Flush any buffered data
    pub fn flush(&mut self) -> Result<(), OutputError> {
        if let Some(ref mut file) = self.current_file {
            file.flush()
                .map_err(|e| OutputError::File(format!("Failed to flush file: {}", e)))?;
        }
        Ok(())
    }

    /// Get the number of entries written
    pub fn entries_written(&self) -> u64 {
        self.entries_written
    }

    /// Get the current file path
    pub fn current_path(&self) -> &Path {
        &self.current_path
    }
}

impl Drop for FileWriter {
    fn drop(&mut self) {
        if let Err(e) = self.flush() {
            warn!(error = %e, "Failed to flush file on drop");
        }
    }
}

/// Insert a date string into a file path
/// e.g., "logs/app.log" + "2024-01-15" -> "logs/app-2024-01-15.log"
fn insert_date_into_path(base: &Path, date: &str) -> PathBuf {
    if let Some(stem) = base.file_stem() {
        if let Some(ext) = base.extension() {
            let new_name = format!("{}-{}.{}", stem.to_string_lossy(), date, ext.to_string_lossy());
            base.with_file_name(new_name)
        } else {
            let new_name = format!("{}-{}", stem.to_string_lossy(), date);
            base.with_file_name(new_name)
        }
    } else {
        base.with_extension(date)
    }
}

use chrono::Timelike;

#[cfg(test)]
mod tests {
    use super::*;
    use logmate_core::{LogEntry, LogLevel, LogSource};
    use std::io::Read;
    use tempfile::TempDir;

    fn create_entry(content: &str) -> EnrichedEntry {
        let mut entry = EnrichedEntry::from(LogEntry::new(LogSource::Stdin, content.to_string()));
        entry.level = Some(LogLevel::Info);
        entry
    }

    fn test_config(dir: &Path, format: &str, rotation: &str) -> FileOutputConfig {
        FileOutputConfig {
            enabled: true,
            path: dir.join("test.log").to_string_lossy().to_string(),
            format: format.to_string(),
            rotation: rotation.to_string(),
            max_size: "1KB".to_string(),
            max_files: 3,
            compress: false, // Disable compression for tests
        }
    }

    #[test]
    fn test_parse_size() {
        assert_eq!(parse_size("100MB"), 100 * 1024 * 1024);
        assert_eq!(parse_size("1GB"), 1024 * 1024 * 1024);
        assert_eq!(parse_size("500KB"), 500 * 1024);
        assert_eq!(parse_size("1024B"), 1024);
        assert_eq!(parse_size("50"), 50 * 1024 * 1024); // Default to MB
    }

    #[test]
    fn test_file_format_from_str() {
        assert_eq!(FileFormat::from_str("jsonl"), FileFormat::JsonLines);
        assert_eq!(FileFormat::from_str("json"), FileFormat::Json);
        assert_eq!(FileFormat::from_str("text"), FileFormat::Text);
        assert_eq!(FileFormat::from_str("txt"), FileFormat::Text);
        assert_eq!(FileFormat::from_str("unknown"), FileFormat::JsonLines);
    }

    #[test]
    fn test_rotation_strategy_from_config() {
        assert_eq!(
            RotationStrategy::from_config("daily", "100MB"),
            RotationStrategy::Daily
        );
        assert_eq!(
            RotationStrategy::from_config("hourly", "100MB"),
            RotationStrategy::Hourly
        );
        assert_eq!(
            RotationStrategy::from_config("size", "50MB"),
            RotationStrategy::Size(50 * 1024 * 1024)
        );
        assert_eq!(
            RotationStrategy::from_config("none", "100MB"),
            RotationStrategy::None
        );
    }

    #[test]
    fn test_write_jsonl() {
        let dir = TempDir::new().unwrap();
        let config = test_config(dir.path(), "jsonl", "none");
        let mut writer = FileWriter::new(config).unwrap();

        let entry = create_entry("Test log message");
        writer.write(&entry).unwrap();
        writer.flush().unwrap();

        let mut content = String::new();
        File::open(writer.current_path())
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();

        assert!(content.contains("Test log message"));
        assert!(content.contains("\"content\""));
    }

    #[test]
    fn test_write_text() {
        let dir = TempDir::new().unwrap();
        let config = test_config(dir.path(), "text", "none");
        let mut writer = FileWriter::new(config).unwrap();

        let entry = create_entry("Test log message");
        writer.write(&entry).unwrap();
        writer.flush().unwrap();

        let mut content = String::new();
        File::open(writer.current_path())
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();

        assert!(content.contains("Test log message"));
        assert!(content.contains("[stdin]"));
        assert!(content.contains("[INFO]"));
    }

    #[test]
    fn test_size_based_rotation() {
        let dir = TempDir::new().unwrap();
        let mut config = test_config(dir.path(), "text", "size");
        config.max_size = "100B".to_string(); // Very small for testing
        config.compress = false;

        let mut writer = FileWriter::new(config).unwrap();

        // Write enough entries to trigger rotation
        for i in 0..20 {
            let entry = create_entry(&format!("Log message number {}", i));
            writer.write(&entry).unwrap();
        }
        writer.flush().unwrap();

        // Check that multiple files were created
        let files: Vec<_> = fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().to_string_lossy().contains("test"))
            .collect();

        assert!(files.len() > 1, "Expected multiple files after rotation");
    }

    #[test]
    fn test_entries_written_count() {
        let dir = TempDir::new().unwrap();
        let config = test_config(dir.path(), "jsonl", "none");
        let mut writer = FileWriter::new(config).unwrap();

        assert_eq!(writer.entries_written(), 0);

        for _ in 0..5 {
            let entry = create_entry("Test message");
            writer.write(&entry).unwrap();
        }

        assert_eq!(writer.entries_written(), 5);
    }

    #[test]
    fn test_insert_date_into_path() {
        let base = PathBuf::from("/var/log/app.log");
        let result = insert_date_into_path(&base, "2024-01-15");
        assert_eq!(result, PathBuf::from("/var/log/app-2024-01-15.log"));

        let base_no_ext = PathBuf::from("/var/log/app");
        let result = insert_date_into_path(&base_no_ext, "2024-01-15");
        assert_eq!(result, PathBuf::from("/var/log/app-2024-01-15"));
    }
}
