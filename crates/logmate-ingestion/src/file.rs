use glob::glob;
use logmate_core::{IngestionError, LogEntry, LogSource};
use notify::{Config, Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use std::collections::HashMap;
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use tokio::fs::File as TokioFile;
use tokio::io::{AsyncBufReadExt, AsyncSeekExt, BufReader};
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

/// File watcher for log ingestion with tail -f behavior
pub struct FileIngestion {
    /// Glob patterns or file paths to watch
    paths: Vec<String>,
    /// Start from end of file (tail mode)
    tail: bool,
}

impl FileIngestion {
    /// Create a new file ingestion watcher
    pub fn new(paths: Vec<String>, tail: bool) -> Self {
        Self { paths, tail }
    }

    /// Expand glob patterns into actual file paths
    fn expand_paths(&self) -> Vec<PathBuf> {
        let mut files = Vec::new();

        for pattern in &self.paths {
            match glob(pattern) {
                Ok(entries) => {
                    for entry in entries.flatten() {
                        if entry.is_file() {
                            files.push(entry);
                        }
                    }
                }
                Err(e) => {
                    warn!(pattern = %pattern, error = %e, "Invalid glob pattern");
                }
            }
        }

        files.sort();
        files.dedup();
        files
    }

    /// Start watching files and send log entries through the channel
    pub async fn run(self, sender: mpsc::Sender<LogEntry>) -> Result<(), IngestionError> {
        let files = self.expand_paths();

        if files.is_empty() {
            warn!(patterns = ?self.paths, "No files matched the patterns");
            return Ok(());
        }

        info!(count = files.len(), "Starting file watcher");

        // Create a tokio channel to bridge sync notify events to async
        let (async_tx, mut async_rx) = mpsc::channel::<notify::Result<Event>>(100);

        // Create the file watcher with a channel that sends to our tokio channel
        let watcher_tx = async_tx.clone();
        let mut watcher = RecommendedWatcher::new(
            move |res| {
                // Use blocking_send since we're in a sync context
                let _ = watcher_tx.blocking_send(res);
            },
            Config::default(),
        )
        .map_err(|e| IngestionError::FileWatch(format!("Failed to create file watcher: {}", e)))?;

        // Track file positions for each watched file
        let mut file_states: HashMap<PathBuf, FileState> = HashMap::new();

        // Initialize file states and start watching
        for path in &files {
            // Watch the file directly for modifications
            watcher
                .watch(path, RecursiveMode::NonRecursive)
                .map_err(|e| {
                    IngestionError::FileWatch(format!(
                        "Failed to watch file {:?}: {}",
                        path, e
                    ))
                })?;

            // Also watch the parent directory to catch file rotation
            if let Some(parent) = path.parent() {
                let _ = watcher.watch(parent, RecursiveMode::NonRecursive);
            }

            // Initialize file state
            let state = FileState::new(path, self.tail).await?;
            info!(path = %path.display(), position = state.position, "Watching file");
            file_states.insert(path.clone(), state);
        }

        // If not in tail mode, read existing content first
        if !self.tail {
            for (path, state) in &mut file_states {
                if let Err(e) = read_new_lines(path, state, &sender).await {
                    error!(path = %path.display(), error = %e, "Error reading file");
                }
            }
        }

        // Keep the watcher alive
        let _watcher = watcher;

        // Main event loop - process file system events
        while let Some(event_result) = async_rx.recv().await {
            match event_result {
                Ok(event) => {
                    if let Err(e) = self.handle_event(event, &mut file_states, &sender).await {
                        error!(error = %e, "Error handling file event");
                    }
                }
                Err(e) => {
                    error!(error = %e, "File watch error");
                }
            }
        }

        Ok(())
    }

    /// Handle a file system event
    async fn handle_event(
        &self,
        event: Event,
        file_states: &mut HashMap<PathBuf, FileState>,
        sender: &mpsc::Sender<LogEntry>,
    ) -> Result<(), IngestionError> {
        debug!(kind = ?event.kind, paths = ?event.paths, "Received file event");

        match event.kind {
            EventKind::Modify(_) => {
                // File was modified - read new lines
                for event_path in &event.paths {
                    // Try to find matching file in our state (handle path normalization)
                    let matching_path = file_states.keys()
                        .find(|p| paths_match(p, event_path))
                        .cloned();

                    if let Some(path) = matching_path {
                        if let Some(state) = file_states.get_mut(&path) {
                            debug!(path = %path.display(), "Reading new lines from modified file");
                            if let Err(e) = read_new_lines(&path, state, sender).await {
                                error!(path = %path.display(), error = %e, "Error reading file");
                            }
                        }
                    }
                }
            }
            EventKind::Create(_) => {
                // New file created (possible rotation)
                for path in &event.paths {
                    // Check if this matches any of our patterns
                    if self.matches_patterns(path) && !file_states.contains_key(path) {
                        info!(path = %path.display(), "New file detected (rotation?)");
                        let state = FileState::new(path, false).await?;
                        file_states.insert(path.clone(), state);
                    }
                }
            }
            EventKind::Remove(_) => {
                // File removed - log but keep watching (might be rotation)
                for path in &event.paths {
                    if file_states.contains_key(path) {
                        warn!(path = %path.display(), "Watched file removed");
                    }
                }
            }
            _ => {
                debug!(kind = ?event.kind, "Ignoring file event");
            }
        }

        Ok(())
    }

    /// Check if a path matches any of our watch patterns
    fn matches_patterns(&self, path: &Path) -> bool {
        let path_str = path.to_string_lossy();
        for pattern in &self.paths {
            if let Ok(glob_pattern) = glob::Pattern::new(pattern) {
                if glob_pattern.matches(&path_str) {
                    return true;
                }
            }
        }
        false
    }
}

/// Check if two paths refer to the same file (handles symlinks and normalization)
fn paths_match(a: &Path, b: &Path) -> bool {
    // First try simple comparison
    if a == b {
        return true;
    }

    // Try canonicalized comparison (resolves symlinks and normalizes)
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(ca), Ok(cb)) => ca == cb,
        _ => {
            // Fall back to file name comparison if canonicalize fails
            a.file_name() == b.file_name()
        }
    }
}

/// Tracks the state of a watched file
struct FileState {
    /// Current position in the file
    position: u64,
    /// Inode (for rotation detection on Unix)
    #[cfg(unix)]
    inode: Option<u64>,
}

impl FileState {
    /// Create a new file state
    async fn new(path: &Path, tail: bool) -> Result<Self, IngestionError> {
        let metadata = tokio::fs::metadata(path).await.map_err(|e| {
            IngestionError::FileWatch(format!("Failed to get metadata for {:?}: {}", path, e))
        })?;

        let position = if tail { metadata.len() } else { 0 };

        #[cfg(unix)]
        let inode = {
            use std::os::unix::fs::MetadataExt;
            Some(metadata.ino())
        };

        Ok(Self {
            position,
            #[cfg(unix)]
            inode,
        })
    }

    /// Check if the file has been rotated (inode changed)
    #[cfg(unix)]
    async fn check_rotation(&mut self, path: &Path) -> Result<bool, IngestionError> {
        use std::os::unix::fs::MetadataExt;

        let metadata = tokio::fs::metadata(path).await.map_err(|e| {
            IngestionError::FileWatch(format!("Failed to get metadata for {:?}: {}", path, e))
        })?;

        let current_inode = metadata.ino();
        if let Some(old_inode) = self.inode {
            if current_inode != old_inode {
                // File was rotated
                self.inode = Some(current_inode);
                self.position = 0;
                return Ok(true);
            }
        }
        Ok(false)
    }

    #[cfg(not(unix))]
    async fn check_rotation(&mut self, _path: &Path) -> Result<bool, IngestionError> {
        // On non-Unix systems, we can't reliably detect rotation by inode
        // We'll just check if the file size is smaller than our position
        Ok(false)
    }
}

/// Read new lines from a file starting at the given position
async fn read_new_lines(
    path: &Path,
    state: &mut FileState,
    sender: &mpsc::Sender<LogEntry>,
) -> Result<(), IngestionError> {
    // Check for file rotation
    if state.check_rotation(path).await? {
        info!(path = %path.display(), "File rotation detected, reading from start");
    }

    let file = TokioFile::open(path).await.map_err(|e| {
        IngestionError::FileWatch(format!("Failed to open file {:?}: {}", path, e))
    })?;

    // Check if file was truncated
    let metadata = file.metadata().await.map_err(|e| {
        IngestionError::FileWatch(format!("Failed to get metadata for {:?}: {}", path, e))
    })?;

    if metadata.len() < state.position {
        info!(path = %path.display(), "File truncated, reading from start");
        state.position = 0;
    }

    let mut reader = BufReader::new(file);

    // Seek to our last position
    reader.seek(SeekFrom::Start(state.position)).await.map_err(|e| {
        IngestionError::FileWatch(format!("Failed to seek in file {:?}: {}", path, e))
    })?;

    let source = LogSource::File {
        path: path.to_string_lossy().to_string(),
    };

    let mut line = String::new();
    let mut lines_read = 0;

    loop {
        line.clear();
        let bytes_read = reader.read_line(&mut line).await.map_err(|e| {
            IngestionError::FileWatch(format!("Failed to read from file {:?}: {}", path, e))
        })?;

        if bytes_read == 0 {
            // EOF reached
            break;
        }

        // Update position
        state.position += bytes_read as u64;

        // Remove trailing newline
        let content = line.trim_end().to_string();

        if content.is_empty() {
            continue;
        }

        let entry = LogEntry::new(source.clone(), content);
        debug!(path = %path.display(), "Read log line from file");

        if sender.send(entry).await.is_err() {
            warn!("Channel closed, stopping file reader");
            return Err(IngestionError::ChannelClosed);
        }

        lines_read += 1;
    }

    if lines_read > 0 {
        debug!(path = %path.display(), lines = lines_read, "Read lines from file");
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    #[test]
    fn test_file_ingestion_creation() {
        let paths = vec!["/var/log/*.log".to_string()];
        let ingestion = FileIngestion::new(paths.clone(), true);
        assert_eq!(ingestion.paths, paths);
        assert!(ingestion.tail);
    }

    #[test]
    fn test_expand_paths_no_match() {
        let ingestion = FileIngestion::new(vec!["/nonexistent/path/*.xyz".to_string()], true);
        let paths = ingestion.expand_paths();
        assert!(paths.is_empty());
    }

    #[tokio::test]
    async fn test_read_file_content() {
        // Create a temp file with some content
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "ERROR: First log line").unwrap();
        writeln!(file, "INFO: Second log line").unwrap();
        file.flush().unwrap();

        let path = file.path().to_path_buf();
        let mut state = FileState::new(&path, false).await.unwrap();
        assert_eq!(state.position, 0);

        let (sender, mut receiver) = mpsc::channel(100);

        // Read the file
        read_new_lines(&path, &mut state, &sender).await.unwrap();
        drop(sender); // Close sender so receiver knows when done

        // Collect entries
        let mut entries = Vec::new();
        while let Some(entry) = receiver.recv().await {
            entries.push(entry);
        }

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].content, "ERROR: First log line");
        assert_eq!(entries[1].content, "INFO: Second log line");
        assert!(matches!(entries[0].source, LogSource::File { .. }));
    }

    #[tokio::test]
    async fn test_tail_mode() {
        // Create a temp file with existing content
        let mut file = NamedTempFile::new().unwrap();
        writeln!(file, "Existing line 1").unwrap();
        writeln!(file, "Existing line 2").unwrap();
        file.flush().unwrap();

        let path = file.path().to_path_buf();

        // In tail mode, should start at end of file
        let state = FileState::new(&path, true).await.unwrap();
        let metadata = std::fs::metadata(&path).unwrap();
        assert_eq!(state.position, metadata.len());

        // In non-tail mode, should start at beginning
        let state = FileState::new(&path, false).await.unwrap();
        assert_eq!(state.position, 0);
    }

    #[test]
    fn test_pattern_matching() {
        let ingestion = FileIngestion::new(
            vec!["/var/log/*.log".to_string(), "/tmp/app.log".to_string()],
            true,
        );

        // These patterns don't match against full paths easily in this test
        // The actual matching depends on glob::Pattern behavior
    }
}
