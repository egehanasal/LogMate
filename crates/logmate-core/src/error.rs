use thiserror::Error;

/// Core error types for LogMate
#[derive(Debug, Error)]
pub enum LogMateError {
    #[error("Configuration error: {0}")]
    Config(String),

    #[error("Ingestion error: {0}")]
    Ingestion(#[from] IngestionError),

    #[error("Pipeline error: {0}")]
    Pipeline(String),

    #[error("Output error: {0}")]
    Output(#[from] OutputError),

    #[error("Module error in '{module}': {message}")]
    Module { module: String, message: String },

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Errors specific to log ingestion
#[derive(Debug, Error)]
pub enum IngestionError {
    #[error("Failed to read from stdin: {0}")]
    Stdin(String),

    #[error("TCP connection error: {0}")]
    Tcp(String),

    #[error("UDP receive error: {0}")]
    Udp(String),

    #[error("File watch error: {0}")]
    FileWatch(String),

    #[error("Channel closed")]
    ChannelClosed,
}

/// Errors specific to output sinks
#[derive(Debug, Error)]
pub enum OutputError {
    #[error("Stdout write error: {0}")]
    Stdout(String),

    #[error("File write error: {0}")]
    File(String),

    #[error("Grafana push error: {0}")]
    Grafana(String),

    #[error("Network error: {0}")]
    Network(String),

    #[error("Serialization error: {0}")]
    Serialization(String),
}

/// Result type alias for LogMate operations
pub type Result<T> = std::result::Result<T, LogMateError>;
