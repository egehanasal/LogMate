//! LogMate Output
//!
//! Output sinks for the LogMate observability engine.
//! Supports stdout, file, and Grafana (Loki/Prometheus).

pub mod file;
pub mod stdout;

#[cfg(feature = "loki")]
pub mod loki;

#[cfg(feature = "prometheus")]
pub mod metrics;

pub use file::{FileFormat, FileWriter, RotationStrategy};
pub use stdout::{OutputFormat, StdoutWriter};

#[cfg(feature = "loki")]
pub use loki::LokiClient;

#[cfg(feature = "prometheus")]
pub use metrics::{MetricsCollector, MetricsServer};
