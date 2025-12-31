//! LogMate Output
//!
//! Output sinks for the LogMate observability engine.
//! Supports stdout, file, and Grafana (Loki/Prometheus).

pub mod stdout;

pub use stdout::{OutputFormat, StdoutWriter};
