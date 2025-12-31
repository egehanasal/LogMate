use chrono::{DateTime, Duration, Utc};
use hdrhistogram::Histogram;
use logmate_core::config::PerformanceMetricsConfig;
use logmate_core::{EnrichedEntry, Module, Result};
use regex::Regex;
use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use tracing::{debug, info};

/// Performance Metrics Module
///
/// Extracts latency values from log entries and tracks rolling window statistics
/// with percentile calculations (P50, P90, P95, P99).
pub struct PerformanceMetricsModule {
    config: PerformanceMetricsConfig,
    latency_patterns: Vec<CompiledLatencyPattern>,
    windows: Arc<Mutex<Vec<RollingWindow>>>,
}

struct CompiledLatencyPattern {
    regex: Regex,
}

/// A rolling time window for tracking latency metrics
struct RollingWindow {
    name: String,
    duration: Duration,
    entries: VecDeque<LatencyEntry>,
    histogram: Histogram<u64>,
    percentiles: Vec<u8>,
}

struct LatencyEntry {
    timestamp: DateTime<Utc>,
    latency_ms: f64,
}

impl RollingWindow {
    fn new(name: String, duration: Duration, percentiles: Vec<u8>) -> Self {
        Self {
            name,
            duration,
            entries: VecDeque::new(),
            // Histogram tracking latencies from 1us to 60 seconds with 3 significant figures
            histogram: Histogram::new_with_bounds(1, 60_000_000, 3).unwrap(),
            percentiles,
        }
    }

    /// Add a latency measurement to the window
    fn record(&mut self, latency_ms: f64) {
        let now = Utc::now();

        // Convert to microseconds for histogram (more precision)
        let latency_us = (latency_ms * 1000.0) as u64;
        let _ = self.histogram.record(latency_us);

        self.entries.push_back(LatencyEntry {
            timestamp: now,
            latency_ms,
        });

        // Clean up old entries
        self.cleanup(now);
    }

    /// Remove entries older than the window duration
    fn cleanup(&mut self, now: DateTime<Utc>) {
        let cutoff = now - self.duration;

        // Remove old entries and rebuild histogram if needed
        let old_len = self.entries.len();
        self.entries.retain(|e| e.timestamp > cutoff);

        // If we removed entries, rebuild the histogram
        if self.entries.len() != old_len {
            self.histogram.reset();
            for entry in &self.entries {
                let latency_us = (entry.latency_ms * 1000.0) as u64;
                let _ = self.histogram.record(latency_us);
            }
        }
    }

    /// Get statistics for this window
    fn stats(&self) -> WindowStats {
        let count = self.histogram.len();

        if count == 0 {
            return WindowStats {
                window: self.name.clone(),
                count: 0,
                min_ms: 0.0,
                max_ms: 0.0,
                mean_ms: 0.0,
                percentiles: vec![],
            };
        }

        let min_us = self.histogram.min();
        let max_us = self.histogram.max();
        let mean_us = self.histogram.mean();

        let percentiles: Vec<PercentileValue> = self.percentiles
            .iter()
            .map(|&p| {
                let value_us = self.histogram.value_at_percentile(p as f64);
                PercentileValue {
                    percentile: p,
                    value_ms: value_us as f64 / 1000.0,
                }
            })
            .collect();

        WindowStats {
            window: self.name.clone(),
            count,
            min_ms: min_us as f64 / 1000.0,
            max_ms: max_us as f64 / 1000.0,
            mean_ms: mean_us / 1000.0,
            percentiles,
        }
    }
}

/// Statistics for a rolling window
#[derive(Debug, Clone)]
pub struct WindowStats {
    pub window: String,
    pub count: u64,
    pub min_ms: f64,
    pub max_ms: f64,
    pub mean_ms: f64,
    pub percentiles: Vec<PercentileValue>,
}

#[derive(Debug, Clone)]
pub struct PercentileValue {
    pub percentile: u8,
    pub value_ms: f64,
}

impl PerformanceMetricsModule {
    /// Create a new performance metrics module with the given configuration
    pub fn new(config: PerformanceMetricsConfig) -> Self {
        // Compile latency patterns
        let latency_patterns: Vec<CompiledLatencyPattern> = config
            .latency_patterns
            .iter()
            .filter_map(|pattern| {
                match Regex::new(pattern) {
                    Ok(regex) => Some(CompiledLatencyPattern { regex }),
                    Err(e) => {
                        tracing::warn!(
                            pattern = %pattern,
                            error = %e,
                            "Failed to compile latency pattern, skipping"
                        );
                        None
                    }
                }
            })
            .collect();

        // Create rolling windows
        let windows: Vec<RollingWindow> = config
            .windows
            .iter()
            .filter_map(|w| {
                parse_duration(w).map(|d| {
                    RollingWindow::new(w.clone(), d, config.percentiles.clone())
                })
            })
            .collect();

        info!(
            patterns = latency_patterns.len(),
            windows = windows.len(),
            "Performance metrics module initialized"
        );

        Self {
            config,
            latency_patterns,
            windows: Arc::new(Mutex::new(windows)),
        }
    }

    /// Create with default configuration
    pub fn with_defaults() -> Self {
        Self::new(PerformanceMetricsConfig::default())
    }

    /// Extract latency value from log content
    fn extract_latency(&self, content: &str) -> Option<f64> {
        for pattern in &self.latency_patterns {
            if let Some(caps) = pattern.regex.captures(content) {
                // Try to get the duration value
                let duration_str = caps.name("duration")
                    .or_else(|| caps.get(1))
                    .map(|m| m.as_str())?;

                // Try to get the unit (default to ms)
                let unit = caps.name("unit")
                    .or_else(|| caps.get(2))
                    .map(|m| m.as_str())
                    .unwrap_or("ms");

                // Parse the duration value
                let value: f64 = duration_str.parse().ok()?;

                // Convert to milliseconds
                let ms = match unit.to_lowercase().as_str() {
                    "us" | "µs" | "micros" | "microseconds" => value / 1000.0,
                    "ms" | "millis" | "milliseconds" => value,
                    "s" | "sec" | "secs" | "seconds" => value * 1000.0,
                    "m" | "min" | "mins" | "minutes" => value * 60_000.0,
                    _ => value, // Default to ms
                };

                debug!(
                    raw_value = value,
                    unit = unit,
                    latency_ms = ms,
                    "Extracted latency"
                );

                return Some(ms);
            }
        }
        None
    }

    /// Record a latency value to all windows
    fn record_latency(&self, latency_ms: f64) {
        if let Ok(mut windows) = self.windows.lock() {
            for window in windows.iter_mut() {
                window.record(latency_ms);
            }
        }
    }

    /// Get current statistics for all windows
    pub fn get_stats(&self) -> Vec<WindowStats> {
        if let Ok(windows) = self.windows.lock() {
            windows.iter().map(|w| w.stats()).collect()
        } else {
            vec![]
        }
    }

    /// Get statistics and log them (useful for periodic reporting)
    pub fn report_stats(&self) {
        let stats = self.get_stats();
        for stat in stats {
            if stat.count > 0 {
                let percentile_str: Vec<String> = stat.percentiles
                    .iter()
                    .map(|p| format!("P{}={:.2}ms", p.percentile, p.value_ms))
                    .collect();

                info!(
                    window = %stat.window,
                    count = stat.count,
                    min_ms = format!("{:.2}", stat.min_ms),
                    max_ms = format!("{:.2}", stat.max_ms),
                    mean_ms = format!("{:.2}", stat.mean_ms),
                    percentiles = %percentile_str.join(", "),
                    "Latency statistics"
                );
            }
        }
    }
}

impl Module for PerformanceMetricsModule {
    fn name(&self) -> &'static str {
        "performance_metrics"
    }

    fn process(&self, mut entry: EnrichedEntry) -> Result<EnrichedEntry> {
        let content = entry.raw.content.clone();

        // Extract latency from the log content
        if let Some(latency_ms) = self.extract_latency(&content) {
            debug!(latency_ms = latency_ms, "Extracted latency from log");
            entry.latency_ms = Some(latency_ms);

            // Record to rolling windows
            self.record_latency(latency_ms);
        }

        Ok(entry)
    }

    fn is_enabled(&self) -> bool {
        self.config.enabled
    }
}

/// Parse a duration string like "1m", "5m", "15m", "1h"
fn parse_duration(s: &str) -> Option<Duration> {
    let s = s.trim().to_lowercase();

    if s.ends_with('s') {
        let num: i64 = s.trim_end_matches('s').parse().ok()?;
        Some(Duration::seconds(num))
    } else if s.ends_with('m') {
        let num: i64 = s.trim_end_matches('m').parse().ok()?;
        Some(Duration::minutes(num))
    } else if s.ends_with('h') {
        let num: i64 = s.trim_end_matches('h').parse().ok()?;
        Some(Duration::hours(num))
    } else if s.ends_with('d') {
        let num: i64 = s.trim_end_matches('d').parse().ok()?;
        Some(Duration::days(num))
    } else {
        // Assume minutes if no suffix
        let num: i64 = s.parse().ok()?;
        Some(Duration::minutes(num))
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
    fn test_module_name() {
        let module = PerformanceMetricsModule::with_defaults();
        assert_eq!(module.name(), "performance_metrics");
    }

    #[test]
    fn test_module_disabled_by_default() {
        let module = PerformanceMetricsModule::with_defaults();
        assert!(!module.is_enabled());
    }

    #[test]
    fn test_extract_latency_ms() {
        let config = PerformanceMetricsConfig {
            enabled: true,
            latency_patterns: vec![r"took (?P<duration>\d+)(?P<unit>ms|s|us)?".to_string()],
            windows: vec!["1m".to_string()],
            percentiles: vec![50, 90, 99],
        };
        let module = PerformanceMetricsModule::new(config);

        let entry = create_entry("Request took 150ms to complete");
        let result = module.process(entry).unwrap();
        assert_eq!(result.latency_ms, Some(150.0));
    }

    #[test]
    fn test_extract_latency_seconds() {
        let config = PerformanceMetricsConfig {
            enabled: true,
            latency_patterns: vec![r"took (?P<duration>\d+\.?\d*)(?P<unit>ms|s|us)?".to_string()],
            windows: vec!["1m".to_string()],
            percentiles: vec![50, 90, 99],
        };
        let module = PerformanceMetricsModule::new(config);

        let entry = create_entry("Request took 2s to complete");
        let result = module.process(entry).unwrap();
        assert_eq!(result.latency_ms, Some(2000.0));
    }

    #[test]
    fn test_extract_latency_microseconds() {
        let config = PerformanceMetricsConfig {
            enabled: true,
            latency_patterns: vec![r"took (?P<duration>\d+)(?P<unit>ms|s|us)?".to_string()],
            windows: vec!["1m".to_string()],
            percentiles: vec![50, 90, 99],
        };
        let module = PerformanceMetricsModule::new(config);

        let entry = create_entry("Query took 500us");
        let result = module.process(entry).unwrap();
        assert_eq!(result.latency_ms, Some(0.5));
    }

    #[test]
    fn test_extract_latency_key_value_format() {
        let config = PerformanceMetricsConfig {
            enabled: true,
            latency_patterns: vec![r"latency[=:]\s*(?P<duration>\d+\.?\d*)(?P<unit>ms|s)?".to_string()],
            windows: vec!["1m".to_string()],
            percentiles: vec![50, 90, 99],
        };
        let module = PerformanceMetricsModule::new(config);

        let entry = create_entry("API call completed latency=45ms status=200");
        let result = module.process(entry).unwrap();
        assert_eq!(result.latency_ms, Some(45.0));
    }

    #[test]
    fn test_extract_latency_decimal() {
        let config = PerformanceMetricsConfig {
            enabled: true,
            latency_patterns: vec![r"took (?P<duration>\d+\.?\d*)(?P<unit>ms|s)?".to_string()],
            windows: vec!["1m".to_string()],
            percentiles: vec![50, 90, 99],
        };
        let module = PerformanceMetricsModule::new(config);

        let entry = create_entry("Request took 1.5s");
        let result = module.process(entry).unwrap();
        assert_eq!(result.latency_ms, Some(1500.0));
    }

    #[test]
    fn test_no_latency_in_log() {
        let module = PerformanceMetricsModule::with_defaults();

        let entry = create_entry("INFO: User logged in successfully");
        let result = module.process(entry).unwrap();
        assert_eq!(result.latency_ms, None);
    }

    #[test]
    fn test_parse_duration_minutes() {
        assert_eq!(parse_duration("1m"), Some(Duration::minutes(1)));
        assert_eq!(parse_duration("5m"), Some(Duration::minutes(5)));
        assert_eq!(parse_duration("15m"), Some(Duration::minutes(15)));
    }

    #[test]
    fn test_parse_duration_seconds() {
        assert_eq!(parse_duration("30s"), Some(Duration::seconds(30)));
        assert_eq!(parse_duration("60s"), Some(Duration::seconds(60)));
    }

    #[test]
    fn test_parse_duration_hours() {
        assert_eq!(parse_duration("1h"), Some(Duration::hours(1)));
        assert_eq!(parse_duration("24h"), Some(Duration::hours(24)));
    }

    #[test]
    fn test_rolling_window_stats() {
        let config = PerformanceMetricsConfig {
            enabled: true,
            latency_patterns: vec![r"took (?P<duration>\d+)(?P<unit>ms)?".to_string()],
            windows: vec!["1m".to_string()],
            percentiles: vec![50, 90, 99],
        };
        let module = PerformanceMetricsModule::new(config);

        // Process several entries with latencies
        for latency in [10, 20, 30, 40, 50, 60, 70, 80, 90, 100] {
            let entry = create_entry(&format!("Request took {}ms", latency));
            let _ = module.process(entry);
        }

        let stats = module.get_stats();
        assert_eq!(stats.len(), 1);

        let stat = &stats[0];
        assert_eq!(stat.window, "1m");
        assert_eq!(stat.count, 10);
        assert!(stat.min_ms >= 10.0 && stat.min_ms <= 11.0);
        assert!(stat.max_ms >= 100.0 && stat.max_ms <= 101.0);
        assert!(stat.mean_ms >= 54.0 && stat.mean_ms <= 56.0);
    }

    #[test]
    fn test_multiple_windows() {
        let config = PerformanceMetricsConfig {
            enabled: true,
            latency_patterns: vec![r"took (?P<duration>\d+)(?P<unit>ms)?".to_string()],
            windows: vec!["1m".to_string(), "5m".to_string(), "15m".to_string()],
            percentiles: vec![50, 90, 99],
        };
        let module = PerformanceMetricsModule::new(config);

        let entry = create_entry("Request took 100ms");
        let _ = module.process(entry);

        let stats = module.get_stats();
        assert_eq!(stats.len(), 3);

        // All windows should have the same entry
        for stat in &stats {
            assert_eq!(stat.count, 1);
        }
    }
}
