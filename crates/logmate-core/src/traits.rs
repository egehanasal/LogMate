use crate::log_entry::EnrichedEntry;
use crate::error::Result;

/// Trait for processing modules in the LogMate pipeline
///
/// Each module receives an enriched entry and can add/modify its fields.
/// Modules are called sequentially, so later modules can use data from earlier ones.
pub trait Module: Send + Sync {
    /// Returns the name of the module (for logging/debugging)
    fn name(&self) -> &'static str;

    /// Process a log entry and return the enriched result
    ///
    /// The module should add its analysis results to the entry.
    /// If the module doesn't find anything relevant, it should return
    /// the entry unchanged.
    fn process(&self, entry: EnrichedEntry) -> Result<EnrichedEntry>;

    /// Check if the module is enabled
    fn is_enabled(&self) -> bool {
        true
    }
}

/// A no-op module that passes entries through unchanged
///
/// Useful as a placeholder or for testing
pub struct PassthroughModule;

impl Module for PassthroughModule {
    fn name(&self) -> &'static str {
        "passthrough"
    }

    fn process(&self, entry: EnrichedEntry) -> Result<EnrichedEntry> {
        Ok(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::log_entry::{LogEntry, LogSource};

    #[test]
    fn test_passthrough_module() {
        let module = PassthroughModule;
        let entry = LogEntry::new(LogSource::Stdin, "test log".to_string());
        let enriched = EnrichedEntry::from(entry);

        let result = module.process(enriched.clone()).unwrap();
        assert_eq!(result.raw.content, enriched.raw.content);
    }
}
