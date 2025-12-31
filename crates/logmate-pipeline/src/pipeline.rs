use logmate_core::config::ModulesConfig;
use logmate_core::{EnrichedEntry, LogEntry, LogMateError, Module, Result};
use logmate_modules::{PatternDetectionModule, StructuralParserModule};
use tracing::{debug, info, warn};

/// Pipeline that orchestrates log processing through multiple modules
pub struct Pipeline {
    modules: Vec<Box<dyn Module>>,
}

impl Pipeline {
    /// Create a new empty pipeline
    pub fn new() -> Self {
        Self {
            modules: Vec::new(),
        }
    }

    /// Create a pipeline from configuration
    pub fn from_config(config: &ModulesConfig) -> Self {
        let mut pipeline = Self::new();

        // Add pattern detection module if enabled
        if config.pattern_detection.enabled {
            let module = PatternDetectionModule::new(config.pattern_detection.clone());
            info!(module = module.name(), "Adding module to pipeline");
            pipeline.modules.push(Box::new(module));
        }

        // Add structural parser module if enabled
        if config.structural_parser.enabled {
            let module = StructuralParserModule::new(config.structural_parser.clone());
            info!(module = module.name(), "Adding module to pipeline");
            pipeline.modules.push(Box::new(module));
        }

        // Future modules will be added here:
        // if config.performance_metrics.enabled { ... }
        // if config.security.enabled { ... }

        pipeline
    }

    /// Add a module to the pipeline
    pub fn add_module<M: Module + 'static>(mut self, module: M) -> Self {
        info!(module = module.name(), "Adding module to pipeline");
        self.modules.push(Box::new(module));
        self
    }

    /// Process a log entry through all modules
    pub fn process(&self, entry: LogEntry) -> Result<EnrichedEntry> {
        let mut enriched = EnrichedEntry::from(entry);

        for module in &self.modules {
            if !module.is_enabled() {
                debug!(module = module.name(), "Skipping disabled module");
                continue;
            }

            debug!(module = module.name(), "Processing through module");

            enriched = module.process(enriched).map_err(|e| {
                warn!(module = module.name(), error = %e, "Module processing failed");
                LogMateError::Module {
                    module: module.name().to_string(),
                    message: e.to_string(),
                }
            })?;
        }

        Ok(enriched)
    }

    /// Get the number of modules in the pipeline
    pub fn module_count(&self) -> usize {
        self.modules.len()
    }

    /// Get the names of all modules in the pipeline
    pub fn module_names(&self) -> Vec<&'static str> {
        self.modules.iter().map(|m| m.name()).collect()
    }
}

impl Default for Pipeline {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use logmate_core::{LogSource, PassthroughModule};

    #[test]
    fn test_empty_pipeline() {
        let pipeline = Pipeline::new();
        assert_eq!(pipeline.module_count(), 0);

        let entry = LogEntry::new(LogSource::Stdin, "test".to_string());
        let result = pipeline.process(entry).unwrap();
        assert_eq!(result.raw.content, "test");
    }

    #[test]
    fn test_pipeline_with_passthrough() {
        let pipeline = Pipeline::new().add_module(PassthroughModule);
        assert_eq!(pipeline.module_count(), 1);
        assert_eq!(pipeline.module_names(), vec!["passthrough"]);

        let entry = LogEntry::new(LogSource::Stdin, "test".to_string());
        let result = pipeline.process(entry).unwrap();
        assert_eq!(result.raw.content, "test");
    }
}
