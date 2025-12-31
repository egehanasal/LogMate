use anyhow::Result;
use clap::Parser;
use logmate_core::Config;
use logmate_ingestion::{create_log_channel, IngestionManager};
use logmate_output::{FileWriter, LokiClient, MetricsCollector, MetricsServer, OutputFormat, StdoutWriter};
use logmate_pipeline::Pipeline;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use tracing::{info, warn, Level};
use tracing_subscriber::FmtSubscriber;

/// LogMate - High-performance observability engine
#[derive(Parser, Debug)]
#[command(name = "logmate")]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to configuration file (TOML)
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Output format: pretty, json, or raw (overrides config)
    #[arg(short, long)]
    format: Option<String>,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Print the default configuration and exit
    #[arg(long)]
    print_config: bool,
}

fn parse_format(format: &str) -> OutputFormat {
    match format.to_lowercase().as_str() {
        "json" => OutputFormat::Json,
        "raw" => OutputFormat::Raw,
        _ => OutputFormat::Pretty,
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();

    // Handle --print-config
    if args.print_config {
        let config = Config::default();
        println!("{}", config.to_toml()?);
        return Ok(());
    }

    // Load configuration
    let config = if let Some(ref config_path) = args.config {
        Config::from_file(config_path)?
    } else {
        Config::default()
    };

    // Initialize tracing based on config or verbose flag
    let verbose = args.verbose || config.general.log_level == "debug" || config.general.log_level == "trace";
    if verbose {
        // CLI --verbose flag overrides config to use DEBUG level
        let level = if args.verbose {
            Level::DEBUG
        } else {
            match config.general.log_level.as_str() {
                "trace" => Level::TRACE,
                "debug" => Level::DEBUG,
                _ => Level::DEBUG,
            }
        };
        FmtSubscriber::builder()
            .with_max_level(level)
            .with_target(false)
            .with_writer(std::io::stderr)
            .init();
        info!(instance = %config.general.instance_name, "Starting LogMate");
    }

    // Determine output format (CLI overrides config)
    let output_format = args
        .format
        .as_deref()
        .unwrap_or(&config.output.stdout.format);

    // Create the log entry channel
    let (sender, mut receiver) = create_log_channel(config.general.buffer_size);

    // Create the pipeline with modules from config
    let pipeline = Pipeline::from_config(&config.modules);
    if verbose {
        info!(modules = ?pipeline.module_names(), "Pipeline initialized with {} module(s)", pipeline.module_count());
    }

    // Create output writers
    let mut stdout_writer = StdoutWriter::with_format(parse_format(output_format));

    // Create file writer if enabled
    let mut file_writer = if config.output.file.enabled {
        match FileWriter::new(config.output.file.clone()) {
            Ok(writer) => {
                if verbose {
                    info!(
                        path = %config.output.file.path,
                        format = %config.output.file.format,
                        rotation = %config.output.file.rotation,
                        "File output enabled"
                    );
                }
                Some(writer)
            }
            Err(e) => {
                warn!(error = %e, "Failed to create file writer, continuing without file output");
                None
            }
        }
    } else {
        None
    };

    // Create metrics collector (always created for internal use)
    let metrics = Arc::new(MetricsCollector::new().expect("Failed to create metrics collector"));

    // Start Prometheus metrics server if enabled
    if config.output.grafana.prometheus.enabled {
        let metrics_server = MetricsServer::new(
            config.output.grafana.prometheus.clone(),
            metrics.clone(),
        );
        tokio::spawn(async move {
            if let Err(e) = metrics_server.run().await {
                eprintln!("Metrics server error: {}", e);
            }
        });
        if verbose {
            info!(
                address = %config.output.grafana.prometheus.bind_address,
                port = config.output.grafana.prometheus.port,
                path = %config.output.grafana.prometheus.path,
                "Prometheus metrics server started"
            );
        }
    }

    // Create Loki client if enabled
    let loki_client = if config.output.grafana.loki.enabled {
        match LokiClient::new(config.output.grafana.loki.clone()) {
            Ok(client) => {
                if verbose {
                    info!(
                        endpoint = %config.output.grafana.loki.endpoint,
                        batch_size = config.output.grafana.loki.batch_size,
                        "Loki output enabled"
                    );
                }
                Some(client)
            }
            Err(e) => {
                warn!(error = %e, "Failed to create Loki client, continuing without Loki output");
                None
            }
        }
    } else {
        None
    };

    // Create and start the ingestion manager
    let mut ingestion = IngestionManager::new(config.ingestion.clone(), sender);
    let source_count = ingestion.start();

    if source_count == 0 {
        eprintln!("Warning: No ingestion sources enabled. Enable stdin, tcp, udp, or file in config.");
        return Ok(());
    }

    if verbose {
        info!(
            sources = source_count,
            stdin = ingestion.has_stdin(),
            network = ingestion.has_network(),
            file = ingestion.has_file(),
            "Ingestion started"
        );
    }

    // Process log entries
    let mut processed_count: u64 = 0;
    while let Some(entry) = receiver.recv().await {
        let start_time = Instant::now();
        metrics.record_received();

        match pipeline.process(entry) {
            Ok(enriched) => {
                // Record processing metrics
                let processing_time = start_time.elapsed().as_secs_f64();
                metrics.record_processing_duration(processing_time);
                metrics.record_processed(
                    enriched.level.as_ref().map(|l| l.to_string()).as_deref(),
                    &enriched.raw.source.to_string(),
                );

                // Record security flags
                for flag in &enriched.security_flags {
                    metrics.record_security_flag(&format!("{:?}", flag));
                }

                // Record latency if extracted
                if let Some(latency_ms) = enriched.latency_ms {
                    metrics.record_latency(latency_ms);
                }

                // Write to stdout if enabled
                if config.output.stdout.enabled {
                    if let Err(e) = stdout_writer.write(&enriched).await {
                        eprintln!("Stdout output error: {}", e);
                        metrics.record_output_error("stdout");
                    }
                }

                // Write to file if enabled
                if let Some(ref mut fw) = file_writer {
                    if let Err(e) = fw.write(&enriched) {
                        eprintln!("File output error: {}", e);
                        metrics.record_output_error("file");
                    }
                }

                // Push to Loki if enabled
                if let Some(ref loki) = loki_client {
                    if let Err(e) = loki.push(&enriched).await {
                        eprintln!("Loki push error: {}", e);
                        metrics.record_output_error("loki");
                    }
                }

                processed_count += 1;
            }
            Err(e) => {
                eprintln!("Pipeline error: {}", e);
                metrics.record_processing_error();
            }
        }
    }

    // Flush Loki buffer
    if let Some(ref loki) = loki_client {
        if let Err(e) = loki.flush().await {
            eprintln!("Failed to flush Loki buffer: {}", e);
        }
        if verbose {
            info!("Loki buffer flushed");
        }
    }

    // Flush file writer
    if let Some(ref mut fw) = file_writer {
        if let Err(e) = fw.flush() {
            eprintln!("Failed to flush file: {}", e);
        }
        if verbose {
            info!(
                entries = fw.entries_written(),
                path = %fw.current_path().display(),
                "File output complete"
            );
        }
    }

    if verbose {
        info!(processed = processed_count, "Processing complete");
    }

    Ok(())
}
