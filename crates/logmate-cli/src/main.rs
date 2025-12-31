use anyhow::Result;
use clap::Parser;
use logmate_core::Config;
use logmate_ingestion::{create_log_channel, IngestionManager};
use logmate_output::{OutputFormat, StdoutWriter};
use logmate_pipeline::Pipeline;
use std::path::PathBuf;
use tracing::{info, Level};
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

    // Create the output writer
    let mut writer = StdoutWriter::with_format(parse_format(output_format));

    // Create and start the ingestion manager
    let mut ingestion = IngestionManager::new(config.ingestion.clone(), sender);
    let source_count = ingestion.start();

    if source_count == 0 {
        eprintln!("Warning: No ingestion sources enabled. Enable stdin, tcp, or udp in config.");
        return Ok(());
    }

    if verbose {
        info!(
            sources = source_count,
            stdin = ingestion.has_stdin(),
            network = ingestion.has_network(),
            "Ingestion started"
        );
    }

    // Process log entries
    let mut processed_count: u64 = 0;
    while let Some(entry) = receiver.recv().await {
        match pipeline.process(entry) {
            Ok(enriched) => {
                if config.output.stdout.enabled {
                    if let Err(e) = writer.write(&enriched).await {
                        eprintln!("Output error: {}", e);
                    }
                }
                processed_count += 1;
            }
            Err(e) => {
                eprintln!("Pipeline error: {}", e);
            }
        }
    }

    if verbose {
        info!(processed = processed_count, "Processing complete");
    }

    Ok(())
}
