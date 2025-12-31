use anyhow::Result;
use clap::Parser;
use logmate_core::Config;
use logmate_ingestion::{create_log_channel, StdinReader};
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
        let level = match config.general.log_level.as_str() {
            "trace" => Level::TRACE,
            "debug" => Level::DEBUG,
            "info" => Level::INFO,
            "warn" => Level::WARN,
            _ => Level::DEBUG,
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

    // Create the pipeline (empty for now, modules will be added later)
    let pipeline = Pipeline::new();
    if verbose {
        info!(modules = ?pipeline.module_names(), "Pipeline initialized");
    }

    // Create the output writer
    let mut writer = StdoutWriter::with_format(parse_format(output_format));

    // Spawn stdin reader (if enabled in config)
    let stdin_handle = if config.ingestion.stdin.enabled {
        Some(tokio::spawn(async move {
            let reader = StdinReader::new();
            reader.run(sender).await
        }))
    } else {
        if verbose {
            info!("Stdin ingestion disabled");
        }
        // Drop the sender so the receiver knows no more messages are coming
        drop(sender);
        None
    };

    // Process log entries
    let mut processed_count = 0;
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

    // Wait for stdin reader to complete
    if let Some(handle) = stdin_handle {
        match handle.await {
            Ok(Ok(lines)) => {
                if verbose {
                    info!(lines_read = lines, processed = processed_count, "Processing complete");
                }
            }
            Ok(Err(e)) => {
                eprintln!("Error: {}", e);
            }
            Err(e) => {
                eprintln!("Error: {}", e);
            }
        }
    }

    Ok(())
}
