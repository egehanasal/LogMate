use anyhow::Result;
use clap::Parser;
use logmate_ingestion::{create_log_channel, StdinReader, DEFAULT_CHANNEL_SIZE};
use logmate_output::{OutputFormat, StdoutWriter};
use logmate_pipeline::Pipeline;
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

/// LogMate - High-performance observability engine
#[derive(Parser, Debug)]
#[command(name = "logmate")]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Output format: pretty, json, or raw
    #[arg(short, long, default_value = "pretty")]
    format: String,

    /// Enable verbose logging
    #[arg(short, long)]
    verbose: bool,

    /// Channel buffer size for log processing
    #[arg(long, default_value_t = DEFAULT_CHANNEL_SIZE)]
    buffer_size: usize,
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

    // Initialize tracing (only show logs in verbose mode)
    if args.verbose {
        FmtSubscriber::builder()
            .with_max_level(Level::DEBUG)
            .with_target(false)
            .with_writer(std::io::stderr)
            .init();
        info!("Starting LogMate");
    }

    // Create the log entry channel
    let (sender, mut receiver) = create_log_channel(args.buffer_size);

    // Create the pipeline (empty for now, modules will be added later)
    let pipeline = Pipeline::new();
    if args.verbose {
        info!(modules = ?pipeline.module_names(), "Pipeline initialized");
    }

    // Create the output writer
    let mut writer = StdoutWriter::with_format(parse_format(&args.format));

    // Spawn stdin reader
    let stdin_handle = tokio::spawn(async move {
        let reader = StdinReader::new();
        reader.run(sender).await
    });

    // Process log entries
    let mut processed_count = 0;
    while let Some(entry) = receiver.recv().await {
        match pipeline.process(entry) {
            Ok(enriched) => {
                if let Err(e) = writer.write(&enriched).await {
                    tracing::error!(error = %e, "Failed to write output");
                }
                processed_count += 1;
            }
            Err(e) => {
                tracing::error!(error = %e, "Pipeline processing failed");
            }
        }
    }

    // Wait for stdin reader to complete
    match stdin_handle.await {
        Ok(Ok(lines)) => {
            if args.verbose {
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

    Ok(())
}
