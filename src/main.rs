//! RuZip - Modern Compression Tool
//!
//! Main entry point for the RuZip command-line application.

use ruzip::cli::{Cli, OutputFormat};
use ruzip::error::Result;
use ruzip::utils::logging::{init_logging, LoggingConfig};
use std::error::Error;
use std::process;
use tracing::Level;

#[tokio::main]
async fn main() {
    let exit_code = match run().await {
        Ok(()) => 0,
        Err(error) => {
            // Try to log the error if logging is initialized
            ruzip::utils::logging::log_error(&error, Some("main"));
            
            // Always print to stderr as fallback
            eprintln!("Error: {}", error);
            
            // Print error chain
            let mut source = error.source();
            let mut level = 1;
            while let Some(err) = source {
                eprintln!("  Caused by ({}): {}", level, err);
                source = err.source();
                level += 1;
            }
            
            // Return appropriate exit code based on error type
            match error.category() {
                "cli" => 2,        // CLI usage error
                "permission" => 13, // Permission denied
                "input" => 22,     // Invalid argument
                "config" => 78,    // Config error
                _ => 1,            // General error
            }
        }
    };
    
    process::exit(exit_code);
}

/// Main application logic
async fn run() -> Result<()> {
    // Parse CLI arguments first
    let cli = Cli::parse_args();
    
    // Initialize logging based on CLI flags
    setup_logging(&cli)?;
    
    tracing::info!("Starting RuZip v{}", env!("CARGO_PKG_VERSION"));
    tracing::debug!("CLI arguments parsed: {:?}", cli);
    
    // Execute the command
    cli.execute().await?;
    
    tracing::info!("RuZip completed successfully");
    Ok(())
}

/// Setup logging based on CLI configuration
fn setup_logging(cli: &Cli) -> Result<()> {
    let level = if cli.quiet {
        Level::ERROR
    } else if cli.verbose > 0 {
        if cli.verbose >= 2 {
            Level::TRACE
        } else {
            Level::DEBUG
        }
    } else {
        Level::INFO
    };
    
    let config = LoggingConfig {
        level,
        json_format: cli.output_format == OutputFormat::Json,
        colored: !cli.quiet && cli.output_format != OutputFormat::Json,
        include_location: cli.verbose > 0,
        include_target: cli.verbose > 0,
        span_events: if cli.verbose > 0 {
            tracing_subscriber::fmt::format::FmtSpan::ENTER | tracing_subscriber::fmt::format::FmtSpan::EXIT
        } else {
            tracing_subscriber::fmt::format::FmtSpan::NONE
        },
        log_file: None, // Could be added as CLI option in future
    };
    
    init_logging(config)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ruzip::cli::Commands;

    #[test]
    fn test_setup_logging() {
        let cli = Cli {
            command: Commands::Version,
            verbose: 0,
            quiet: false,
            output_format: OutputFormat::Human,
            config: None,
            threads: 0,
            progress: false,
            dry_run: false,
        };
        
        // Should not panic (might fail if logging already initialized)
        let _ = setup_logging(&cli);
    }

    #[test]
    fn test_verbose_logging_setup() {
        let cli = Cli {
            command: Commands::Version,
            verbose: 1,
            quiet: false,
            output_format: OutputFormat::Human,
            config: None,
            threads: 0,
            progress: false,
            dry_run: false,
        };
        
        // Should not panic (might fail if logging already initialized)
        let _ = setup_logging(&cli);
    }

    #[test]
    fn test_json_output_logging_setup() {
        let cli = Cli {
            command: Commands::Version,
            verbose: 0,
            quiet: false,
            output_format: OutputFormat::Json,
            config: None,
            threads: 0,
            progress: false,
            dry_run: false,
        };
        
        // Should not panic (might fail if logging already initialized)
        let _ = setup_logging(&cli);
    }
}