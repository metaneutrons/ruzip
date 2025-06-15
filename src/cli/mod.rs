//! Command Line Interface for RuZip
//!
//! This module provides the complete CLI interface including argument parsing,
//! command execution, and shell completion generation.

pub mod commands;
pub mod parser;
pub mod completion;

pub use commands::*;
pub use parser::*;

use crate::error::Result;
use clap::{ArgAction, Parser, Subcommand};
use std::path::PathBuf;

/// RuZip - Modern Compression Tool
#[derive(Parser, Debug)]
#[command(
    name = "ruzip",
    version = env!("CARGO_PKG_VERSION"),
    about = "A modern, fast, and secure compression tool",
    long_about = "RuZip is a high-performance compression tool built with Rust, \
                  featuring ZSTD compression, AES-256 encryption, digital signatures, \
                  and multi-threading support.\n\n\
                  EXAMPLES:\n  \
                  ruzip a archive.rzp file1.txt file2.txt    # Create archive\n  \
                  ruzip x archive.rzp                        # Extract archive\n  \
                  ruzip l archive.rzp                        # List contents\n  \
                  ruzip d archive.rzp file1.txt              # Delete files\n\n\
                  Use 'ruzip <command> --help' for detailed command options.",
    author = "RuZip Development Team",
    after_help = "For more information about a specific command, use 'ruzip <command> --help'."
)]
pub struct Cli {
    /// Command to execute
    #[command(subcommand)]
    pub command: Commands,

    /// Enable verbose output (can be used multiple times for increased verbosity)
    #[arg(short, long, global = true, action = ArgAction::Count)]
    pub verbose: u8,

    /// Quiet mode (minimal output)
    #[arg(short, long, global = true, conflicts_with = "verbose", action = ArgAction::SetTrue)]
    pub quiet: bool,

    /// Output format
    #[arg(long, global = true, value_enum, default_value = "human")]
    pub output_format: OutputFormat,

    /// Configuration file path
    #[arg(long, global = true)]
    pub config: Option<PathBuf>,

    /// Number of threads to use (0 = auto-detect)
    #[arg(short = 't', long = "thread-count", global = true, default_value = "0")]
    pub threads: u16,

    /// Enable progress bar
    #[arg(long, global = true, action = ArgAction::SetTrue)]
    pub progress: bool,

    /// Dry run mode (preview without execution)
    #[arg(long, global = true, action = ArgAction::SetTrue)]
    pub dry_run: bool,
}

/// Available output formats
#[derive(clap::ValueEnum, Clone, Debug, PartialEq)]
pub enum OutputFormat {
    /// Human-readable output
    Human,
    /// JSON output for scripting
    Json,
    /// Minimal output
    Minimal,
}

/// Available commands
#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Add files to archive (create or append)
    #[command(name = "a", alias = "add")]
    Add(AddCommand),

    /// Extract files from archive (preserve structure)
    #[command(name = "x", alias = "extract")]
    Extract(ExtractCommand),

    /// Extract files without directory structure (flatten)
    #[command(name = "e", alias = "extract-here")]
    ExtractHere(ExtractHereCommand),

    /// List archive contents (show files and metadata)
    #[command(name = "l", alias = "list")]
    List(ListCommand),

    /// Test archive integrity (verify checksums)
    #[command(name = "t", alias = "test")]
    Test(TestCommand),

    /// Delete files from archive (safe mode by default)
    #[command(name = "d", alias = "delete")]
    Delete(DeleteCommand),

    /// Update files in archive (replace existing)
    #[command(name = "u", alias = "update")]
    Update(UpdateCommand),

    /// Generate shell completions (bash, zsh, fish, powershell)
    #[command(name = "completion")]
    Completion(CompletionCommand),

    /// Show version information
    #[command(name = "version")]
    Version,
}

impl Cli {
    /// Parse command line arguments
    pub fn parse_args() -> Self {
        Self::parse()
    }

    /// Execute the parsed command
    pub async fn execute(&self) -> Result<()> {
        // Execute the command
        match &self.command {
            Commands::Add(cmd) => cmd.execute(self).await,
            Commands::Extract(cmd) => cmd.execute(self).await,
            Commands::ExtractHere(cmd) => cmd.execute(self).await,
            Commands::List(cmd) => cmd.execute(self).await,
            Commands::Test(cmd) => cmd.execute(self).await,
            Commands::Delete(cmd) => cmd.execute(self).await,
            Commands::Update(cmd) => cmd.execute(self).await,
            Commands::Completion(cmd) => cmd.execute(self).await,
            Commands::Version => {
                self.show_version();
                Ok(())
            }
        }
    }


    /// Show version information
    fn show_version(&self) {
        match self.output_format {
            OutputFormat::Json => {
                println!("{{\"name\":\"{}\",\"version\":\"{}\"}}", 
                    env!("CARGO_PKG_NAME"), 
                    env!("CARGO_PKG_VERSION"));
            }
            _ => {
                println!("{} {}", env!("CARGO_PKG_NAME"), env!("CARGO_PKG_VERSION"));
                if self.verbose > 0 {
                    println!("Built with Rust");
                    println!("Target: {}", std::env::consts::ARCH);
                }
            }
        }
    }

    /// Get effective thread count
    pub fn effective_threads(&self) -> usize {
        if self.threads == 0 {
            num_cpus::get()
        } else {
            self.threads as usize
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn test_cli_parsing() {
        // Test basic command parsing
        let cli = Cli::try_parse_from(&["ruzip", "a", "test.rzp", "file.txt"]).unwrap();
        
        assert!(matches!(cli.command, Commands::Add(_)));
        assert_eq!(cli.verbose, 0);
        assert!(!cli.quiet);
        assert_eq!(cli.output_format, OutputFormat::Human);
    }

    #[test]
    fn test_global_flags() {
        let cli = Cli::try_parse_from(&[
            "ruzip", "--verbose", "--progress", "--thread-count", "4",
            "l", "test.rzp"
        ]).unwrap();
        
        assert!(cli.verbose > 0);
        assert!(cli.progress);
        assert_eq!(cli.threads, 4);
        assert!(matches!(cli.command, Commands::List(_)));
    }

    #[test]
    fn test_output_format() {
        let cli = Cli::try_parse_from(&[
            "ruzip", "--output-format", "json", "version"
        ]).unwrap();
        
        assert_eq!(cli.output_format, OutputFormat::Json);
    }

    #[test]
    fn test_conflicting_flags() {
        // Verbose and quiet should conflict
        let result = Cli::try_parse_from(&[
            "ruzip", "--verbose", "--quiet", "version"
        ]);
        
        assert!(result.is_err());
    }

    #[test]
    fn test_command_aliases() {
        // Test that aliases work
        let cli1 = Cli::try_parse_from(&["ruzip", "a", "test.rzp", "file.txt"]).unwrap();
        let cli2 = Cli::try_parse_from(&["ruzip", "add", "test.rzp", "file.txt"]).unwrap();
        
        // Both should parse to the same command type
        assert!(matches!(cli1.command, Commands::Add(_)));
        assert!(matches!(cli2.command, Commands::Add(_)));
    }

    #[test]
    fn test_effective_threads() {
        let cli = Cli::try_parse_from(&["ruzip", "--thread-count", "8", "version"]).unwrap();
        assert_eq!(cli.effective_threads(), 8);
        
        let cli = Cli::try_parse_from(&["ruzip", "--thread-count", "0", "version"]).unwrap();
        assert!(cli.effective_threads() > 0); // Should auto-detect
    }

    #[test]
    fn verify_cli() {
        // Verify the CLI structure is valid
        Cli::command().debug_assert();
    }
}