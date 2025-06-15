//! Error handling for RuZip
//!
//! Comprehensive error types with context preservation and chain support.

use thiserror::Error;

/// Result type alias for RuZip operations
pub type Result<T> = std::result::Result<T, RuzipError>;

/// Comprehensive error type for all RuZip operations
#[derive(Error, Debug)]
pub enum RuzipError {
    /// I/O related errors
    #[error("I/O error: {message}")]
    Io {
        message: String,
        #[source]
        source: std::io::Error,
    },

    /// Compression/decompression errors
    #[error("Compression error: {message}")]
    Compression {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Cryptographic errors
    #[error("Cryptographic error: {message}")]
    Crypto {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Archive format errors
    #[error("Archive format error: {message}")]
    ArchiveFormat {
        message: String,
        context: Option<String>,
    },

    /// CLI argument parsing errors
    #[error("CLI error: {message}")]
    Cli {
        message: String,
        #[source]
        source: Option<clap::Error>,
    },

    /// Configuration errors
    #[error("Configuration error: {message}")]
    Config {
        message: String,
        file_path: Option<std::path::PathBuf>,
    },

    /// Permission/access errors
    #[error("Permission denied: {message}")]
    Permission {
        message: String,
        path: Option<std::path::PathBuf>,
    },

    /// Invalid input errors
    #[error("Invalid input: {message}")]
    InvalidInput {
        message: String,
        input: Option<String>,
    },

    /// Resource exhaustion errors
    #[error("Resource exhausted: {message}")]
    ResourceExhausted {
        message: String,
        resource_type: String,
    },

    /// Threading errors
    #[error("Threading error: {message}")]
    Threading {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Memory management errors
    #[error("Memory error: {message}")]
    Memory {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Invalid archive errors
    #[error("Invalid archive: {message}")]
    InvalidArchive {
        message: String,
        context: Option<String>,
    },

    /// Internal errors (should not normally occur)
    #[error("Internal error: {message}")]
    Internal {
        message: String,
        location: Option<&'static str>,
    },

    // --- New Archive Specific Errors ---
    #[error("Failed to parse archive header: {details}")]
    HeaderParseError { details: String },

    #[error("Failed to parse file entry '{entry_name:?}' in archive: {details}")]
    EntryParseError {
        entry_name: Option<String>,
        details: String,
    },

    #[error("Checksum mismatch for entry '{entry_name}': expected {expected}, found {actual}")]
    ChecksumMismatch {
        entry_name: String,
        expected: String, // Hex strings or similar
        actual: String,
    },

    #[error("Archive is too short for operation '{operation}'. Expected at least {expected_len} bytes, found {actual_len} bytes.")]
    ArchiveTooShort {
        operation: String,
        expected_len: u64,
        actual_len: u64,
    },

    #[error("Unsupported archive version: read {version_read}, supported versions are {supported_min}-{supported_max}.")]
    InvalidVersion {
        version_read: u16,
        supported_min: u16,
        supported_max: u16,
    },
}

impl RuzipError {
    /// Create a new I/O error with context
    pub fn io_error<S: Into<String>>(message: S, source: std::io::Error) -> Self {
        Self::Io {
            message: message.into(),
            source,
        }
    }

    /// Create a new compression error with optional source
    pub fn compression_error<S: Into<String>>(
        message: S,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self::Compression {
            message: message.into(),
            source,
        }
    }

    /// Create a new crypto error with optional source
    pub fn crypto_error<S: Into<String>>(
        message: S,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self::Crypto {
            message: message.into(),
            source,
        }
    }

    /// Create a new archive format error
    pub fn archive_format_error<S: Into<String>>(message: S, context: Option<String>) -> Self {
        Self::ArchiveFormat {
            message: message.into(),
            context,
        }
    }

    /// Create a new CLI error
    pub fn cli_error<S: Into<String>>(message: S, source: Option<clap::Error>) -> Self {
        Self::Cli {
            message: message.into(),
            source,
        }
    }

    /// Create a new configuration error
    pub fn config_error<S: Into<String>>(
        message: S,
        file_path: Option<std::path::PathBuf>,
    ) -> Self {
        Self::Config {
            message: message.into(),
            file_path,
        }
    }

    /// Create a new permission error
    pub fn permission_error<S: Into<String>>(
        message: S,
        path: Option<std::path::PathBuf>,
    ) -> Self {
        Self::Permission {
            message: message.into(),
            path,
        }
    }

    /// Create a new invalid input error
    pub fn invalid_input<S: Into<String>>(message: S, input: Option<String>) -> Self {
        Self::InvalidInput {
            message: message.into(),
            input,
        }
    }

    /// Create a new resource exhausted error
    pub fn resource_exhausted<S: Into<String>>(message: S, resource_type: String) -> Self {
        Self::ResourceExhausted {
            message: message.into(),
            resource_type,
        }
    }

    /// Create a new threading error
    pub fn threading_error<S: Into<String>>(
        message: S,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self::Threading {
            message: message.into(),
            source,
        }
    }

    /// Create a new memory error
    pub fn memory_error<S: Into<String>>(
        message: S,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self::Memory {
            message: message.into(),
            source,
        }
    }

    /// Create a new invalid archive error
    pub fn invalid_archive<S: Into<String>>(message: S, context: Option<String>) -> Self {
        Self::InvalidArchive {
            message: message.into(),
            context,
        }
    }

    /// Create a new internal error
    pub fn internal_error<S: Into<String>>(message: S, location: Option<&'static str>) -> Self {
        Self::Internal {
            message: message.into(),
            location,
        }
    }

    // --- Constructors for New Archive Specific Errors ---
    pub fn header_parse_error<S: Into<String>>(details: S) -> Self {
        Self::HeaderParseError {
            details: details.into(),
        }
    }

    pub fn entry_parse_error<S: Into<String>>(
        entry_name: Option<String>,
        details: S,
    ) -> Self {
        Self::EntryParseError {
            entry_name,
            details: details.into(),
        }
    }

    pub fn checksum_mismatch<S1: Into<String>, S2: Into<String>, S3: Into<String>>(
        entry_name: S1,
        expected: S2,
        actual: S3,
    ) -> Self {
        Self::ChecksumMismatch {
            entry_name: entry_name.into(),
            expected: expected.into(),
            actual: actual.into(),
        }
    }

    pub fn archive_too_short<S: Into<String>>(
        operation: S,
        expected_len: u64,
        actual_len: u64,
    ) -> Self {
        Self::ArchiveTooShort {
            operation: operation.into(),
            expected_len,
            actual_len,
        }
    }

    pub fn invalid_version(version_read: u16, supported_min: u16, supported_max: u16) -> Self {
        Self::InvalidVersion {
            version_read,
            supported_min,
            supported_max,
        }
    }

    /// Check if this is a recoverable error
    pub fn is_recoverable(&self) -> bool {
        match self {
            RuzipError::Io { .. } => true,
            RuzipError::Permission { .. } => false,
            RuzipError::ResourceExhausted { .. } => true,
            RuzipError::InvalidInput { .. } => false,
            RuzipError::Threading { .. } => true,
            RuzipError::Memory { .. } => true,
            RuzipError::InvalidArchive { .. } => false,
            RuzipError::Internal { .. } => false,
            _ => true,
        }
    }

    /// Get error category for reporting
    pub fn category(&self) -> &'static str {
        match self {
            RuzipError::Io { .. } => "io",
            RuzipError::Compression { .. } => "compression",
            RuzipError::Crypto { .. } => "crypto",
            RuzipError::ArchiveFormat { .. } => "archive",
            RuzipError::Cli { .. } => "cli",
            RuzipError::Config { .. } => "config",
            RuzipError::Permission { .. } => "permission",
            RuzipError::InvalidInput { .. } => "input",
            RuzipError::ResourceExhausted { .. } => "resource",
            RuzipError::Threading { .. } => "threading",
            RuzipError::Memory { .. } => "memory",
            RuzipError::InvalidArchive { .. } => "archive",
            RuzipError::Internal { .. } => "internal",
            // Categories for new errors
            RuzipError::HeaderParseError { .. } => "archive_header",
            RuzipError::EntryParseError { .. } => "archive_entry",
            RuzipError::ChecksumMismatch { .. } => "archive_checksum",
            RuzipError::ArchiveTooShort { .. } => "archive_format",
            RuzipError::InvalidVersion { .. } => "archive_version",
        }
    }
}

// Conversion implementations for common error types
impl From<std::io::Error> for RuzipError {
    fn from(err: std::io::Error) -> Self {
        Self::io_error("I/O operation failed", err)
    }
}

impl From<clap::Error> for RuzipError {
    fn from(err: clap::Error) -> Self {
        Self::cli_error("Command line parsing failed", Some(err))
    }
}

impl From<toml::de::Error> for RuzipError {
    fn from(err: toml::de::Error) -> Self {
        Self::config_error(
            format!("TOML parsing failed: {}", err),
            None,
        )
    }
}

impl From<serde_json::Error> for RuzipError {
    fn from(err: serde_json::Error) -> Self {
        Self::config_error(
            format!("JSON parsing failed: {}", err),
            None,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;

    #[test]
    fn test_error_construction() {
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let ruzip_err = RuzipError::io_error("Failed to read file", io_err);
        
        assert_eq!(ruzip_err.category(), "io");
        assert!(ruzip_err.is_recoverable());
    }

    #[test]
    fn test_error_chain() {
        use std::error::Error;
        
        let io_err = io::Error::new(io::ErrorKind::PermissionDenied, "access denied");
        let ruzip_err = RuzipError::from(io_err);
        
        // Test that the error chain is preserved
        assert!(ruzip_err.source().is_some());
        assert_eq!(ruzip_err.category(), "io");
    }

    #[test]
    fn test_error_recoverability() {
        let permission_err = RuzipError::permission_error("No write access", None);
        assert!(!permission_err.is_recoverable());
        
        let io_err = RuzipError::io_error("Temporary failure", 
            io::Error::new(io::ErrorKind::Interrupted, "interrupted"));
        assert!(io_err.is_recoverable());
    }

    #[test]
    fn test_error_display() {
        let err = RuzipError::archive_format_error(
            "Invalid header magic",
            Some("Expected 'RUZIP', found 'TEST'".to_string())
        );
        
        let display_str = format!("{}", err);
        assert!(display_str.contains("Archive format error"));
        assert!(display_str.contains("Invalid header magic"));
    }

    #[test]
    fn test_from_conversions() {
        // Test io::Error conversion
        let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
        let ruzip_err: RuzipError = io_err.into();
        assert_eq!(ruzip_err.category(), "io");

        // Test clap::Error conversion  
        let clap_err = clap::Error::new(clap::error::ErrorKind::MissingRequiredArgument);
        let ruzip_err: RuzipError = clap_err.into();
        assert_eq!(ruzip_err.category(), "cli");
    }
}

/// Error recovery trait for production hardening
pub trait ErrorRecovery {
    /// Get the recovery strategy for this error
    fn recovery_strategy(&self) -> RecoveryStrategy;
    
    /// Attempt to recover from this error
    fn attempt_recovery(&self) -> Result<()>;
    
    /// Check if this error is recoverable
    fn is_recoverable(&self) -> bool;
}

/// Recovery strategies for different error types
#[derive(Debug, Clone, PartialEq)]
pub enum RecoveryStrategy {
    /// Retry with backoff
    Retry {
        max_attempts: u32,
        backoff_ms: u64
    },
    /// Skip and continue processing
    Skip {
        continue_processing: bool
    },
    /// Use fallback method
    Fallback {
        alternative_method: String
    },
    /// Abort with cleanup
    Abort {
        cleanup_required: bool
    },
}

impl ErrorRecovery for RuzipError {
    fn recovery_strategy(&self) -> RecoveryStrategy {
        match self {
            RuzipError::Io { .. } => RecoveryStrategy::Retry {
                max_attempts: 3,
                backoff_ms: 1000,
            },
            RuzipError::ResourceExhausted { resource_type, .. } => {
                match resource_type.as_str() {
                    "memory" => RecoveryStrategy::Fallback {
                        alternative_method: "streaming".to_string(),
                    },
                    "disk" => RecoveryStrategy::Abort {
                        cleanup_required: true,
                    },
                    _ => RecoveryStrategy::Retry {
                        max_attempts: 2,
                        backoff_ms: 500,
                    },
                }
            },
            RuzipError::Threading { .. } => RecoveryStrategy::Retry {
                max_attempts: 2,
                backoff_ms: 200,
            },
            RuzipError::Memory { .. } => RecoveryStrategy::Fallback {
                alternative_method: "single-threaded".to_string(),
            },
            RuzipError::Compression { .. } => RecoveryStrategy::Fallback {
                alternative_method: "store".to_string(),
            },
            RuzipError::Permission { .. } => RecoveryStrategy::Abort {
                cleanup_required: false,
            },
            RuzipError::InvalidInput { .. } => RecoveryStrategy::Abort {
                cleanup_required: false,
            },
            RuzipError::InvalidArchive { .. } => RecoveryStrategy::Skip {
                continue_processing: false,
            },
            RuzipError::Internal { .. } => RecoveryStrategy::Abort {
                cleanup_required: true,
            },
            // Recovery strategies for new errors (defaulting to Abort or Skip)
            RuzipError::HeaderParseError { .. } |
            RuzipError::EntryParseError { .. } |
            RuzipError::ChecksumMismatch { .. } |
            RuzipError::ArchiveTooShort { .. } |
            RuzipError::InvalidVersion { .. } => RecoveryStrategy::Abort {
                cleanup_required: false, // Typically, parsing errors are not recoverable by retry
            },
            _ => RecoveryStrategy::Retry {
                max_attempts: 1,
                backoff_ms: 100,
            },
        }
    }

    fn attempt_recovery(&self) -> Result<()> {
        match self.recovery_strategy() {
            RecoveryStrategy::Retry { max_attempts, backoff_ms } => {
                tracing::info!(
                    "Attempting recovery with retry strategy: {} attempts, {}ms backoff",
                    max_attempts, backoff_ms
                );
                // Recovery logic would be implemented by the caller
                Ok(())
            },
            RecoveryStrategy::Skip { continue_processing } => {
                tracing::warn!(
                    "Skipping error and continuing processing: {}",
                    continue_processing
                );
                Ok(())
            },
            RecoveryStrategy::Fallback { alternative_method } => {
                tracing::info!(
                    "Using fallback recovery method: {}",
                    alternative_method
                );
                Ok(())
            },
            RecoveryStrategy::Abort { cleanup_required } => {
                tracing::error!(
                    "Aborting operation, cleanup required: {}",
                    cleanup_required
                );
                Err(RuzipError::internal_error(
                    "Recovery failed - operation aborted",
                    Some("error_recovery"),
                ))
            },
        }
    }

    fn is_recoverable(&self) -> bool {
        !matches!(
            self.recovery_strategy(),
            RecoveryStrategy::Abort { .. }
        )
    }
}

/// Production error recovery manager
pub struct ErrorRecoveryManager {
    max_global_retries: u32,
    recovery_stats: std::sync::Arc<std::sync::Mutex<RecoveryStats>>,
}

/// Statistics for error recovery
#[derive(Debug, Default)]
pub struct RecoveryStats {
    pub total_errors: u64,
    pub recovered_errors: u64,
    pub failed_recoveries: u64,
    pub retry_attempts: u64,
    pub fallback_uses: u64,
    pub skipped_errors: u64,
}

impl ErrorRecoveryManager {
    pub fn new(max_global_retries: u32) -> Self {
        Self {
            max_global_retries,
            recovery_stats: std::sync::Arc::new(std::sync::Mutex::new(RecoveryStats::default())),
        }
    }

    /// Attempt to recover from an error with exponential backoff
    pub async fn recover_with_backoff<F, T>(&self,
        error: &RuzipError,
        operation: F
    ) -> Result<T>
    where
        F: Fn() -> Result<T> + Send + Sync,
    {
        let strategy = error.recovery_strategy();
        let mut stats = self.recovery_stats.lock().unwrap();
        stats.total_errors += 1;
        drop(stats);

        match strategy {
            RecoveryStrategy::Retry { max_attempts, backoff_ms } => {
                let attempts = std::cmp::min(max_attempts, self.max_global_retries);
                
                for attempt in 1..=attempts {
                    match operation() {
                        Ok(result) => {
                            let mut stats = self.recovery_stats.lock().unwrap();
                            stats.recovered_errors += 1;
                            stats.retry_attempts += attempt as u64;
                            return Ok(result);
                        },
                        Err(e) if attempt < attempts => {
                            tracing::warn!(
                                "Recovery attempt {} failed: {}, retrying in {}ms",
                                attempt, e, backoff_ms * attempt as u64
                            );
                            
                            // Exponential backoff
                            let delay = backoff_ms * (2_u64.pow(attempt - 1));
                            tokio::time::sleep(tokio::time::Duration::from_millis(delay)).await;
                        },
                        Err(e) => {
                            let mut stats = self.recovery_stats.lock().unwrap();
                            stats.failed_recoveries += 1;
                            return Err(e);
                        }
                    }
                }
                
                let mut stats = self.recovery_stats.lock().unwrap();
                stats.failed_recoveries += 1;
                Err(RuzipError::internal_error(
                    "All recovery attempts failed",
                    Some("error_recovery_manager"),
                ))
            },
            RecoveryStrategy::Skip { .. } => {
                let mut stats = self.recovery_stats.lock().unwrap();
                stats.skipped_errors += 1;
                Err(RuzipError::internal_error(
                    "Error skipped during recovery",
                    Some("error_recovery_manager"),
                ))
            },
            RecoveryStrategy::Fallback { .. } => {
                let mut stats = self.recovery_stats.lock().unwrap();
                stats.fallback_uses += 1;
                // Fallback logic should be implemented by caller
                operation()
            },
            RecoveryStrategy::Abort { .. } => {
                let mut stats = self.recovery_stats.lock().unwrap();
                stats.failed_recoveries += 1;
                Err(RuzipError::internal_error(
                    "Recovery aborted",
                    Some("error_recovery_manager"),
                ))
            },
        }
    }

    /// Get recovery statistics
    pub fn get_stats(&self) -> RecoveryStats {
        self.recovery_stats.lock().unwrap().clone()
    }

    /// Reset recovery statistics
    pub fn reset_stats(&self) {
        let mut stats = self.recovery_stats.lock().unwrap();
        *stats = RecoveryStats::default();
    }
}

impl Clone for RecoveryStats {
    fn clone(&self) -> Self {
        Self {
            total_errors: self.total_errors,
            recovered_errors: self.recovered_errors,
            failed_recoveries: self.failed_recoveries,
            retry_attempts: self.retry_attempts,
            fallback_uses: self.fallback_uses,
            skipped_errors: self.skipped_errors,
        }
    }
}