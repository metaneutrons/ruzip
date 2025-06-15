//! Archive format implementation for RuZip
//!
//! This module defines the RuZip (.rzp) archive format with binary serialization,
//! integrity checking, and version compatibility.

pub mod format;
pub mod header;
pub mod entry;
pub mod writer;
pub mod reader;
pub mod validation;
pub mod appender;
pub mod deleter;
pub mod reconstructor;
pub mod modifier;

use crate::error::{Result, RuzipError};
use std::path::Path;

pub use format::{ArchiveFormat, FormatVersion};
pub use header::ArchiveHeader;
pub use entry::{FileEntry, FileMetadata, EntryType};
pub use writer::ArchiveWriter;
pub use reader::ArchiveReader;
pub use validation::ArchiveValidator;
pub use appender::{ArchiveAppender, CompressionInfo, AppendInfo};
pub use deleter::{ArchiveDeleter, DeletionPreview};
pub use reconstructor::ArchiveReconstructor;
pub use modifier::ArchiveModifier;

/// Magic bytes for RuZip archive format
pub const RUZIP_MAGIC: &[u8; 4] = b"RUZP";

/// Current archive format version
pub const CURRENT_VERSION: u16 = 1;

/// Minimum supported version for backward compatibility
pub const MIN_SUPPORTED_VERSION: u16 = 1;

/// Maximum archive size (16 TB)
pub const MAX_ARCHIVE_SIZE: u64 = 16 * 1024 * 1024 * 1024 * 1024;

/// Maximum number of entries in an archive
pub const MAX_ENTRIES: u64 = 1_000_000;

/// Archive creation options
#[derive(Debug, Clone)]
pub struct ArchiveOptions {
    /// Compression level
    pub compression_level: crate::compression::CompressionLevel,
    /// Compression method
    pub compression_method: crate::compression::CompressionMethod,
    /// Preserve file permissions
    pub preserve_permissions: bool,
    /// Preserve timestamps
    pub preserve_timestamps: bool,
    /// Store file checksums
    pub store_checksums: bool,
    /// Enable integrity verification
    pub verify_integrity: bool,
    /// Maximum memory usage for operations
    pub max_memory: usize,
}

impl Default for ArchiveOptions {
    fn default() -> Self {
        Self {
            compression_level: crate::compression::CompressionLevel::default(),
            compression_method: crate::compression::CompressionMethod::default(),
            preserve_permissions: true,
            preserve_timestamps: true,
            store_checksums: true,
            verify_integrity: true,
            max_memory: 512 * 1024 * 1024, // 512MB
        }
    }
}

/// Archive information structure
#[derive(Debug, Clone)]
pub struct ArchiveInfo {
    /// Format version
    pub version: u16,
    /// Total number of entries
    pub entry_count: u64,
    /// Total uncompressed size
    pub uncompressed_size: u64,
    /// Total compressed size
    pub compressed_size: u64,
    /// Archive creation timestamp
    pub created_at: u64,
    /// Archive modification timestamp
    pub modified_at: u64,
    /// Overall compression ratio
    pub compression_ratio: f64,
    /// Archive checksum
    pub checksum: Option<[u8; 32]>,
}

impl ArchiveInfo {
    /// Calculate compression percentage
    pub fn compression_percentage(&self) -> f64 {
        if self.uncompressed_size > 0 {
            (1.0 - self.compression_ratio) * 100.0
        } else {
            0.0
        }
    }

    /// Check if archive has integrity protection
    pub fn has_integrity_protection(&self) -> bool {
        self.checksum.is_some()
    }
}

/// Archive statistics for operations
#[derive(Debug, Clone, Default)]
pub struct ArchiveStats {
    /// Files processed
    pub files_processed: u64,
    /// Directories processed
    pub directories_processed: u64,
    /// Bytes processed
    pub bytes_processed: u64,
    /// Errors encountered
    pub errors_encountered: u64,
    /// Processing speed in MB/s
    pub processing_speed: f64,
    /// Operation duration in milliseconds
    pub duration_ms: u64,
    /// Compression ratio achieved
    pub compression_ratio: f64,
    /// Throughput in MB/s
    pub throughput_mb_s: f64,
}

impl ArchiveStats {
    /// Get total items processed
    pub fn total_items(&self) -> u64 {
        self.files_processed + self.directories_processed
    }

    /// Calculate processing speed
    pub fn calculate_speed(&mut self) {
        if self.duration_ms > 0 {
            let duration_secs = self.duration_ms as f64 / 1000.0;
            let mb_processed = self.bytes_processed as f64 / (1024.0 * 1024.0);
            self.processing_speed = mb_processed / duration_secs;
        }
    }
}

/// Utility functions for archive operations
pub mod utils {
    use super::*;
    use std::fs;

    /// Check if a file is a valid RuZip archive
    pub fn is_ruzip_archive<P: AsRef<Path>>(path: P) -> Result<bool> {
        let mut file = fs::File::open(path.as_ref()).map_err(|e| {
            RuzipError::io_error(
                format!("Failed to open file: {}", path.as_ref().display()),
                e,
            )
        })?;

        use std::io::Read;
        let mut magic = [0u8; 4];
        match file.read_exact(&mut magic) {
            Ok(()) => Ok(&magic == RUZIP_MAGIC),
            Err(_) => Ok(false), // File too short or read error
        }
    }

    /// Get archive information without fully reading the archive
    pub fn get_archive_info<P: AsRef<Path>>(path: P) -> Result<ArchiveInfo> {
        let reader = ArchiveReader::<std::fs::File>::open(path)?;
        reader.info()
    }

    /// Validate archive path for creation
    pub fn validate_archive_path<P: AsRef<Path>>(path: P) -> Result<()> {
        let path = path.as_ref();
        
        // Check if parent directory exists
        if let Some(parent) = path.parent() {
            if !parent.exists() {
                return Err(RuzipError::invalid_input(
                    format!("Parent directory does not exist: {}", parent.display()),
                    Some(parent.display().to_string()),
                ));
            }
        }

        // Check file extension
        if let Some(ext) = path.extension() {
            if ext != "rzp" {
                tracing::warn!("Archive does not have .rzp extension: {}", path.display());
            }
        }

        // Check if file already exists
        if path.exists() {
            return Err(RuzipError::invalid_input(
                format!("Archive file already exists: {}", path.display()),
                Some(path.display().to_string()),
            ));
        }

        Ok(())
    }

    /// Calculate estimated archive size
    pub fn estimate_archive_size<P: AsRef<Path>>(
        paths: &[P],
        compression_level: crate::compression::CompressionLevel,
    ) -> Result<u64> {
        let mut total_size = 0u64;
        let ratio_multiplier = compression_level.estimated_ratio_multiplier();

        for path in paths {
            let path = path.as_ref();
            if path.is_file() {
                let metadata = fs::metadata(path).map_err(|e| {
                    RuzipError::io_error(
                        format!("Failed to get metadata for: {}", path.display()),
                        e,
                    )
                })?;
                total_size += metadata.len();
            } else if path.is_dir() {
                total_size += estimate_directory_size(path)?;
            }
        }

        // Apply compression ratio and add overhead for headers/metadata (~5%)
        let compressed_size = (total_size as f64 * ratio_multiplier) as u64;
        let overhead = (compressed_size as f64 * 0.05) as u64;
        
        Ok(compressed_size + overhead)
    }

    fn estimate_directory_size<P: AsRef<Path>>(dir: P) -> Result<u64> {
        use walkdir::WalkDir;
        let mut total_size = 0u64;

        for entry in WalkDir::new(dir.as_ref()) {
            let entry = entry.map_err(|e| {
                RuzipError::io_error("Failed to walk directory", e.into())
            })?;

            if entry.file_type().is_file() {
                let metadata = entry.metadata().map_err(|e| {
                    RuzipError::io_error(
                        format!("Failed to get metadata for: {}", entry.path().display()),
                        e.into(),
                    )
                })?;
                total_size += metadata.len();
            }
        }

        Ok(total_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs;

    #[test]
    fn test_archive_options_default() {
        let options = ArchiveOptions::default();
        assert!(options.preserve_permissions);
        assert!(options.preserve_timestamps);
        assert!(options.store_checksums);
        assert!(options.verify_integrity);
        assert_eq!(options.max_memory, 512 * 1024 * 1024);
    }

    #[test]
    fn test_archive_info_calculations() {
        let info = ArchiveInfo {
            version: 1,
            entry_count: 10,
            uncompressed_size: 1000,
            compressed_size: 600,
            created_at: 1234567890,
            modified_at: 1234567890,
            compression_ratio: 0.6,
            checksum: Some([0u8; 32]),
        };

        assert_eq!(info.compression_percentage(), 40.0);
        assert!(info.has_integrity_protection());
    }

    #[test]
    fn test_archive_stats() {
        let mut stats = ArchiveStats {
            files_processed: 5,
            directories_processed: 2,
            bytes_processed: 10 * 1024 * 1024, // 10MB
            duration_ms: 1000, // 1 second
            ..Default::default()
        };

        assert_eq!(stats.total_items(), 7);
        
        stats.calculate_speed();
        assert_eq!(stats.processing_speed, 10.0); // 10 MB/s
    }

    #[test]
    fn test_validate_archive_path() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("test.rzp");

        // Should pass validation for new file
        assert!(utils::validate_archive_path(&archive_path).is_ok());

        // Create the file and test again
        fs::write(&archive_path, b"test").unwrap();
        assert!(utils::validate_archive_path(&archive_path).is_err());

        // Test non-existent parent directory
        let bad_path = temp_dir.path().join("nonexistent").join("test.rzp");
        assert!(utils::validate_archive_path(&bad_path).is_err());
    }

    #[test]
    fn test_is_ruzip_archive() {
        let temp_dir = TempDir::new().unwrap();
        
        // Test valid RuZip archive
        let ruzip_path = temp_dir.path().join("test.rzp");
        fs::write(&ruzip_path, RUZIP_MAGIC).unwrap();
        assert!(utils::is_ruzip_archive(&ruzip_path).unwrap());

        // Test invalid file
        let invalid_path = temp_dir.path().join("invalid.rzp");
        fs::write(&invalid_path, b"INVALID").unwrap();
        assert!(!utils::is_ruzip_archive(&invalid_path).unwrap());

        // Test too short file
        let short_path = temp_dir.path().join("short.rzp");
        fs::write(&short_path, b"RZ").unwrap();
        assert!(!utils::is_ruzip_archive(&short_path).unwrap());
    }

    #[test]
    fn test_estimate_archive_size() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        fs::write(&test_file, b"Hello, World!").unwrap();

        let level = crate::compression::CompressionLevel::new(6).unwrap();
        let estimated_size = utils::estimate_archive_size(&[&test_file], level).unwrap();
        
        // Should be less than original due to compression, but with some overhead
        assert!(estimated_size > 0);
        assert!(estimated_size < 100); // Much smaller than original due to small file
    }
}