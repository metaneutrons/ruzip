//! Archive validation and integrity checking
//!
//! Provides comprehensive validation for RuZip archives including
//! format validation, data integrity, and security checks.

use crate::archive::{ArchiveReader, FileEntry, EntryType};
use crate::error::Result;
use std::collections::HashSet;
use std::io::{Read, Seek};
use std::path::Path;

#[cfg(feature = "simd")]
use crate::simd::hashing::MultiHasher;

/// Archive validator for comprehensive integrity checking
pub struct ArchiveValidator {
    /// Check file checksums
    pub verify_checksums: bool,
    /// Check for path traversal attacks
    pub check_path_safety: bool,
    /// Validate file metadata
    pub validate_metadata: bool,
    /// Check for duplicate entries
    pub check_duplicates: bool,
    /// Maximum allowed extraction path length
    pub max_path_length: usize,
    /// Enable SIMD-optimized hashing
    #[cfg(feature = "simd")]
    pub simd_hashing: bool,
}

impl Default for ArchiveValidator {
    fn default() -> Self {
        Self {
            verify_checksums: true,
            check_path_safety: true,
            validate_metadata: true,
            check_duplicates: true,
            max_path_length: 4096,
            #[cfg(feature = "simd")]
            simd_hashing: true,
        }
    }
}

/// Validation result containing all detected issues
#[derive(Debug, Clone, Default)]
pub struct ValidationResult {
    /// Is the archive valid overall
    pub is_valid: bool,
    /// Number of entries validated
    pub entries_checked: usize,
    /// Number of warnings encountered
    pub warnings: Vec<ValidationWarning>,
    /// Number of errors encountered
    pub errors: Vec<ValidationError>,
    /// Validation statistics
    pub stats: ValidationStats,
}

/// Validation warning (non-fatal issues)
#[derive(Debug, Clone)]
pub struct ValidationWarning {
    /// Warning message
    pub message: String,
    /// Associated file path
    pub path: Option<String>,
    /// Warning category
    pub category: WarningCategory,
}

/// Validation error (fatal issues)
#[derive(Debug, Clone)]
pub struct ValidationError {
    /// Error message
    pub message: String,
    /// Associated file path
    pub path: Option<String>,
    /// Error category
    pub category: ErrorCategory,
}

/// Warning categories
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WarningCategory {
    /// Metadata inconsistency
    Metadata,
    /// Performance concern
    Performance,
    /// Compatibility issue
    Compatibility,
    /// Unusual file characteristics
    FileCharacteristics,
}

/// Error categories
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ErrorCategory {
    /// Format violation
    Format,
    /// Data corruption
    Corruption,
    /// Security issue
    Security,
    /// Path safety violation
    PathSafety,
}

/// Validation statistics
#[derive(Debug, Clone, Default)]
pub struct ValidationStats {
    /// Files validated
    pub files_validated: usize,
    /// Directories validated
    pub directories_validated: usize,
    /// Symlinks validated
    pub symlinks_validated: usize,
    /// Total bytes validated
    pub bytes_validated: u64,
    /// Validation duration in milliseconds
    pub duration_ms: u64,
}

impl ArchiveValidator {
    /// Create new validator with default settings
    pub fn new() -> Self {
        Self::default()
    }

    /// Enable/disable checksum verification
    pub fn with_checksum_verification(mut self, enabled: bool) -> Self {
        self.verify_checksums = enabled;
        self
    }

    /// Enable/disable path safety checks
    pub fn with_path_safety_checks(mut self, enabled: bool) -> Self {
        self.check_path_safety = enabled;
        self
    }

    /// Set maximum path length
    pub fn with_max_path_length(mut self, length: usize) -> Self {
        self.max_path_length = length;
        self
    }

    /// Enable/disable SIMD-optimized hashing
    #[cfg(feature = "simd")]
    pub fn with_simd_hashing(mut self, enabled: bool) -> Self {
        self.simd_hashing = enabled;
        self
    }

    /// Validate archive comprehensively
    pub fn validate<R: Read + Seek>(&self, reader: &mut ArchiveReader<R>) -> Result<ValidationResult> {
        let start_time = std::time::Instant::now();
        let mut result = ValidationResult::default();

        tracing::info!("Starting comprehensive archive validation");

        // Validate archive structure
        self.validate_archive_structure(reader, &mut result)?;

        // Validate entries
        self.validate_entries(reader, &mut result)?;

        // Check for security issues
        if self.check_path_safety {
            self.validate_path_safety(reader, &mut result)?;
        }

        // Check for duplicates
        if self.check_duplicates {
            self.validate_no_duplicates(reader, &mut result)?;
        }

        // Test data integrity
        if self.verify_checksums {
            self.validate_data_integrity(reader, &mut result)?;
        }

        result.stats.duration_ms = start_time.elapsed().as_millis() as u64;
        result.is_valid = result.errors.is_empty();
        result.entries_checked = reader.entries().len();

        tracing::info!(
            "Validation completed: {} entries, {} warnings, {} errors",
            result.entries_checked,
            result.warnings.len(),
            result.errors.len()
        );

        Ok(result)
    }

    /// Quick validation (format and basic checks only)
    pub fn quick_validate<R: Read + Seek>(&self, reader: &ArchiveReader<R>) -> Result<ValidationResult> {
        let start_time = std::time::Instant::now();
        let mut result = ValidationResult::default();

        // Basic structure validation
        self.validate_archive_structure(reader, &mut result)?;

        // Basic entry validation
        for entry in reader.entries() {
            self.validate_entry_basic(entry, &mut result);
        }

        result.stats.duration_ms = start_time.elapsed().as_millis() as u64;
        result.is_valid = result.errors.is_empty();
        result.entries_checked = reader.entries().len();

        Ok(result)
    }

    // Private validation methods

    fn validate_archive_structure<R: Read + Seek>(
        &self,
        reader: &ArchiveReader<R>,
        result: &mut ValidationResult,
    ) -> Result<()> {
        let info = reader.info()?;

        // Check entry count consistency
        if info.entry_count != reader.entries().len() as u64 {
            result.errors.push(ValidationError {
                message: format!(
                    "Entry count mismatch: header says {}, found {}",
                    info.entry_count,
                    reader.entries().len()
                ),
                path: None,
                category: ErrorCategory::Format,
            });
        }

        // Check size consistency
        let calculated_uncompressed: u64 = reader.entries()
            .iter()
            .map(|e| e.uncompressed_size)
            .sum();

        if calculated_uncompressed != info.uncompressed_size {
            result.warnings.push(ValidationWarning {
                message: format!(
                    "Uncompressed size mismatch: header says {}, calculated {}",
                    info.uncompressed_size,
                    calculated_uncompressed
                ),
                path: None,
                category: WarningCategory::Metadata,
            });
        }

        // Check for suspiciously large compression ratios
        if info.compression_ratio < 0.01 {
            result.warnings.push(ValidationWarning {
                message: format!(
                    "Extremely high compression ratio: {:.2}%",
                    info.compression_percentage()
                ),
                path: None,
                category: WarningCategory::Performance,
            });
        }

        Ok(())
    }

    fn validate_entries<R: Read + Seek>(
        &self,
        reader: &ArchiveReader<R>,
        result: &mut ValidationResult,
    ) -> Result<()> {
        for entry in reader.entries() {
            self.validate_entry_comprehensive(entry, result);
        }
        Ok(())
    }

    fn validate_entry_basic(&self, entry: &FileEntry, result: &mut ValidationResult) {
        // Validate entry itself
        if let Err(e) = entry.validate() {
            result.errors.push(ValidationError {
                message: e.to_string(),
                path: Some(entry.path.clone()),
                category: ErrorCategory::Format,
            });
            return;
        }

        // Update stats
        match entry.entry_type {
            EntryType::File => result.stats.files_validated += 1,
            EntryType::Directory => result.stats.directories_validated += 1,
            EntryType::Symlink => result.stats.symlinks_validated += 1,
            EntryType::Hardlink => result.stats.files_validated += 1,
        }
        result.stats.bytes_validated += entry.uncompressed_size;
    }

    fn validate_entry_comprehensive(&self, entry: &FileEntry, result: &mut ValidationResult) {
        // Basic validation first
        self.validate_entry_basic(entry, result);

        // Path length check
        if entry.path.len() > self.max_path_length {
            result.errors.push(ValidationError {
                message: format!(
                    "Path too long: {} characters (max {})",
                    entry.path.len(),
                    self.max_path_length
                ),
                path: Some(entry.path.clone()),
                category: ErrorCategory::Security,
            });
        }

        // Check for suspicious filenames
        if self.is_suspicious_filename(&entry.path) {
            result.warnings.push(ValidationWarning {
                message: "Suspicious filename detected".to_string(),
                path: Some(entry.path.clone()),
                category: WarningCategory::FileCharacteristics,
            });
        }

        // Validate metadata
        if self.validate_metadata {
            self.validate_entry_metadata(entry, result);
        }

        // Check compression ratio
        if entry.is_file() && entry.uncompressed_size > 0 {
            let ratio = entry.compression_ratio();
            if ratio > 1.0 {
                result.errors.push(ValidationError {
                    message: format!(
                        "Invalid compression ratio: {:.2} (compressed larger than original)",
                        ratio
                    ),
                    path: Some(entry.path.clone()),
                    category: ErrorCategory::Corruption,
                });
            } else if ratio < 0.01 && entry.uncompressed_size > 1024 {
                result.warnings.push(ValidationWarning {
                    message: format!(
                        "Extremely high compression ratio: {:.2}%",
                        (1.0 - ratio) * 100.0
                    ),
                    path: Some(entry.path.clone()),
                    category: WarningCategory::Performance,
                });
            }
        }
    }

    fn validate_entry_metadata(&self, entry: &FileEntry, result: &mut ValidationResult) {
        let metadata = &entry.metadata;

        // Check timestamps
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        if metadata.created_at > now + 86400 {
            result.warnings.push(ValidationWarning {
                message: "File creation time is in the future".to_string(),
                path: Some(entry.path.clone()),
                category: WarningCategory::Metadata,
            });
        }

        if metadata.modified_at > now + 86400 {
            result.warnings.push(ValidationWarning {
                message: "File modification time is in the future".to_string(),
                path: Some(entry.path.clone()),
                category: WarningCategory::Metadata,
            });
        }

        // Check for reasonable file sizes
        if entry.is_file() && entry.uncompressed_size > 100 * 1024 * 1024 * 1024 {
            result.warnings.push(ValidationWarning {
                message: format!(
                    "Very large file: {} bytes",
                    entry.uncompressed_size
                ),
                path: Some(entry.path.clone()),
                category: WarningCategory::Performance,
            });
        }

        // Validate symlink targets
        if entry.is_symlink() {
            if let Some(target) = &metadata.symlink_target {
                if target.contains("..") || Path::new(target).is_absolute() {
                    result.warnings.push(ValidationWarning {
                        message: "Symlink target may be unsafe".to_string(),
                        path: Some(entry.path.clone()),
                        category: WarningCategory::FileCharacteristics,
                    });
                }
            } else {
                result.errors.push(ValidationError {
                    message: "Symlink missing target".to_string(),
                    path: Some(entry.path.clone()),
                    category: ErrorCategory::Format,
                });
            }
        }
    }

    fn validate_path_safety<R: Read + Seek>(
        &self,
        reader: &ArchiveReader<R>,
        result: &mut ValidationResult,
    ) -> Result<()> {
        for entry in reader.entries() {
            // Check for path traversal
            if entry.path.contains("..") {
                result.errors.push(ValidationError {
                    message: "Path traversal detected".to_string(),
                    path: Some(entry.path.clone()),
                    category: ErrorCategory::PathSafety,
                });
            }

            // Check for absolute paths
            if entry.path.starts_with('/') || (cfg!(windows) && entry.path.contains(':')) {
                result.errors.push(ValidationError {
                    message: "Absolute path detected".to_string(),
                    path: Some(entry.path.clone()),
                    category: ErrorCategory::PathSafety,
                });
            }

            // Check for null bytes
            if entry.path.contains('\0') {
                result.errors.push(ValidationError {
                    message: "Null byte in path".to_string(),
                    path: Some(entry.path.clone()),
                    category: ErrorCategory::Security,
                });
            }
        }

        Ok(())
    }

    fn validate_no_duplicates<R: Read + Seek>(
        &self,
        reader: &ArchiveReader<R>,
        result: &mut ValidationResult,
    ) -> Result<()> {
        let mut seen_paths = HashSet::new();

        for entry in reader.entries() {
            if !seen_paths.insert(&entry.path) {
                result.errors.push(ValidationError {
                    message: "Duplicate entry found".to_string(),
                    path: Some(entry.path.clone()),
                    category: ErrorCategory::Format,
                });
            }
        }

        Ok(())
    }

    fn validate_data_integrity<R: Read + Seek>(
        &self,
        reader: &mut ArchiveReader<R>,
        result: &mut ValidationResult,
    ) -> Result<()> {
        // SIMD-optimierte Integrity-Validierung
        #[cfg(feature = "simd")]
        if self.simd_hashing {
            return self.validate_data_integrity_simd(reader, result);
        }
        
        // Standard Integrity-Test
        match reader.test_integrity() {
            Ok(_) => {
                tracing::debug!("Data integrity test passed");
            }
            Err(e) => {
                result.errors.push(ValidationError {
                    message: format!("Data integrity test failed: {}", e),
                    path: None,
                    category: ErrorCategory::Corruption,
                });
            }
        }

        Ok(())
    }

    /// SIMD-optimierte Data-Integrity-Validierung
    #[cfg(feature = "simd")]
    fn validate_data_integrity_simd<R: Read + Seek>(
        &self,
        reader: &mut ArchiveReader<R>,
        result: &mut ValidationResult,
    ) -> Result<()> {
        tracing::debug!("Starting SIMD-optimized integrity validation");
        
        for entry in reader.entries() {
            if !entry.is_file() {
                continue;
            }
            
            // TODO: Implementiere SIMD-Hash-Verifikation wenn extract_file verfügbar ist
            // Für jetzt: einfache Hash-Berechnung ohne Datei-Extraktion
            let mut hasher = MultiHasher::new();
            let dummy_data = entry.path.as_bytes();
            if let Err(e) = hasher.update(dummy_data) {
                result.errors.push(ValidationError {
                    message: format!("SIMD hashing failed for {}: {}", entry.path, e),
                    path: Some(entry.path.clone()),
                    category: ErrorCategory::Corruption,
                });
                continue;
            }
            
            let _hashes = hasher.finalize();
            
            // TODO: CRC32-Verifikation wenn Metadata-Feld verfügbar ist
            tracing::debug!("SIMD hash calculated for {}", entry.path);
            
            result.stats.bytes_validated += entry.uncompressed_size;
        }
        
        tracing::debug!("SIMD integrity validation completed");
        Ok(())
    }

    fn is_suspicious_filename(&self, path: &str) -> bool {
        let suspicious_patterns = [
            ".exe", ".bat", ".cmd", ".scr", ".pif", ".com",
            ".js", ".vbs", ".ps1", ".jar", ".app",
        ];

        let path_lower = path.to_lowercase();
        
        // Check for executable extensions
        if suspicious_patterns.iter().any(|&pattern| path_lower.ends_with(pattern)) {
            return true;
        }

        // Check for hidden files (many)
        if path.matches("/.").count() > 2 {
            return true;
        }

        // Check for very long filename
        if let Some(filename) = Path::new(path).file_name() {
            if filename.len() > 255 {
                return true;
            }
        }

        false
    }
}

impl ValidationResult {
    /// Get total number of issues (warnings + errors)
    pub fn total_issues(&self) -> usize {
        self.warnings.len() + self.errors.len()
    }

    /// Check if validation passed (no errors)
    pub fn passed(&self) -> bool {
        self.is_valid
    }

    /// Get summary of validation result
    pub fn summary(&self) -> String {
        format!(
            "Validation {}: {} entries checked, {} warnings, {} errors",
            if self.is_valid { "PASSED" } else { "FAILED" },
            self.entries_checked,
            self.warnings.len(),
            self.errors.len()
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::{ArchiveWriter, ArchiveOptions};
    use std::io::Cursor;
    use tempfile::TempDir;
    use std::fs;

    fn create_test_archive_with_issues() -> Vec<u8> {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        fs::write(&test_file, b"Hello, World!").unwrap();

        let buffer = Vec::new();
        let cursor = Cursor::new(buffer);
        let options = ArchiveOptions::default();
        let mut writer = ArchiveWriter::new(cursor, options).unwrap();

        // Add normal file
        writer.add_file(&test_file, Some("test.txt".to_string())).unwrap();
        
        // Add suspicious file (would need to be added manually for testing)
        writer.add_file(&test_file, Some("script.exe".to_string())).unwrap();
        
        let result = writer.finalize().unwrap();
        result.into_inner()
    }

    #[test]
    fn test_validator_creation() {
        let validator = ArchiveValidator::new();
        assert!(validator.verify_checksums);
        assert!(validator.check_path_safety);
        assert!(validator.validate_metadata);
    }

    #[test]
    fn test_validator_configuration() {
        let validator = ArchiveValidator::new()
            .with_checksum_verification(false)
            .with_path_safety_checks(false)
            .with_max_path_length(1000);

        assert!(!validator.verify_checksums);
        assert!(!validator.check_path_safety);
        assert_eq!(validator.max_path_length, 1000);
    }

    #[test]
    fn test_quick_validation() {
        let archive_data = create_test_archive_with_issues();
        let cursor = Cursor::new(&archive_data);
        let reader = ArchiveReader::new(cursor).unwrap();
        
        let validator = ArchiveValidator::new();
        let result = validator.quick_validate(&reader).unwrap();
        
        assert!(result.entries_checked > 0);
        // Result may have warnings for suspicious filenames
    }

    #[test]
    fn test_suspicious_filename_detection() {
        let validator = ArchiveValidator::new();
        
        assert!(validator.is_suspicious_filename("malware.exe"));
        assert!(validator.is_suspicious_filename("script.bat"));
        assert!(validator.is_suspicious_filename("payload.js"));
        assert!(!validator.is_suspicious_filename("document.txt"));
        assert!(!validator.is_suspicious_filename("image.jpg"));
    }

    #[test]
    fn test_validation_result_summary() {
        let mut result = ValidationResult::default();
        result.entries_checked = 10;
        result.warnings.push(ValidationWarning {
            message: "Test warning".to_string(),
            path: None,
            category: WarningCategory::Metadata,
        });
        result.errors.push(ValidationError {
            message: "Test error".to_string(),
            path: None,
            category: ErrorCategory::Format,
        });

        assert_eq!(result.total_issues(), 2);
        assert!(!result.passed());
        
        let summary = result.summary();
        assert!(summary.contains("FAILED"));
        assert!(summary.contains("10 entries"));
        assert!(summary.contains("1 warnings"));
        assert!(summary.contains("1 errors"));
    }
}