//! Archive deletion functionality
//!
//! Provides traits and implementations for deleting files from RuZip archives,
//! supporting both safe reconstruction and in-place modification approaches.

use crate::archive::{ArchiveStats, FileEntry};
use crate::error::{Result, RuzipError};
use std::path::Path;

/// Trait for archive deletion operations
pub trait ArchiveDeleter {
    /// Delete files from archive using the safe reconstruction approach
    fn delete_files_safe<P: AsRef<Path>>(
        &self,
        archive_path: P,
        files_to_delete: &[String],
        recursive: bool,
        create_backup: bool,
    ) -> Result<ArchiveStats>;

    /// Delete files from archive using in-place modification
    fn delete_files_inplace<P: AsRef<Path>>(
        &self,
        archive_path: P,
        files_to_delete: &[String],
        recursive: bool,
        create_backup: bool,
    ) -> Result<ArchiveStats>;

    /// Preview which files would be deleted (dry run)
    fn preview_deletion<P: AsRef<Path>>(
        &self,
        archive_path: P,
        files_to_delete: &[String],
        recursive: bool,
    ) -> Result<DeletionPreview>;
}

/// Preview of files that would be deleted
#[derive(Debug, Clone)]
pub struct DeletionPreview {
    /// Files that match the deletion criteria
    pub files_to_delete: Vec<FileEntry>,
    /// Total size that would be reclaimed
    pub space_to_reclaim: u64,
    /// Number of directories that would be affected
    pub directories_affected: u64,
    /// Warnings about potentially dangerous operations
    pub warnings: Vec<String>,
}

impl DeletionPreview {
    /// Create a new empty preview
    pub fn new() -> Self {
        Self {
            files_to_delete: Vec::new(),
            space_to_reclaim: 0,
            directories_affected: 0,
            warnings: Vec::new(),
        }
    }

    /// Get total number of files to delete
    pub fn file_count(&self) -> usize {
        self.files_to_delete.len()
    }

    /// Check if this operation has warnings
    pub fn has_warnings(&self) -> bool {
        !self.warnings.is_empty()
    }

    /// Add a warning to the preview
    pub fn add_warning(&mut self, warning: String) {
        self.warnings.push(warning);
    }

    /// Calculate statistics for the preview
    pub fn calculate_stats(&mut self) {
        self.space_to_reclaim = self.files_to_delete
            .iter()
            .map(|entry| entry.uncompressed_size)
            .sum();

        // Count unique directories
        use std::collections::HashSet;
        let mut dirs = HashSet::new();
        for entry in &self.files_to_delete {
            if let Some(parent) = entry.parent_path() {
                dirs.insert(parent);
            }
        }
        self.directories_affected = dirs.len() as u64;
    }
}

/// File matching utilities for deletion operations
pub mod matching {
    use super::*;
    use crate::archive::FileEntry;

    /// Find files matching deletion patterns
    pub fn find_files_to_delete(
        entries: &[FileEntry],
        patterns: &[String],
        recursive: bool,
    ) -> Result<Vec<usize>> {
        let mut indices_to_delete = Vec::new();
        
        for pattern in patterns {
            let matching_indices = find_pattern_matches(entries, pattern, recursive)?;
            indices_to_delete.extend(matching_indices);
        }
        
        // Remove duplicates and sort
        indices_to_delete.sort_unstable();
        indices_to_delete.dedup();
        
        Ok(indices_to_delete)
    }

    /// Find entries matching a specific pattern
    fn find_pattern_matches(
        entries: &[FileEntry],
        pattern: &str,
        recursive: bool,
    ) -> Result<Vec<usize>> {
        let mut matches = Vec::new();
        
        for (index, entry) in entries.iter().enumerate() {
            if matches_pattern(&entry.path, pattern)? {
                matches.push(index);
                
                // If this is a directory and recursive is enabled,
                // also include all files within it
                if recursive && entry.entry_type == crate::archive::EntryType::Directory {
                    let dir_prefix = format!("{}/", entry.path);
                    for (sub_index, sub_entry) in entries.iter().enumerate() {
                        if sub_entry.path.starts_with(&dir_prefix) {
                            matches.push(sub_index);
                        }
                    }
                }
            }
        }
        
        Ok(matches)
    }

    /// Check if a path matches a pattern (supports basic glob patterns)
    fn matches_pattern(path: &str, pattern: &str) -> Result<bool> {
        // Exact match
        if path == pattern {
            return Ok(true);
        }
        
        // Simple wildcard support
        if pattern.contains('*') {
            return Ok(matches_glob_pattern(path, pattern));
        }
        
        // Directory prefix match (for recursive deletion)
        if pattern.ends_with('/') {
            return Ok(path.starts_with(pattern));
        }
        
        Ok(false)
    }

    /// Basic glob pattern matching (simplified implementation)
    pub fn matches_glob_pattern(path: &str, pattern: &str) -> bool {
        // Convert glob pattern to regex-like matching
        // This is a simplified implementation - in production, use a proper glob library
        
        if pattern == "*" {
            return true;
        }
        
        if pattern.starts_with("*.") {
            let extension = &pattern[2..];
            return path.ends_with(&format!(".{}", extension));
        }
        
        if pattern.ends_with("/*") {
            let prefix = &pattern[..pattern.len()-2];
            return path.starts_with(&format!("{}/", prefix));
        }
        
        // More complex patterns would require a proper glob library
        false
    }
}

/// Validation utilities for deletion operations
pub mod validation {
    use super::*;
    use std::fs;

    /// Result of validation checks
    #[derive(Debug, Clone)]
    pub struct ValidationResult {
        pub errors: Vec<String>,
        pub warnings: Vec<String>,
    }

    impl ValidationResult {
        pub fn new() -> Self {
            Self {
                errors: Vec::new(),
                warnings: Vec::new(),
            }
        }

        pub fn add_error(&mut self, error: String) {
            self.errors.push(error);
        }

        pub fn add_warning(&mut self, warning: String) {
            self.warnings.push(warning);
        }

        pub fn has_errors(&self) -> bool {
            !self.errors.is_empty()
        }

        pub fn has_warnings(&self) -> bool {
            !self.warnings.is_empty()
        }
    }

    /// Validate deletion operation prerequisites
    pub fn validate_deletion_operation<P: AsRef<Path>>(
        archive_path: P,
        _files_to_delete: &[String],
        in_place: bool,
        create_backup: bool,
    ) -> Result<ValidationResult> {
        let mut result = ValidationResult::new();
        let path = archive_path.as_ref();
        
        // Check if archive exists and is readable
        if !path.exists() {
            result.add_error(format!("Archive does not exist: {}", path.display()));
            return Ok(result);
        }
        
        // Check if archive is writable (for in-place operations)
        if in_place {
            let metadata = fs::metadata(path).map_err(|e| {
                RuzipError::io_error(
                    format!("Failed to get archive metadata: {}", path.display()),
                    e,
                )
            })?;
            
            if metadata.permissions().readonly() {
                result.add_error("Archive is read-only, cannot perform in-place deletion".to_string());
            }
        }
        
        // Check available disk space for safe operations
        if !in_place {
            let archive_size = fs::metadata(path)
                .map_err(|e| RuzipError::io_error("Failed to get archive size", e))?
                .len();
            
            // For safe operations, we need at least the archive size in free space
            if let Some(available_space) = get_available_space(path.parent().unwrap_or(path))? {
                if available_space < archive_size {
                    result.add_warning(format!(
                        "Low disk space: {} bytes available, {} bytes needed",
                        available_space, archive_size
                    ));
                }
            }
        }
        
        // Validate backup location if requested
        if create_backup {
            let backup_path = generate_backup_path(path);
            if backup_path.exists() {
                result.add_warning(format!(
                    "Backup file already exists: {}",
                    backup_path.display()
                ));
            }
        }
        
        Ok(result)
    }

    /// Get available disk space for a path
    fn get_available_space<P: AsRef<Path>>(path: P) -> Result<Option<u64>> {
        // This is a simplified implementation
        // In production, use proper platform-specific APIs
        use std::fs;
        
        match fs::metadata(path) {
            Ok(_) => {
                // Return None to indicate we can't determine available space
                // A real implementation would use platform-specific APIs
                Ok(None)
            }
            Err(_) => Ok(None),
        }
    }

    /// Generate backup path for an archive
    pub fn generate_backup_path<P: AsRef<Path>>(archive_path: P) -> std::path::PathBuf {
        let path = archive_path.as_ref();
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        if let Some(parent) = path.parent() {
            let filename = path.file_name().unwrap_or_default();
            parent.join(format!("{}.backup.{}", filename.to_string_lossy(), timestamp))
        } else {
            std::path::PathBuf::from(format!("{}.backup.{}", path.to_string_lossy(), timestamp))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::{EntryType, FileMetadata};

    fn create_test_entry(path: &str, entry_type: EntryType, size: u64) -> FileEntry {
        FileEntry {
            path: path.to_string(),
            entry_type,
            uncompressed_size: size,
            compressed_size: size / 2,
            data_offset: 0,
            metadata: FileMetadata::empty(),
            checksum: None,
            flags: crate::archive::entry::EntryFlags::default(),
            compression_method: 0, // ZSTD
            signature: None,
            extensions: std::collections::HashMap::new(),
        }
    }

    #[test]
    fn test_deletion_preview() {
        let mut preview = DeletionPreview::new();
        assert_eq!(preview.file_count(), 0);
        assert!(!preview.has_warnings());
        
        preview.files_to_delete.push(create_test_entry("test.txt", EntryType::File, 100));
        preview.files_to_delete.push(create_test_entry("dir/file.txt", EntryType::File, 200));
        
        preview.calculate_stats();
        assert_eq!(preview.file_count(), 2);
        assert_eq!(preview.space_to_reclaim, 300);
    }

    #[test]
    fn test_pattern_matching() {
        let entries = vec![
            create_test_entry("file.txt", EntryType::File, 100),
            create_test_entry("file.tmp", EntryType::File, 50),
            create_test_entry("dir/nested.txt", EntryType::File, 200),
            create_test_entry("test.log", EntryType::File, 150),
        ];

        // Test exact match
        let indices = matching::find_files_to_delete(&entries, &["file.txt".to_string()], false).unwrap();
        assert_eq!(indices, vec![0]);

        // Test wildcard match
        let indices = matching::find_files_to_delete(&entries, &["*.tmp".to_string()], false).unwrap();
        assert_eq!(indices, vec![1]);
    }

    #[test]
    fn test_glob_pattern_matching() {
        assert!(matching::matches_glob_pattern("file.txt", "*.txt"));
        assert!(matching::matches_glob_pattern("file.tmp", "*.tmp"));
        assert!(!matching::matches_glob_pattern("file.txt", "*.tmp"));
        assert!(matching::matches_glob_pattern("anything", "*"));
    }

    #[test]
    fn test_validation_result() {
        let mut result = validation::ValidationResult::new();
        assert!(!result.has_errors());
        assert!(!result.has_warnings());
        
        result.add_error("Test error".to_string());
        result.add_warning("Test warning".to_string());
        
        assert!(result.has_errors());
        assert!(result.has_warnings());
        assert_eq!(result.errors.len(), 1);
        assert_eq!(result.warnings.len(), 1);
    }
}