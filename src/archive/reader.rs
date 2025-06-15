//! Archive reader implementation
//!
//! Provides functionality to read RuZip archives, list contents,
//! and extract files with integrity verification.

use crate::archive::{
    ArchiveHeader, ArchiveInfo, ArchiveStats, FileEntry,
};
use crate::compression::{CompressionEngine, CompressionMethod, Compressor};
use crate::error::{Result, RuzipError};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::Instant;
use tracing;

/// Archive reader for reading RuZip archives
pub struct ArchiveReader<R: Read + Seek> {
    reader: BufReader<R>,
    header: ArchiveHeader,
    entries: Vec<FileEntry>,
    entry_map: HashMap<String, usize>,
    compression_engine: CompressionEngine,
}

impl<R: Read + Seek> ArchiveReader<R> {
    /// Open archive from reader
    pub fn new(mut reader: R) -> Result<Self> {
        // Read and validate header
        reader.seek(SeekFrom::Start(0))?;
        let header = ArchiveHeader::deserialize(&mut reader)?;
        
        let compression_method = match header.compression_method {
            0 => CompressionMethod::Zstd,
            1 => CompressionMethod::Store,
            // TODO: Add support for other methods if they are defined in header.rs spec
            id => return Err(RuzipError::header_parse_error(format!(
                "Unsupported compression_method ID '{}' in archive header.",
                id
            ))),
        };

        let compression_engine = CompressionEngine::new()
            .with_method(compression_method);

        let mut archive_reader = Self {
            reader: BufReader::new(reader),
            header,
            entries: Vec::new(),
            entry_map: HashMap::new(),
            compression_engine,
        };

        // Read entry table
        archive_reader.read_entry_table()?;

        Ok(archive_reader)
    }

    /// Open archive from file path
    pub fn open<P: AsRef<Path>>(path: P) -> Result<ArchiveReader<File>> {
        let file = File::open(path.as_ref()).map_err(|e| {
            RuzipError::io_error(
                format!("Failed to open archive: {}", path.as_ref().display()),
                e,
            )
        })?;

        ArchiveReader::new(file)
    }

    /// Get archive information
    pub fn info(&self) -> Result<ArchiveInfo> {
        let compression_ratio = if self.header.uncompressed_size > 0 {
            self.header.compressed_size as f64 / self.header.uncompressed_size as f64
        } else {
            1.0
        };

        Ok(ArchiveInfo {
            version: self.header.version,
            entry_count: self.header.entry_count,
            uncompressed_size: self.header.uncompressed_size,
            compressed_size: self.header.compressed_size,
            created_at: self.header.created_at,
            modified_at: self.header.modified_at,
            compression_ratio,
            checksum: None, // TODO: Implement archive-level checksum
        })
    }

    /// Get list of all entries
    pub fn entries(&self) -> &[FileEntry] {
        &self.entries
    }

    /// Get entry by path
    pub fn get_entry(&self, path: &str) -> Option<&FileEntry> {
        self.entry_map.get(path)
            .and_then(|&index| self.entries.get(index))
    }

    /// Check if archive contains a specific path
    pub fn contains(&self, path: &str) -> bool {
        self.entry_map.contains_key(path)
    }

    /// List entries with optional filter
    pub fn list_entries<F>(&self, filter: Option<F>) -> Vec<&FileEntry>
    where
        F: Fn(&FileEntry) -> bool,
    {
        match filter {
            Some(f) => self.entries.iter().filter(|entry| f(entry)).collect(),
            None => self.entries.iter().collect(),
        }
    }

    /// Extract all files to destination directory
    pub fn extract_all<P: AsRef<Path>>(&mut self, dest_dir: P) -> Result<ArchiveStats> {
        let dest_dir = dest_dir.as_ref();
        let start_time = Instant::now();
        let mut stats = ArchiveStats::default();

        tracing::info!("Extracting {} entries to: {}", self.entries.len(), dest_dir.display());

        // Create destination directory if it doesn't exist
        if !dest_dir.exists() {
            fs::create_dir_all(dest_dir).map_err(|e| {
                RuzipError::io_error(
                    format!("Failed to create destination directory: {}", dest_dir.display()),
                    e,
                )
            })?;
        }

        // First pass: create all directories
        for entry in &self.entries {
            if entry.is_directory() {
                let entry_path = dest_dir.join(&entry.path);
                if !entry_path.exists() {
                    fs::create_dir_all(&entry_path).map_err(|e| {
                        RuzipError::io_error(
                            format!("Failed to create directory: {}", entry_path.display()),
                            e,
                        )
                    })?;
                    stats.directories_processed += 1;
                }
            }
        }

        // Second pass: extract files
        let entries_clone = self.entries.clone();
        for entry in &entries_clone {
            if entry.is_file() {
                let entry_path = dest_dir.join(&entry.path);
                
                // Ensure parent directory exists
                if let Some(parent) = entry_path.parent() {
                    if !parent.exists() {
                        fs::create_dir_all(parent).map_err(|e| {
                            RuzipError::io_error(
                                format!("Failed to create parent directory: {}", parent.display()),
                                e,
                            )
                        })?;
                    }
                }

                self.extract_file_entry(entry, &entry_path, dest_dir)?;
                stats.files_processed += 1;
                stats.bytes_processed += entry.uncompressed_size;
            } else if entry.is_symlink() {
                self.extract_symlink_entry(entry, dest_dir)?;
                stats.files_processed += 1;
            }
        }

        stats.duration_ms = start_time.elapsed().as_millis() as u64;
        stats.calculate_speed();

        tracing::info!("Extraction completed: {} files, {} directories", 
                      stats.files_processed, stats.directories_processed);

        Ok(stats)
    }

    /// Extract specific files by path
    pub fn extract_files<P: AsRef<Path>>(&mut self, dest_dir: P, file_paths: &[String]) -> Result<ArchiveStats> {
        let dest_dir = dest_dir.as_ref();
        let start_time = Instant::now();
        let mut stats = ArchiveStats::default();

        tracing::info!("Extracting {} specific files to: {}", file_paths.len(), dest_dir.display());

        for file_path in file_paths {
            if let Some(entry) = self.get_entry(file_path).cloned() {
                let entry_path = dest_dir.join(&entry.path);

                // Ensure parent directory exists
                if let Some(parent) = entry_path.parent() {
                    if !parent.exists() {
                        fs::create_dir_all(parent).map_err(|e| {
                            RuzipError::io_error(
                                format!("Failed to create parent directory: {}", parent.display()),
                                e,
                            )
                        })?;
                    }
                }

                if entry.is_file() {
                    self.extract_file_entry(&entry, &entry_path, dest_dir)?;
                    stats.files_processed += 1;
                    stats.bytes_processed += entry.uncompressed_size;
                } else if entry.is_directory() {
                    fs::create_dir_all(&entry_path).map_err(|e| {
                        RuzipError::io_error(
                            format!("Failed to create directory: {}", entry_path.display()),
                            e,
                        )
                    })?;
                    stats.directories_processed += 1;
                } else if entry.is_symlink() {
                    self.extract_symlink_entry(&entry, dest_dir)?;
                    stats.files_processed += 1;
                }
            } else {
                tracing::warn!("File not found in archive: {}", file_path);
                stats.errors_encountered += 1;
            }
        }

        stats.duration_ms = start_time.elapsed().as_millis() as u64;
        stats.calculate_speed();

        Ok(stats)
    }

    /// Test archive integrity
    pub fn test_integrity(&mut self) -> Result<ArchiveStats> {
        let start_time = Instant::now();
        let mut stats = ArchiveStats::default();

        tracing::info!("Testing integrity of {} entries", self.entries.len());

        for entry in &self.entries {
            if entry.is_file() && entry.uncompressed_size > 0 {
                // Read and decompress file data without writing to disk
                self.reader.seek(SeekFrom::Start(entry.data_offset))?;
                
                let mut compressed_data = vec![0u8; entry.compressed_size as usize];
                self.reader.read_exact(&mut compressed_data).map_err(|e| {
                    RuzipError::io_error(
                        format!("Failed to read compressed data for: {}", entry.path),
                        e,
                    )
                })?;

                // Decompress to verify integrity
                let mut cursor = std::io::Cursor::new(&compressed_data);
                let mut output = Vec::new();
                
                let _decompress_stats = self.compression_engine.decompress(
                    &mut cursor,
                    &mut output,
                )?;

                // Verify decompressed size matches expected
                if output.len() != entry.uncompressed_size as usize {
                        return Err(RuzipError::entry_parse_error(
                            Some(entry.path.clone()),
                        format!(
                                "Decompressed size mismatch. Expected {}, got {}.",
                            entry.uncompressed_size,
                            output.len()
                        ),
                    ));
                }

                // Verify checksum if available
                if let Some(expected_checksum) = &entry.checksum {
                        let actual_checksum_bytes = self.calculate_data_checksum(&output);
                        // Convert checksums to hex strings for comparison in error messages
                        let expected_hex = expected_checksum.iter().map(|b| format!("{:02x}", b)).collect::<String>();
                        let actual_hex = actual_checksum_bytes.iter().map(|b| format!("{:02x}", b)).collect::<String>();

                        if actual_checksum_bytes != *expected_checksum {
                            return Err(RuzipError::checksum_mismatch(
                                entry.path.clone(),
                                expected_hex,
                                actual_hex,
                        ));
                    }
                }

                stats.files_processed += 1;
                stats.bytes_processed += entry.uncompressed_size;
            }
        }

        stats.duration_ms = start_time.elapsed().as_millis() as u64;
        stats.calculate_speed();

        tracing::info!("Integrity test completed: {} files verified", stats.files_processed);

        Ok(stats)
    }

    // Private implementation methods

    fn read_entry_table(&mut self) -> Result<()> {
        // Read entry table from the offset stored in header
        if self.header.entry_table_offset > 0 {
            self.reader.seek(SeekFrom::Start(self.header.entry_table_offset))?;
        } else {
            // Fallback to old behavior for compatibility
            let data_end = ArchiveHeader::SIZE as u64 + self.header.compressed_size;
            self.reader.seek(SeekFrom::Start(data_end))?;
        }

        // Try to read entry table
        let mut entry_data = Vec::new();
        self.reader.read_to_end(&mut entry_data)?;

        if !entry_data.is_empty() {
            self.entries = bincode::deserialize(&entry_data).map_err(|e| {
                RuzipError::entry_parse_error(
                    None, // Error is for the whole table, not a specific entry name
                    format!("Failed to deserialize entry table: {}", e),
                )
            })?;

            // Build entry map for fast lookups
            for (index, entry) in self.entries.iter().enumerate() {
                self.entry_map.insert(entry.path.clone(), index);
            }

            // Validate entry count matches header
            if self.entries.len() != self.header.entry_count as usize {
                return Err(RuzipError::header_parse_error(format!(
                    "Entry count mismatch. Header states {}, but found {} entries in table.",
                    self.header.entry_count,
                    self.entries.len()
                )));
            }
        }

        Ok(())
    }

    fn extract_file_entry(&mut self, entry: &FileEntry, dest_path: &Path, base_dir: &Path) -> Result<()> {
        // Validate path safety
        self.validate_extraction_path_with_base(dest_path, Some(base_dir))?;

        // Seek to file data
        self.reader.seek(SeekFrom::Start(entry.data_offset))?;

        // Create output file
        let output_file = File::create(dest_path).map_err(|e| {
            RuzipError::io_error(
                format!("Failed to create file: {}", dest_path.display()),
                e,
            )
        })?;
        let mut writer = BufWriter::new(output_file);

        // Decompress file data
        let mut compressed_reader = (&mut self.reader).take(entry.compressed_size);
        
        if entry.compression_method == 1 { // Store method
            std::io::copy(&mut compressed_reader, &mut writer).map_err(|e| {
                RuzipError::io_error("Failed to copy file data", e)
            })?;
        } else {
            // Use compression engine for decompression
            self.compression_engine.decompress(&mut compressed_reader, &mut writer)?;
        }

        writer.flush()?;
        drop(writer);

        // Restore metadata if requested
        self.restore_file_metadata(dest_path, &entry.metadata)?;

        Ok(())
    }

    fn extract_symlink_entry(&mut self, entry: &FileEntry, dest_dir: &Path) -> Result<()> {
        if let Some(target) = &entry.metadata.symlink_target {
            let link_path = dest_dir.join(&entry.path);
            
            // Validate path safety
            self.validate_extraction_path_with_base(&link_path, link_path.parent())?;

            #[cfg(unix)]
            {
                std::os::unix::fs::symlink(target, &link_path).map_err(|e| {
                    RuzipError::io_error(
                        format!("Failed to create symlink: {}", link_path.display()),
                        e,
                    )
                })?;
            }

            #[cfg(windows)]
            {
                // On Windows, try to create a directory symlink first, then file symlink
                if std::os::windows::fs::symlink_dir(target, &link_path).is_err() {
                    std::os::windows::fs::symlink_file(target, &link_path).map_err(|e| {
                        RuzipError::io_error(
                            format!("Failed to create symlink: {}", link_path.display()),
                            e,
                        )
                    })?;
                }
            }
        }

        Ok(())
    }

    fn validate_extraction_path_with_base(&self, path: &Path, base_dir: Option<&Path>) -> Result<()> {
        // Check for path traversal attacks using multiple validation approaches
        
        // Primary security check: component-based validation
        if path.components().any(|comp| comp.as_os_str() == "..") {
            return Err(RuzipError::invalid_input(
                format!("Invalid extraction path: contains '..' components '{}'", path.display()),
                Some(path.display().to_string()),
            ));
        }
        
        // Attempt to canonicalize paths for robust validation
        let normalized_path = path.canonicalize().unwrap_or_else(|_| {
            // If canonicalization fails (path doesn't exist yet), try to resolve manually
            self.resolve_path_manually(path)
        });
        
        // Secondary security check: normalized path validation
        if normalized_path.components().any(|comp| comp.as_os_str() == "..") {
            return Err(RuzipError::invalid_input(
                format!("Invalid extraction path: normalized path contains '..' components '{}'", normalized_path.display()),
                Some(normalized_path.display().to_string()),
            ));
        }
        
        // Tertiary security check: ensure normalized path stays within base directory (if provided)
        if let Some(base) = base_dir {
            // Ensure both paths are resolved consistently by canonicalizing the base first
            let canonical_base = base.canonicalize().unwrap_or_else(|_| base.to_path_buf());
            
            // For the file path, try to construct the expected canonical path
            let expected_canonical_path = canonical_base.join(
                path.strip_prefix(base).unwrap_or(path)
            );
            
            // Check if the manually constructed path is within the base
            if !expected_canonical_path.starts_with(&canonical_base) {
                return Err(RuzipError::invalid_input(
                    format!(
                        "Invalid extraction path: '{}' would escape base directory '{}'",
                        expected_canonical_path.display(),
                        canonical_base.display()
                    ),
                    Some(format!("path={}, base={}", expected_canonical_path.display(), canonical_base.display())),
                ));
            }
        }

        Ok(())
    }
    
    /// Manually resolve a path when canonicalize() fails (for non-existent paths)
    fn resolve_path_manually(&self, path: &Path) -> std::path::PathBuf {
        let mut resolved = std::path::PathBuf::new();
        
        for component in path.components() {
            match component {
                std::path::Component::Prefix(prefix) => resolved.push(prefix.as_os_str()),
                std::path::Component::RootDir => resolved.push("/"),
                std::path::Component::CurDir => {
                    // Skip current directory references
                }
                std::path::Component::ParentDir => {
                    // Handle parent directory references
                    if !resolved.pop() {
                        // If we can't go up further, this is a potential traversal
                        resolved.push("..");
                    }
                }
                std::path::Component::Normal(name) => {
                    resolved.push(name);
                }
            }
        }
        
        resolved
    }

    fn restore_file_metadata(&self, path: &Path, metadata: &crate::archive::FileMetadata) -> Result<()> {
        // Set timestamps
        if let Some(modified_time) = std::time::UNIX_EPOCH.checked_add(std::time::Duration::from_secs(metadata.modified_at)) {
            if let Some(accessed_time) = std::time::UNIX_EPOCH.checked_add(std::time::Duration::from_secs(metadata.accessed_at)) {
                let _ = filetime::set_file_times(path,
                    filetime::FileTime::from_system_time(accessed_time),
                    filetime::FileTime::from_system_time(modified_time));
            }
        }

        // Set permissions (Unix only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let perms = std::fs::Permissions::from_mode(metadata.permissions);
            let _ = std::fs::set_permissions(path, perms);
        }

        Ok(())
    }

    fn calculate_data_checksum(&self, data: &[u8]) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize().into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::{ArchiveWriter, ArchiveOptions};
    use std::io::Cursor;
    use tempfile::TempDir;

    fn create_test_archive() -> Vec<u8> {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        fs::write(&test_file, b"Hello, World!").unwrap();

        let buffer = Vec::new();
        let cursor = Cursor::new(buffer);
        let options = ArchiveOptions::default();
        let mut writer = ArchiveWriter::new(cursor, options).unwrap();

        writer.add_file(&test_file, Some("test.txt".to_string())).unwrap();
        
        let result = writer.finalize().unwrap();
        result.into_inner()
    }

    #[test]
    fn test_archive_reader_creation() {
        let archive_data = create_test_archive();
        let cursor = Cursor::new(&archive_data);
        
        let reader = ArchiveReader::new(cursor);
        match reader {
            Ok(_) => {},
            Err(e) => panic!("Failed to create reader: {}", e),
        }
    }

    #[test]
    fn test_archive_info() {
        let archive_data = create_test_archive();
        let cursor = Cursor::new(&archive_data);
        let reader = ArchiveReader::new(cursor).unwrap();
        
        let info = reader.info().unwrap();
        assert_eq!(info.entry_count, 1);
        assert!(info.uncompressed_size > 0);
    }

    #[test]
    fn test_list_entries() {
        let archive_data = create_test_archive();
        let cursor = Cursor::new(&archive_data);
        let reader = ArchiveReader::new(cursor).unwrap();
        
        let entries = reader.entries();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "test.txt");
        
        assert!(reader.contains("test.txt"));
        assert!(!reader.contains("nonexistent.txt"));
    }

    #[test]
    fn test_get_entry() {
        let archive_data = create_test_archive();
        let cursor = Cursor::new(&archive_data);
        let reader = ArchiveReader::new(cursor).unwrap();
        
        let entry = reader.get_entry("test.txt");
        assert!(entry.is_some());
        assert_eq!(entry.unwrap().path, "test.txt");
        
        let missing = reader.get_entry("missing.txt");
        assert!(missing.is_none());
    }

    #[test]
    fn test_extract_all() {
        let archive_data = create_test_archive();
        let cursor = Cursor::new(&archive_data);
        let mut reader = ArchiveReader::new(cursor).unwrap();
        
        let temp_dir = TempDir::new().unwrap();
        let stats = reader.extract_all(temp_dir.path()).unwrap();
        
        assert_eq!(stats.files_processed, 1);
        
        let extracted_file = temp_dir.path().join("test.txt");
        assert!(extracted_file.exists());
        
        let content = fs::read_to_string(&extracted_file).unwrap();
        assert_eq!(content, "Hello, World!");
    }

    #[test]
    fn test_extract_specific_files() {
        let archive_data = create_test_archive();
        let cursor = Cursor::new(&archive_data);
        let mut reader = ArchiveReader::new(cursor).unwrap();
        
        let temp_dir = TempDir::new().unwrap();
        let files_to_extract = vec!["test.txt".to_string()];
        let stats = reader.extract_files(temp_dir.path(), &files_to_extract).unwrap();
        
        assert_eq!(stats.files_processed, 1);
        
        let extracted_file = temp_dir.path().join("test.txt");
        assert!(extracted_file.exists());
    }

    #[test]
    fn test_integrity_test() {
        let archive_data = create_test_archive();
        let cursor = Cursor::new(&archive_data);
        let mut reader = ArchiveReader::new(cursor).unwrap();
        
        let stats = reader.test_integrity().unwrap();
        assert_eq!(stats.files_processed, 1);
        assert!(stats.bytes_processed > 0);
    }

    #[test]
    fn test_validate_extraction_path() {
        // Initialize test logging to capture our debug output
        let _ = crate::utils::logging::init_test_logging();
        
        let archive_data = create_test_archive();
        let cursor = Cursor::new(&archive_data);
        let reader = ArchiveReader::new(cursor).unwrap();
        
        // Use tempdir for realistic testing with actual filesystem paths
        let temp_dir = TempDir::new().unwrap();
        let temp_path = temp_dir.path();
        
        // Test 1: Valid normal path within temp directory
        let valid_path = temp_path.join("safe").join("file.txt");
        let result = reader.validate_extraction_path_with_base(&valid_path, Some(temp_path));
        assert!(result.is_ok(), "Valid path should pass validation: {:?}", result.err());
        
        // Test 2: Path with .. components (should fail)
        let dangerous_path = temp_path.join("safe").join("..").join("..").join("..").join("etc").join("passwd");
        let result = reader.validate_extraction_path_with_base(&dangerous_path, Some(temp_path));
        assert!(result.is_err(), "Path with .. components should fail validation");
        
        // Test 3: Relative path without .. (should pass)
        let relative_path = Path::new("safe/subfolder/file.txt");
        let result = reader.validate_extraction_path_with_base(relative_path, None);
        assert!(result.is_ok(), "Safe relative path should pass validation: {:?}", result.err());
        
        // Test 4: Path that becomes dangerous after normalization
        let tricky_path = temp_path.join("safe").join(".").join("subdir").join("..").join("..").join("..").join("etc").join("passwd");
        let result = reader.validate_extraction_path_with_base(&tricky_path, Some(temp_path));
        assert!(result.is_err(), "Tricky path should fail validation after normalization");
        
        println!("All path validation tests completed");
    }
}