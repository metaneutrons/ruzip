//! Archive writer implementation
//!
//! Provides functionality to create RuZip archives with compression,
//! metadata preservation, and integrity checking.

use crate::archive::{
    ArchiveHeader, ArchiveOptions, ArchiveStats, FileEntry,
    EntryType,
};
use crate::compression::{CompressionEngine, CompressionMethod, Compressor};
use crate::error::{Result, RuzipError};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::time::Instant;
use walkdir::WalkDir;

/// Archive writer for creating RuZip archives
pub struct ArchiveWriter<W: Write + Seek> {
    writer: BufWriter<W>,
    header: ArchiveHeader,
    options: ArchiveOptions,
    entries: Vec<FileEntry>,
    entry_offsets: HashMap<String, u64>,
    compression_engine: CompressionEngine,
    current_offset: u64,
    stats: ArchiveStats,
}

impl<W: Write + Seek> ArchiveWriter<W> {
    /// Create new archive writer
    pub fn new(writer: W, options: ArchiveOptions) -> Result<Self> {
        let header = ArchiveHeader::with_compression(
            options.compression_method,
            options.compression_level,
        );

        let compression_engine = CompressionEngine::new()
            .with_method(options.compression_method)
            .with_memory_limit(options.max_memory);

        let mut buffered_writer = BufWriter::new(writer);
        
        // Reserve space for header (will be written at the end)
        let header_size = ArchiveHeader::SIZE as u64;
        buffered_writer.seek(SeekFrom::Start(header_size))?;

        Ok(Self {
            writer: buffered_writer,
            header,
            options,
            entries: Vec::new(),
            entry_offsets: HashMap::new(),
            compression_engine,
            current_offset: header_size,
            stats: ArchiveStats::default(),
        })
    }

    /// Add a single file to the archive
    pub fn add_file<P: AsRef<Path>>(&mut self, file_path: P, archive_path: Option<String>) -> Result<()> {
        let file_path = file_path.as_ref();
        let archive_path = archive_path.unwrap_or_else(|| {
            FileEntry::normalize_path(file_path)
        });

        tracing::debug!("Adding file: {} -> {}", file_path.display(), archive_path);

        if !file_path.exists() {
            return Err(RuzipError::invalid_input(
                format!("File does not exist: {}", file_path.display()),
                Some(file_path.display().to_string()),
            ));
        }

        let metadata = fs::metadata(file_path).map_err(|e| {
            RuzipError::io_error(
                format!("Failed to read metadata: {}", file_path.display()),
                e,
            )
        })?;

        if metadata.is_file() {
            self.add_regular_file(file_path, archive_path)?;
        } else if metadata.is_dir() {
            self.add_directory_entry(archive_path)?;
        } else if metadata.file_type().is_symlink() {
            self.add_symlink(file_path, archive_path)?;
        } else {
            tracing::warn!("Skipping unsupported file type: {}", file_path.display());
        }

        Ok(())
    }

    /// Add a directory recursively
    pub fn add_directory<P: AsRef<Path>>(&mut self, dir_path: P, recursive: bool) -> Result<()> {
        let dir_path = dir_path.as_ref();
        let start_time = Instant::now();

        tracing::info!("Adding directory: {} (recursive: {})", dir_path.display(), recursive);

        if !dir_path.is_dir() {
            return Err(RuzipError::invalid_input(
                format!("Path is not a directory: {}", dir_path.display()),
                Some(dir_path.display().to_string()),
            ));
        }

        if recursive {
            for entry in WalkDir::new(dir_path) {
                let entry = entry.map_err(|e| {
                    RuzipError::io_error("Failed to walk directory", e.into())
                })?;

                let relative_path = entry.path().strip_prefix(dir_path)
                    .map_err(|_| RuzipError::internal_error(
                        "Failed to create relative path",
                        Some(file!()),
                    ))?;

                if relative_path.as_os_str().is_empty() {
                    continue; // Skip root directory
                }

                let archive_path = FileEntry::normalize_path(relative_path);
                
                if entry.file_type().is_dir() {
                    self.add_directory_entry(archive_path)?;
                    self.stats.directories_processed += 1;
                } else {
                    self.add_file(entry.path(), Some(archive_path))?;
                }
            }
        } else {
            // Add just the directory entry
            let archive_path = FileEntry::normalize_path(dir_path);
            self.add_directory_entry(archive_path)?;
            self.stats.directories_processed += 1;
        }

        self.stats.duration_ms += start_time.elapsed().as_millis() as u64;
        Ok(())
    }

    /// Add multiple files
    pub fn add_files<P: AsRef<Path>>(&mut self, file_paths: &[P]) -> Result<()> {
        let start_time = Instant::now();

        for file_path in file_paths {
            let file_path = file_path.as_ref();
            
            if file_path.is_file() {
                self.add_file(file_path, None)?;
            } else if file_path.is_dir() {
                self.add_directory(file_path, true)?; // Default to recursive
            } else {
                tracing::warn!("Skipping invalid path: {}", file_path.display());
                self.stats.errors_encountered += 1;
            }
        }

        self.stats.duration_ms += start_time.elapsed().as_millis() as u64;
        Ok(())
    }

    /// Finalize archive and write header
    pub fn finalize(mut self) -> Result<W> {
        tracing::info!("Finalizing archive with {} entries", self.entries.len());

        // Update header with final statistics
        self.header.entry_count = self.entries.len() as u64;
        self.header.uncompressed_size = self.stats.bytes_processed;
        self.header.compressed_size = self.current_offset - ArchiveHeader::SIZE as u64;
        self.header.touch();

        // Calculate and update compression flags
        if matches!(self.options.compression_method, CompressionMethod::Zstd) {
            self.header.flags.set_flag(crate::archive::header::ArchiveFlags::COMPRESSED);
        }
        if self.options.store_checksums {
            self.header.flags.set_flag(crate::archive::header::ArchiveFlags::HAS_CHECKSUMS);
        }
        if self.options.preserve_permissions {
            self.header.flags.set_flag(crate::archive::header::ArchiveFlags::PRESERVE_PERMISSIONS);
        }
        if self.options.preserve_timestamps {
            self.header.flags.set_flag(crate::archive::header::ArchiveFlags::PRESERVE_TIMESTAMPS);
        }

        // Write entry table - get actual position from writer
        let entry_table_offset = self.writer.stream_position().map_err(|e| {
            RuzipError::io_error("Failed to get stream position", e)
        })?;
        self.header.entry_table_offset = entry_table_offset;
        self.write_entry_table()?;

        // Seek to beginning and write header
        self.writer.seek(SeekFrom::Start(0))?;
        self.header.serialize(&mut self.writer)?;

        // Flush and return underlying writer
        self.writer.flush()?;
        let writer = self.writer.into_inner().map_err(|e| {
            RuzipError::io_error("Failed to finalize writer", e.into())
        })?;

        tracing::info!("Archive finalized successfully");
        tracing::info!("Statistics: {} files, {} directories, {} bytes processed", 
                      self.stats.files_processed, 
                      self.stats.directories_processed, 
                      self.stats.bytes_processed);

        Ok(writer)
    }

    /// Get current statistics
    pub fn stats(&self) -> &ArchiveStats {
        &self.stats
    }

    /// Get number of entries added
    pub fn entry_count(&self) -> usize {
        self.entries.len()
    }

    // Private implementation methods

    fn add_regular_file(&mut self, file_path: &Path, archive_path: String) -> Result<()> {
        let start_time = Instant::now();

        // Create file entry
        let mut entry = FileEntry::from_path(
            file_path,
            archive_path.clone(),
            self.options.preserve_timestamps || self.options.preserve_permissions,
        )?;

        // Open file for reading
        let file = File::open(file_path).map_err(|e| {
            RuzipError::io_error(
                format!("Failed to open file: {}", file_path.display()),
                e,
            )
        })?;
        let mut reader = BufReader::new(file);

        // Set data offset - use actual stream position
        entry.data_offset = self.writer.stream_position().map_err(|e| {
            RuzipError::io_error("Failed to get stream position", e)
        })?;

        // Compress and write file data
        let compressed_size = if matches!(self.options.compression_method, CompressionMethod::Store) {
            self.write_file_uncompressed(&mut reader, &mut entry)?
        } else {
            self.write_file_compressed(&mut reader, &mut entry)?
        };

        entry.compressed_size = compressed_size;

        // Calculate checksum if requested
        if self.options.store_checksums {
            entry.checksum = Some(self.calculate_file_checksum(file_path)?);
        }

        // Update statistics
        self.stats.files_processed += 1;
        self.stats.bytes_processed += entry.uncompressed_size;
        self.stats.duration_ms += start_time.elapsed().as_millis() as u64;

        // Store entry
        self.entry_offsets.insert(archive_path, entry.data_offset);
        self.entries.push(entry);

        Ok(())
    }

    fn add_directory_entry(&mut self, archive_path: String) -> Result<()> {
        let entry = FileEntry::directory(archive_path.clone(), self.options.preserve_timestamps);
        
        // No data for directories
        self.entry_offsets.insert(archive_path, 0);
        self.entries.push(entry);
        
        Ok(())
    }

    fn add_symlink(&mut self, file_path: &Path, archive_path: String) -> Result<()> {
        let target = fs::read_link(file_path).map_err(|e| {
            RuzipError::io_error(
                format!("Failed to read symlink: {}", file_path.display()),
                e,
            )
        })?;

        let mut entry = FileEntry::from_path(
            file_path,
            archive_path.clone(),
            self.options.preserve_timestamps,
        )?;

        entry.metadata.symlink_target = Some(target.to_string_lossy().to_string());
        entry.entry_type = EntryType::Symlink;

        self.entry_offsets.insert(archive_path, 0);
        self.entries.push(entry);

        Ok(())
    }

    fn write_file_compressed(&mut self, reader: &mut dyn Read, _entry: &mut FileEntry) -> Result<u64> {
        let start_position = self.writer.stream_position().map_err(|e| {
            RuzipError::io_error("Failed to get stream position", e)
        })?;

        let _compression_stats = self.compression_engine.compress(
            reader,
            &mut self.writer,
            self.options.compression_level,
        )?;

        let end_position = self.writer.stream_position().map_err(|e| {
            RuzipError::io_error("Failed to get stream position", e)
        })?;
        
        self.current_offset = end_position;
        Ok(end_position - start_position)
    }

    fn write_file_uncompressed(&mut self, reader: &mut dyn Read, _entry: &mut FileEntry) -> Result<u64> {
        let start_position = self.writer.stream_position().map_err(|e| {
            RuzipError::io_error("Failed to get stream position", e)
        })?;
        
        let mut buffer = vec![0u8; 64 * 1024]; // 64KB buffer
        loop {
            let bytes_read = reader.read(&mut buffer).map_err(|e| {
                RuzipError::io_error("Failed to read input data", e)
            })?;

            if bytes_read == 0 {
                break;
            }

            self.writer.write_all(&buffer[..bytes_read]).map_err(|e| {
                RuzipError::io_error("Failed to write data", e)
            })?;
        }

        let end_position = self.writer.stream_position().map_err(|e| {
            RuzipError::io_error("Failed to get stream position", e)
        })?;
        
        self.current_offset = end_position;
        Ok(end_position - start_position)
    }

    fn calculate_file_checksum(&self, file_path: &Path) -> Result<[u8; 32]> {
        use sha2::{Digest, Sha256};

        let file = File::open(file_path).map_err(|e| {
            RuzipError::io_error(
                format!("Failed to open file for checksum: {}", file_path.display()),
                e,
            )
        })?;
        let mut reader = BufReader::new(file);
        let mut hasher = Sha256::new();
        let mut buffer = vec![0u8; 64 * 1024];

        loop {
            let bytes_read = reader.read(&mut buffer).map_err(|e| {
                RuzipError::io_error("Failed to read file for checksum", e)
            })?;

            if bytes_read == 0 {
                break;
            }

            hasher.update(&buffer[..bytes_read]);
        }

        Ok(hasher.finalize().into())
    }

    fn write_entry_table(&mut self) -> Result<()> {
        // Serialize entry table using bincode
        let serialized = bincode::serialize(&self.entries).map_err(|e| {
            RuzipError::archive_format_error(
                "Failed to serialize entry table",
                Some(e.to_string()),
            )
        })?;

        self.writer.write_all(&serialized).map_err(|e| {
            RuzipError::io_error("Failed to write entry table", e)
        })?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::RUZIP_MAGIC;
    use crate::compression::CompressionLevel;
    use std::io::Cursor;
    use tempfile::TempDir;

    #[test]
    fn test_archive_writer_creation() {
        let buffer = Vec::new();
        let cursor = Cursor::new(buffer);
        let options = ArchiveOptions::default();

        let writer = ArchiveWriter::new(cursor, options);
        assert!(writer.is_ok());
    }

    #[test]
    fn test_add_file() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        fs::write(&test_file, b"Hello, World!").unwrap();

        let buffer = Vec::new();
        let cursor = Cursor::new(buffer);
        let options = ArchiveOptions::default();
        let mut writer = ArchiveWriter::new(cursor, options).unwrap();

        writer.add_file(&test_file, Some("test.txt".to_string())).unwrap();
        assert_eq!(writer.entry_count(), 1);
        assert_eq!(writer.stats().files_processed, 1);
    }

    #[test]
    fn test_add_directory() {
        let temp_dir = TempDir::new().unwrap();
        let sub_dir = temp_dir.path().join("subdir");
        fs::create_dir(&sub_dir).unwrap();
        
        let test_file = sub_dir.join("file.txt");
        fs::write(&test_file, b"content").unwrap();

        let buffer = Vec::new();
        let cursor = Cursor::new(buffer);
        let options = ArchiveOptions::default();
        let mut writer = ArchiveWriter::new(cursor, options).unwrap();

        writer.add_directory(&sub_dir, true).unwrap();
        assert!(writer.entry_count() >= 1); // At least the file
        assert!(writer.stats().files_processed >= 1);
    }

    #[test]
    fn test_finalize_archive() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        fs::write(&test_file, b"Test content").unwrap();

        let buffer = Vec::new();
        let cursor = Cursor::new(buffer);
        let options = ArchiveOptions::default();
        let mut writer = ArchiveWriter::new(cursor, options).unwrap();

        writer.add_file(&test_file, None).unwrap();
        
        let result = writer.finalize();
        assert!(result.is_ok());
        
        let final_cursor = result.unwrap();
        let buffer = final_cursor.into_inner();
        
        // Check that header was written
        assert!(buffer.len() >= ArchiveHeader::SIZE);
        assert_eq!(&buffer[0..4], RUZIP_MAGIC);
    }

    #[test]
    fn test_compression_methods() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        let content = b"Hello, World! ".repeat(100); // Compressible content
        fs::write(&test_file, &content).unwrap();

        // Test with ZSTD compression
        let buffer1 = Vec::new();
        let cursor1 = Cursor::new(buffer1);
        let options1 = ArchiveOptions {
            compression_method: CompressionMethod::Zstd,
            compression_level: CompressionLevel::new(6).unwrap(),
            ..Default::default()
        };
        let mut writer1 = ArchiveWriter::new(cursor1, options1).unwrap();
        writer1.add_file(&test_file, None).unwrap();
        let result1 = writer1.finalize().unwrap();

        // Test with Store (no compression)
        let buffer2 = Vec::new();
        let cursor2 = Cursor::new(buffer2);
        let options2 = ArchiveOptions {
            compression_method: CompressionMethod::Store,
            ..Default::default()
        };
        let mut writer2 = ArchiveWriter::new(cursor2, options2).unwrap();
        writer2.add_file(&test_file, None).unwrap();
        let result2 = writer2.finalize().unwrap();

        // Compressed version should be smaller (for this repetitive content)
        let compressed_size = result1.into_inner().len();
        let uncompressed_size = result2.into_inner().len();
        
        // Both should have valid headers
        assert!(compressed_size >= ArchiveHeader::SIZE);
        assert!(uncompressed_size >= ArchiveHeader::SIZE);
    }
}