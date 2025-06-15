//! Archive appender for extending existing RuZip archives
//!
//! This module provides functionality to append files to existing archives
//! without rebuilding the entire archive structure.

use crate::archive::{
    ArchiveReader, ArchiveWriter, ArchiveOptions, ArchiveStats, FileEntry, ArchiveHeader
};
use crate::compression::Compressor;
use crate::error::{Result, RuzipError};
use std::fs::{File, OpenOptions};
use std::io::{Write, Seek, SeekFrom, Read, BufReader, BufWriter};
use std::path::{Path, PathBuf};
use std::time::Instant;

/// Archive appender for extending existing archives
pub struct ArchiveAppender {
    archive_path: PathBuf,
    existing_entries: Vec<FileEntry>,
    existing_stats: ArchiveStats,
    options: ArchiveOptions,
    new_entries: Vec<FileEntry>,
    temp_file_path: PathBuf,
    current_data_offset: u64,
}

/// Information needed for append operations
#[derive(Debug, Clone)]
pub struct AppendInfo {
    pub entries: Vec<FileEntry>,
    pub data_end_offset: u64,
    pub total_uncompressed_size: u64,
    pub total_compressed_size: u64,
    pub entry_count: u64,
}

/// Compression information for progress display
#[derive(Debug)]
pub struct CompressionInfo {
    pub file_path: PathBuf,
    pub uncompressed_size: u64,
    pub compressed_size: u64,
    pub compression_ratio: f64,
}

impl CompressionInfo {
    pub fn compression_percentage(&self) -> f64 {
        if self.uncompressed_size > 0 {
            (1.0 - (self.compressed_size as f64 / self.uncompressed_size as f64)) * 100.0
        } else {
            0.0
        }
    }
}

impl ArchiveAppender {
    /// Create appender for existing archive
    pub fn from_existing<P: AsRef<Path>>(
        archive_path: P, 
        options: ArchiveOptions
    ) -> Result<Self> {
        let archive_path = archive_path.as_ref().to_path_buf();
        
        // Read existing archive
        let reader = ArchiveReader::<File>::open(&archive_path)?;
        let append_info = reader.get_append_info()?;
        
        // Create temporary file for atomic operation
        let temp_file_path = archive_path.with_extension("rzp.tmp");
        
        Ok(Self {
            archive_path,
            existing_entries: append_info.entries,
            existing_stats: ArchiveStats {
                files_processed: append_info.entry_count,
                bytes_processed: append_info.total_uncompressed_size,
                ..Default::default()
            },
            options,
            new_entries: Vec::new(),
            temp_file_path,
            current_data_offset: append_info.data_end_offset,
        })
    }
    
    /// Create appender for new archive
    pub fn for_new_archive<P: AsRef<Path>>(
        archive_path: P, 
        options: ArchiveOptions
    ) -> Result<Self> {
        let archive_path = archive_path.as_ref().to_path_buf();
        let temp_file_path = archive_path.with_extension("rzp.tmp");
        
        Ok(Self {
            archive_path,
            existing_entries: Vec::new(),
            existing_stats: ArchiveStats::default(),
            options,
            new_entries: Vec::new(),
            temp_file_path,
            current_data_offset: ArchiveHeader::SIZE as u64,
        })
    }
    
    /// Add file with compression info
    pub fn add_file<P: AsRef<Path>>(
        &mut self, 
        file_path: P, 
        archive_path: Option<String>
    ) -> Result<CompressionInfo> {
        let file_path = file_path.as_ref();
        
        // Get file metadata
        let metadata = file_path.metadata().map_err(|e| {
            RuzipError::io_error(
                format!("Failed to get metadata for: {}", file_path.display()),
                e,
            )
        })?;
        
        if !metadata.is_file() {
            return Err(RuzipError::invalid_input(
                format!("Path is not a file: {}", file_path.display()),
                None,
            ));
        }
        
        let uncompressed_size = metadata.len();
        
        // Determine archive path
        let entry_path = archive_path.unwrap_or_else(|| {
            FileEntry::normalize_path(file_path)
        });
        
        // Check for duplicate paths
        if self.existing_entries.iter().any(|e| e.path == entry_path) ||
           self.new_entries.iter().any(|e| e.path == entry_path) {
            return Err(RuzipError::invalid_input(
                format!("File already exists in archive: {}", entry_path),
                Some(entry_path),
            ));
        }
        
        // For now, estimate compressed size using temporary compression
        let compressed_size = self.estimate_compressed_size(file_path)?;
        
        // Create file entry
        let mut entry = FileEntry::from_path(
            file_path,
            entry_path.clone(),
            self.options.preserve_timestamps || self.options.preserve_permissions,
        )?;
        
        // Set data offset and sizes
        entry.data_offset = self.current_data_offset;
        entry.compressed_size = compressed_size;
        entry.uncompressed_size = uncompressed_size;
        entry.compression_method = match self.options.compression_method {
            crate::compression::CompressionMethod::Zstd => 0,
            #[cfg(feature = "brotli-support")]
            crate::compression::CompressionMethod::Brotli => 2,
            #[cfg(feature = "lz4-support")]
            crate::compression::CompressionMethod::Lz4 => 3,
            crate::compression::CompressionMethod::Store => 1,
        };
        
        // Update current offset for next file
        self.current_data_offset += compressed_size;
        
        // Store entry
        self.new_entries.push(entry);
        
        let compression_ratio = if uncompressed_size > 0 {
            compressed_size as f64 / uncompressed_size as f64
        } else {
            1.0
        };
        
        Ok(CompressionInfo {
            file_path: file_path.to_path_buf(),
            uncompressed_size,
            compressed_size,
            compression_ratio,
        })
    }
    
    /// Add directory recursively
    pub fn add_directory<P: AsRef<Path>>(
        &mut self, 
        dir_path: P, 
        recursive: bool
    ) -> Result<Vec<CompressionInfo>> {
        let dir_path = dir_path.as_ref();
        let mut compression_infos = Vec::new();
        
        if !dir_path.is_dir() {
            return Err(RuzipError::invalid_input(
                format!("Path is not a directory: {}", dir_path.display()),
                None,
            ));
        }
        
        if recursive {
            use walkdir::WalkDir;
            
            for entry in WalkDir::new(dir_path) {
                let entry = entry.map_err(|e| {
                    RuzipError::io_error("Failed to walk directory", e.into())
                })?;
                
                if entry.file_type().is_file() {
                    let relative_path = entry.path().strip_prefix(dir_path)
                        .map_err(|_| RuzipError::invalid_input(
                            "Failed to create relative path",
                            None,
                        ))?
                        .to_string_lossy()
                        .replace('\\', "/"); // Normalize path separators
                    
                    let compression_info = self.add_file(
                        entry.path(), 
                        Some(relative_path)
                    )?;
                    compression_infos.push(compression_info);
                }
            }
        } else {
            // Only add files in the immediate directory
            let entries = std::fs::read_dir(dir_path).map_err(|e| {
                RuzipError::io_error(
                    format!("Failed to read directory: {}", dir_path.display()),
                    e,
                )
            })?;
            
            for entry in entries {
                let entry = entry.map_err(|e| {
                    RuzipError::io_error("Failed to read directory entry", e)
                })?;
                
                if entry.file_type().map_err(|e| {
                    RuzipError::io_error("Failed to get file type", e)
                })?.is_file() {
                    let file_name = entry.file_name().to_string_lossy().to_string();
                    let compression_info = self.add_file(
                        entry.path(), 
                        Some(file_name)
                    )?;
                    compression_infos.push(compression_info);
                }
            }
        }
        
        Ok(compression_infos)
    }
    
    /// Finalize archive with updated entry table and header
    pub fn finalize(self) -> Result<ArchiveStats> {
        let start_time = Instant::now();
        
        if self.archive_path.exists() {
            // Append to existing archive
            self.finalize_append()
        } else {
            // Create new archive
            self.finalize_new()
        }
        .map(|mut stats| {
            stats.duration_ms = start_time.elapsed().as_millis() as u64;
            stats.calculate_speed();
            stats
        })
    }
    
    // Private implementation methods
    
    fn estimate_compressed_size(&self, file_path: &Path) -> Result<u64> {
        // For now, use a simple heuristic based on file size and compression level
        let file_size = file_path.metadata()?.len();
        
        let compression_ratio = match self.options.compression_method {
            crate::compression::CompressionMethod::Store => 1.0,
            crate::compression::CompressionMethod::Zstd => {
                // Estimate based on compression level
                match self.options.compression_level.value() {
                    1..=3 => 0.7,   // Light compression
                    4..=6 => 0.6,   // Medium compression
                    7..=9 => 0.5,   // High compression
                    _ => 0.6,       // Default
                }
            }
            #[cfg(feature = "brotli-support")]
            crate::compression::CompressionMethod::Brotli => {
                // Brotli typically achieves better compression than ZSTD
                match self.options.compression_level.value() {
                    1..=3 => 0.6,   // Light compression
                    4..=6 => 0.5,   // Medium compression
                    7..=9 => 0.4,   // High compression
                    _ => 0.5,       // Default
                }
            }
            #[cfg(feature = "lz4-support")]
            crate::compression::CompressionMethod::Lz4 => {
                // LZ4 is faster but achieves lower compression ratios
                match self.options.compression_level.value() {
                    1..=3 => 0.8,   // Light compression
                    4..=6 => 0.7,   // Medium compression
                    7..=9 => 0.6,   // High compression
                    _ => 0.7,       // Default
                }
            }
        };
        
        Ok((file_size as f64 * compression_ratio) as u64)
    }
    
    fn finalize_new(&self) -> Result<ArchiveStats> {
        // Create new archive using ArchiveWriter
        let temp_file = File::create(&self.temp_file_path)?;
        let mut writer = ArchiveWriter::new(temp_file, self.options.clone())?;
        
        // Add all new files
        for entry in &self.new_entries {
            // Reconstruct original file path from entry
            let original_path = PathBuf::from(&entry.path);
            writer.add_file(&original_path, Some(entry.path.clone()))?;
        }
        
        let stats = writer.stats().clone();
        let _final_file = writer.finalize()?;
        
        // Atomically replace original file
        std::fs::rename(&self.temp_file_path, &self.archive_path)?;
        
        Ok(stats)
    }
    
    fn finalize_append(&self) -> Result<ArchiveStats> {
        // Copy existing archive to temp file and append new data
        std::fs::copy(&self.archive_path, &self.temp_file_path)?;
        
        let mut temp_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&self.temp_file_path)?;
        
        // Seek to end of existing data (before entry table)
        let data_end_offset = self.current_data_offset - self.calculate_new_data_size();
        temp_file.seek(SeekFrom::Start(data_end_offset))?;
        
        // Append new file data
        self.append_new_file_data(&mut temp_file)?;
        
        // Write updated entry table
        let all_entries: Vec<FileEntry> = self.existing_entries.iter()
            .chain(self.new_entries.iter())
            .cloned()
            .collect();
        
        let entry_table_offset = temp_file.seek(SeekFrom::Current(0))?;
        let entry_table_data = bincode::serialize(&all_entries).map_err(|e| {
            RuzipError::archive_format_error(
                "Failed to serialize entry table",
                Some(e.to_string()),
            )
        })?;
        temp_file.write_all(&entry_table_data)?;
        
        // Update header
        self.update_header(&mut temp_file, &all_entries, entry_table_offset)?;
        
        temp_file.flush()?;
        drop(temp_file);
        
        // Atomically replace original file
        std::fs::rename(&self.temp_file_path, &self.archive_path)?;
        
        // Calculate final stats
        let mut stats = self.existing_stats.clone();
        stats.files_processed += self.new_entries.len() as u64;
        stats.bytes_processed += self.new_entries.iter()
            .map(|e| e.uncompressed_size)
            .sum::<u64>();
        
        Ok(stats)
    }
    
    fn calculate_new_data_size(&self) -> u64 {
        self.new_entries.iter()
            .map(|e| e.compressed_size)
            .sum()
    }
    
    fn append_new_file_data(&self, temp_file: &mut File) -> Result<()> {
        use crate::compression::CompressionEngine;
        
        let compression_engine = CompressionEngine::new()
            .with_method(self.options.compression_method.clone());
        
        for entry in &self.new_entries {
            // Read source file
            let source_file = File::open(&entry.path)?;
            let mut reader = BufReader::new(source_file);
            
            if entry.compression_method == 1 { // Store method
                std::io::copy(&mut reader, &mut *temp_file)?;
            } else {
                // Compress and write
                let mut writer = BufWriter::new(&mut *temp_file);
                compression_engine.compress(&mut reader, &mut writer, self.options.compression_level)?;
                writer.flush()?;
            }
        }
        
        Ok(())
    }
    
    fn update_header(&self, temp_file: &mut File, all_entries: &[FileEntry], entry_table_offset: u64) -> Result<()> {
        // Calculate new totals
        let total_uncompressed: u64 = all_entries.iter().map(|e| e.uncompressed_size).sum();
        let total_compressed: u64 = all_entries.iter().map(|e| e.compressed_size).sum();
        
        // Read existing header
        temp_file.seek(SeekFrom::Start(0))?;
        let mut header = ArchiveHeader::deserialize(&mut *temp_file)?;
        
        // Update header fields
        header.entry_count = all_entries.len() as u64;
        header.uncompressed_size = total_uncompressed;
        header.compressed_size = total_compressed;
        header.entry_table_offset = entry_table_offset;
        header.modified_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        
        // Write updated header
        temp_file.seek(SeekFrom::Start(0))?;
        header.serialize(&mut *temp_file)?;
        
        Ok(())
    }
}

// Extension trait for ArchiveReader to support append operations
impl<R: Read + Seek> ArchiveReader<R> {
    /// Get information needed for append operations
    pub fn get_append_info(&self) -> Result<AppendInfo> {
        let info = self.info()?;
        Ok(AppendInfo {
            entries: self.entries().to_vec(),
            data_end_offset: info.compressed_size + crate::archive::ArchiveHeader::SIZE as u64,
            total_uncompressed_size: info.uncompressed_size,
            total_compressed_size: info.compressed_size,
            entry_count: info.entry_count,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::archive::ArchiveOptions;
    use tempfile::TempDir;
    use std::fs;

    #[test]
    fn test_appender_for_new_archive() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("test.rzp");
        let options = ArchiveOptions::default();
        
        let appender = ArchiveAppender::for_new_archive(&archive_path, options);
        assert!(appender.is_ok());
        
        let appender = appender.unwrap();
        assert_eq!(appender.existing_entries.len(), 0);
        assert_eq!(appender.new_entries.len(), 0);
    }
    
    #[test]
    fn test_add_file_to_new_archive() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("test.rzp");
        let test_file = temp_dir.path().join("test.txt");
        
        fs::write(&test_file, b"Hello, World!").unwrap();
        
        let options = ArchiveOptions::default();
        let mut appender = ArchiveAppender::for_new_archive(&archive_path, options).unwrap();
        
        let compression_info = appender.add_file(&test_file, None).unwrap();
        assert_eq!(compression_info.uncompressed_size, 13);
        assert!(compression_info.compressed_size > 0);
        assert_eq!(appender.new_entries.len(), 1);
    }
    
    #[test]
    fn test_compression_info_calculations() {
        let compression_info = CompressionInfo {
            file_path: PathBuf::from("test.txt"),
            uncompressed_size: 1000,
            compressed_size: 600,
            compression_ratio: 0.6,
        };
        
        assert_eq!(compression_info.compression_percentage(), 40.0);
    }
    
    #[test]
    fn test_duplicate_file_detection() {
        let temp_dir = TempDir::new().unwrap();
        let archive_path = temp_dir.path().join("test.rzp");
        let test_file = temp_dir.path().join("test.txt");
        
        fs::write(&test_file, b"Hello, World!").unwrap();
        
        let options = ArchiveOptions::default();
        let mut appender = ArchiveAppender::for_new_archive(&archive_path, options).unwrap();
        
        // First add should succeed
        assert!(appender.add_file(&test_file, Some("test.txt".to_string())).is_ok());
        
        // Second add with same path should fail
        assert!(appender.add_file(&test_file, Some("test.txt".to_string())).is_err());
    }
}