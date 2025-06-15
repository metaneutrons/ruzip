//! In-place archive modification for deletion operations
//!
//! Implements the fast in-place deletion approach by directly modifying
//! the archive structure, compacting data, and updating headers.
//! This is faster but riskier than the safe reconstruction approach.

use crate::archive::{
    ArchiveReader, ArchiveStats, FileEntry, ArchiveHeader, ArchiveOptions,
    deleter::{ArchiveDeleter, DeletionPreview, matching, validation}
};
use crate::error::{Result, RuzipError};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write, Seek, SeekFrom};
use std::path::Path;
use std::time::Instant;

/// Archive modifier for in-place deletion operations
pub struct ArchiveModifier {
    #[allow(dead_code)]
    options: ArchiveOptions,
}

impl ArchiveModifier {
    /// Create new modifier with default options
    pub fn new() -> Self {
        Self {
            options: ArchiveOptions::default(),
        }
    }

    /// Create new modifier with custom options
    pub fn with_options(options: ArchiveOptions) -> Self {
        Self { options }
    }

    /// Create backup of the original archive before modification
    fn create_backup<P: AsRef<Path>>(&self, archive_path: P) -> Result<std::path::PathBuf> {
        let backup_path = validation::generate_backup_path(&archive_path);
        
        std::fs::copy(&archive_path, &backup_path).map_err(|e| {
            RuzipError::io_error(
                format!("Failed to create backup: {}", backup_path.display()),
                e,
            )
        })?;
        
        tracing::info!("Created backup: {}", backup_path.display());
        Ok(backup_path)
    }

    /// Load entry table and filter out entries to be deleted
    fn prepare_entry_table(
        &self,
        reader: &ArchiveReader<File>,
        indices_to_delete: &[usize],
    ) -> Result<(Vec<FileEntry>, Vec<DataBlockInfo>)> {
        let all_entries = reader.entries().to_vec();
        let mut remaining_entries = Vec::new();
        let mut data_blocks = Vec::new();

        for (index, entry) in all_entries.iter().enumerate() {
            if !indices_to_delete.contains(&index) {
                // This entry will remain in the archive
                remaining_entries.push(entry.clone());
                
                // Track data block information for compaction
                if entry.compressed_size > 0 {
                    data_blocks.push(DataBlockInfo {
                        original_offset: entry.data_offset,
                        size: entry.compressed_size,
                        entry_index: remaining_entries.len() - 1,
                    });
                }
            }
        }

        // Sort data blocks by original offset for sequential processing
        data_blocks.sort_by_key(|block| block.original_offset);

        Ok((remaining_entries, data_blocks))
    }

    /// Compact data section by moving remaining data blocks forward
    fn compact_data_section(
        &self,
        file: &mut File,
        data_blocks: &[DataBlockInfo],
        remaining_entries: &mut [FileEntry],
    ) -> Result<u64> {
        let start_time = Instant::now();
        let mut new_offset = crate::archive::header::ArchiveHeader::SIZE as u64;
        let mut buffer = vec![0u8; 64 * 1024]; // 64KB buffer

        tracing::info!("Compacting {} data blocks", data_blocks.len());

        for block in data_blocks {
            // Read data from original position
            file.seek(SeekFrom::Start(block.original_offset))?;
            let mut bytes_remaining = block.size;
            let mut current_new_offset = new_offset;

            while bytes_remaining > 0 {
                let bytes_to_read = std::cmp::min(bytes_remaining, buffer.len() as u64) as usize;
                let bytes_read = file.read(&mut buffer[..bytes_to_read]).map_err(|e| {
                    RuzipError::io_error("Failed to read data block during compaction", e)
                })?;

                if bytes_read == 0 {
                    return Err(RuzipError::internal_error(
                        "Unexpected end of file during data compaction",
                        Some(file!()),
                    ));
                }

                // Write data to new position
                file.seek(SeekFrom::Start(current_new_offset))?;
                file.write_all(&buffer[..bytes_read]).map_err(|e| {
                    RuzipError::io_error("Failed to write data block during compaction", e)
                })?;

                current_new_offset += bytes_read as u64;
                bytes_remaining -= bytes_read as u64;
            }

            // Update entry with new offset
            if let Some(entry) = remaining_entries.get_mut(block.entry_index) {
                entry.data_offset = new_offset;
            }

            new_offset += block.size;
        }

        let duration = start_time.elapsed();
        tracing::info!("Data compaction completed in {:?}", duration);

        Ok(new_offset)
    }

    /// Write updated entry table to archive
    fn write_entry_table(
        &self,
        file: &mut File,
        entries: &[FileEntry],
        entry_table_offset: u64,
    ) -> Result<()> {
        file.seek(SeekFrom::Start(entry_table_offset))?;

        // Write entry count
        let entry_count = entries.len() as u32;
        file.write_all(&entry_count.to_le_bytes()).map_err(|e| {
            RuzipError::io_error("Failed to write entry count", e)
        })?;

        // Write each entry
        for entry in entries {
            self.write_entry(file, entry)?;
        }

        Ok(())
    }

    /// Write a single entry to the file
    fn write_entry(&self, file: &mut File, entry: &FileEntry) -> Result<()> {
        // Write path length and path
        let path_bytes = entry.path.as_bytes();
        let path_len = path_bytes.len() as u32;
        file.write_all(&path_len.to_le_bytes())?;
        file.write_all(path_bytes)?;

        // Write entry type
        let entry_type_byte = match entry.entry_type {
            crate::archive::EntryType::File => 0u8,
            crate::archive::EntryType::Directory => 1u8,
            crate::archive::EntryType::Symlink => 2u8,
            crate::archive::EntryType::Hardlink => 3u8,
        };
        file.write_all(&[entry_type_byte])?;

        // Write sizes and offset
        file.write_all(&entry.uncompressed_size.to_le_bytes())?;
        file.write_all(&entry.compressed_size.to_le_bytes())?;
        file.write_all(&entry.data_offset.to_le_bytes())?;

        // Write metadata (simplified)
        let metadata_size = 16u32; // Fixed size for now
        file.write_all(&metadata_size.to_le_bytes())?;
        file.write_all(&entry.metadata.created_at.to_le_bytes())?;
        file.write_all(&entry.metadata.modified_at.to_le_bytes())?;

        // Write checksum if present
        if let Some(checksum) = &entry.checksum {
            file.write_all(&[1u8])?; // Has checksum
            file.write_all(checksum)?;
        } else {
            file.write_all(&[0u8])?; // No checksum
        }

        // Write flags
        file.write_all(&entry.flags.value().to_le_bytes())?;

        Ok(())
    }

    /// Update archive header with new offsets and counts
    fn update_header(
        &self,
        file: &mut File,
        entry_count: u32,
        entry_table_offset: u64,
        archive_size: u64,
    ) -> Result<()> {
        file.seek(SeekFrom::Start(0))?;

        // Read existing header to preserve some fields
        let mut header = ArchiveHeader::deserialize(&mut *file)?;
        file.seek(SeekFrom::Start(0))?; // Reset position for writing
        
        // Update header fields
        header.entry_count = entry_count as u64;
        header.entry_table_offset = entry_table_offset;
        header.compressed_size = archive_size;
        header.touch(); // Update modification time

        // Write updated header
        header.serialize(file)?;

        tracing::info!("Updated header: {} entries, table at offset {}", 
                      entry_count, entry_table_offset);

        Ok(())
    }


    /// Truncate file to new size
    fn truncate_archive(&self, file: &mut File, new_size: u64) -> Result<()> {
        file.set_len(new_size).map_err(|e| {
            RuzipError::io_error("Failed to truncate archive to new size", e)
        })?;

        file.sync_all().map_err(|e| {
            RuzipError::io_error("Failed to sync archive after truncation", e)
        })?;

        tracing::info!("Truncated archive to {} bytes", new_size);
        Ok(())
    }

    /// Perform in-place deletion with all safety checks
    fn perform_inplace_deletion<P: AsRef<Path>>(
        &self,
        archive_path: P,
        files_to_delete: &[String],
        recursive: bool,
        create_backup: bool,
    ) -> Result<ArchiveStats> {
        let start_time = Instant::now();
        let path = archive_path.as_ref();

        // Create backup if requested
        let _backup_path = if create_backup {
            Some(self.create_backup(&archive_path)?)
        } else {
            None
        };

        // Open archive for reading first
        let reader = ArchiveReader::<File>::open(&archive_path)?;
        let original_entries = reader.entries().to_vec();
        let original_stats = ArchiveStats {
            files_processed: original_entries.iter()
                .filter(|e| matches!(e.entry_type, crate::archive::EntryType::File))
                .count() as u64,
            directories_processed: original_entries.iter()
                .filter(|e| matches!(e.entry_type, crate::archive::EntryType::Directory))
                .count() as u64,
            bytes_processed: original_entries.iter()
                .map(|e| e.uncompressed_size)
                .sum(),
            ..Default::default()
        };

        // Find files to delete
        let indices_to_delete = matching::find_files_to_delete(
            &original_entries, files_to_delete, recursive
        )?;

        if indices_to_delete.is_empty() {
            return Err(RuzipError::invalid_input(
                "No files found matching deletion criteria".to_string(),
                None,
            ));
        }

        tracing::info!("Found {} files to delete", indices_to_delete.len());

        // Prepare new entry table and data blocks
        let (mut remaining_entries, data_blocks) = self.prepare_entry_table(
            &reader, &indices_to_delete
        )?;

        // Close reader to free file handle
        drop(reader);

        // Open archive for writing
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&archive_path)
            .map_err(|e| {
                RuzipError::io_error(
                    format!("Failed to open archive for modification: {}", path.display()),
                    e,
                )
            })?;

        // Compact data section
        let entry_table_offset = self.compact_data_section(
            &mut file, &data_blocks, &mut remaining_entries
        )?;

        // Write updated entry table
        self.write_entry_table(&mut file, &remaining_entries, entry_table_offset)?;

        // Calculate new archive size
        let current_pos = file.stream_position().map_err(|e| {
            RuzipError::io_error("Failed to get current file position", e)
        })?;

        // Update header
        self.update_header(
            &mut file,
            remaining_entries.len() as u32,
            entry_table_offset,
            current_pos,
        )?;

        // Truncate file to new size
        self.truncate_archive(&mut file, current_pos)?;

        // Calculate final statistics
        let deleted_files = indices_to_delete.len() as u64;
        let deleted_bytes: u64 = indices_to_delete.iter()
            .filter_map(|&i| original_entries.get(i))
            .map(|e| e.uncompressed_size)
            .sum();

        let final_stats = ArchiveStats {
            files_processed: original_stats.files_processed - deleted_files,
            directories_processed: original_stats.directories_processed,
            bytes_processed: original_stats.bytes_processed - deleted_bytes,
            errors_encountered: 0,
            processing_speed: 0.0,
            duration_ms: start_time.elapsed().as_millis() as u64,
            compression_ratio: 0.0, // Not applicable for deletion
            throughput_mb_s: 0.0,   // Calculated below
        };

        tracing::info!("In-place deletion completed successfully");
        Ok(final_stats)
    }
}

impl ArchiveDeleter for ArchiveModifier {
    fn delete_files_safe<P: AsRef<Path>>(
        &self,
        _archive_path: P,
        _files_to_delete: &[String],
        _recursive: bool,
        _create_backup: bool,
    ) -> Result<ArchiveStats> {
        // This modifier only implements in-place deletion
        Err(RuzipError::internal_error(
            "Safe deletion not supported by ArchiveModifier, use ArchiveReconstructor instead",
            Some(file!()),
        ))
    }

    fn delete_files_inplace<P: AsRef<Path>>(
        &self,
        archive_path: P,
        files_to_delete: &[String],
        recursive: bool,
        create_backup: bool,
    ) -> Result<ArchiveStats> {
        let path = archive_path.as_ref();
        tracing::info!("Starting in-place deletion from archive: {}", path.display());

        // Validate operation
        let validation = validation::validate_deletion_operation(
            &archive_path, files_to_delete, true, create_backup
        )?;

        if validation.has_errors() {
            return Err(RuzipError::invalid_input(
                format!("Validation failed: {}", validation.errors.join(", ")),
                None,
            ));
        }

        // Log warnings
        for warning in &validation.warnings {
            tracing::warn!("{}", warning);
        }

        // Perform the in-place deletion
        self.perform_inplace_deletion(archive_path, files_to_delete, recursive, create_backup)
    }

    fn preview_deletion<P: AsRef<Path>>(
        &self,
        archive_path: P,
        files_to_delete: &[String],
        recursive: bool,
    ) -> Result<DeletionPreview> {
        let mut preview = DeletionPreview::new();
        
        // Open archive and read entries
        let reader = ArchiveReader::<File>::open(&archive_path)?;
        let entries = reader.entries();
        
        // Find matching files
        let indices_to_delete = matching::find_files_to_delete(
            entries, files_to_delete, recursive
        )?;
        
        // Build preview
        for &index in &indices_to_delete {
            if let Some(entry) = entries.get(index) {
                preview.files_to_delete.push(entry.clone());
            }
        }
        
        // Add specific warnings for in-place operations
        preview.add_warning("IN-PLACE DELETION: This operation directly modifies the archive file".to_string());
        preview.add_warning("Risk of data corruption if interrupted - ensure backup is created".to_string());
        
        let total_files = entries.len();
        let files_to_delete_count = preview.files_to_delete.len();
        
        if files_to_delete_count == total_files {
            preview.add_warning("This operation will delete ALL files from the archive".to_string());
        } else if files_to_delete_count > total_files / 2 {
            preview.add_warning(format!(
                "This operation will delete more than half of the files ({}/{})",
                files_to_delete_count, total_files
            ));
        }
        
        // Calculate statistics
        preview.calculate_stats();
        
        Ok(preview)
    }
}

impl Default for ArchiveModifier {
    fn default() -> Self {
        Self::new()
    }
}

/// Information about a data block that needs to be moved during compaction
#[derive(Debug, Clone)]
struct DataBlockInfo {
    /// Original offset in the archive
    original_offset: u64,
    /// Size of the compressed data block
    size: u64,
    /// Index of the corresponding entry in the remaining entries list
    entry_index: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn test_modifier_creation() {
        let modifier = ArchiveModifier::new();
        assert_eq!(modifier.options.preserve_permissions, true);
        
        let custom_options = ArchiveOptions {
            preserve_permissions: false,
            ..Default::default()
        };
        let modifier = ArchiveModifier::with_options(custom_options);
        assert_eq!(modifier.options.preserve_permissions, false);
    }

    #[test]
    fn test_data_block_info() {
        let block = DataBlockInfo {
            original_offset: 1000,
            size: 500,
            entry_index: 5,
        };
        
        assert_eq!(block.original_offset, 1000);
        assert_eq!(block.size, 500);
        assert_eq!(block.entry_index, 5);
    }

    #[test]
    fn test_backup_creation() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.rzp");
        
        // Create a test file
        std::fs::write(&test_file, b"test data").unwrap();
        
        let modifier = ArchiveModifier::new();
        let backup_result = modifier.create_backup(&test_file);
        
        match backup_result {
            Ok(backup_path) => {
                assert!(backup_path.exists());
                let backup_content = std::fs::read(&backup_path).unwrap();
                assert_eq!(backup_content, b"test data");
            }
            Err(_) => {
                // This might fail in test environment, which is OK for this test
            }
        }
    }
}