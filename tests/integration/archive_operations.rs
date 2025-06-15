//! Integration tests for archive operations
//!
//! Tests the complete archive creation, listing, extraction, and validation workflow
//! to ensure Phase 2 functionality works end-to-end.

use ruzip::archive::{ArchiveWriter, ArchiveReader, ArchiveOptions, ArchiveValidator};
use ruzip::compression::{CompressionLevel, CompressionMethod};
use ruzip::error::Result;
use std::fs;
use std::io::Cursor;
use tempfile::TempDir;

/// Test basic archive creation and extraction
#[test]
fn test_create_and_extract_archive() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    
    // Create test files
    let test_file1 = temp_dir.path().join("file1.txt");
    let test_file2 = temp_dir.path().join("file2.txt");
    fs::write(&test_file1, b"Hello, World!")?;
    fs::write(&test_file2, b"This is a test file with more content for compression testing.")?;
    
    let sub_dir = temp_dir.path().join("subdir");
    fs::create_dir(&sub_dir)?;
    let test_file3 = sub_dir.join("file3.txt");
    fs::write(&test_file3, b"File in subdirectory")?;
    
    // Create archive
    let archive_buffer = Vec::new();
    let cursor = Cursor::new(archive_buffer);
    let options = ArchiveOptions {
        compression_level: CompressionLevel::new(6)?,
        compression_method: CompressionMethod::Zstd,
        preserve_permissions: true,
        preserve_timestamps: true,
        store_checksums: true,
        verify_integrity: true,
        max_memory: 512 * 1024 * 1024,
    };
    
    let mut writer = ArchiveWriter::new(cursor, options)?;
    writer.add_file(&test_file1, Some("file1.txt".to_string()))?;
    writer.add_file(&test_file2, Some("file2.txt".to_string()))?;
    writer.add_file(&test_file3, Some("subdir/file3.txt".to_string()))?;
    
    let archive_cursor = writer.finalize()?;
    let archive_data = archive_cursor.into_inner();
    
    // Verify archive was created
    assert!(archive_data.len() > 64); // At least header size
    
    // Read archive back
    let read_cursor = Cursor::new(&archive_data);
    let mut reader = ArchiveReader::new(read_cursor)?;
    
    // Verify archive info
    let info = reader.info()?;
    assert_eq!(info.entry_count, 3);
    assert!(info.uncompressed_size > 0);
    assert!(info.compressed_size > 0);
    
    // Extract to new directory
    let extract_dir = TempDir::new().unwrap();
    let stats = reader.extract_all(extract_dir.path())?;
    
    assert_eq!(stats.files_processed, 3);
    assert!(stats.bytes_processed > 0);
    
    // Verify extracted files
    let extracted_file1 = extract_dir.path().join("file1.txt");
    let extracted_file2 = extract_dir.path().join("file2.txt");
    let extracted_file3 = extract_dir.path().join("subdir/file3.txt");
    
    assert!(extracted_file1.exists());
    assert!(extracted_file2.exists());
    assert!(extracted_file3.exists());
    
    assert_eq!(fs::read_to_string(&extracted_file1)?, "Hello, World!");
    assert_eq!(fs::read_to_string(&extracted_file2)?, "This is a test file with more content for compression testing.");
    assert_eq!(fs::read_to_string(&extracted_file3)?, "File in subdirectory");
    
    Ok(())
}

/// Test archive listing functionality
#[test]
fn test_archive_listing() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    
    // Create test files
    let test_files = ["file1.txt", "file2.dat", "document.pdf"];
    for (i, filename) in test_files.iter().enumerate() {
        let file_path = temp_dir.path().join(filename);
        fs::write(&file_path, format!("Content of file {}", i + 1))?;
    }
    
    // Create archive
    let archive_buffer = Vec::new();
    let cursor = Cursor::new(archive_buffer);
    let options = ArchiveOptions::default();
    
    let mut writer = ArchiveWriter::new(cursor, options)?;
    for filename in &test_files {
        let file_path = temp_dir.path().join(filename);
        writer.add_file(&file_path, Some(filename.to_string()))?;
    }
    
    let archive_cursor = writer.finalize()?;
    let archive_data = archive_cursor.into_inner();
    
    // Read and list archive contents
    let read_cursor = Cursor::new(&archive_data);
    let reader = ArchiveReader::new(read_cursor)?;
    
    let entries = reader.entries();
    assert_eq!(entries.len(), 3);
    
    // Check all files are listed
    let entry_paths: Vec<&str> = entries.iter().map(|e| e.path.as_str()).collect();
    for filename in &test_files {
        assert!(entry_paths.contains(filename));
    }
    
    // Test filtered listing
    let txt_entries = reader.list_entries(Some(|entry| entry.path.ends_with(".txt")));
    assert_eq!(txt_entries.len(), 1);
    assert_eq!(txt_entries[0].path, "file1.txt");
    
    // Test entry lookup
    assert!(reader.contains("file1.txt"));
    assert!(reader.contains("document.pdf"));
    assert!(!reader.contains("nonexistent.txt"));
    
    let entry = reader.get_entry("file2.dat");
    assert!(entry.is_some());
    assert_eq!(entry.unwrap().path, "file2.dat");
    
    Ok(())
}

/// Test selective extraction
#[test] 
fn test_selective_extraction() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    
    // Create multiple test files
    let test_files = ["keep1.txt", "keep2.txt", "skip1.txt", "skip2.txt"];
    for filename in &test_files {
        let file_path = temp_dir.path().join(filename);
        fs::write(&file_path, format!("Content of {}", filename))?;
    }
    
    // Create archive
    let archive_buffer = Vec::new();
    let cursor = Cursor::new(archive_buffer);
    let options = ArchiveOptions::default();
    
    let mut writer = ArchiveWriter::new(cursor, options)?;
    for filename in &test_files {
        let file_path = temp_dir.path().join(filename);
        writer.add_file(&file_path, Some(filename.to_string()))?;
    }
    
    let archive_cursor = writer.finalize()?;
    let archive_data = archive_cursor.into_inner();
    
    // Extract only specific files
    let read_cursor = Cursor::new(&archive_data);
    let mut reader = ArchiveReader::new(read_cursor)?;
    
    let extract_dir = TempDir::new().unwrap();
    let files_to_extract = vec!["keep1.txt".to_string(), "keep2.txt".to_string()];
    let stats = reader.extract_files(extract_dir.path(), &files_to_extract)?;
    
    assert_eq!(stats.files_processed, 2);
    
    // Verify only selected files were extracted
    assert!(extract_dir.path().join("keep1.txt").exists());
    assert!(extract_dir.path().join("keep2.txt").exists());
    assert!(!extract_dir.path().join("skip1.txt").exists());
    assert!(!extract_dir.path().join("skip2.txt").exists());
    
    Ok(())
}

/// Test archive integrity validation
#[test]
fn test_archive_integrity() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    
    // Create test file
    let test_file = temp_dir.path().join("test.txt");
    fs::write(&test_file, b"Test content for integrity validation")?;
    
    // Create archive with checksums
    let archive_buffer = Vec::new();
    let cursor = Cursor::new(archive_buffer);
    let options = ArchiveOptions {
        store_checksums: true,
        verify_integrity: true,
        ..Default::default()
    };
    
    let mut writer = ArchiveWriter::new(cursor, options)?;
    writer.add_file(&test_file, Some("test.txt".to_string()))?;
    
    let archive_cursor = writer.finalize()?;
    let archive_data = archive_cursor.into_inner();
    
    // Test integrity
    let read_cursor = Cursor::new(&archive_data);
    let mut reader = ArchiveReader::new(read_cursor)?;
    
    let integrity_stats = reader.test_integrity()?;
    assert_eq!(integrity_stats.files_processed, 1);
    assert!(integrity_stats.bytes_processed > 0);
    
    Ok(())
}

/// Test comprehensive archive validation
#[test]
fn test_archive_validation() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    
    // Create test files with various characteristics
    let normal_file = temp_dir.path().join("normal.txt");
    fs::write(&normal_file, b"Normal file content")?;
    
    let large_file = temp_dir.path().join("large.dat");
    fs::write(&large_file, vec![0u8; 1024 * 1024])?; // 1MB file
    
    // Create archive
    let archive_buffer = Vec::new();
    let cursor = Cursor::new(archive_buffer);
    let options = ArchiveOptions {
        store_checksums: true,
        preserve_permissions: true,
        preserve_timestamps: true,
        ..Default::default()
    };
    
    let mut writer = ArchiveWriter::new(cursor, options)?;
    writer.add_file(&normal_file, Some("normal.txt".to_string()))?;
    writer.add_file(&large_file, Some("large.dat".to_string()))?;
    
    let archive_cursor = writer.finalize()?;
    let archive_data = archive_cursor.into_inner();
    
    // Validate archive
    let read_cursor = Cursor::new(&archive_data);
    let mut reader = ArchiveReader::new(read_cursor)?;
    
    let validator = ArchiveValidator::new()
        .with_checksum_verification(true)
        .with_path_safety_checks(true);
    
    let validation_result = validator.validate(&mut reader)?;
    
    assert!(validation_result.passed());
    assert_eq!(validation_result.entries_checked, 2);
    assert!(validation_result.errors.is_empty());
    
    Ok(())
}

/// Test compression ratio targets
#[test]
fn test_compression_ratios() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    
    // Test text compression (should achieve ≥60%)
    let text_file = temp_dir.path().join("text.txt");
    let text_content = "This is highly compressible text content. ".repeat(1000);
    fs::write(&text_file, &text_content)?;
    
    let archive_buffer = Vec::new();
    let cursor = Cursor::new(archive_buffer);
    let options = ArchiveOptions {
        compression_level: CompressionLevel::new(6)?,
        compression_method: CompressionMethod::Zstd,
        ..Default::default()
    };
    
    let mut writer = ArchiveWriter::new(cursor, options)?;
    writer.add_file(&text_file, Some("text.txt".to_string()))?;
    
    let archive_cursor = writer.finalize()?;
    let archive_data = archive_cursor.into_inner();
    
    // Read back and check compression ratio
    let read_cursor = Cursor::new(&archive_data);
    let reader = ArchiveReader::new(read_cursor)?;
    
    let info = reader.info()?;
    let compression_percentage = info.compression_percentage();
    
    // Text should compress by at least 60%
    assert!(compression_percentage >= 60.0, 
           "Text compression {:.1}% below target 60%", compression_percentage);
    
    Ok(())
}

/// Test different compression methods
#[test]
fn test_compression_methods() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    
    let test_file = temp_dir.path().join("test.txt");
    fs::write(&test_file, b"Test content for compression method testing")?;
    
    // Test ZSTD compression
    let zstd_archive = {
        let archive_buffer = Vec::new();
        let cursor = Cursor::new(archive_buffer);
        let options = ArchiveOptions {
            compression_method: CompressionMethod::Zstd,
            compression_level: CompressionLevel::new(6)?,
            ..Default::default()
        };
        
        let mut writer = ArchiveWriter::new(cursor, options)?;
        writer.add_file(&test_file, Some("test.txt".to_string()))?;
        
        let archive_cursor = writer.finalize()?;
        archive_cursor.into_inner()
    };
    
    // Test Store (no compression)
    let store_archive = {
        let archive_buffer = Vec::new();
        let cursor = Cursor::new(archive_buffer);
        let options = ArchiveOptions {
            compression_method: CompressionMethod::Store,
            ..Default::default()
        };
        
        let mut writer = ArchiveWriter::new(cursor, options)?;
        writer.add_file(&test_file, Some("test.txt".to_string()))?;
        
        let archive_cursor = writer.finalize()?;
        archive_cursor.into_inner()
    };
    
    // ZSTD archive should be smaller than store archive (for this content)
    assert!(zstd_archive.len() <= store_archive.len());
    
    // Both should extract to same content
    let extract_dir1 = TempDir::new().unwrap();
    let extract_dir2 = TempDir::new().unwrap();
    
    let mut reader1 = ArchiveReader::new(Cursor::new(&zstd_archive))?;
    let mut reader2 = ArchiveReader::new(Cursor::new(&store_archive))?;
    
    reader1.extract_all(extract_dir1.path())?;
    reader2.extract_all(extract_dir2.path())?;
    
    let content1 = fs::read_to_string(extract_dir1.path().join("test.txt"))?;
    let content2 = fs::read_to_string(extract_dir2.path().join("test.txt"))?;
    
    assert_eq!(content1, content2);
    assert_eq!(content1, "Test content for compression method testing");
    
    Ok(())
}

/// Test error handling and edge cases
#[test]
fn test_error_handling() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    
    // Test invalid compression level
    let result = CompressionLevel::new(100);
    assert!(result.is_err());
    
    // Test adding non-existent file
    let archive_buffer = Vec::new();
    let cursor = Cursor::new(archive_buffer);
    let options = ArchiveOptions::default();
    let mut writer = ArchiveWriter::new(cursor, options)?;
    
    let non_existent_file = temp_dir.path().join("does_not_exist.txt");
    let result = writer.add_file(&non_existent_file, None);
    assert!(result.is_err());
    
    // Test reading invalid archive
    let invalid_data = b"Not an archive";
    let cursor = Cursor::new(invalid_data);
    let result = ArchiveReader::new(cursor);
    assert!(result.is_err());
    
    Ok(())
}

/// Test memory usage limits
#[test]
fn test_memory_limits() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    
    // Create a reasonably sized test file
    let test_file = temp_dir.path().join("test.txt");
    fs::write(&test_file, vec![b'A'; 1024 * 1024])?; // 1MB
    
    // Test with restricted memory
    let archive_buffer = Vec::new();
    let cursor = Cursor::new(archive_buffer);
    let options = ArchiveOptions {
        max_memory: 1024 * 1024, // 1MB limit
        ..Default::default()
    };
    
    let mut writer = ArchiveWriter::new(cursor, options)?;
    
    // Should still work with memory limits
    writer.add_file(&test_file, Some("test.txt".to_string()))?;
    let archive_cursor = writer.finalize()?;
    
    // Verify archive works
    let archive_data = archive_cursor.into_inner();
    let read_cursor = Cursor::new(&archive_data);
    let mut reader = ArchiveReader::new(read_cursor)?;
    
    let extract_dir = TempDir::new().unwrap();
    let stats = reader.extract_all(extract_dir.path())?;
    
    assert_eq!(stats.files_processed, 1);
    assert_eq!(stats.bytes_processed, 1024 * 1024);
    
    Ok(())
}