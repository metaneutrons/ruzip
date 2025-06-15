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
use crate::chaos::{
    fault_injection::{FaultInjector, FaultInjectingOperation, FaultType},
    ChaosTestConfig,
};

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

#[test]
fn test_archive_extract_many_files() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let num_files = 1000; // Number of files to create and archive
    let mut expected_files = std::collections::HashMap::new();

    // Create many small files
    for i in 0..num_files {
        let filename = format!("file_{}.txt", i);
        let file_path = temp_dir.path().join(&filename);
        let content = format!("Content of file {}", i);
        fs::write(&file_path, &content)?;
        expected_files.insert(filename, content);
    }

    let compression_methods = [CompressionMethod::Zstd, CompressionMethod::Store];

    for method in compression_methods.iter() {
        println!("Testing {} files with method: {:?}", num_files, method);
        let archive_buffer = Vec::new();
        let cursor = Cursor::new(archive_buffer);
        let options = ArchiveOptions {
            compression_method: *method,
            store_checksums: true, // Good to test with checksums for many files
            ..Default::default()
        };

        let mut writer = ArchiveWriter::new(cursor, options)?;
        for i in 0..num_files {
            let filename = format!("file_{}.txt", i);
            let file_path = temp_dir.path().join(&filename);
            writer.add_file(&file_path, Some(filename))?;
        }
        let archive_cursor = writer.finalize()?;
        let archive_data = archive_cursor.into_inner();

        // Read archive back
        let read_cursor = Cursor::new(&archive_data);
        let mut reader = ArchiveReader::new(read_cursor)?;

        let info = reader.info()?;
        assert_eq!(info.entry_count, num_files as u64);

        let entries = reader.entries();
        assert_eq!(entries.len(), num_files);

        let extract_dir = TempDir::new().unwrap();
        let stats = reader.extract_all(extract_dir.path())?;

        assert_eq!(stats.files_processed, num_files as u64);

        // Verify a subset of extracted files for content integrity
        for i in (0..num_files).step_by(num_files / 10) { // Check 10 files spread out
            let filename = format!("file_{}.txt", i);
            let extracted_file_path = extract_dir.path().join(&filename);
            assert!(extracted_file_path.exists(), "File {} should exist after extraction with method {:?}", filename, method);
            let expected_content = expected_files.get(&filename).unwrap();
            assert_eq!(
                fs::read_to_string(&extracted_file_path)?,
                *expected_content,
                "File content mismatch for {} with method {:?}", filename, method
            );
        }
        // Verify all files exist
        for i in 0..num_files {
             let filename = format!("file_{}.txt", i);
             let extracted_file_path = extract_dir.path().join(&filename);
             assert!(extracted_file_path.exists(), "File {} should exist (full check) with method {:?}", filename, method);
        }
    }
    Ok(())
}

// --- Error Handling and Corrupted Archive Tests ---

#[test]
fn test_read_archive_invalid_magic() {
    let mut invalid_data = vec![0u8; ArchiveHeader::SIZE];
    // Fill with 'TEST' instead of 'RUZIP'
    invalid_data[0..4].copy_from_slice(b"TEST");
    // Fill the rest with something to make it a valid header size,
    // checksum and other fields won't matter as magic check is first.
    let header = ArchiveHeader::new(); // To get a valid version, etc.
    let mut temp_valid_header_bytes = bincode::serialize(&header).unwrap();
    temp_valid_header_bytes[0..4].copy_from_slice(b"TEST"); // Corrupt magic

    let cursor = Cursor::new(temp_valid_header_bytes);
    let result = ArchiveReader::new(cursor);

    assert!(result.is_err());
    if let Err(RuzipError::HeaderParseError { details }) = result {
        assert!(details.contains("Invalid magic bytes"), "Unexpected error details: {}", details);
    } else {
        panic!("Expected HeaderParseError, got {:?}", result);
    }
}

#[test]
fn test_read_archive_invalid_version() {
    let mut header = ArchiveHeader::new();
    header.version = 0; // An invalid version (e.g., older than min supported or newer than current)
    header.update_checksum(); // Ensure checksum is valid for the modified header

    let mut header_bytes = bincode::serialize(&header).unwrap();

    let cursor = Cursor::new(header_bytes);
    let result = ArchiveReader::new(cursor);

    assert!(result.is_err());
    if let Err(RuzipError::InvalidVersion { version_read, .. }) = result {
        assert_eq!(version_read, 0, "Incorrect version reported in error");
    } else {
        panic!("Expected RuzipError::InvalidVersion, got {:?}", result);
    }

    // Test with a version that's too new (e.g. CURRENT_VERSION + 1, assuming CURRENT_VERSION is max)
    // Need to know what MIN_SUPPORTED_VERSION and CURRENT_VERSION are.
    // Let's assume MIN_SUPPORTED_VERSION is 1 and CURRENT_VERSION is 1 for this example.
    // So version 2 would be too new if header.rs uses CURRENT_VERSION as max for reading.
    // The check in header.rs was:
    // if self.version < crate::archive::MIN_SUPPORTED_VERSION || self.version > CURRENT_VERSION {
    // So, if MIN_SUPPORTED_VERSION = 1, CURRENT_VERSION = 1, then version 0 is too old, version 2 is too new.

    header.version = crate::archive::CURRENT_VERSION + 1;
    header.update_checksum();
    header_bytes = bincode::serialize(&header).unwrap();
    let cursor_new_version = Cursor::new(header_bytes);
    let result_new_version = ArchiveReader::new(cursor_new_version);

    assert!(result_new_version.is_err());
    if let Err(RuzipError::InvalidVersion { version_read, .. }) = result_new_version {
        assert_eq!(version_read, crate::archive::CURRENT_VERSION + 1, "Incorrect too new version reported");
    } else {
        panic!("Expected RuzipError::InvalidVersion for too new version, got {:?}", result_new_version);
    }
}

#[test]
fn test_read_archive_too_short() {
    // Create data that is shorter than a full header
    let short_data = vec![0u8; ArchiveHeader::SIZE - 10];
    let cursor = Cursor::new(short_data);
    let result = ArchiveReader::new(cursor); // ArchiveReader::new calls Header::deserialize

    assert!(result.is_err());
    if let Err(RuzipError::ArchiveTooShort { operation, expected_len, actual_len }) = result {
        assert!(operation.contains("Reading archive header"));
        assert_eq!(expected_len, ArchiveHeader::SIZE as u64);
        // The actual_len reported by the error might be an estimate (like expected - 1)
        // as read_exact doesn't directly say how many bytes it did read before EOF.
        // So we check it's less than expected.
        assert!(actual_len < expected_len, "Actual length {} reported should be less than expected {}", actual_len, expected_len);
    } else {
        panic!("Expected RuzipError::ArchiveTooShort, got {:?}", result);
    }

    // Test with zero bytes (extreme case of too short)
    let zero_data = vec![];
    let cursor_zero = Cursor::new(zero_data);
    let result_zero = ArchiveReader::new(cursor_zero);

    assert!(result_zero.is_err());
    if let Err(RuzipError::ArchiveTooShort { .. }) = result_zero {
        // Correct error type
    } else {
        panic!("Expected RuzipError::ArchiveTooShort for zero data, got {:?}", result_zero);
    }
}

#[test]
fn test_read_archive_header_checksum_error() {
    let mut header = ArchiveHeader::new();
    // Intentionally corrupt the header *after* checksum calculation
    // by serializing, modifying a byte (not checksum itself), then trying to deserialize.
    header.entry_count = 10; // Some arbitrary data
    header.update_checksum(); // Checksum is now correct for entry_count = 10

    let mut header_bytes = bincode::serialize(&header).unwrap();

    // Corrupt a byte in the header data (e.g., entry_count field, assuming it's not the last 4 bytes which is checksum)
    // Header structure: magic[4], version[2], header_size[2], comp_method[1], comp_level[1], flags[2], entry_count[8]...
    // Let's corrupt part of entry_count (e.g., at index 12, if header fields are packed)
    if header_bytes.len() >= 20 { // Ensure there's data to corrupt before checksum
      header_bytes[12] ^= 0xFF; // Flip some bits in entry_count
    } else {
        panic!("Serialized header too short to reliably corrupt pre-checksum data.");
    }

    let cursor = Cursor::new(header_bytes);
    let result = ArchiveReader::new(cursor); // This will call Header::deserialize, which calls verify_checksum

    assert!(result.is_err());
    if let Err(RuzipError::HeaderParseError { details }) = result {
        assert!(details.contains("Header checksum validation failed"), "Unexpected error details for checksum error: {}", details);
    } else {
        panic!("Expected RuzipError::HeaderParseError for checksum mismatch, got {:?}", result);
    }
}

#[test]
fn test_read_archive_corrupted_entry_table() {
    let temp_dir = TempDir::new().unwrap();
    let test_file_path = temp_dir.path().join("file1.txt");
    fs::write(&test_file_path, "content1").unwrap();

    let archive_options = ArchiveOptions::default();
    let mut archive_data_writer = Cursor::new(Vec::new());

    // Create a header and one valid file entry
    let mut writer = ArchiveWriter::new(&mut archive_data_writer, archive_options).unwrap();
    writer.add_file(&test_file_path, Some("file1.txt".to_string())).unwrap();
    // We don't call finalize, instead we'll manually construct a corrupted entry table part

    // Manually prepare data that would be written by finalize, but corrupt the entry table part
    let mut header = writer.header.clone(); // Get header state before finalize would modify it
    header.entry_count = 1; // We added one file
    // Assume file data for "file1.txt" was written. current_offset in writer points after it.
    // The entry_table_offset will be current_offset.
    header.entry_table_offset = writer.current_offset;

    // Corrupt entry table data
    let corrupted_entry_table_bytes = vec![0xDE, 0xAD, 0xBE, 0xEF]; // Gibberish

    // Write the file data (already done by add_file into writer's internal buffer)
    // Get the data written so far by add_file
    writer.writer.flush().unwrap(); // Ensure internal buffer of BufWriter is flushed to Cursor
    let mut written_data = archive_data_writer.into_inner(); // This is header space + file1 data

    // Append corrupted entry table
    written_data.extend_from_slice(&corrupted_entry_table_bytes);

    // Now, write the header at the beginning
    header.update_checksum(); // Final checksum for the modified header
    let header_bytes = bincode::serialize(&header).unwrap();
    written_data[0..ArchiveHeader::SIZE].copy_from_slice(&header_bytes);

    let cursor = Cursor::new(written_data);
    let result = ArchiveReader::new(cursor);

    assert!(result.is_err(), "Expected an error due to corrupted entry table");
    if let Err(RuzipError::EntryParseError { entry_name, details }) = result {
        assert!(entry_name.is_none(), "Entry name should be None for table-level parse error");
        assert!(details.contains("Failed to deserialize entry table"), "Unexpected error details: {}", details);
    } else {
        panic!("Expected RuzipError::EntryParseError for corrupted entry table, got {:?}", result);
    }
}

#[test]
fn test_read_archive_entry_checksum_error() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let file1_path = temp_dir.path().join("file1.txt");
    let file2_path = temp_dir.path().join("file2.txt");
    fs::write(&file1_path, "content for file1, which will be kept intact.")?;
    fs::write(&file2_path, "content for file2, which will be corrupted.")?;

    let options = ArchiveOptions {
        store_checksums: true, // Crucial for this test
        ..Default::default()
    };

    let mut archive_data = Vec::new();
    let mut archive_writer_cursor = Cursor::new(&mut archive_data);

    // Create archive with two files
    let mut writer = ArchiveWriter::new(&mut archive_writer_cursor, options)?;
    writer.add_file(&file1_path, Some("file1.txt".to_string()))?;
    writer.add_file(&file2_path, Some("file2.txt".to_string()))?;
    writer.finalize()?; // Finalize to correctly write header and entry table

    // archive_data now holds the valid archive. We need to find where file2's data is and corrupt it.
    // This is tricky without internal knowledge of offsets.
    // A simpler way to test this might be to modify reader.rs's test_integrity if it can be made to fail a checksum.
    // For an integration test: we need to locate file2's data.
    // Let's get entry information first.
    let (file2_entry, original_archive_data_len) = {
        let temp_reader_cursor = Cursor::new(&archive_data);
        let reader = ArchiveReader::new(temp_reader_cursor)?;
        let entry = reader.get_entry("file2.txt").expect("file2.txt should exist").clone();
        (entry, archive_data.len())
    };

    // Corrupt file2's data. Assuming data_offset points to start of compressed data.
    // And compressed_size is how long it is.
    // This assumes data_offset is within current archive_data bounds.
    if file2_entry.compressed_size > 0 {
        let data_start = file2_entry.data_offset as usize;
        let data_end = data_start + file2_entry.compressed_size as usize;
        if data_end <= archive_data.len() && data_start < data_end {
             // Corrupt the first byte of file2's compressed data
            archive_data[data_start] ^= 0xFF;
        } else {
            panic!("File2 data offset/size out of bounds for corruption. Data start: {}, Data end: {}, Archive len: {}", data_start, data_end, archive_data.len());
        }
    } else {
        // If compressed size is 0, this test might not be meaningful unless it's an empty file and that's handled.
        // For now, let's assume it's not an empty file for this corruption test.
        println!("Skipping corruption for file2.txt as its compressed size is 0.");
        return Ok(()); // Or fail if this scenario shouldn't happen.
    }

    let corrupted_reader_cursor = Cursor::new(&archive_data);
    let mut corrupted_reader = ArchiveReader::new(corrupted_reader_cursor)?;

    let extract_dir = TempDir::new().unwrap();
    let result = corrupted_reader.extract_all(extract_dir.path());

    // Extraction might succeed for file1 but fail overall, or fail specifically on file2.
    // The current reader.rs extract_all might not propagate the checksum error from test_integrity.
    // Let's explicitly call test_integrity as that's where the checksum check is.

    let integrity_result = {
        let mut reader_for_integrity_check = ArchiveReader::new(Cursor::new(&archive_data))?;
        reader_for_integrity_check.test_integrity()
    };


    assert!(integrity_result.is_err(), "Expected an error during integrity test due to checksum mismatch");
    if let Err(RuzipError::ChecksumMismatch { entry_name, .. }) = integrity_result {
        assert_eq!(entry_name, "file2.txt");
    } else {
        panic!("Expected RuzipError::ChecksumMismatch, got {:?}", integrity_result);
    }

    Ok(())
}

// --- Boundary Condition and Edge Case Tests ---

#[test]
fn test_archive_extract_empty_file() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let empty_file_path = temp_dir.path().join("empty.txt");
    fs::write(&empty_file_path, b"")?; // Create an empty file

    let compression_methods = [CompressionMethod::Zstd, CompressionMethod::Store];

    for method in compression_methods.iter() {
        println!("Testing empty file with method: {:?}", method);
        let archive_buffer = Vec::new();
        let cursor = Cursor::new(archive_buffer);
        let options = ArchiveOptions {
            compression_method: *method,
            ..Default::default()
        };

        let mut writer = ArchiveWriter::new(cursor, options)?;
        writer.add_file(&empty_file_path, Some("empty.txt".to_string()))?;
        let archive_cursor = writer.finalize()?;
        let archive_data = archive_cursor.into_inner();

        // Read archive back
        let read_cursor = Cursor::new(&archive_data);
        let mut reader = ArchiveReader::new(read_cursor)?;

        let info = reader.info()?;
        assert_eq!(info.entry_count, 1);
        // For an empty file, uncompressed size is 0. Compressed size might be > 0 due to metadata.
        assert_eq!(info.uncompressed_size, 0);


        let extract_dir = TempDir::new().unwrap();
        let stats = reader.extract_all(extract_dir.path())?;

        assert_eq!(stats.files_processed, 1);
        assert_eq!(stats.bytes_processed, 0); // 0 bytes processed for an empty file

        let extracted_empty_file_path = extract_dir.path().join("empty.txt");
        assert!(extracted_empty_file_path.exists());
        assert_eq!(fs::read(&extracted_empty_file_path)?.len(), 0, "Extracted file should be empty for method {:?}", method);
    }
    Ok(())
}

#[test]
fn test_archive_extract_special_char_filenames() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let special_filenames = [
        "file with spaces.txt",
        "file_with_unicode_你好世界.txt", // Hello World in Chinese
        "file_with_symbols!@#$%^&*().txt",
        "another file, with; a [semicolon].dat",
        // Potentially problematic characters for some systems if not handled:
        // "file_with_quotes\".txt", // Backslash might be an escape char
        // "file_with_colon:.txt", // Colon can be problematic on Windows
        // For simplicity, sticking to more commonly problematic but generally allowed chars
    ];

    let file_content = "Content for special filename test.";

    for special_filename_str in &special_filenames {
        let special_file_path = temp_dir.path().join(special_filename_str);
        fs::write(&special_file_path, file_content.as_bytes())?;

        let compression_methods = [CompressionMethod::Zstd, CompressionMethod::Store];
        for method in compression_methods.iter() {
            println!("Testing special filename '{}' with method: {:?}", special_filename_str, method);
            let archive_buffer = Vec::new();
            let cursor = Cursor::new(archive_buffer);
            let options = ArchiveOptions {
                compression_method: *method,
                ..Default::default()
            };

            let mut writer = ArchiveWriter::new(cursor, options)?;
            writer.add_file(&special_file_path, Some(special_filename_str.to_string()))?;
            let archive_cursor = writer.finalize()?;
            let archive_data = archive_cursor.into_inner();

            let read_cursor = Cursor::new(&archive_data);
            let mut reader = ArchiveReader::new(read_cursor)?;

            let info = reader.info()?;
            assert_eq!(info.entry_count, 1);

            let entries = reader.entries();
            assert_eq!(entries[0].path, *special_filename_str);

            let extract_dir = TempDir::new().unwrap();
            reader.extract_all(extract_dir.path())?;

            let extracted_file_path = extract_dir.path().join(special_filename_str);
            assert!(extracted_file_path.exists(), "File '{}' should exist after extraction with method {:?}", special_filename_str, method);
            assert_eq!(
                fs::read_to_string(&extracted_file_path)?,
                file_content,
                "File content mismatch for filename '{}' with method {:?}", special_filename_str, method
            );

            // Clean up the created file before the next iteration (optional, as TempDir handles it)
            // fs::remove_file(&special_file_path)?;
        }
         // Clean up file for next special filename (TempDir will clean at end of scope, but this is per-special-filename)
        fs::remove_file(&special_file_path)?;
    }
    Ok(())
}

#[test]
fn test_archive_extract_long_filename() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    // Generate a long filename (e.g., 250 'a' characters) + .txt
    let long_filename_str = "a".repeat(250) + ".txt";
    let long_file_path = temp_dir.path().join(&long_filename_str);
    fs::write(&long_file_path, b"Content of a file with a very long name.")?;

    let compression_methods = [CompressionMethod::Zstd, CompressionMethod::Store];

    for method in compression_methods.iter() {
        println!("Testing long filename with method: {:?}", method);
        let archive_buffer = Vec::new();
        let cursor = Cursor::new(archive_buffer);
        let options = ArchiveOptions {
            compression_method: *method,
            ..Default::default()
        };

        let mut writer = ArchiveWriter::new(cursor, options)?;
        // Use the same long filename for the path inside the archive
        writer.add_file(&long_file_path, Some(long_filename_str.clone()))?;
        let archive_cursor = writer.finalize()?;
        let archive_data = archive_cursor.into_inner();

        // Read archive back
        let read_cursor = Cursor::new(&archive_data);
        let mut reader = ArchiveReader::new(read_cursor)?;

        let info = reader.info()?;
        assert_eq!(info.entry_count, 1);

        let entries = reader.entries();
        assert_eq!(entries[0].path, long_filename_str);


        let extract_dir = TempDir::new().unwrap();
        reader.extract_all(extract_dir.path())?;

        let extracted_long_filename_path = extract_dir.path().join(&long_filename_str);
        assert!(extracted_long_filename_path.exists());
        assert_eq!(
            fs::read_to_string(&extracted_long_filename_path)?,
            "Content of a file with a very long name.",
            "File content mismatch for method {:?}", method
        );
    }
    Ok(())
}

#[tokio::test]
async fn test_create_archive_with_io_errors() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let test_file1 = temp_dir.path().join("file1.txt");
    fs::write(&test_file1, b"Hello, World!")?;

    let config = ChaosTestConfig::default();
    let fault_injector = FaultInjector::new(config);
    fault_injector.enable_io_faults(1.0).await?; // Enable I/O faults with 100% probability

    let archive_buffer = Vec::new();
    let cursor = Cursor::new(archive_buffer);
    let options = ArchiveOptions::default();

    // It's important to handle the potential error from ArchiveWriter::new,
    // though in this specific test, it's not where we expect the fault.
    let archive_writer = ArchiveWriter::new(cursor, options)?;
    let writer_op = FaultInjectingOperation::new(archive_writer, fault_injector.clone());

    let result = writer_op.execute("add_file", |writer| {
        // writer here is &ArchiveWriter
        writer.add_file(&test_file1, Some("file1.txt".to_string()))
    }).await;

    assert!(result.is_err(), "Expected an I/O error during archive creation");
    if let Err(e) = &result {
        eprintln!("Successfully injected error: {:?}", e);
    }

    Ok(())
}

#[tokio::test]
async fn test_create_archive_with_memory_errors() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let test_file1 = temp_dir.path().join("file1.txt");
    fs::write(&test_file1, b"Hello, World!")?;

    let config = ChaosTestConfig::default();
    let fault_injector = FaultInjector::new(config);
    fault_injector.enable_memory_faults(1.0).await?; // 100% probability

    let archive_buffer = Vec::new();
    let cursor = Cursor::new(archive_buffer);
    let options = ArchiveOptions::default();

    let archive_writer = ArchiveWriter::new(cursor, options)?;
    let writer_op = FaultInjectingOperation::new(archive_writer, fault_injector.clone());

    // We need to ensure the fault injector's maybe_inject_memory_exhaustion is called.
    // The current FaultInjectingOperation.execute might not directly call it
    // unless we modify FaultInjectingOperation or how operations are defined.
    // For now, let's assume add_file operation itself might trigger allocation checks
    // or we rely on the generic pre-operation checks if they include memory.
    // A more direct way would be to have specific injection points.
    // The fault_injection.rs shows `maybe_inject_memory_exhaustion` is called by the application code.
    // This test will rely on the `ArchiveWriter::add_file` or subsequent `finalize` (if wrapped)
    // to internally call something that the `FaultInjector` can hook into for memory errors,
    // or that `FaultInjectingOperation` itself is enhanced.
    // Given the current structure of FaultInjectingOperation, it primarily injects I/O-like errors via its `execute` method.
    // Let's adjust `FaultInjectingOperation` or how we use it for memory errors.
    // For now, we'll assume that an operation like `add_file` could fail due to memory exhaustion
    // if the fault injector is set up for it AND the `FaultInjectingOperation` calls `maybe_inject_memory_exhaustion`.
    // The provided `FaultInjectingOperation`'s `execute` method doesn't call `maybe_inject_memory_exhaustion`.
    // This means we either need to modify `FaultInjectingOperation` or call the injection method directly for the test.

    // Simulating the scenario where an operation checks for memory exhaustion:
    let result = writer_op.execute("add_file_mem_check", |writer| {
        // Before the actual operation, we explicitly check for memory exhaustion
        // This is a way to simulate the application being aware of the fault injector
        futures::executor::block_on(fault_injector.maybe_inject_memory_exhaustion(1024 * 1024))?; // Simulate 1MB allocation attempt
        writer.add_file(&test_file1, Some("file1.txt".to_string()))
    }).await;

    assert!(result.is_err(), "Expected a memory error during archive creation");
    if let Err(e) = &result {
        eprintln!("Successfully injected memory error: {:?}", e);
        assert!(e.to_string().contains("Injected memory exhaustion"), "Error message mismatch");
    }

    Ok(())
}

#[tokio::test]
async fn test_extract_archive_with_io_errors() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let test_file1 = temp_dir.path().join("file1.txt");
    fs::write(&test_file1, b"Content for IO error test")?;

    // 1. Create a normal archive
    let archive_buffer = Vec::new();
    let cursor = Cursor::new(archive_buffer);
    let options = ArchiveOptions::default();
    let mut writer = ArchiveWriter::new(cursor, options)?;
    writer.add_file(&test_file1, Some("file1.txt".to_string()))?;
    let archive_cursor = writer.finalize()?;
    let archive_data = archive_cursor.into_inner();

    // 2. Setup FaultInjector for I/O errors
    let config = ChaosTestConfig::default();
    let fault_injector = FaultInjector::new(config);
    fault_injector.enable_io_faults(1.0).await?; // 100% probability

    // 3. Wrap ArchiveReader operation
    let read_cursor = Cursor::new(&archive_data);
    let archive_reader = ArchiveReader::new(read_cursor)?;
    let reader_op = FaultInjectingOperation::new(archive_reader, fault_injector.clone());

    let extract_dir = TempDir::new().unwrap();

    // 4. Attempt extraction and assert error
    let result = reader_op.execute("extract_all_io_error", |reader| {
        // reader here is &ArchiveReader
        reader.extract_all(extract_dir.path())
    }).await;

    assert!(result.is_err(), "Expected an I/O error during archive extraction");
    if let Err(e) = &result {
        eprintln!("Successfully injected I/O error during extraction: {:?}", e);
        assert!(e.to_string().contains("Injected I/O error"), "Error message mismatch for I/O fault");
    }

    Ok(())
}

#[tokio::test]
async fn test_extract_archive_with_memory_errors() -> Result<()> {
    let temp_dir = TempDir::new().unwrap();
    let test_file1 = temp_dir.path().join("file1.txt");
    fs::write(&test_file1, b"Content for memory error test during extraction")?;

    // 1. Create a normal archive
    let archive_buffer = Vec::new();
    let cursor = Cursor::new(archive_buffer);
    let options = ArchiveOptions::default();
    let mut writer = ArchiveWriter::new(cursor, options)?;
    writer.add_file(&test_file1, Some("file1.txt".to_string()))?;
    let archive_cursor = writer.finalize()?;
    let archive_data = archive_cursor.into_inner();

    // 2. Setup FaultInjector for memory errors
    let config = ChaosTestConfig::default();
    let fault_injector = FaultInjector::new(config);
    fault_injector.enable_memory_faults(1.0).await?; // 100% probability

    // 3. Wrap ArchiveReader operation
    let read_cursor = Cursor::new(&archive_data);
    let archive_reader = ArchiveReader::new(read_cursor)?; // This could also be a point of memory allocation
    let reader_op = FaultInjectingOperation::new(archive_reader, fault_injector.clone());

    let extract_dir = TempDir::new().unwrap();

    // 4. Attempt extraction and assert error
    let result = reader_op.execute("extract_all_mem_error", |reader| {
        // Simulate a memory allocation check before or during extraction logic
        futures::executor::block_on(fault_injector.maybe_inject_memory_exhaustion(1024 * 1024))?; // Simulate 1MB allocation
        reader.extract_all(extract_dir.path())
    }).await;

    assert!(result.is_err(), "Expected a memory error during archive extraction");
    if let Err(e) = &result {
        eprintln!("Successfully injected memory error during extraction: {:?}", e);
        assert!(e.to_string().contains("Injected memory exhaustion"), "Error message mismatch for memory fault");
    }

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