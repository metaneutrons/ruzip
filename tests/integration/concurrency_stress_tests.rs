//! Concurrency and Stress Tests for ruzip archive operations

#[cfg(test)]
mod tests {
    use ruzip::archive::{ArchiveReader, ArchiveOptions, ArchiveWriter};
    use ruzip::compression::{CompressionLevel, CompressionMethod};
    use ruzip::error::Result;
    use ruzip::threading::ThreadConfig;
    use std::collections::HashMap;
    use std::fs;
    use std::io::{Cursor, Read, Write};
    use std::path::{Path, PathBuf};
    use std::sync::Arc;
    use tempfile::TempDir;
    use tokio::task::JoinHandle;

    // Helper function to create a set of unique files in a directory
    fn create_test_files(
        base_dir: &Path,
        num_files: usize,
        prefix: &str,
    ) -> Result<HashMap<String, Vec<u8>>> {
        let mut files_map = HashMap::new();
        for i in 0..num_files {
            let filename = format!("{}_file_{}.txt", prefix, i);
            let file_path = base_dir.join(&filename);
            let content = format!("Content for {} file {}", prefix, i).into_bytes();
            fs::write(&file_path, &content)?;
            files_map.insert(filename, content);
        }
        Ok(files_map)
    }

    // Helper function to verify extracted files against an expected map
    fn verify_extracted_files(
        extract_dir: &Path,
        expected_files: &HashMap<String, Vec<u8>>,
    ) -> Result<()> {
        for (filename, expected_content) in expected_files {
            let extracted_file_path = extract_dir.join(filename);
            assert!(extracted_file_path.exists(), "File {} does not exist", filename);
            let content = fs::read(&extracted_file_path)?;
            assert_eq!(content, *expected_content, "Content mismatch for file {}", filename);
        }
        let entries = fs::read_dir(extract_dir)?.count();
        assert_eq!(entries, expected_files.len(), "Mismatch in number of extracted files");
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_archive_creation() -> Result<()> {
        let num_concurrent_tasks = 4;
        let files_per_archive = 5;
        let mut tasks: Vec<JoinHandle<Result<(Vec<u8>, HashMap<String, Vec<u8>>)>>> = Vec::new();

        for i in 0..num_concurrent_tasks {
            let task_id = format!("task_{}", i);
            let handle = tokio::spawn(async move {
                let temp_dir = TempDir::new()?;
                let expected_files =
                    create_test_files(temp_dir.path(), files_per_archive, &task_id)?;

                let archive_buffer = Vec::new();
                let cursor = Cursor::new(archive_buffer);
                let options = ArchiveOptions {
                    compression_method: CompressionMethod::Zstd, // Or make it configurable
                    ..Default::default()
                };

                let mut writer = ArchiveWriter::new(cursor, options)?;
                for (filename, _) in &expected_files {
                    let file_path = temp_dir.path().join(filename);
                    writer.add_file(&file_path, Some(filename.clone()))?;
                }
                let archive_cursor = writer.finalize()?;
                let archive_data = archive_cursor.into_inner();

                Ok((archive_data, expected_files))
            });
            tasks.push(handle);
        }

        for handle in tasks {
            let result = handle.await.expect("Tokio task panicked");
            assert!(result.is_ok(), "Archive creation task failed: {:?}", result.err());
            let (archive_data, expected_files) = result.unwrap();

            assert!(!archive_data.is_empty(), "Archive data should not be empty");

            // Verify the created archive
            let read_cursor = Cursor::new(&archive_data);
            let mut reader = ArchiveReader::new(read_cursor)?;

            let info = reader.info()?;
            assert_eq!(info.entry_count, files_per_archive as u64);

            let extract_dir = TempDir::new()?;
            reader.extract_all(extract_dir.path())?;
            verify_extracted_files(extract_dir.path(), &expected_files)?;
        }
        Ok(())
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn test_concurrent_archive_extraction() -> Result<()> {
        let num_concurrent_tasks = 4;
        let files_per_archive = 5;
        let mut sample_archives: Vec<(Arc<Vec<u8>>, Arc<HashMap<String, Vec<u8>>>)> = Vec::new();

        // 1. Create sample archives first
        for i in 0..num_concurrent_tasks {
            let task_id = format!("sample_archive_{}", i);
            let temp_dir = TempDir::new()?;
            let expected_files =
                create_test_files(temp_dir.path(), files_per_archive, &task_id)?;

            let archive_buffer = Vec::new();
            let cursor = Cursor::new(archive_buffer);
            let options = ArchiveOptions {
                compression_method: CompressionMethod::Zstd,
                ..Default::default()
            };

            let mut writer = ArchiveWriter::new(cursor, options)?;
            for (filename, _) in &expected_files {
                let file_path = temp_dir.path().join(filename);
                writer.add_file(&file_path, Some(filename.clone()))?;
            }
            let archive_cursor = writer.finalize()?;
            sample_archives.push((
                Arc::new(archive_cursor.into_inner()),
                Arc::new(expected_files),
            ));
        }

        // 2. Spawn tasks to extract these archives concurrently
        let mut tasks: Vec<JoinHandle<Result<()>>> = Vec::new();
        for (archive_data_arc, expected_files_arc) in sample_archives {
            let handle = tokio::spawn(async move {
                let extract_dir = TempDir::new()?;
                let read_cursor = Cursor::new(archive_data_arc.as_slice());
                let mut reader = ArchiveReader::new(read_cursor)?;

                reader.extract_all(extract_dir.path())?;
                verify_extracted_files(extract_dir.path(), &expected_files_arc)?;
                Ok(())
            });
            tasks.push(handle);
        }

        for handle in tasks {
            let result = handle.await.expect("Tokio task panicked during extraction");
            assert!(result.is_ok(), "Archive extraction task failed: {:?}", result.err());
        }
        Ok(())
    }

    // Helper to create a nested directory structure
    fn create_nested_directory_structure(
        base_path: &Path,
        current_depth: u32,
        max_depth: u32,
        files_per_dir: u32,
        dirs_per_dir: u32,
        file_list: &mut HashMap<PathBuf, Vec<u8>>,
    ) -> Result<()> {
        if current_depth >= max_depth {
            return Ok(());
        }

        for i in 0..files_per_dir {
            let filename = format!("file_d{}_n{}.txt", current_depth, i);
            let file_path = base_path.join(&filename);
            let content = format!("Content for {}", filename).into_bytes();
            fs::write(&file_path, &content)?;
            // Store path relative to the initial base_path for later verification
            file_list.insert(file_path, content);
        }

        for i in 0..dirs_per_dir {
            let dirname = format!("dir_d{}_n{}", current_depth, i);
            let dir_path = base_path.join(&dirname);
            fs::create_dir(&dir_path)?;
            create_nested_directory_structure(&dir_path, current_depth + 1, max_depth, files_per_dir, dirs_per_dir, file_list)?;
        }
        Ok(())
    }

    // Helper to collect all file paths and their content from a directory
    fn collect_files_from_disk(
        base_dir: &Path,
        root_for_relative_path: &Path,
    ) -> Result<HashMap<PathBuf, Vec<u8>>> {
        let mut files_map = HashMap::new();
        let mut dirs_to_visit = vec![base_dir.to_path_buf()];

        while let Some(dir) = dirs_to_visit.pop() {
            for entry in fs::read_dir(dir)? {
                let entry = entry?;
                let path = entry.path();
                if path.is_dir() {
                    dirs_to_visit.push(path);
                } else {
                    let relative_path = path.strip_prefix(root_for_relative_path).unwrap().to_path_buf();
                    let content = fs::read(&path)?;
                    files_map.insert(relative_path, content);
                }
            }
        }
        Ok(files_map)
    }


    #[tokio::test(flavor = "multi_thread", worker_threads = 4)] // Tokio test for async parts if any, main logic is sync blocking
    async fn test_stress_archive_large_directory() -> Result<()> {
        let source_temp_dir = TempDir::new()?;
        let mut source_files_manifest: HashMap<PathBuf, Vec<u8>> = HashMap::new();

        // Create a moderately large directory structure
        // e.g., 3 levels deep, 5 files/dir, 3 dirs/dir
        // Total files = 5 * (1 + 3 + 3^2) = 5 * (1+3+9) = 5 * 13 = 65 ( manageable for a test)
        // For more stress: 4 levels, 10 files/dir, 3 dirs/dir = 10 * (1+3+9+27) = 10 * 40 = 400 files
        // Let's go with something that generates a few hundred files.
        // Depth 4, 5 files/dir, 3 dirs/dir => 5 * (1+3+9+27) = 200 files.
        // Depth 3, 10 files/dir, 5 dirs/dir => 10 * (1+5+25) = 310 files.
        create_nested_directory_structure(source_temp_dir.path(), 0, 3, 10, 5, &mut source_files_manifest)?;

        // Adjust manifest paths to be relative for verification
        let mut relative_source_manifest = HashMap::new();
        for (abs_path, content) in source_files_manifest {
            relative_source_manifest.insert(
                abs_path.strip_prefix(source_temp_dir.path()).unwrap().to_path_buf(),
                content
            );
        }


        let archive_buffer = Vec::new();
        let cursor = Cursor::new(archive_buffer);
        let options = ArchiveOptions {
            compression_method: CompressionMethod::Zstd,
            compression_level: CompressionLevel::new(1)?, // Faster compression for stress test
            thread_config: Some(ThreadConfig::new().with_thread_count(4)), // Use multiple threads
            ..Default::default()
        };

        let mut writer = ArchiveWriter::new(cursor, options)?;
        // Add the entire directory. The paths stored in archive should be relative to source_temp_dir.path()
        writer.add_directory(source_temp_dir.path(), None)?;
        let archive_cursor = writer.finalize()?;
        let archive_data = archive_cursor.into_inner();

        assert!(!archive_data.is_empty(), "Archive data should not be empty after large dir archival");

        // Extract the archive
        let extract_temp_dir = TempDir::new()?;
        let read_cursor = Cursor::new(&archive_data);
        let mut reader = ArchiveReader::new(read_cursor)?;

        let reader_info = reader.info()?;
        assert_eq!(reader_info.entry_count, relative_source_manifest.len() as u64, "Mismatch in entry count");

        reader.extract_all(extract_temp_dir.path())?;

        // Verify the extracted structure and content
        let extracted_files_manifest = collect_files_from_disk(extract_temp_dir.path(), extract_temp_dir.path())?;

        assert_eq!(extracted_files_manifest.len(), relative_source_manifest.len(), "Mismatch in number of files after extraction");

        for (rel_path, expected_content) in &relative_source_manifest {
            let extracted_content = extracted_files_manifest.get(rel_path).ok_or_else(|| {
                ruzip::error::RuzipError::FileNotFound(format!("Extracted file not found: {:?}", rel_path))
            })?;
            assert_eq!(extracted_content, expected_content, "Content mismatch for file {:?}", rel_path);
        }

        Ok(())
    }
}
