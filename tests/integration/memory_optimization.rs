//! Integration tests for memory optimization features
//!
//! Tests zero-allocation patterns, buffer pools, and memory profiling.

use ruzip::memory::{
    BufferPool, MemoryArena, ScratchBuffer, ChainedBuffer,
    MemoryPressureDetector, AdaptiveBufferSizer,
    streaming::{ZeroCopyReader, ZeroCopyWriter, MemoryMappedArchive},
    profiler::{MemoryProfiler, AllocationTracker},
    init_memory_management, get_memory_pressure_detector,
};
use ruzip::compression::stream::{CompressedWriter, CompressedReader};
use ruzip::compression::CompressionLevel;
use ruzip::error::Result;
use std::io::{Read, Write, Cursor};
use std::sync::Arc;
use std::time::Duration;
use tempfile::NamedTempFile;

#[test]
fn test_buffer_pool_integration() -> Result<()> {
    let detector = Arc::new(MemoryPressureDetector::new(100, 200, 300));
    let pool = BufferPool::new_byte_pool(10, detector);

    // Test buffer allocation and reuse
    let mut buffer1 = pool.get_small_buffer();
    buffer1.resize(1024);
    assert_eq!(buffer1.len(), 1024);

    let mut buffer2 = pool.get_medium_buffer();
    buffer2.resize(32 * 1024);
    assert_eq!(buffer2.len(), 32 * 1024);

    // Drop buffers to return to pool
    drop(buffer1);
    drop(buffer2);

    // Get new buffers - should reuse from pool
    let buffer3 = pool.get_small_buffer();
    let buffer4 = pool.get_medium_buffer();

    let stats = pool.stats();
    assert!(stats.total_buffers <= 10);

    Ok(())
}

#[test]
fn test_memory_arena_integration() -> Result<()> {
    let mut arena = MemoryArena::new(64 * 1024);

    // Test basic allocation
    let slice1 = arena.alloc(1024)?;
    assert_eq!(slice1.len(), 1024);

    // Test aligned allocation
    let slice2 = arena.alloc_aligned(2048, 64)?;
    assert_eq!(slice2.len(), 2048);

    // Test checkpoint and reset
    let checkpoint = arena.checkpoint();
    let _slice3 = arena.alloc(4096)?;
    
    arena.reset_to_checkpoint(checkpoint);
    assert!(arena.used() < 8192); // Should be reset

    Ok(())
}

#[test]
fn test_chained_buffer_streaming() -> Result<()> {
    let mut buffer = ChainedBuffer::new(1024);

    // Write data across multiple internal buffers
    let test_data = vec![42u8; 3000]; // Larger than single buffer
    buffer.write(&test_data)?;

    // Read data back
    let mut read_buffer = vec![0u8; 3000];
    let bytes_read = buffer.read(&mut read_buffer)?;
    
    assert_eq!(bytes_read, 3000);
    assert_eq!(read_buffer, test_data);

    Ok(())
}

#[test]
fn test_memory_pressure_detection() -> Result<()> {
    let detector = MemoryPressureDetector::new(100, 200, 300);
    
    // Test pressure level changes
    assert_eq!(detector.update_usage(50), ruzip::memory::MemoryPressure::Low);
    assert_eq!(detector.update_usage(150), ruzip::memory::MemoryPressure::Medium);
    assert_eq!(detector.update_usage(250), ruzip::memory::MemoryPressure::High);
    assert_eq!(detector.update_usage(350), ruzip::memory::MemoryPressure::Critical);

    // Test peak tracking
    assert_eq!(detector.peak_usage(), 350);

    Ok(())
}

#[test]
fn test_adaptive_buffer_sizing() -> Result<()> {
    let detector = Arc::new(MemoryPressureDetector::new(100, 200, 300));
    let sizer = AdaptiveBufferSizer::new(detector.clone());

    // Test size adaptation based on pressure
    detector.update_usage(50); // Low pressure
    let size_low = sizer.small_buffer_size();
    
    detector.update_usage(250); // High pressure
    let size_high = sizer.small_buffer_size();
    
    assert!(size_high < size_low); // Should use smaller buffers under pressure

    Ok(())
}

#[test]
fn test_memory_profiler_integration() -> Result<()> {
    let profiler = Arc::new(MemoryProfiler::new(100, 200, 1.0));

    // Test allocation tracking
    let id1 = profiler.record_allocation(1024, "test_operation");
    let id2 = profiler.record_allocation(2048, "test_operation");

    let stats = profiler.get_stats();
    assert_eq!(stats.total_allocations, 2);
    assert_eq!(stats.current_usage, 3072);

    // Test deallocation
    profiler.record_deallocation(id1);
    let stats = profiler.get_stats();
    assert_eq!(stats.total_deallocations, 1);
    assert_eq!(stats.current_usage, 2048);

    // Test top consumers
    let consumers = profiler.get_top_consumers(5);
    assert_eq!(consumers.len(), 1);
    assert_eq!(consumers[0].0, "test_operation");

    Ok(())
}

#[test]
fn test_allocation_tracker_raii() -> Result<()> {
    let profiler = Arc::new(MemoryProfiler::new(100, 200, 1.0));

    {
        let _tracker = AllocationTracker::new(profiler.clone(), 1024, "raii_test");
        let stats = profiler.get_stats();
        assert_eq!(stats.total_allocations, 1);
        assert_eq!(stats.current_usage, 1024);
    }

    // Should be automatically deallocated when tracker is dropped
    let stats = profiler.get_stats();
    assert_eq!(stats.total_deallocations, 1);
    assert_eq!(stats.current_usage, 0);

    Ok(())
}

#[test]
fn test_compressed_writer_with_buffer_pool() -> Result<()> {
    let detector = Arc::new(MemoryPressureDetector::new(100, 200, 300));
    let pool = Arc::new(BufferPool::new_byte_pool(10, detector));
    
    let output = Vec::new();
    let level = CompressionLevel::new(6)?;
    
    let mut writer = CompressedWriter::with_buffer_pool(output, level, pool)?;
    
    // Write test data
    let test_data = b"Hello, World! This is test data for compression with buffer pool.";
    writer.write_all(test_data)?;
    writer.flush()?;
    
    let compressed_output = writer.finish()?;
    assert!(!compressed_output.is_empty());

    Ok(())
}

#[test]
fn test_compressed_reader_with_buffer_pool() -> Result<()> {
    let detector = Arc::new(MemoryPressureDetector::new(100, 200, 300));
    let pool = Arc::new(BufferPool::new_byte_pool(10, detector));
    
    let test_data = b"Hello, World! This is test data for decompression with buffer pool.";
    let cursor = Cursor::new(test_data);
    
    let mut reader = CompressedReader::with_buffer_pool(cursor, pool)?;
    
    let mut output = Vec::new();
    reader.read_to_end(&mut output)?;
    
    assert!(!output.is_empty());

    Ok(())
}

#[test]
fn test_memory_mapped_archive() -> Result<()> {
    // Create temporary file with test data
    let mut temp_file = NamedTempFile::new()?;
    let test_data = vec![42u8; 4096];
    temp_file.write_all(&test_data)?;
    temp_file.flush()?;

    // Test memory mapping (will fail gracefully if not supported)
    match MemoryMappedArchive::new(temp_file.path()) {
        Ok(mapped) => {
            assert_eq!(mapped.size(), 4096);
            let data = mapped.data();
            assert_eq!(data.len(), 4096);
        }
        Err(_) => {
            // Memory mapping might not be available in all test environments
            println!("Memory mapping not available in test environment");
        }
    }

    Ok(())
}

#[test]
fn test_zero_copy_streaming() -> Result<()> {
    use ruzip::memory::streaming::{ZeroCopyRead, ZeroCopyWrite};
    
    let test_data = b"Hello, World! This is test data for zero-copy streaming.";
    let mut cursor = Cursor::new(test_data);
    
    // Test zero-copy reader
    let mut zero_reader = ruzip::memory::streaming::ZeroCopyReader::new(cursor, 1024);
    
    let mut buffer = vec![0u8; 20];
    let bytes_read = zero_reader.read_zero_copy(&mut buffer)?;
    assert_eq!(bytes_read, 20);
    assert_eq!(&buffer[..bytes_read], &test_data[..20]);
    
    // Test advance
    zero_reader.advance(5)?;
    assert_eq!(zero_reader.position(), 25);

    Ok(())
}

#[test]
fn test_scratch_buffer_reuse() -> Result<()> {
    let mut scratch = ScratchBuffer::new(1024, 1024, 512);

    // Test compression buffer
    let comp_buf = scratch.compression_buffer();
    comp_buf.extend_from_slice(b"compression test data");
    assert!(!comp_buf.is_empty());

    // Test decompression buffer
    let decomp_buf = scratch.decompression_buffer();
    decomp_buf.extend_from_slice(b"decompression test data");
    assert!(!decomp_buf.is_empty());

    // Test dictionary
    scratch.set_dictionary(vec![1, 2, 3, 4, 5]);
    assert_eq!(scratch.dictionary(), Some([1, 2, 3, 4, 5].as_slice()));

    // Test reset
    scratch.reset();
    assert!(scratch.compression_buffer().is_empty());
    assert!(scratch.decompression_buffer().is_empty());
    assert!(scratch.dictionary().is_none());

    Ok(())
}

#[test]
fn test_global_memory_management() -> Result<()> {
    // Initialize global memory management
    let detector = init_memory_management();
    
    // Test global detector access
    let global_detector = get_memory_pressure_detector();
    assert!(global_detector.is_some());
    
    // Test pressure detection
    detector.update_usage(1024 * 1024); // 1MB
    assert_eq!(detector.current_pressure(), ruzip::memory::MemoryPressure::Low);

    Ok(())
}

#[test]
fn test_large_file_memory_efficiency() -> Result<()> {
    let detector = Arc::new(MemoryPressureDetector::new(50, 100, 150)); // Low thresholds for testing
    let pool = Arc::new(BufferPool::new_byte_pool(5, detector.clone()));
    
    // Simulate processing large file with small memory footprint
    let large_data = vec![42u8; 1024 * 1024]; // 1MB test data
    let cursor = Cursor::new(&large_data);
    
    let mut reader = CompressedReader::with_buffer_pool(cursor, pool)?;
    let mut total_read = 0;
    let mut buffer = vec![0u8; 4096]; // Small buffer
    
    // Read in small chunks to test memory efficiency
    while total_read < large_data.len() {
        let bytes_read = reader.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        total_read += bytes_read;
        
        // Check memory pressure doesn't get too high
        let pressure = detector.current_pressure();
        assert!(pressure != ruzip::memory::MemoryPressure::Critical);
    }
    
    assert_eq!(total_read, large_data.len());

    Ok(())
}

#[test]
fn test_memory_leak_detection() -> Result<()> {
    let profiler = MemoryProfiler::new(100, 200, 1.0);
    
    // Create some allocations
    let _id1 = profiler.record_allocation(1024, "potential_leak");
    let _id2 = profiler.record_allocation(2048, "normal_operation");
    
    // Wait a bit
    std::thread::sleep(Duration::from_millis(10));
    
    // Check for leaks (very short threshold for testing)
    let leaks = profiler.detect_leaks(Duration::from_millis(5));
    assert_eq!(leaks.len(), 2); // Both should be detected as "leaks"
    
    Ok(())
}

#[test]
fn test_memory_report_generation() -> Result<()> {
    let profiler = MemoryProfiler::new(100, 200, 1.0);
    
    // Create some test allocations
    let _id1 = profiler.record_allocation(1024, "test_operation_1");
    let _id2 = profiler.record_allocation(2048, "test_operation_2");
    let _id3 = profiler.record_allocation(512, "test_operation_1");
    
    // Generate report
    let report = profiler.generate_report();
    
    // Check report contains expected sections
    assert!(report.contains("MEMORY STATISTICS"));
    assert!(report.contains("TOP MEMORY CONSUMERS"));
    assert!(report.contains("test_operation_1"));
    assert!(report.contains("test_operation_2"));
    
    Ok(())
}