//! Integration tests for alternative compression algorithms
//!
//! Tests Brotli, LZ4, and adaptive compression functionality
//! with various data types and configurations.

use ruzip::compression::{
    AdaptiveCompressionEngine, BrotliEngine, CompressionLevel, Compressor, Lz4Engine,
    PerformanceProfile, CompressionAlgorithm, FileType,
};
use std::io::Cursor;
use tempfile::NamedTempFile;
use std::io::{Write, Read, Seek, SeekFrom};

/// Test data for compression algorithms
struct TestData;

impl TestData {
    fn text_data() -> Vec<u8> {
        b"Hello, World! This is a test string for compression algorithms. \
          It contains repeated patterns and should compress well with most algorithms. \
          Lorem ipsum dolor sit amet, consectetur adipiscing elit. ".repeat(100)
    }

    fn json_data() -> Vec<u8> {
        br#"{"users":[{"name":"Alice","age":30,"active":true},{"name":"Bob","age":25,"active":false}]}"#.repeat(50)
    }

    fn binary_data() -> Vec<u8> {
        (0..=255u8).cycle().take(10000).collect()
    }

    fn repetitive_data() -> Vec<u8> {
        b"ABCD".repeat(2500) // 10KB of repeated pattern
    }

    fn random_data() -> Vec<u8> {
        // Simulate high-entropy data
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut data = Vec::with_capacity(10000);
        let mut hasher = DefaultHasher::new();
        
        for i in 0..10000 {
            i.hash(&mut hasher);
            data.push((hasher.finish() & 0xFF) as u8);
        }
        data
    }
}

#[cfg(feature = "brotli-support")]
mod brotli_tests {
    use super::*;

    #[test]
    fn test_brotli_compression_roundtrip() {
        let engine = BrotliEngine::new();
        let input_data = TestData::text_data();
        let level = CompressionLevel::new(6).unwrap();

        // Compress
        let mut input = Cursor::new(&input_data);
        let mut compressed = Cursor::new(Vec::new());
        let compress_stats = engine.compress(&mut input, &mut compressed, level).unwrap();

        assert_eq!(compress_stats.original_size, input_data.len() as u64);
        assert!(compress_stats.compressed_size > 0);
        assert!(compress_stats.compressed_size < input_data.len() as u64);

        // Decompress
        compressed.set_position(0);
        let mut decompressed = Cursor::new(Vec::new());
        let decompress_stats = engine.decompress(&mut compressed, &mut decompressed).unwrap();

        // Verify round-trip
        assert_eq!(decompressed.into_inner(), input_data);
        assert_eq!(decompress_stats.original_size, input_data.len() as u64);
    }

    #[test]
    fn test_brotli_different_quality_levels() {
        let input_data = TestData::text_data();
        
        let mut compression_ratios = Vec::new();
        
        for level_value in [1, 6, 11, 22] {
            let engine = BrotliEngine::new();
            let level = CompressionLevel::new(level_value).unwrap();
            
            let mut input = Cursor::new(&input_data);
            let mut compressed = Cursor::new(Vec::new());
            let stats = engine.compress(&mut input, &mut compressed, level).unwrap();
            
            compression_ratios.push((level_value, stats.ratio));
        }
        
        // Higher levels should generally achieve better compression
        // (though this isn't guaranteed for all data types)
        assert!(compression_ratios.len() == 4);
        
        // Verify all compressions completed successfully
        for (level, ratio) in compression_ratios {
            assert!(ratio > 0.0 && ratio <= 1.0, "Invalid ratio {} for level {}", ratio, level);
        }
    }

    #[test]
    fn test_brotli_text_mode_optimization() {
        let engine = BrotliEngine::new();
        let text_data = TestData::text_data();
        let level = CompressionLevel::new(6).unwrap();

        // Test that text data compresses well
        let mut input = Cursor::new(&text_data);
        let mut compressed = Cursor::new(Vec::new());
        let stats = engine.compress(&mut input, &mut compressed, level).unwrap();

        // Text should compress to less than 50% of original size
        assert!(stats.ratio < 0.5, "Text compression ratio {} is not good enough", stats.ratio);
    }

    #[test]
    fn test_brotli_json_compression() {
        let engine = BrotliEngine::new();
        let json_data = TestData::json_data();
        let level = CompressionLevel::new(9).unwrap();

        let mut input = Cursor::new(&json_data);
        let mut compressed = Cursor::new(Vec::new());
        let stats = engine.compress(&mut input, &mut compressed, level).unwrap();

        // JSON should compress very well due to repetitive structure
        assert!(stats.ratio < 0.3, "JSON compression ratio {} is not good enough", stats.ratio);

        // Verify decompression
        compressed.set_position(0);
        let mut decompressed = Cursor::new(Vec::new());
        engine.decompress(&mut compressed, &mut decompressed).unwrap();
        assert_eq!(decompressed.into_inner(), json_data);
    }
}

#[cfg(feature = "lz4-support")]
mod lz4_tests {
    use super::*;

    #[test]
    fn test_lz4_compression_roundtrip() {
        let engine = Lz4Engine::new();
        let input_data = TestData::text_data();
        let level = CompressionLevel::new(6).unwrap();

        // Compress
        let mut input = Cursor::new(&input_data);
        let mut compressed = Cursor::new(Vec::new());
        let compress_stats = engine.compress(&mut input, &mut compressed, level).unwrap();

        assert_eq!(compress_stats.original_size, input_data.len() as u64);
        assert!(compress_stats.compressed_size > 0);

        // Decompress
        compressed.set_position(0);
        let mut decompressed = Cursor::new(Vec::new());
        let decompress_stats = engine.decompress(&mut compressed, &mut decompressed).unwrap();

        // Verify round-trip
        assert_eq!(decompressed.into_inner(), input_data);
        assert_eq!(decompress_stats.original_size, input_data.len() as u64);
    }

    #[test]
    fn test_lz4_speed_vs_compression_levels() {
        let input_data = TestData::repetitive_data();
        
        let mut results = Vec::new();
        
        // Test different compression levels
        for level_value in [1, 6, 12, 22] {
            let engine = Lz4Engine::new();
            let level = CompressionLevel::new(level_value).unwrap();
            
            let start = std::time::Instant::now();
            let mut input = Cursor::new(&input_data);
            let mut compressed = Cursor::new(Vec::new());
            let stats = engine.compress(&mut input, &mut compressed, level).unwrap();
            let duration = start.elapsed();
            
            results.push((level_value, stats.ratio, duration.as_millis()));
        }
        
        // Verify all compressions completed
        assert_eq!(results.len(), 4);
        
        // LZ4 should be very fast (< 100ms for 10KB)
        for (level, ratio, duration_ms) in results {
            assert!(duration_ms < 100, "LZ4 level {} took {}ms, too slow", level, duration_ms);
            assert!(ratio > 0.0 && ratio <= 1.0, "Invalid ratio {} for level {}", ratio, level);
        }
    }

    #[test]
    fn test_lz4_block_independence() {
        let engine = Lz4Engine::new().with_block_independence(true);
        let input_data = TestData::binary_data();
        let level = CompressionLevel::new(6).unwrap();

        let mut input = Cursor::new(&input_data);
        let mut compressed = Cursor::new(Vec::new());
        let stats = engine.compress(&mut input, &mut compressed, level).unwrap();

        // Verify compression completed
        assert!(stats.compressed_size > 0);
        assert_eq!(stats.original_size, input_data.len() as u64);

        // Verify decompression
        compressed.set_position(0);
        let mut decompressed = Cursor::new(Vec::new());
        engine.decompress(&mut compressed, &mut decompressed).unwrap();
        assert_eq!(decompressed.into_inner(), input_data);
    }

    #[test]
    fn test_lz4_different_block_sizes() {
        let input_data = TestData::text_data();
        let level = CompressionLevel::new(6).unwrap();
        
        let block_sizes = [16 * 1024, 64 * 1024, 256 * 1024];
        
        for block_size in block_sizes {
            let engine = Lz4Engine::new().with_block_size(block_size);
            
            let mut input = Cursor::new(&input_data);
            let mut compressed = Cursor::new(Vec::new());
            let stats = engine.compress(&mut input, &mut compressed, level).unwrap();
            
            assert!(stats.compressed_size > 0);
            
            // Verify decompression
            compressed.set_position(0);
            let mut decompressed = Cursor::new(Vec::new());
            engine.decompress(&mut compressed, &mut decompressed).unwrap();
            assert_eq!(decompressed.into_inner(), input_data);
        }
    }
}

mod adaptive_tests {
    use super::*;

    #[test]
    fn test_adaptive_file_type_detection() {
        let engine = AdaptiveCompressionEngine::new();

        // Test text detection
        let text_data = b"Hello, World! This is plain text content.";
        assert_eq!(engine.detect_file_type(text_data), FileType::Text);

        // Test JSON detection
        let json_data = br#"{"key": "value", "number": 42}"#;
        assert_eq!(engine.detect_file_type(json_data), FileType::StructuredText);

        // Test XML detection
        let xml_data = b"<?xml version=\"1.0\"?><root><item>test</item></root>";
        assert_eq!(engine.detect_file_type(xml_data), FileType::StructuredText);

        // Test source code detection
        let rust_code = b"fn main() {\n    println!(\"Hello, world!\");\n}";
        assert_eq!(engine.detect_file_type(rust_code), FileType::SourceCode);

        // Test binary detection
        let binary_data = &[0xFF, 0xFE, 0x00, 0x01, 0x80, 0x90];
        assert_eq!(engine.detect_file_type(binary_data), FileType::Binary);
    }

    #[test]
    fn test_adaptive_entropy_calculation() {
        let engine = AdaptiveCompressionEngine::new();

        // Low entropy (repeated data)
        let low_entropy_data = vec![0u8; 1000];
        let entropy = engine.calculate_entropy(&low_entropy_data);
        assert!(entropy < 1.0, "Low entropy data should have entropy < 1.0, got {}", entropy);

        // High entropy (varied data)
        let high_entropy_data: Vec<u8> = (0..=255).cycle().take(1000).collect();
        let entropy = engine.calculate_entropy(&high_entropy_data);
        assert!(entropy > 6.0, "High entropy data should have entropy > 6.0, got {}", entropy);

        // Medium entropy (text data)
        let text_data = TestData::text_data();
        let entropy = engine.calculate_entropy(&text_data);
        assert!(entropy > 3.0 && entropy < 6.0, "Text data should have medium entropy, got {}", entropy);
    }

    #[test]
    fn test_adaptive_algorithm_selection() {
        let engine = AdaptiveCompressionEngine::new()
            .with_profile(PerformanceProfile::Balanced);

        // Text should prefer Brotli (if available) or ZSTD
        let algorithm = engine.select_algorithm(FileType::Text, 10000, Some(4.0));
        #[cfg(feature = "brotli-support")]
        assert_eq!(algorithm, CompressionAlgorithm::Brotli);
        #[cfg(not(feature = "brotli-support"))]
        assert_eq!(algorithm, CompressionAlgorithm::Zstd);

        // Already compressed files should be stored
        let algorithm = engine.select_algorithm(FileType::Archive, 10000, Some(7.8));
        assert_eq!(algorithm, CompressionAlgorithm::Store);

        // High entropy data should be stored
        let algorithm = engine.select_algorithm(FileType::Binary, 10000, Some(7.9));
        assert_eq!(algorithm, CompressionAlgorithm::Store);

        // Small files should be stored
        let algorithm = engine.select_algorithm(FileType::Text, 500, Some(4.0));
        assert_eq!(algorithm, CompressionAlgorithm::Store);
    }

    #[test]
    fn test_adaptive_performance_profiles() {
        // Fast profile
        let fast_engine = AdaptiveCompressionEngine::new()
            .with_profile(PerformanceProfile::Fast);
        let fast_algo = fast_engine.select_algorithm(FileType::Binary, 10000, Some(4.0));
        
        #[cfg(feature = "lz4-support")]
        assert_eq!(fast_algo, CompressionAlgorithm::Lz4);
        #[cfg(not(feature = "lz4-support"))]
        assert_eq!(fast_algo, CompressionAlgorithm::Zstd);

        // Maximum profile
        let max_engine = AdaptiveCompressionEngine::new()
            .with_profile(PerformanceProfile::Maximum);
        let max_algo = max_engine.select_algorithm(FileType::Text, 10000, Some(4.0));
        
        #[cfg(feature = "brotli-support")]
        assert_eq!(max_algo, CompressionAlgorithm::Brotli);
        #[cfg(not(feature = "brotli-support"))]
        assert_eq!(max_algo, CompressionAlgorithm::Zstd);
    }

    #[test]
    fn test_adaptive_compression_roundtrip() {
        let engine = AdaptiveCompressionEngine::new()
            .with_profile(PerformanceProfile::Balanced);
        let input_data = TestData::text_data();
        let level = CompressionLevel::new(6).unwrap();

        // Compress
        let mut input = Cursor::new(&input_data);
        let mut compressed = Cursor::new(Vec::new());
        let compress_stats = engine.compress(&mut input, &mut compressed, level).unwrap();

        assert_eq!(compress_stats.original_size, input_data.len() as u64);
        assert!(compress_stats.compressed_size > 0);

        // Decompress
        compressed.set_position(0);
        let mut decompressed = Cursor::new(Vec::new());
        let decompress_stats = engine.decompress(&mut compressed, &mut decompressed).unwrap();

        // Verify round-trip
        assert_eq!(decompressed.into_inner(), input_data);
        assert_eq!(decompress_stats.original_size, input_data.len() as u64);
    }

    #[test]
    fn test_adaptive_with_seekable_reader() {
        let engine = AdaptiveCompressionEngine::new()
            .with_profile(PerformanceProfile::Balanced)
            .with_entropy_analysis(true);

        // Create a temporary file with test data
        let mut temp_file = NamedTempFile::new().unwrap();
        let test_data = TestData::json_data();
        temp_file.write_all(&test_data).unwrap();
        temp_file.flush().unwrap();

        // Test analysis with seekable reader
        let mut file = std::fs::File::open(temp_file.path()).unwrap();
        let file_size = test_data.len() as u64;
        
        let (algorithm, file_type, entropy) = engine
            .analyze_and_select(&mut file, file_size)
            .unwrap();

        // Should detect as structured text
        assert_eq!(file_type, FileType::StructuredText);
        
        // Should have entropy value
        assert!(entropy.is_some());
        let entropy_value = entropy.unwrap();
        assert!(entropy_value > 0.0 && entropy_value < 8.0);

        // Should select appropriate algorithm
        #[cfg(feature = "brotli-support")]
        assert_eq!(algorithm, CompressionAlgorithm::Brotli);
        #[cfg(not(feature = "brotli-support"))]
        assert_eq!(algorithm, CompressionAlgorithm::Zstd);
    }

    #[test]
    fn test_adaptive_configuration() {
        let engine = AdaptiveCompressionEngine::new()
            .with_profile(PerformanceProfile::Fast)
            .with_sample_size(4096)
            .with_min_compression_size(2048)
            .with_entropy_analysis(false)
            .with_fallback_algorithm(CompressionAlgorithm::Zstd);

        // Test that small files are stored
        let algorithm = engine.select_algorithm(FileType::Text, 1000, None);
        assert_eq!(algorithm, CompressionAlgorithm::Store);

        // Test that entropy analysis is disabled (no entropy provided)
        let algorithm = engine.select_algorithm(FileType::Text, 10000, None);
        assert_ne!(algorithm, CompressionAlgorithm::Store); // Should not store due to high entropy
    }
}

#[cfg(all(feature = "brotli-support", feature = "lz4-support"))]
mod algorithm_comparison_tests {
    use super::*;

    #[test]
    fn test_compression_ratio_comparison() {
        let test_data = TestData::text_data();
        let level = CompressionLevel::new(11).unwrap(); // High compression
        
        let mut results = Vec::new();

        // Test ZSTD
        let zstd_engine = ruzip::compression::CompressionEngine::new();
        let mut input = Cursor::new(&test_data);
        let mut compressed = Cursor::new(Vec::new());
        let stats = zstd_engine.compress(&mut input, &mut compressed, level).unwrap();
        results.push(("ZSTD", stats.ratio));

        // Test Brotli
        let brotli_engine = BrotliEngine::new();
        let mut input = Cursor::new(&test_data);
        let mut compressed = Cursor::new(Vec::new());
        let stats = brotli_engine.compress(&mut input, &mut compressed, level).unwrap();
        results.push(("Brotli", stats.ratio));

        // Test LZ4
        let lz4_engine = Lz4Engine::new();
        let mut input = Cursor::new(&test_data);
        let mut compressed = Cursor::new(Vec::new());
        let stats = lz4_engine.compress(&mut input, &mut compressed, level).unwrap();
        results.push(("LZ4", stats.ratio));

        // All algorithms should achieve some compression on text data
        for (algorithm, ratio) in results {
            assert!(ratio < 1.0, "{} should compress text data, got ratio {}", algorithm, ratio);
            assert!(ratio > 0.0, "{} ratio should be positive, got {}", algorithm, ratio);
        }
    }

    #[test]
    fn test_speed_comparison() {
        let test_data = TestData::repetitive_data();
        let level = CompressionLevel::new(6).unwrap();
        
        let mut results = Vec::new();

        // Test LZ4 (should be fastest)
        let lz4_engine = Lz4Engine::new();
        let start = std::time::Instant::now();
        let mut input = Cursor::new(&test_data);
        let mut compressed = Cursor::new(Vec::new());
        lz4_engine.compress(&mut input, &mut compressed, level).unwrap();
        let lz4_duration = start.elapsed();
        results.push(("LZ4", lz4_duration.as_millis()));

        // Test ZSTD
        let zstd_engine = ruzip::compression::CompressionEngine::new();
        let start = std::time::Instant::now();
        let mut input = Cursor::new(&test_data);
        let mut compressed = Cursor::new(Vec::new());
        zstd_engine.compress(&mut input, &mut compressed, level).unwrap();
        let zstd_duration = start.elapsed();
        results.push(("ZSTD", zstd_duration.as_millis()));

        // Test Brotli
        let brotli_engine = BrotliEngine::new();
        let start = std::time::Instant::now();
        let mut input = Cursor::new(&test_data);
        let mut compressed = Cursor::new(Vec::new());
        brotli_engine.compress(&mut input, &mut compressed, level).unwrap();
        let brotli_duration = start.elapsed();
        results.push(("Brotli", brotli_duration.as_millis()));

        // LZ4 should generally be the fastest
        // (Though exact timing depends on system and data)
        for (algorithm, duration_ms) in results {
            assert!(duration_ms < 1000, "{} took {}ms, seems too slow", algorithm, duration_ms);
        }
    }
}