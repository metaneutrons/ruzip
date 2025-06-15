//! Compression algorithm comparison benchmarks
//!
//! Benchmarks different compression algorithms (ZSTD, Brotli, LZ4)
//! across various file types and sizes to measure performance trade-offs.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use ruzip::compression::{
    AdaptiveCompressionEngine, BrotliEngine, CompressionLevel, Compressor, Lz4Engine,
    PerformanceProfile,
};
use ruzip::compression::engine::CompressionEngine;
use std::io::Cursor;

/// Test data generators for different file types
struct TestDataGenerator;

impl TestDataGenerator {
    /// Generate text data (high compressibility)
    fn generate_text_data(size: usize) -> Vec<u8> {
        let base_text = "Lorem ipsum dolor sit amet, consectetur adipiscing elit. \
                         Sed do eiusmod tempor incididunt ut labore et dolore magna aliqua. \
                         Ut enim ad minim veniam, quis nostrud exercitation ullamco laboris. ";
        
        let mut data = Vec::with_capacity(size);
        while data.len() < size {
            data.extend_from_slice(base_text.as_bytes());
        }
        data.truncate(size);
        data
    }

    /// Generate JSON data (structured text)
    fn generate_json_data(size: usize) -> Vec<u8> {
        let base_json = r#"{"name":"John Doe","age":30,"city":"New York","items":[1,2,3,4,5],"active":true}"#;
        
        let mut data = Vec::with_capacity(size);
        data.push(b'[');
        
        let mut first = true;
        while data.len() < size - 1 {
            if !first {
                data.push(b',');
            }
            data.extend_from_slice(base_json.as_bytes());
            first = false;
        }
        data.push(b']');
        data.truncate(size);
        data
    }

    /// Generate binary data (low compressibility)
    fn generate_binary_data(size: usize) -> Vec<u8> {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut data = Vec::with_capacity(size);
        let mut hasher = DefaultHasher::new();
        
        for i in 0..size {
            i.hash(&mut hasher);
            data.push((hasher.finish() & 0xFF) as u8);
        }
        data
    }

    /// Generate repetitive data (very high compressibility)
    fn generate_repetitive_data(size: usize) -> Vec<u8> {
        let pattern = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        let mut data = Vec::with_capacity(size);
        
        while data.len() < size {
            data.extend_from_slice(pattern);
        }
        data.truncate(size);
        data
    }

    /// Generate source code data
    fn generate_source_code_data(size: usize) -> Vec<u8> {
        let base_code = r#"
fn fibonacci(n: u64) -> u64 {
    match n {
        0 => 0,
        1 => 1,
        _ => fibonacci(n - 1) + fibonacci(n - 2),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_fibonacci() {
        assert_eq!(fibonacci(0), 0);
        assert_eq!(fibonacci(1), 1);
        assert_eq!(fibonacci(10), 55);
    }
}
"#;
        
        let mut data = Vec::with_capacity(size);
        while data.len() < size {
            data.extend_from_slice(base_code.as_bytes());
        }
        data.truncate(size);
        data
    }
}

/// Benchmark compression algorithms on different data types
fn bench_compression_algorithms(c: &mut Criterion) {
    let sizes = vec![1024, 10 * 1024, 100 * 1024, 1024 * 1024]; // 1KB to 1MB
    let level = CompressionLevel::new(6).unwrap(); // Balanced level

    for size in sizes {
        let mut group = c.benchmark_group(format!("compression_{}KB", size / 1024));
        group.throughput(Throughput::Bytes(size as u64));

        // Test different data types
        let test_cases = vec![
            ("text", TestDataGenerator::generate_text_data(size)),
            ("json", TestDataGenerator::generate_json_data(size)),
            ("binary", TestDataGenerator::generate_binary_data(size)),
            ("repetitive", TestDataGenerator::generate_repetitive_data(size)),
            ("source_code", TestDataGenerator::generate_source_code_data(size)),
        ];

        for (data_type, data) in test_cases {
            // ZSTD compression
            group.bench_with_input(
                BenchmarkId::new("zstd", data_type),
                &data,
                |b, data| {
                    let engine = CompressionEngine::new();
                    b.iter(|| {
                        let mut input = Cursor::new(data);
                        let mut output = Cursor::new(Vec::new());
                        black_box(engine.compress(&mut input, &mut output, level).unwrap());
                    });
                },
            );

            // Brotli compression (if available)
            #[cfg(feature = "brotli-support")]
            group.bench_with_input(
                BenchmarkId::new("brotli", data_type),
                &data,
                |b, data| {
                    let engine = BrotliEngine::new();
                    b.iter(|| {
                        let mut input = Cursor::new(data);
                        let mut output = Cursor::new(Vec::new());
                        black_box(engine.compress(&mut input, &mut output, level).unwrap());
                    });
                },
            );

            // LZ4 compression (if available)
            #[cfg(feature = "lz4-support")]
            group.bench_with_input(
                BenchmarkId::new("lz4", data_type),
                &data,
                |b, data| {
                    let engine = Lz4Engine::new();
                    b.iter(|| {
                        let mut input = Cursor::new(data);
                        let mut output = Cursor::new(Vec::new());
                        black_box(engine.compress(&mut input, &mut output, level).unwrap());
                    });
                },
            );

            // Adaptive compression
            group.bench_with_input(
                BenchmarkId::new("adaptive_balanced", data_type),
                &data,
                |b, data| {
                    let engine = AdaptiveCompressionEngine::new()
                        .with_profile(PerformanceProfile::Balanced);
                    b.iter(|| {
                        let mut input = Cursor::new(data);
                        let mut output = Cursor::new(Vec::new());
                        black_box(engine.compress(&mut input, &mut output, level).unwrap());
                    });
                },
            );

            // Adaptive compression - fast profile
            group.bench_with_input(
                BenchmarkId::new("adaptive_fast", data_type),
                &data,
                |b, data| {
                    let engine = AdaptiveCompressionEngine::new()
                        .with_profile(PerformanceProfile::Fast);
                    b.iter(|| {
                        let mut input = Cursor::new(data);
                        let mut output = Cursor::new(Vec::new());
                        black_box(engine.compress(&mut input, &mut output, level).unwrap());
                    });
                },
            );
        }

        group.finish();
    }
}

/// Benchmark compression ratios across algorithms
fn bench_compression_ratios(c: &mut Criterion) {
    let mut group = c.benchmark_group("compression_ratios");
    let size = 100 * 1024; // 100KB test
    let level = CompressionLevel::new(11).unwrap(); // High compression

    let test_data = vec![
        ("text", TestDataGenerator::generate_text_data(size)),
        ("json", TestDataGenerator::generate_json_data(size)),
        ("source_code", TestDataGenerator::generate_source_code_data(size)),
    ];

    for (data_type, data) in test_data {
        // Measure actual compression ratios
        group.bench_function(&format!("ratio_analysis_{}", data_type), |b| {
            b.iter(|| {
                let mut results = Vec::new();

                // ZSTD
                let engine = CompressionEngine::new();
                let mut input = Cursor::new(&data);
                let mut output = Cursor::new(Vec::new());
                let stats = engine.compress(&mut input, &mut output, level).unwrap();
                results.push(("zstd", stats.ratio));

                // Brotli
                #[cfg(feature = "brotli-support")]
                {
                    let engine = BrotliEngine::new();
                    let mut input = Cursor::new(&data);
                    let mut output = Cursor::new(Vec::new());
                    let stats = engine.compress(&mut input, &mut output, level).unwrap();
                    results.push(("brotli", stats.ratio));
                }

                // LZ4
                #[cfg(feature = "lz4-support")]
                {
                    let engine = Lz4Engine::new();
                    let mut input = Cursor::new(&data);
                    let mut output = Cursor::new(Vec::new());
                    let stats = engine.compress(&mut input, &mut output, level).unwrap();
                    results.push(("lz4", stats.ratio));
                }

                black_box(results);
            });
        });
    }

    group.finish();
}

/// Benchmark decompression performance
fn bench_decompression_performance(c: &mut Criterion) {
    let mut group = c.benchmark_group("decompression_performance");
    let size = 100 * 1024; // 100KB
    let level = CompressionLevel::new(6).unwrap();

    let test_data = TestDataGenerator::generate_text_data(size);

    // Pre-compress data with different algorithms
    let mut compressed_data = Vec::new();

    // ZSTD
    let engine = CompressionEngine::new();
    let mut input = Cursor::new(&test_data);
    let mut output = Cursor::new(Vec::new());
    engine.compress(&mut input, &mut output, level).unwrap();
    compressed_data.push(("zstd", output.into_inner()));

    // Brotli
    #[cfg(feature = "brotli-support")]
    {
        let engine = BrotliEngine::new();
        let mut input = Cursor::new(&test_data);
        let mut output = Cursor::new(Vec::new());
        engine.compress(&mut input, &mut output, level).unwrap();
        compressed_data.push(("brotli", output.into_inner()));
    }

    // LZ4
    #[cfg(feature = "lz4-support")]
    {
        let engine = Lz4Engine::new();
        let mut input = Cursor::new(&test_data);
        let mut output = Cursor::new(Vec::new());
        engine.compress(&mut input, &mut output, level).unwrap();
        compressed_data.push(("lz4", output.into_inner()));
    }

    // Benchmark decompression
    for (algorithm, data) in compressed_data {
        group.throughput(Throughput::Bytes(data.len() as u64));
        
        group.bench_with_input(
            BenchmarkId::new("decompress", algorithm),
            &data,
            |b, compressed| {
                b.iter(|| {
                    let mut input = Cursor::new(compressed);
                    let mut output = Cursor::new(Vec::new());
                    
                    match algorithm {
                        "zstd" => {
                            let engine = CompressionEngine::new();
                            black_box(engine.decompress(&mut input, &mut output).unwrap());
                        }
                        #[cfg(feature = "brotli-support")]
                        "brotli" => {
                            let engine = BrotliEngine::new();
                            black_box(engine.decompress(&mut input, &mut output).unwrap());
                        }
                        #[cfg(feature = "lz4-support")]
                        "lz4" => {
                            let engine = Lz4Engine::new();
                            black_box(engine.decompress(&mut input, &mut output).unwrap());
                        }
                        _ => {}
                    }
                });
            },
        );
    }

    group.finish();
}

/// Benchmark adaptive algorithm selection overhead
fn bench_adaptive_selection_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("adaptive_selection");
    let sizes = vec![1024, 10 * 1024, 100 * 1024];

    for size in sizes {
        let data = TestDataGenerator::generate_text_data(size);
        
        group.bench_with_input(
            BenchmarkId::new("file_type_detection", size),
            &data,
            |b, data| {
                let engine = AdaptiveCompressionEngine::new();
                b.iter(|| {
                    black_box(engine.detect_file_type(data));
                });
            },
        );

        group.bench_with_input(
            BenchmarkId::new("entropy_calculation", size),
            &data,
            |b, data| {
                let engine = AdaptiveCompressionEngine::new();
                b.iter(|| {
                    black_box(engine.calculate_entropy(data));
                });
            },
        );
    }

    group.finish();
}

criterion_group!(
    compression_benches,
    bench_compression_algorithms,
    bench_compression_ratios,
    bench_decompression_performance,
    bench_adaptive_selection_overhead
);

criterion_main!(compression_benches);