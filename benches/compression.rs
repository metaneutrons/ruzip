//! Compression benchmarks for RuZip Phase 2
//!
//! Tests compression performance across different levels and data types
//! to validate the ≥150 MB/s single-thread performance goal.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use ruzip::compression::{CompressionEngine, CompressionLevel, CompressionMethod, Compressor};
use std::io::Cursor;

/// Generate test data of different types
fn generate_test_data(size: usize, data_type: TestDataType) -> Vec<u8> {
    match data_type {
        TestDataType::Text => {
            // Highly compressible text data
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit. ".repeat(size / 56)
                .into_bytes()
        }
        TestDataType::Binary => {
            // Semi-compressible binary data
            (0..size).map(|i| (i % 256) as u8).collect()
        }
        TestDataType::Random => {
            // Incompressible random data
            use std::collections::hash_map::DefaultHasher;
            use std::hash::{Hash, Hasher};
            
            (0..size).map(|i| {
                let mut hasher = DefaultHasher::new();
                i.hash(&mut hasher);
                (hasher.finish() % 256) as u8
            }).collect()
        }
        TestDataType::AlreadyCompressed => {
            // Simulate already compressed data (PNG-like pattern)
            let mut data = Vec::with_capacity(size);
            for i in 0..size {
                data.push(match i % 4 {
                    0 => 0x89,
                    1 => 0x50,
                    2 => 0x4E,
                    3 => 0x47,
                    _ => unreachable!(),
                });
            }
            data
        }
    }
}

#[derive(Clone, Copy)]
enum TestDataType {
    Text,
    Binary, 
    Random,
    AlreadyCompressed,
}

impl std::fmt::Display for TestDataType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TestDataType::Text => write!(f, "text"),
            TestDataType::Binary => write!(f, "binary"),
            TestDataType::Random => write!(f, "random"),
            TestDataType::AlreadyCompressed => write!(f, "compressed"),
        }
    }
}

/// Benchmark compression at different levels
fn bench_compression_levels(c: &mut Criterion) {
    let mut group = c.benchmark_group("compression_levels");
    
    // Test data sizes: 1MB, 10MB
    let sizes = [1024 * 1024, 10 * 1024 * 1024];
    let levels = [1, 3, 6, 9, 12, 16, 22];
    
    for &size in &sizes {
        group.throughput(Throughput::Bytes(size as u64));
        
        let test_data = generate_test_data(size, TestDataType::Text);
        
        for &level in &levels {
            let level_obj = CompressionLevel::new(level).unwrap();
            
            group.bench_with_input(
                BenchmarkId::new("zstd", format!("{}MB_level{}", size / (1024 * 1024), level)),
                &level,
                |b, _| {
                    let engine = CompressionEngine::new()
                        .with_method(CompressionMethod::Zstd);
                    
                    b.iter(|| {
                        let input = Cursor::new(&test_data);
                        let mut output = Vec::new();
                        
                        let _stats = engine.compress(
                            input,
                            &mut output,
                            black_box(level_obj),
                        ).unwrap();
                        
                        black_box(output);
                    });
                },
            );
        }
    }
    
    group.finish();
}

/// Benchmark different data types
fn bench_data_types(c: &mut Criterion) {
    let mut group = c.benchmark_group("data_types");
    
    let size = 10 * 1024 * 1024; // 10MB
    let level = CompressionLevel::new(6).unwrap(); // Default level
    let data_types = [
        TestDataType::Text,
        TestDataType::Binary,
        TestDataType::Random,
        TestDataType::AlreadyCompressed,
    ];
    
    group.throughput(Throughput::Bytes(size as u64));
    
    for data_type in &data_types {
        let test_data = generate_test_data(size, *data_type);
        
        group.bench_with_input(
            BenchmarkId::new("zstd", data_type.to_string()),
            data_type,
            |b, _| {
                let engine = CompressionEngine::new()
                    .with_method(CompressionMethod::Zstd);
                
                b.iter(|| {
                    let input = Cursor::new(&test_data);
                    let mut output = Vec::new();
                    
                    let _stats = engine.compress(
                        input,
                        &mut output,
                        black_box(level),
                    ).unwrap();
                    
                    black_box(output);
                });
            },
        );
    }
    
    group.finish();
}

/// Benchmark compression ratios
fn bench_compression_ratios(c: &mut Criterion) {
    let mut group = c.benchmark_group("compression_ratios");
    group.sample_size(20); // Fewer samples for ratio testing
    
    let size = 1024 * 1024; // 1MB for ratio testing
    let levels = [1, 6, 12, 22];
    let data_types = [TestDataType::Text, TestDataType::Binary, TestDataType::Random];
    
    for data_type in &data_types {
        let test_data = generate_test_data(size, *data_type);
        
        for &level in &levels {
            let level_obj = CompressionLevel::new(level).unwrap();
            
            group.bench_with_input(
                BenchmarkId::new("ratio", format!("{}_level{}", data_type, level)),
                &level,
                |b, _| {
                    let engine = CompressionEngine::new()
                        .with_method(CompressionMethod::Zstd);
                    
                    b.iter(|| {
                        let input = Cursor::new(&test_data);
                        let mut output = Vec::new();
                        
                        let stats = engine.compress(
                            input,
                            &mut output,
                            black_box(level_obj),
                        ).unwrap();
                        
                        // Validate compression ratios meet targets
                        match data_type {
                            TestDataType::Text => {
                                // Should achieve ≥60% compression (ratio ≤0.4)
                                assert!(stats.ratio <= 0.4, 
                                       "Text compression ratio {:.1}% below target 60%", 
                                       (1.0 - stats.ratio) * 100.0);
                            }
                            TestDataType::Binary => {
                                // Should achieve ≥30% compression (ratio ≤0.7)
                                assert!(stats.ratio <= 0.7,
                                       "Binary compression ratio {:.1}% below target 30%", 
                                       (1.0 - stats.ratio) * 100.0);
                            }
                            TestDataType::Random => {
                                // Should achieve ≥5% compression (ratio ≤0.95)
                                assert!(stats.ratio <= 0.95,
                                       "Random data compression ratio {:.1}% below target 5%", 
                                       (1.0 - stats.ratio) * 100.0);
                            }
                            _ => {}
                        }
                        
                        black_box((output, stats));
                    });
                },
            );
        }
    }
    
    group.finish();
}

/// Benchmark decompression performance
fn bench_decompression(c: &mut Criterion) {
    let mut group = c.benchmark_group("decompression");
    
    let size = 10 * 1024 * 1024; // 10MB
    let level = CompressionLevel::new(6).unwrap();
    let engine = CompressionEngine::new().with_method(CompressionMethod::Zstd);
    
    // Pre-compress test data
    let test_data = generate_test_data(size, TestDataType::Text);
    let input = Cursor::new(&test_data);
    let mut compressed_data = Vec::new();
    let _stats = engine.compress(input, &mut compressed_data, level).unwrap();
    
    group.throughput(Throughput::Bytes(size as u64));
    
    group.bench_function("zstd_decompress", |b| {
        b.iter(|| {
            let input = Cursor::new(&compressed_data);
            let mut output = Vec::new();
            
            let _stats = engine.decompress(input, &mut output).unwrap();
            
            black_box(output);
        });
    });
    
    group.finish();
}

/// Benchmark memory usage under different buffer sizes
fn bench_memory_efficiency(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_efficiency");
    
    let size = 10 * 1024 * 1024; // 10MB
    let level = CompressionLevel::new(6).unwrap();
    let test_data = generate_test_data(size, TestDataType::Text);
    
    let buffer_sizes = [64 * 1024, 256 * 1024, 1024 * 1024, 4 * 1024 * 1024];
    
    for &buffer_size in &buffer_sizes {
        group.bench_with_input(
            BenchmarkId::new("buffer_size", format!("{}KB", buffer_size / 1024)),
            &buffer_size,
            |b, &buf_size| {
                b.iter(|| {
                    let engine = CompressionEngine::new()
                        .with_method(CompressionMethod::Zstd)
                        .with_buffer_size(buf_size);
                    
                    let input = Cursor::new(&test_data);
                    let mut output = Vec::new();
                    
                    let _stats = engine.compress(
                        input,
                        &mut output,
                        black_box(level),
                    ).unwrap();
                    
                    black_box(output);
                });
            },
        );
    }
    
    group.finish();
}

/// Performance validation test
fn bench_performance_targets(c: &mut Criterion) {
    let mut group = c.benchmark_group("performance_targets");
    group.sample_size(50);
    
    let size = 10 * 1024 * 1024; // 10MB
    let level = CompressionLevel::new(3).unwrap(); // Level 3 for ≥150 MB/s target
    let test_data = generate_test_data(size, TestDataType::Text);
    
    group.throughput(Throughput::Bytes(size as u64));
    
    group.bench_function("target_150mbps", |b| {
        let engine = CompressionEngine::new()
            .with_method(CompressionMethod::Zstd);
        
        b.iter(|| {
            let start = std::time::Instant::now();
            
            let input = Cursor::new(&test_data);
            let mut output = Vec::new();
            
            let stats = engine.compress(
                input,
                &mut output,
                black_box(level),
            ).unwrap();
            
            let duration = start.elapsed();
            let mb_per_sec = (size as f64 / (1024.0 * 1024.0)) / duration.as_secs_f64();
            
            // Validate ≥150 MB/s target
            if mb_per_sec < 150.0 {
                eprintln!("Warning: Performance target not met: {:.1} MB/s < 150 MB/s", mb_per_sec);
            }
            
            black_box((output, stats, mb_per_sec));
        });
    });
    
    group.finish();
}

criterion_group!(
    compression_benches,
    bench_compression_levels,
    bench_data_types,
    bench_compression_ratios,
    bench_decompression,
    bench_memory_efficiency,
    bench_performance_targets
);

criterion_main!(compression_benches);