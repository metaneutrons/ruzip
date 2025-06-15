//! SIMD Performance Benchmarks
//!
//! Benchmarks SIMD optimizations against scalar implementations
//! for various operations in RuZip.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use ruzip::simd::{
    hashing::{SimdCrc32, SimdBlake3, SimdSha256, MultiHasher},
    compression::{SimdMemCopy, SimdEntropy, SimdZstdPreprocessor},
    get_simd_capabilities,
};
use std::time::Duration;

/// Create test data of various sizes
fn create_test_data(size: usize) -> Vec<u8> {
    (0..size).map(|i| (i % 256) as u8).collect()
}

/// Create compressible test data
fn create_compressible_data(size: usize) -> Vec<u8> {
    let pattern = b"Hello, World! This is a test pattern for compression. ";
    let mut data = Vec::with_capacity(size);
    while data.len() < size {
        data.extend_from_slice(pattern);
    }
    data.truncate(size);
    data
}

/// Benchmark CRC32 SIMD vs Scalar
fn bench_crc32(c: &mut Criterion) {
    let caps = get_simd_capabilities();
    
    let mut group = c.benchmark_group("crc32");
    
    for size in [1024, 8192, 65536, 1024 * 1024].iter() {
        let data = create_test_data(*size);
        group.throughput(Throughput::Bytes(*size as u64));
        
        // SIMD CRC32
        if caps.crc32 {
            group.bench_with_input(
                BenchmarkId::new("simd", size),
                &data,
                |b, data| {
                    b.iter(|| {
                        let mut hasher = SimdCrc32::new();
                        hasher.update(black_box(data)).unwrap();
                        black_box(hasher.finalize())
                    })
                },
            );
        }
        
        // Scalar CRC32
        group.bench_with_input(
            BenchmarkId::new("scalar", size),
            &data,
            |b, data| {
                b.iter(|| {
                    black_box(crc32fast::hash(black_box(data)))
                })
            },
        );
    }
    
    group.finish();
}

/// Benchmark Blake3 SIMD vs Scalar
fn bench_blake3(c: &mut Criterion) {
    let mut group = c.benchmark_group("blake3");
    
    for size in [1024, 8192, 65536, 1024 * 1024].iter() {
        let data = create_test_data(*size);
        group.throughput(Throughput::Bytes(*size as u64));
        
        // SIMD Blake3
        group.bench_with_input(
            BenchmarkId::new("simd", size),
            &data,
            |b, data| {
                b.iter(|| {
                    let mut hasher = SimdBlake3::new();
                    hasher.update(black_box(data));
                    black_box(hasher.finalize())
                })
            },
        );
        
        // Standard Blake3
        group.bench_with_input(
            BenchmarkId::new("standard", size),
            &data,
            |b, data| {
                b.iter(|| {
                    black_box(blake3::hash(black_box(data)))
                })
            },
        );
    }
    
    group.finish();
}

/// Benchmark SHA-256 SIMD vs Scalar
fn bench_sha256(c: &mut Criterion) {
    let mut group = c.benchmark_group("sha256");
    
    for size in [1024, 8192, 65536, 1024 * 1024].iter() {
        let data = create_test_data(*size);
        group.throughput(Throughput::Bytes(*size as u64));
        
        // SIMD SHA-256
        group.bench_with_input(
            BenchmarkId::new("simd", size),
            &data,
            |b, data| {
                b.iter(|| {
                    let mut hasher = SimdSha256::new();
                    hasher.update(black_box(data));
                    black_box(hasher.finalize())
                })
            },
        );
        
        // Standard SHA-256
        group.bench_with_input(
            BenchmarkId::new("standard", size),
            &data,
            |b, data| {
                b.iter(|| {
                    use sha2::{Digest, Sha256};
                    let mut hasher = Sha256::new();
                    hasher.update(black_box(data));
                    black_box(hasher.finalize())
                })
            },
        );
    }
    
    group.finish();
}

/// Benchmark Multi-Hash Performance
fn bench_multi_hash(c: &mut Criterion) {
    let mut group = c.benchmark_group("multi_hash");
    
    for size in [1024, 8192, 65536, 1024 * 1024].iter() {
        let data = create_test_data(*size);
        group.throughput(Throughput::Bytes(*size as u64));
        
        // Multi-Hash SIMD
        group.bench_with_input(
            BenchmarkId::new("simd_multi", size),
            &data,
            |b, data| {
                b.iter(|| {
                    let mut hasher = MultiHasher::new();
                    hasher.update(black_box(data)).unwrap();
                    black_box(hasher.finalize())
                })
            },
        );
        
        // Separate hashes
        group.bench_with_input(
            BenchmarkId::new("separate", size),
            &data,
            |b, data| {
                b.iter(|| {
                    use sha2::{Digest, Sha256};
                    
                    let crc = crc32fast::hash(black_box(data));
                    let blake3 = blake3::hash(black_box(data));
                    let mut sha_hasher = Sha256::new();
                    sha_hasher.update(black_box(data));
                    let sha256 = sha_hasher.finalize();
                    
                    black_box((crc, blake3, sha256))
                })
            },
        );
    }
    
    group.finish();
}

/// Benchmark Memory Copy SIMD vs Scalar
fn bench_memory_copy(c: &mut Criterion) {
    let caps = get_simd_capabilities();
    
    let mut group = c.benchmark_group("memory_copy");
    
    for size in [1024, 8192, 65536, 1024 * 1024].iter() {
        let src = create_test_data(*size);
        group.throughput(Throughput::Bytes(*size as u64));
        
        // SIMD Memory Copy
        if caps.avx2 || caps.sse2 || caps.neon {
            group.bench_with_input(
                BenchmarkId::new("simd", size),
                &src,
                |b, src| {
                    b.iter(|| {
                        let mut dst = vec![0u8; src.len()];
                        SimdMemCopy::copy_aligned(black_box(src), black_box(&mut dst)).unwrap();
                        black_box(dst)
                    })
                },
            );
        }
        
        // Standard Memory Copy
        group.bench_with_input(
            BenchmarkId::new("standard", size),
            &src,
            |b, src| {
                b.iter(|| {
                    let mut dst = vec![0u8; src.len()];
                    dst.copy_from_slice(black_box(src));
                    black_box(dst)
                })
            },
        );
    }
    
    group.finish();
}

/// Benchmark Entropy Calculation SIMD vs Scalar
fn bench_entropy_calculation(c: &mut Criterion) {
    let caps = get_simd_capabilities();
    
    let mut group = c.benchmark_group("entropy_calculation");
    
    for size in [1024, 8192, 65536, 1024 * 1024].iter() {
        let data = create_test_data(*size);
        group.throughput(Throughput::Bytes(*size as u64));
        
        // SIMD Entropy
        if caps.avx2 || caps.sse2 || caps.neon {
            group.bench_with_input(
                BenchmarkId::new("simd", size),
                &data,
                |b, data| {
                    b.iter(|| {
                        black_box(SimdEntropy::calculate_entropy(black_box(data)))
                    })
                },
            );
        }
        
        // Scalar Entropy (manual implementation)
        group.bench_with_input(
            BenchmarkId::new("scalar", size),
            &data,
            |b, data| {
                b.iter(|| {
                    let mut counts = [0u32; 256];
                    for &byte in black_box(data) {
                        counts[byte as usize] += 1;
                    }
                    
                    let mut entropy = 0.0;
                    let total = data.len() as f64;
                    
                    for &count in &counts {
                        if count > 0 {
                            let probability = count as f64 / total;
                            entropy -= probability * probability.log2();
                        }
                    }
                    
                    black_box(entropy)
                })
            },
        );
    }
    
    group.finish();
}

/// Benchmark ZSTD Preprocessing SIMD vs Scalar
fn bench_zstd_preprocessing(c: &mut Criterion) {
    let caps = get_simd_capabilities();
    
    let mut group = c.benchmark_group("zstd_preprocessing");
    
    for size in [1024, 8192, 65536, 1024 * 1024].iter() {
        let data = create_compressible_data(*size);
        group.throughput(Throughput::Bytes(*size as u64));
        
        // SIMD Preprocessing
        if caps.avx2 || caps.sse2 || caps.neon {
            group.bench_with_input(
                BenchmarkId::new("simd", size),
                &data,
                |b, data| {
                    b.iter(|| {
                        black_box(SimdZstdPreprocessor::preprocess(black_box(data)).unwrap())
                    })
                },
            );
        }
        
        // No preprocessing (direct copy)
        group.bench_with_input(
            BenchmarkId::new("direct", size),
            &data,
            |b, data| {
                b.iter(|| {
                    black_box(data.to_vec())
                })
            },
        );
    }
    
    group.finish();
}

/// Benchmark End-to-End Archive Operations
fn bench_archive_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("archive_operations");
    group.measurement_time(Duration::from_secs(10));
    
    for size in [64 * 1024, 1024 * 1024].iter() {
        let data = create_compressible_data(*size);
        group.throughput(Throughput::Bytes(*size as u64));
        
        // SIMD-optimized archive validation
        group.bench_with_input(
            BenchmarkId::new("simd_validation", size),
            &data,
            |b, data| {
                b.iter(|| {
                    // Simulate archive validation with SIMD hashing
                    let mut hasher = MultiHasher::new();
                    hasher.update(black_box(data)).unwrap();
                    let hashes = hasher.finalize();
                    
                    // Simulate entropy analysis
                    let entropy = SimdEntropy::calculate_entropy(black_box(data));
                    let level = SimdEntropy::recommend_compression_level(entropy);
                    
                    black_box((hashes, entropy, level))
                })
            },
        );
        
        // Standard archive validation
        group.bench_with_input(
            BenchmarkId::new("standard_validation", size),
            &data,
            |b, data| {
                b.iter(|| {
                    use sha2::{Digest, Sha256};
                    
                    // Standard hashing
                    let crc = crc32fast::hash(black_box(data));
                    let blake3 = blake3::hash(black_box(data));
                    let mut sha_hasher = Sha256::new();
                    sha_hasher.update(black_box(data));
                    let sha256 = sha_hasher.finalize();
                    
                    // Simple entropy calculation
                    let mut counts = [0u32; 256];
                    for &byte in black_box(data) {
                        counts[byte as usize] += 1;
                    }
                    let mut entropy = 0.0;
                    let total = data.len() as f64;
                    for &count in &counts {
                        if count > 0 {
                            let probability = count as f64 / total;
                            entropy -= probability * probability.log2();
                        }
                    }
                    
                    black_box((crc, blake3, sha256, entropy))
                })
            },
        );
    }
    
    group.finish();
}


criterion_group!(
    name = simd_benches;
    config = Criterion::default()
        .warm_up_time(Duration::from_secs(1))
        .measurement_time(Duration::from_secs(3))
        .sample_size(100);
    targets = 
        bench_crc32,
        bench_blake3,
        bench_sha256,
        bench_multi_hash,
        bench_memory_copy,
        bench_entropy_calculation,
        bench_zstd_preprocessing,
        bench_archive_operations
);

criterion_main!(simd_benches);