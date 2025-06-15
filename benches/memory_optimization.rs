//! Memory optimization benchmarks
//!
//! Benchmarks for zero-allocation patterns, buffer pools, and memory efficiency.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId, Throughput};
use ruzip::memory::{
    BufferPool, MemoryArena, ScratchBuffer, ChainedBuffer,
    MemoryPressureDetector, AdaptiveBufferSizer,
    streaming::{ZeroCopyReader, ZeroCopyRead},
    profiler::MemoryProfiler,
};
use ruzip::compression::stream::CompressedWriter;
use ruzip::compression::CompressionLevel;
use std::io::{Read, Write, Cursor};
use std::sync::Arc;

fn bench_buffer_pool_allocation(c: &mut Criterion) {
    let mut group = c.benchmark_group("buffer_pool_allocation");
    
    let detector = Arc::new(MemoryPressureDetector::new(100, 200, 300));
    let pool = Arc::new(BufferPool::new_byte_pool(100, detector));
    
    group.bench_function("get_small_buffer", |b| {
        b.iter(|| {
            let buffer = pool.get_small_buffer();
            black_box(buffer);
        })
    });
    
    group.bench_function("get_medium_buffer", |b| {
        b.iter(|| {
            let buffer = pool.get_medium_buffer();
            black_box(buffer);
        })
    });
    
    group.bench_function("get_large_buffer", |b| {
        b.iter(|| {
            let buffer = pool.get_large_buffer();
            black_box(buffer);
        })
    });
    
    // Compare with direct allocation
    group.bench_function("direct_allocation_small", |b| {
        b.iter(|| {
            let buffer = vec![0u8; 4 * 1024];
            black_box(buffer);
        })
    });
    
    group.bench_function("direct_allocation_medium", |b| {
        b.iter(|| {
            let buffer = vec![0u8; 64 * 1024];
            black_box(buffer);
        })
    });
    
    group.finish();
}

fn bench_memory_arena_allocation(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_arena_allocation");
    
    for size in [1024, 4096, 16384, 65536].iter() {
        group.throughput(Throughput::Bytes(*size as u64));
        
        group.bench_with_input(BenchmarkId::new("arena_alloc", size), size, |b, &size| {
            let mut arena = MemoryArena::new(1024 * 1024); // 1MB arena
            b.iter(|| {
                arena.reset();
                let slice = arena.alloc(size).unwrap();
                black_box(slice);
            })
        });
        
        group.bench_with_input(BenchmarkId::new("vec_alloc", size), size, |b, &size| {
            b.iter(|| {
                let vec = vec![0u8; size];
                black_box(vec);
            })
        });
    }
    
    group.finish();
}

fn bench_chained_buffer_streaming(c: &mut Criterion) {
    let mut group = c.benchmark_group("chained_buffer_streaming");
    
    for data_size in [1024, 8192, 65536, 524288].iter() {
        group.throughput(Throughput::Bytes(*data_size as u64));
        
        let test_data = vec![42u8; *data_size];
        
        group.bench_with_input(BenchmarkId::new("chained_buffer", data_size), &test_data, |b, data| {
            b.iter(|| {
                let mut buffer = ChainedBuffer::new(4096);
                buffer.write(data).unwrap();
                
                let mut read_buf = vec![0u8; data.len()];
                let bytes_read = buffer.read(&mut read_buf).unwrap();
                black_box(bytes_read);
            })
        });
        
        group.bench_with_input(BenchmarkId::new("vec_buffer", data_size), &test_data, |b, data| {
            b.iter(|| {
                let mut buffer = Vec::new();
                buffer.extend_from_slice(data);
                
                let read_buf = buffer.clone();
                black_box(read_buf);
            })
        });
    }
    
    group.finish();
}

fn bench_zero_copy_streaming(c: &mut Criterion) {
    let mut group = c.benchmark_group("zero_copy_streaming");
    
    for data_size in [1024, 8192, 65536, 524288].iter() {
        group.throughput(Throughput::Bytes(*data_size as u64));
        
        let test_data = vec![42u8; *data_size];
        
        group.bench_with_input(BenchmarkId::new("zero_copy_read", data_size), &test_data, |b, data| {
            b.iter(|| {
                let cursor = Cursor::new(data);
                let mut reader = ZeroCopyReader::new(cursor, 4096);
                
                let mut total_read = 0;
                let mut buffer = vec![0u8; 1024];
                
                while total_read < data.len() {
                    match reader.read_zero_copy(&mut buffer) {
                        Ok(0) => break,
                        Ok(n) => total_read += n,
                        Err(_) => break,
                    }
                }
                
                black_box(total_read);
            })
        });
        
        group.bench_with_input(BenchmarkId::new("standard_read", data_size), &test_data, |b, data| {
            b.iter(|| {
                let mut cursor = Cursor::new(data);
                let mut total_read = 0;
                let mut buffer = vec![0u8; 1024];
                
                while total_read < data.len() {
                    match cursor.read(&mut buffer) {
                        Ok(0) => break,
                        Ok(n) => total_read += n,
                        Err(_) => break,
                    }
                }
                
                black_box(total_read);
            })
        });
    }
    
    group.finish();
}

fn bench_compressed_writer_with_pools(c: &mut Criterion) {
    let mut group = c.benchmark_group("compressed_writer_pools");
    
    let detector = Arc::new(MemoryPressureDetector::new(100, 200, 300));
    let pool = Arc::new(BufferPool::new_byte_pool(10, detector));
    let level = CompressionLevel::new(6).unwrap();
    
    for data_size in [1024, 8192, 65536].iter() {
        group.throughput(Throughput::Bytes(*data_size as u64));
        
        let test_data = vec![42u8; *data_size];
        
        group.bench_with_input(BenchmarkId::new("with_buffer_pool", data_size), &test_data, |b, data| {
            b.iter(|| {
                let output = Vec::new();
                let mut writer = CompressedWriter::with_buffer_pool(output, level, pool.clone()).unwrap();
                writer.write_all(data).unwrap();
                let result = writer.finish().unwrap();
                black_box(result);
            })
        });
        
        group.bench_with_input(BenchmarkId::new("without_pool", data_size), &test_data, |b, data| {
            b.iter(|| {
                let output = Vec::new();
                let mut writer = CompressedWriter::new(output, level).unwrap();
                writer.write_all(data).unwrap();
                let result = writer.finish().unwrap();
                black_box(result);
            })
        });
    }
    
    group.finish();
}

fn bench_memory_pressure_adaptation(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_pressure_adaptation");
    
    let detector = Arc::new(MemoryPressureDetector::new(50, 100, 150));
    let sizer = AdaptiveBufferSizer::new(detector.clone());
    
    // Test buffer size adaptation under different pressure levels
    group.bench_function("low_pressure", |b| {
        detector.update_usage(25); // Low pressure
        b.iter(|| {
            let size = sizer.chunk_size();
            black_box(size);
        })
    });
    
    group.bench_function("medium_pressure", |b| {
        detector.update_usage(75); // Medium pressure
        b.iter(|| {
            let size = sizer.chunk_size();
            black_box(size);
        })
    });
    
    group.bench_function("high_pressure", |b| {
        detector.update_usage(125); // High pressure
        b.iter(|| {
            let size = sizer.chunk_size();
            black_box(size);
        })
    });
    
    group.bench_function("critical_pressure", |b| {
        detector.update_usage(175); // Critical pressure
        b.iter(|| {
            let size = sizer.chunk_size();
            black_box(size);
        })
    });
    
    group.finish();
}

fn bench_memory_profiler_overhead(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_profiler_overhead");
    
    let profiler = Arc::new(MemoryProfiler::new(100, 200, 1.0)); // 100% sampling
    let profiler_low_sample = Arc::new(MemoryProfiler::new(100, 200, 0.1)); // 10% sampling
    
    group.bench_function("no_profiling", |b| {
        b.iter(|| {
            let data = vec![42u8; 1024];
            black_box(data);
        })
    });
    
    group.bench_function("full_profiling", |b| {
        b.iter(|| {
            let id = profiler.record_allocation(1024, "benchmark");
            let data = vec![42u8; 1024];
            profiler.record_deallocation(id);
            black_box(data);
        })
    });
    
    group.bench_function("sampled_profiling", |b| {
        b.iter(|| {
            let id = profiler_low_sample.record_allocation(1024, "benchmark");
            let data = vec![42u8; 1024];
            profiler_low_sample.record_deallocation(id);
            black_box(data);
        })
    });
    
    group.finish();
}

fn bench_scratch_buffer_reuse(c: &mut Criterion) {
    let mut group = c.benchmark_group("scratch_buffer_reuse");
    
    group.bench_function("with_reuse", |b| {
        let mut scratch = ScratchBuffer::new(64 * 1024, 64 * 1024, 16 * 1024);
        b.iter(|| {
            let comp_len = {
                let comp_buf = scratch.compression_buffer();
                comp_buf.extend_from_slice(&vec![42u8; 1024]);
                comp_buf.len()
            };
            
            let decomp_len = {
                let decomp_buf = scratch.decompression_buffer();
                decomp_buf.extend_from_slice(&vec![24u8; 1024]);
                decomp_buf.len()
            };
            
            black_box((comp_len, decomp_len));
        })
    });
    
    group.bench_function("without_reuse", |b| {
        b.iter(|| {
            let mut comp_buf = Vec::with_capacity(64 * 1024);
            comp_buf.extend_from_slice(&vec![42u8; 1024]);
            
            let mut decomp_buf = Vec::with_capacity(64 * 1024);
            decomp_buf.extend_from_slice(&vec![24u8; 1024]);
            
            black_box((comp_buf.len(), decomp_buf.len()));
        })
    });
    
    group.finish();
}

fn bench_large_file_memory_efficiency(c: &mut Criterion) {
    let mut group = c.benchmark_group("large_file_memory_efficiency");
    group.sample_size(10); // Fewer samples for large data
    
    let detector = Arc::new(MemoryPressureDetector::new(50, 100, 150));
    let pool = Arc::new(BufferPool::new_byte_pool(5, detector));
    
    // Test buffer pool efficiency vs direct allocation
    group.bench_function("with_buffer_pool", |b| {
        b.iter(|| {
            let mut total_capacity = 0;
            for _ in 0..100 {
                let buffer = pool.get_small_buffer();
                total_capacity += buffer.capacity();
                black_box(&buffer);
                // Buffer is automatically returned to pool when dropped
            }
            black_box(total_capacity);
        })
    });
    
    group.bench_function("direct_allocation", |b| {
        b.iter(|| {
            let mut total_capacity = 0;
            for _ in 0..100 {
                let buffer = vec![0u8; 4096];
                total_capacity += buffer.capacity();
                black_box(&buffer);
                // Buffer is dropped/deallocated
            }
            black_box(total_capacity);
        })
    });
    
    group.finish();
}

fn bench_allocation_count_reduction(c: &mut Criterion) {
    let mut group = c.benchmark_group("allocation_count_reduction");
    
    let detector = Arc::new(MemoryPressureDetector::new(100, 200, 300));
    let pool = Arc::new(BufferPool::new_byte_pool(20, detector));
    
    group.bench_function("many_small_allocations_pooled", |b| {
        b.iter(|| {
            let mut buffers = Vec::new();
            for _ in 0..100 {
                let buffer = pool.get_small_buffer();
                buffers.push(buffer);
            }
            black_box(buffers);
        })
    });
    
    group.bench_function("many_small_allocations_direct", |b| {
        b.iter(|| {
            let mut buffers = Vec::new();
            for _ in 0..100 {
                let buffer = vec![0u8; 4 * 1024];
                buffers.push(buffer);
            }
            black_box(buffers);
        })
    });
    
    group.finish();
}

criterion_group!(
    memory_benches,
    bench_buffer_pool_allocation,
    bench_memory_arena_allocation,
    bench_chained_buffer_streaming,
    bench_zero_copy_streaming,
    bench_compressed_writer_with_pools,
    bench_memory_pressure_adaptation,
    bench_memory_profiler_overhead,
    bench_scratch_buffer_reuse,
    bench_large_file_memory_efficiency,
    bench_allocation_count_reduction
);

criterion_main!(memory_benches);