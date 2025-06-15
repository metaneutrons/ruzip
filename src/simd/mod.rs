//! SIMD optimizations for RuZip
//! 
//! This module provides SIMD (Single Instruction, Multiple Data) optimizations
//! for critical performance paths in RuZip, including hashing and
//! compression preprocessing.

use std::sync::OnceLock;

pub mod hashing;
pub mod compression;

/// SIMD capabilities detected at runtime
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SimdCapabilities {
    /// x86_64 SIMD features
    pub sse2: bool,
    pub sse4_2: bool,
    pub avx: bool,
    pub avx2: bool,
    pub avx512f: bool,
    
    /// ARM64 SIMD features
    pub neon: bool,
    pub sve: bool,
    
    /// Hardware CRC32 support
    pub crc32: bool,
}

/// Global SIMD capabilities (detected once at runtime)
static SIMD_CAPS: OnceLock<SimdCapabilities> = OnceLock::new();

/// Detects SIMD capabilities at runtime
pub fn detect_simd_capabilities() -> SimdCapabilities {
    #[cfg(target_arch = "x86_64")]
    {
        SimdCapabilities {
            sse2: is_x86_feature_detected!("sse2"),
            sse4_2: is_x86_feature_detected!("sse4.2"),
            avx: is_x86_feature_detected!("avx"),
            avx2: is_x86_feature_detected!("avx2"),
            avx512f: is_x86_feature_detected!("avx512f"),
            neon: false,
            sve: false,
            crc32: is_x86_feature_detected!("sse4.2"), // SSE4.2 includes CRC32
        }
    }
    
    #[cfg(target_arch = "aarch64")]
    {
        SimdCapabilities {
            sse2: false,
            sse4_2: false,
            avx: false,
            avx2: false,
            avx512f: false,
            neon: std::arch::is_aarch64_feature_detected!("neon"),
            sve: std::arch::is_aarch64_feature_detected!("sve"),
            crc32: std::arch::is_aarch64_feature_detected!("crc"),
        }
    }
    
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        // Fallback for other architectures
        SimdCapabilities {
            sse2: false,
            sse4_2: false,
            avx: false,
            avx2: false,
            avx512f: false,
            neon: false,
            sve: false,
            crc32: false,
        }
    }
}

/// Returns SIMD capabilities (cached)
pub fn get_simd_capabilities() -> &'static SimdCapabilities {
    SIMD_CAPS.get_or_init(detect_simd_capabilities)
}

/// Trait for SIMD-optimized operations with fallback
pub trait SimdOperation<T> {
    /// SIMD-optimized implementation
    fn simd_operation(&self, data: &[T]) -> Vec<T>;
    
    /// Scalar fallback implementation
    fn scalar_operation(&self, data: &[T]) -> Vec<T>;
    
    /// Automatic selection between SIMD and scalar
    fn execute(&self, data: &[T]) -> Vec<T> {
        let caps = get_simd_capabilities();
        
        // Decision based on available SIMD features
        if self.can_use_simd(caps) && data.len() >= self.min_simd_size() {
            self.simd_operation(data)
        } else {
            self.scalar_operation(data)
        }
    }
    
    /// Checks if SIMD is available for this operation
    fn can_use_simd(&self, caps: &SimdCapabilities) -> bool;
    
    /// Minimum data size for SIMD optimization
    fn min_simd_size(&self) -> usize {
        64 // Default: 64 bytes
    }
}

/// Memory alignment utilities for SIMD
pub mod alignment {
    /// Checks if a pointer is aligned for SIMD
    pub fn is_aligned<T>(ptr: *const T, alignment: usize) -> bool {
        (ptr as usize) % alignment == 0
    }
    
    /// Creates an aligned vector for SIMD operations
    pub fn create_aligned_vec<T: Clone + Default>(size: usize, alignment: usize) -> Vec<T> {
        let mut vec = Vec::with_capacity(size + alignment);
        
        // Fill until desired alignment
        while (vec.as_ptr() as usize) % alignment != 0 {
            vec.push(T::default());
        }
        
        // Resize to desired size
        vec.resize(size, T::default());
        vec
    }
    
    /// 16-byte Alignment for SSE
    pub const SSE_ALIGNMENT: usize = 16;
    
    /// 32-byte Alignment for AVX
    pub const AVX_ALIGNMENT: usize = 32;
    
    /// 64-byte Alignment for AVX-512
    pub const AVX512_ALIGNMENT: usize = 64;
}

/// Benchmark utilities for SIMD vs Scalar comparisons
#[cfg(feature = "simd")]
pub mod benchmark {
    use super::*;
    use std::time::{Duration, Instant};
    
    /// Benchmark result for SIMD vs Scalar
    #[derive(Debug)]
    pub struct BenchmarkResult {
        pub simd_time: Duration,
        pub scalar_time: Duration,
        pub speedup: f64,
        pub data_size: usize,
    }
    
    /// Runs a benchmark between SIMD and Scalar
    pub fn benchmark_simd_vs_scalar<T, Op>(
        operation: &Op,
        data: &[T],
        iterations: usize,
    ) -> BenchmarkResult
    where
        T: Clone,
        Op: SimdOperation<T>,
    {
        // SIMD Benchmark
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = operation.simd_operation(data);
        }
        let simd_time = start.elapsed();
        
        // Scalar Benchmark
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = operation.scalar_operation(data);
        }
        let scalar_time = start.elapsed();
        
        let speedup = scalar_time.as_nanos() as f64 / simd_time.as_nanos() as f64;
        
        BenchmarkResult {
            simd_time,
            scalar_time,
            speedup,
            data_size: data.len(),
        }
    }
}

/// Initializes SIMD subsystem and prints capabilities
pub fn init_simd() -> &'static SimdCapabilities {
    let caps = get_simd_capabilities();
    
    tracing::info!("SIMD Capabilities detected:");
    
    #[cfg(target_arch = "x86_64")]
    {
        tracing::info!("  SSE2: {}", caps.sse2);
        tracing::info!("  SSE4.2: {}", caps.sse4_2);
        tracing::info!("  AVX: {}", caps.avx);
        tracing::info!("  AVX2: {}", caps.avx2);
        tracing::info!("  AVX-512F: {}", caps.avx512f);
    }
    
    #[cfg(target_arch = "aarch64")]
    {
        tracing::info!("  NEON: {}", caps.neon);
        tracing::info!("  SVE: {}", caps.sve);
    }
    
    tracing::info!("  Hardware CRC32: {}", caps.crc32);
    
    caps
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_simd_detection() {
        let caps = detect_simd_capabilities();
        
        // At least one capability should be available on modern CPUs
        #[cfg(target_arch = "x86_64")]
        assert!(caps.sse2); // SSE2 is available on all x86_64 CPUs
        
        #[cfg(target_arch = "aarch64")]
        assert!(caps.neon); // NEON is available on all ARM64 CPUs
    }
    
    #[test]
    fn test_alignment_check() {
        let data = vec![1u8; 64];
        let ptr = data.as_ptr();
        
        // Test various alignments
        assert!(alignment::is_aligned(ptr, 1));
        // Further alignment tests depend on the actual pointer address
    }
    
    #[test]
    fn test_aligned_vec_creation() {
        let vec = alignment::create_aligned_vec::<u8>(64, alignment::AVX_ALIGNMENT);
        assert_eq!(vec.len(), 64);
        assert!(alignment::is_aligned(vec.as_ptr(), alignment::AVX_ALIGNMENT));
    }
}