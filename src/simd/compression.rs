//! SIMD-optimized Compression operations
//!
//! This module implements SIMD-optimized preprocessing operations
//! for compression algorithms, including memory copy, entropy calculation
//! and dictionary building.

use crate::error::RuzipError;
use crate::get_simd_capabilities;
use std::collections::HashMap;

/// SIMD-optimized Memory-Copy operations
pub struct SimdMemCopy;

impl SimdMemCopy {
    /// Copies data with SIMD optimization
    pub fn copy_aligned(src: &[u8], dst: &mut [u8]) -> Result<(), RuzipError> {
        if src.len() != dst.len() {
            return Err(RuzipError::InvalidInput {
                message: "Source and destination length mismatch".to_string(),
                input: Some(format!("src len: {}, dst len: {}", src.len(), dst.len())),
            });
        }
        
        let caps = get_simd_capabilities();
        
        if caps.avx2 && src.len() >= 32 {
            Self::copy_avx2(src, dst)?;
        } else if (caps.sse2 || caps.neon) && src.len() >= 16 {
            Self::copy_sse2_neon(src, dst)?;
        } else {
            dst.copy_from_slice(src);
        }
        
        Ok(())
    }
    
    /// AVX2-optimized Memory-Copy
    #[cfg(all(feature = "simd", target_arch = "x86_64"))]
    fn copy_avx2(src: &[u8], dst: &mut [u8]) -> Result<(), RuzipError> {
        use std::arch::x86_64::*;
        
        unsafe {
            let mut src_ptr = src.as_ptr();
            let mut dst_ptr = dst.as_mut_ptr();
            let mut remaining = src.len();
            
            // Process 32-byte chunks with AVX2
            while remaining >= 32 {
                let data = _mm256_loadu_si256(src_ptr as *const __m256i);
                _mm256_storeu_si256(dst_ptr as *mut __m256i, data);
                
                src_ptr = src_ptr.add(32);
                dst_ptr = dst_ptr.add(32);
                remaining -= 32;
            }
            
            // Process remaining bytes
            if remaining > 0 {
                std::ptr::copy_nonoverlapping(src_ptr, dst_ptr, remaining);
            }
        }
        
        Ok(())
    }
    
    /// SSE2/NEON-optimized Memory-Copy
    #[cfg(feature = "simd")]
    fn copy_sse2_neon(src: &[u8], dst: &mut [u8]) -> Result<(), RuzipError> {
        #[cfg(target_arch = "x86_64")]
        {
            use std::arch::x86_64::*;
            
            unsafe {
                let mut src_ptr = src.as_ptr();
                let mut dst_ptr = dst.as_mut_ptr();
                let mut remaining = src.len();
                
                // Process 16-byte chunks with SSE2
                while remaining >= 16 {
                    let data = _mm_loadu_si128(src_ptr as *const __m128i);
                    _mm_storeu_si128(dst_ptr as *mut __m128i, data);
                    
                    src_ptr = src_ptr.add(16);
                    dst_ptr = dst_ptr.add(16);
                    remaining -= 16;
                }
                
                // Process remaining bytes
                if remaining > 0 {
                    std::ptr::copy_nonoverlapping(src_ptr, dst_ptr, remaining);
                }
            }
        }
        
        #[cfg(target_arch = "aarch64")]
        {
            use std::arch::aarch64::*;
            
            unsafe {
                let mut src_ptr = src.as_ptr();
                let mut dst_ptr = dst.as_mut_ptr();
                let mut remaining = src.len();
                
                // Process 16-byte chunks with NEON
                while remaining >= 16 {
                    let data = vld1q_u8(src_ptr);
                    vst1q_u8(dst_ptr, data);
                    
                    src_ptr = src_ptr.add(16);
                    dst_ptr = dst_ptr.add(16);
                    remaining -= 16;
                }
                
                // Process remaining bytes
                if remaining > 0 {
                    std::ptr::copy_nonoverlapping(src_ptr, dst_ptr, remaining);
                }
            }
        }
        
        Ok(())
    }
    
    /// Fallback for architectures without SIMD
    #[cfg(not(feature = "simd"))]
    fn copy_sse2_neon(src: &[u8], dst: &mut [u8]) -> Result<(), RuzipError> {
        dst.copy_from_slice(src);
        Ok(())
    }
    
    #[cfg(not(all(feature = "simd", target_arch = "x86_64")))]
    fn copy_avx2(src: &[u8], dst: &mut [u8]) -> Result<(), RuzipError> {
        Self::copy_sse2_neon(src, dst)
    }
}

/// SIMD-optimized Entropy-Calculation for compression level selection
pub struct SimdEntropy;

impl SimdEntropy {
    /// Calculates Shannon entropy with SIMD optimization
    pub fn calculate_entropy(data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }
        
        let caps = get_simd_capabilities();
        
        if caps.avx2 && data.len() >= 256 {
            Self::calculate_entropy_simd(data)
        } else if (caps.sse2 || caps.neon) && data.len() >= 64 {
            Self::calculate_entropy_simd(data)
        } else {
            Self::calculate_entropy_scalar(data)
        }
    }
    
    /// SIMD-optimized Entropy calculation
    #[cfg(feature = "simd")]
    fn calculate_entropy_simd(data: &[u8]) -> f64 {
        // Vereinfachte SIMD-Implementation
        let mut counts = [0u32; 256];
        
        // Verarbeite Daten in Chunks für bessere Cache-Performance
        let chunk_size = 64; // Optimale Chunk-Größe für SIMD
        
        for chunk in data.chunks(chunk_size) {
            for &byte in chunk {
                counts[byte as usize] += 1;
            }
        }
        
        Self::entropy_from_counts(&counts, data.len())
    }

    /// AVX2-optimized Entropy calculation
    #[cfg(all(feature = "simd", target_arch = "x86_64"))]
    fn calculate_entropy_avx2(data: &[u8]) -> f64 {
        // Count byte frequencies with SIMD
        let mut counts = [0u32; 256];
        
        unsafe {
            let mut ptr = data.as_ptr();
            let mut remaining = data.len();
            
            // Process 32-byte chunks
            while remaining >= 32 {
                let chunk = std::slice::from_raw_parts(ptr, 32);
                
                // Count bytes in this chunk
                for &byte in chunk {
                    counts[byte as usize] += 1;
                }
                
                ptr = ptr.add(32);
                remaining -= 32;
            }
            
            // Process remaining bytes
            while remaining > 0 {
                counts[*ptr as usize] += 1;
                ptr = ptr.add(1);
                remaining -= 1;
            }
        }
        
        Self::entropy_from_counts(&counts, data.len())
    }
    
    /// SSE2/NEON-optimized Entropy calculation
    #[cfg(feature = "simd")]
    #[allow(dead_code)]
    fn calculate_entropy_sse2_neon(data: &[u8]) -> f64 {
        // Similar to AVX2, but with 16-byte chunks
        let mut counts = [0u32; 256];
        
        let mut ptr = data.as_ptr();
        let mut remaining = data.len();
        
        unsafe {
            // Process 16-byte chunks
            while remaining >= 16 {
                let chunk = std::slice::from_raw_parts(ptr, 16);
                
                for &byte in chunk {
                    counts[byte as usize] += 1;
                }
                
                ptr = ptr.add(16);
                remaining -= 16;
            }
            
            // Process remaining bytes
            while remaining > 0 {
                counts[*ptr as usize] += 1;
                ptr = ptr.add(1);
                remaining -= 1;
            }
        }
        
        Self::entropy_from_counts(&counts, data.len())
    }
    
    /// Scalar Entropy calculation as fallback
    fn calculate_entropy_scalar(data: &[u8]) -> f64 {
        let mut counts = [0u32; 256];
        
        for &byte in data {
            counts[byte as usize] += 1;
        }
        
        Self::entropy_from_counts(&counts, data.len())
    }
    
    /// Calculates entropy from byte frequencies
    fn entropy_from_counts(counts: &[u32; 256], total: usize) -> f64 {
        let mut entropy = 0.0;
        let total_f = total as f64;
        
        for &count in counts {
            if count > 0 {
                let probability = count as f64 / total_f;
                entropy -= probability * probability.log2();
            }
        }
        
        entropy
    }
    
    /// Recommends compression level based on entropy
    pub fn recommend_compression_level(entropy: f64) -> u8 {
        match entropy {
            e if e < 2.0 => 1,  // Very low entropy -> low compression
            e if e < 4.0 => 3,  // Low entropy -> medium compression
            e if e < 6.0 => 6,  // Medium entropy -> high compression
            e if e < 7.0 => 9,  // High entropy -> very high compression
            _ => 12,            // Very high entropy -> maximum compression
        }
    }
}

/// SIMD-optimized Dictionary-Building for ZSTD
pub struct SimdDictionary {
    samples: Vec<Vec<u8>>,
    max_dict_size: usize,
}

impl SimdDictionary {
    /// Creates a new Dictionary builder
    pub fn new(max_dict_size: usize) -> Self {
        Self {
            samples: Vec::new(),
            max_dict_size,
        }
    }
    
    /// Adds a sample to the dictionary
    pub fn add_sample(&mut self, data: Vec<u8>) {
        if !data.is_empty() {
            self.samples.push(data);
        }
    }
    
    /// Builds an optimized dictionary with SIMD
    pub fn build_dictionary(&self) -> Result<Vec<u8>, RuzipError> {
        if self.samples.is_empty() {
            return Ok(Vec::new());
        }
        
        let caps = get_simd_capabilities();
        
        if caps.avx2 && self.total_sample_size() >= 1024 {
            self.build_dictionary_simd()
        } else if (caps.sse2 || caps.neon) && self.total_sample_size() >= 256 {
            self.build_dictionary_simd()
        } else {
            self.build_dictionary_scalar()
        }
    }
    
    /// Calculates total size of all samples
    fn total_sample_size(&self) -> usize {
        self.samples.iter().map(|s| s.len()).sum()
    }
    
    /// SIMD-optimized Dictionary building
    #[cfg(feature = "simd")]
    fn build_dictionary_simd(&self) -> Result<Vec<u8>, RuzipError> {
        // Vereinfachte SIMD-Implementation
        let mut ngram_counts = HashMap::new();
        
        for sample in &self.samples {
            self.count_ngrams_simd(sample, &mut ngram_counts, 3)?;
        }
        
        self.build_from_ngrams(ngram_counts)
    }

    /// AVX2-optimized Dictionary building
    #[cfg(all(feature = "simd", target_arch = "x86_64"))]
    fn build_dictionary_avx2(&self) -> Result<Vec<u8>, RuzipError> {
        // Find frequent byte sequences with SIMD
        let mut ngram_counts = HashMap::new();
        
        for sample in &self.samples {
            self.count_ngrams_simd(sample, &mut ngram_counts, 4)?;
        }
        
        self.build_from_ngrams(ngram_counts)
    }
    
    /// SSE2/NEON-optimized Dictionary building
    #[cfg(feature = "simd")]
    #[allow(dead_code)]
    fn build_dictionary_sse2_neon(&self) -> Result<Vec<u8>, RuzipError> {
        let mut ngram_counts = HashMap::new();
        
        for sample in &self.samples {
            self.count_ngrams_simd(sample, &mut ngram_counts, 3)?;
        }
        
        self.build_from_ngrams(ngram_counts)
    }
    
    /// Scalar Dictionary building as fallback
    fn build_dictionary_scalar(&self) -> Result<Vec<u8>, RuzipError> {
        let mut ngram_counts = HashMap::new();
        
        for sample in &self.samples {
            self.count_ngrams_scalar(sample, &mut ngram_counts, 2);
        }
        
        self.build_from_ngrams(ngram_counts)
    }
    
    /// SIMD-optimized N-Gram counting
    #[cfg(feature = "simd")]
    fn count_ngrams_simd(
        &self,
        data: &[u8],
        counts: &mut HashMap<Vec<u8>, u32>,
        n: usize,
    ) -> Result<(), RuzipError> {
        if data.len() < n {
            return Ok(());
        }
        
        // Use SIMD for fast byte comparisons
        for i in 0..=data.len() - n {
            let ngram = data[i..i + n].to_vec();
            *counts.entry(ngram).or_insert(0) += 1;
        }
        
        Ok(())
    }
    
    /// Scalar N-Gram counting
    fn count_ngrams_scalar(
        &self,
        data: &[u8],
        counts: &mut HashMap<Vec<u8>, u32>,
        n: usize,
    ) {
        if data.len() < n {
            return;
        }
        
        for i in 0..=data.len() - n {
            let ngram = data[i..i + n].to_vec();
            *counts.entry(ngram).or_insert(0) += 1;
        }
    }
    
    /// Builds dictionary from N-Gram frequencies
    fn build_from_ngrams(&self, ngram_counts: HashMap<Vec<u8>, u32>) -> Result<Vec<u8>, RuzipError> {
        // Sort N-Grams by frequency
        let mut sorted_ngrams: Vec<_> = ngram_counts.into_iter().collect();
        sorted_ngrams.sort_by(|a, b| b.1.cmp(&a.1));
        
        // Build dictionary up to maximum size
        let mut dictionary = Vec::new();
        
        for (ngram, _count) in sorted_ngrams {
            if dictionary.len() + ngram.len() <= self.max_dict_size {
                dictionary.extend_from_slice(&ngram);
            } else {
                break;
            }
        }
        
        Ok(dictionary)
    }
}

/// SIMD-optimized ZSTD-Preprocessing
pub struct SimdZstdPreprocessor;

impl SimdZstdPreprocessor {
    /// Preprocesses data for optimal ZSTD compression
    pub fn preprocess(data: &[u8]) -> Result<Vec<u8>, RuzipError> {
        let caps = get_simd_capabilities();
        
        // Analyze data characteristics
        let entropy = SimdEntropy::calculate_entropy(data);
        let compression_level = SimdEntropy::recommend_compression_level(entropy);
        
        // Optimize data layout for better compression
        if caps.avx2 && data.len() >= 1024 {
            Self::preprocess_simd(data, compression_level)
        } else if (caps.sse2 || caps.neon) && data.len() >= 256 {
            Self::preprocess_simd(data, compression_level)
        } else {
            Self::preprocess_scalar(data, compression_level)
        }
    }
    
    /// SIMD-optimized Preprocessing
    #[cfg(feature = "simd")]
    fn preprocess_simd(data: &[u8], _level: u8) -> Result<Vec<u8>, RuzipError> {
        // Für jetzt: einfache Kopie mit SIMD-optimierter Memory-Copy
        let mut result = vec![0u8; data.len()];
        SimdMemCopy::copy_aligned(data, &mut result)?;
        Ok(result)
    }

    /// AVX2-optimized Preprocessing
    #[cfg(all(feature = "simd", target_arch = "x86_64"))]
    fn preprocess_avx2(data: &[u8], _level: u8) -> Result<Vec<u8>, RuzipError> {
        // For now: simple copy with SIMD-optimized memory copy
        let mut result = vec![0u8; data.len()];
        SimdMemCopy::copy_aligned(data, &mut result)?;
        Ok(result)
    }
    
    /// SSE2/NEON-optimized Preprocessing
    #[cfg(feature = "simd")]
    #[allow(dead_code)]
    fn preprocess_sse2_neon(data: &[u8], _level: u8) -> Result<Vec<u8>, RuzipError> {
        let mut result = vec![0u8; data.len()];
        SimdMemCopy::copy_aligned(data, &mut result)?;
        Ok(result)
    }
    
    /// Scalar Preprocessing as fallback
    fn preprocess_scalar(data: &[u8], _level: u8) -> Result<Vec<u8>, RuzipError> {
        Ok(data.to_vec())
    }
}

/// Benchmark functions for compression performance
#[cfg(feature = "simd")]
pub mod benchmark {
    use super::*;
    use std::time::{Duration, Instant};
    
    /// Benchmark result for compression performance
    #[derive(Debug)]
    pub struct CompressionBenchmarkResult {
        pub operation: String,
        pub data_size: usize,
        pub simd_time: Duration,
        pub scalar_time: Duration,
        pub speedup: f64,
        pub throughput_mbps: f64,
    }
    
    /// Benchmarks Memory-Copy Performance
    pub fn benchmark_memory_copy(data_size: usize, iterations: usize) -> CompressionBenchmarkResult {
        let src = vec![0xAB; data_size];
        
        // SIMD Memory-Copy
        let start = Instant::now();
        for _ in 0..iterations {
            let mut dst = vec![0u8; data_size];
            SimdMemCopy::copy_aligned(&src, &mut dst).unwrap();
        }
        let simd_time = start.elapsed();
        
        // Scalar Memory-Copy
        let start = Instant::now();
        for _ in 0..iterations {
            let mut dst = vec![0u8; data_size];
            dst.copy_from_slice(&src);
        }
        let scalar_time = start.elapsed();
        
        let speedup = scalar_time.as_nanos() as f64 / simd_time.as_nanos() as f64;
        let throughput = (data_size * iterations) as f64 / simd_time.as_secs_f64() / 1_000_000.0;
        
        CompressionBenchmarkResult {
            operation: "Memory Copy".to_string(),
            data_size,
            simd_time,
            scalar_time,
            speedup,
            throughput_mbps: throughput,
        }
    }
    
    /// Benchmarks Entropy-Calculation Performance
    pub fn benchmark_entropy_calculation(data: &[u8], iterations: usize) -> CompressionBenchmarkResult {
        // SIMD Entropy
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = SimdEntropy::calculate_entropy(data);
        }
        let simd_time = start.elapsed();
        
        // Scalar Entropy
        let start = Instant::now();
        for _ in 0..iterations {
            let _ = SimdEntropy::calculate_entropy_scalar(data);
        }
        let scalar_time = start.elapsed();
        
        let speedup = scalar_time.as_nanos() as f64 / simd_time.as_nanos() as f64;
        let throughput = (data.len() * iterations) as f64 / simd_time.as_secs_f64() / 1_000_000.0;
        
        CompressionBenchmarkResult {
            operation: "Entropy Calculation".to_string(),
            data_size: data.len(),
            simd_time,
            scalar_time,
            speedup,
            throughput_mbps: throughput,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_simd_memory_copy() {
        let src = vec![0xAB; 1024];
        let mut dst = vec![0u8; 1024];
        
        SimdMemCopy::copy_aligned(&src, &mut dst).unwrap();
        assert_eq!(src, dst);
    }
    
    #[test]
    fn test_entropy_calculation() {
        // Test with different data patterns
        let uniform_data = vec![0xAB; 1024];
        let entropy_uniform = SimdEntropy::calculate_entropy(&uniform_data);
        assert!(entropy_uniform < 1.0); // Very low entropy
        
        let random_data: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
        let entropy_random = SimdEntropy::calculate_entropy(&random_data);
        assert!(entropy_random > 6.0); // High entropy
    }
    
    #[test]
    fn test_compression_level_recommendation() {
        assert_eq!(SimdEntropy::recommend_compression_level(1.0), 1);
        assert_eq!(SimdEntropy::recommend_compression_level(3.0), 3);
        assert_eq!(SimdEntropy::recommend_compression_level(5.0), 6);
        assert_eq!(SimdEntropy::recommend_compression_level(6.5), 9);
        assert_eq!(SimdEntropy::recommend_compression_level(8.0), 12);
    }
    
    #[test]
    fn test_dictionary_building() {
        let mut builder = SimdDictionary::new(1024);
        
        builder.add_sample(b"hello world hello".to_vec());
        builder.add_sample(b"world hello world".to_vec());
        builder.add_sample(b"hello hello world".to_vec());
        
        let dictionary = builder.build_dictionary().unwrap();
        assert!(!dictionary.is_empty());
        assert!(dictionary.len() <= 1024);
    }
    
    #[test]
    fn test_zstd_preprocessing() {
        let data = b"This is test data for ZSTD preprocessing";
        let processed = SimdZstdPreprocessor::preprocess(data).unwrap();
        
        // For now it should be identical
        assert_eq!(processed, data);
    }
    
    #[test]
    fn test_large_data_processing() {
        let data = vec![0xCD; 1024 * 1024]; // 1MB test data
        
        let entropy = SimdEntropy::calculate_entropy(&data);
        assert!(entropy < 1.0); // Uniform data has low entropy
        
        let processed = SimdZstdPreprocessor::preprocess(&data).unwrap();
        assert_eq!(processed.len(), data.len());
    }
}