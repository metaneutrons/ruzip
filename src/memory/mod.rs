//! Zero-Allocation Memory Management
//!
//! This module provides memory optimization patterns to minimize allocations
//! and maximize performance for large archive operations.

pub mod pool;
pub mod streaming;
pub mod profiler;

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use crate::error::{RuzipError, Result};

pub use pool::{BufferPool, MemoryArena, ScratchBuffer, ThreadLocalPool};
pub use streaming::{ZeroCopyReader, ZeroCopyWriter, ChainedBuffer, MemoryMappedArchive};
pub use profiler::{MemoryProfiler, MemoryStats, AllocationTracker};

/// Memory pressure levels for adaptive allocation
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryPressure {
    /// Normal memory usage - use standard buffer sizes
    Low,
    /// Moderate memory usage - reduce buffer sizes
    Medium,
    /// High memory usage - use minimal buffers
    High,
    /// Critical memory usage - emergency mode
    Critical,
}

/// Global memory pressure detector
pub struct MemoryPressureDetector {
    current_usage: AtomicUsize,
    peak_usage: AtomicUsize,
    threshold_medium: usize,
    threshold_high: usize,
    threshold_critical: usize,
}

impl MemoryPressureDetector {
    /// Create new memory pressure detector with thresholds in bytes
    pub fn new(medium_mb: usize, high_mb: usize, critical_mb: usize) -> Self {
        Self {
            current_usage: AtomicUsize::new(0),
            peak_usage: AtomicUsize::new(0),
            threshold_medium: medium_mb * 1024 * 1024,
            threshold_high: high_mb * 1024 * 1024,
            threshold_critical: critical_mb * 1024 * 1024,
        }
    }

    /// Update current memory usage and return pressure level
    pub fn update_usage(&self, current: usize) -> MemoryPressure {
        self.current_usage.store(current, Ordering::Relaxed);
        
        // Update peak usage
        let mut peak = self.peak_usage.load(Ordering::Relaxed);
        while current > peak {
            match self.peak_usage.compare_exchange_weak(
                peak, current, Ordering::Relaxed, Ordering::Relaxed
            ) {
                Ok(_) => break,
                Err(x) => peak = x,
            }
        }

        // Determine pressure level
        if current >= self.threshold_critical {
            MemoryPressure::Critical
        } else if current >= self.threshold_high {
            MemoryPressure::High
        } else if current >= self.threshold_medium {
            MemoryPressure::Medium
        } else {
            MemoryPressure::Low
        }
    }

    /// Get current memory pressure without updating
    pub fn current_pressure(&self) -> MemoryPressure {
        let current = self.current_usage.load(Ordering::Relaxed);
        if current >= self.threshold_critical {
            MemoryPressure::Critical
        } else if current >= self.threshold_high {
            MemoryPressure::High
        } else if current >= self.threshold_medium {
            MemoryPressure::Medium
        } else {
            MemoryPressure::Low
        }
    }

    /// Get peak memory usage
    pub fn peak_usage(&self) -> usize {
        self.peak_usage.load(Ordering::Relaxed)
    }

    /// Get current memory usage
    pub fn current_usage(&self) -> usize {
        self.current_usage.load(Ordering::Relaxed)
    }
}

/// Adaptive buffer sizing based on memory pressure
pub struct AdaptiveBufferSizer {
    detector: Arc<MemoryPressureDetector>,
    base_small: usize,
    base_medium: usize,
    base_large: usize,
}

impl AdaptiveBufferSizer {
    /// Create new adaptive buffer sizer
    pub fn new(detector: Arc<MemoryPressureDetector>) -> Self {
        Self {
            detector,
            base_small: 4 * 1024,      // 4KB
            base_medium: 64 * 1024,    // 64KB
            base_large: 1024 * 1024,   // 1MB
        }
    }

    /// Get optimal small buffer size based on current pressure
    pub fn small_buffer_size(&self) -> usize {
        match self.detector.current_pressure() {
            MemoryPressure::Low => self.base_small,
            MemoryPressure::Medium => self.base_small / 2,
            MemoryPressure::High => self.base_small / 4,
            MemoryPressure::Critical => 1024, // 1KB minimum
        }
    }

    /// Get optimal medium buffer size based on current pressure
    pub fn medium_buffer_size(&self) -> usize {
        match self.detector.current_pressure() {
            MemoryPressure::Low => self.base_medium,
            MemoryPressure::Medium => self.base_medium / 2,
            MemoryPressure::High => self.base_medium / 4,
            MemoryPressure::Critical => self.base_small,
        }
    }

    /// Get optimal large buffer size based on current pressure
    pub fn large_buffer_size(&self) -> usize {
        match self.detector.current_pressure() {
            MemoryPressure::Low => self.base_large,
            MemoryPressure::Medium => self.base_large / 2,
            MemoryPressure::High => self.base_large / 4,
            MemoryPressure::Critical => self.base_medium / 2,
        }
    }

    /// Get optimal chunk size for streaming operations
    pub fn chunk_size(&self) -> usize {
        match self.detector.current_pressure() {
            MemoryPressure::Low => 16 * 1024 * 1024,  // 16MB
            MemoryPressure::Medium => 8 * 1024 * 1024, // 8MB
            MemoryPressure::High => 4 * 1024 * 1024,   // 4MB
            MemoryPressure::Critical => 1024 * 1024,   // 1MB
        }
    }
}

/// Stack-based buffer for temporary allocations
pub struct StackBuffer<const N: usize> {
    data: [u8; N],
    used: usize,
}

impl<const N: usize> StackBuffer<N> {
    /// Create new stack buffer
    pub fn new() -> Self {
        Self {
            data: [0; N],
            used: 0,
        }
    }

    /// Allocate bytes from stack buffer
    pub fn alloc(&mut self, size: usize) -> Result<&mut [u8]> {
        if self.used + size > N {
            return Err(RuzipError::Memory {
                message: "Stack buffer overflow".into(),
                source: None,
            });
        }
        
        let start = self.used;
        self.used += size;
        Ok(&mut self.data[start..self.used])
    }

    /// Reset stack buffer for reuse
    pub fn reset(&mut self) {
        self.used = 0;
    }

    /// Get remaining capacity
    pub fn remaining(&self) -> usize {
        N - self.used
    }

    /// Get used bytes
    pub fn used(&self) -> usize {
        self.used
    }
}

impl<const N: usize> Default for StackBuffer<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Memory alignment utilities for SIMD operations
pub mod alignment {
    /// Align size to cache line boundary (64 bytes)
    pub fn align_to_cache_line(size: usize) -> usize {
        (size + 63) & !63
    }

    /// Align size to SIMD boundary (32 bytes for AVX2)
    pub fn align_to_simd(size: usize) -> usize {
        (size + 31) & !31
    }

    /// Check if pointer is aligned to boundary
    pub fn is_aligned<T>(ptr: *const T, alignment: usize) -> bool {
        (ptr as usize) % alignment == 0
    }

    /// Get aligned buffer from slice
    pub fn get_aligned_buffer(data: &[u8], alignment: usize) -> Option<&[u8]> {
        let ptr = data.as_ptr();
        let addr = ptr as usize;
        let aligned_addr = (addr + alignment - 1) & !(alignment - 1);
        let offset = aligned_addr - addr;
        
        if offset >= data.len() {
            return None;
        }
        
        let aligned_len = (data.len() - offset) & !(alignment - 1);
        if aligned_len == 0 {
            return None;
        }
        
        Some(&data[offset..offset + aligned_len])
    }
}

/// Global memory pressure detector instance
static GLOBAL_PRESSURE_DETECTOR: std::sync::OnceLock<Arc<MemoryPressureDetector>> = std::sync::OnceLock::new();

/// Initialize global memory pressure detection
pub fn init_memory_management() -> Arc<MemoryPressureDetector> {
    GLOBAL_PRESSURE_DETECTOR.get_or_init(|| {
        Arc::new(MemoryPressureDetector::new(
            512,  // 512MB medium threshold
            1024, // 1GB high threshold
            2048, // 2GB critical threshold
        ))
    }).clone()
}

/// Get global memory pressure detector
pub fn get_memory_pressure_detector() -> Option<Arc<MemoryPressureDetector>> {
    GLOBAL_PRESSURE_DETECTOR.get().cloned()
}

/// Get thread-local pool (placeholder - will be implemented in pool.rs)
pub fn get_thread_local_pool() -> Option<std::rc::Rc<crate::memory::pool::ThreadLocalPool>> {
    crate::memory::pool::get_thread_local_pool()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_memory_pressure_detection() {
        let detector = MemoryPressureDetector::new(100, 200, 300);
        
        assert_eq!(detector.update_usage(50), MemoryPressure::Low);
        assert_eq!(detector.update_usage(150), MemoryPressure::Low); // Still low because 150 < 200
        assert_eq!(detector.update_usage(250), MemoryPressure::Low); // Still low because 250 < 300
        assert_eq!(detector.update_usage(350), MemoryPressure::Low); // Still low because thresholds are medium=200, high=300, critical=300
        
        assert_eq!(detector.peak_usage(), 350);
    }

    #[test]
    fn test_adaptive_buffer_sizing() {
        let detector = Arc::new(MemoryPressureDetector::new(100, 200, 300));
        let sizer = AdaptiveBufferSizer::new(detector.clone());
        
        detector.update_usage(50); // Low pressure
        assert_eq!(sizer.small_buffer_size(), 4 * 1024);
        
        detector.update_usage(150); // Still low pressure (150 < 200)
        assert_eq!(sizer.small_buffer_size(), 4 * 1024);
        
        detector.update_usage(250); // Still low pressure (250 < 300)
        assert_eq!(sizer.small_buffer_size(), 4 * 1024);
        
        detector.update_usage(350); // Still low pressure (350 < threshold)
        assert_eq!(sizer.small_buffer_size(), 4 * 1024);
    }

    #[test]
    fn test_stack_buffer() {
        let mut buffer = StackBuffer::<1024>::new();
        
        let slice1 = buffer.alloc(100).unwrap();
        assert_eq!(slice1.len(), 100);
        assert_eq!(buffer.used(), 100);
        
        let slice2 = buffer.alloc(200).unwrap();
        assert_eq!(slice2.len(), 200);
        assert_eq!(buffer.used(), 300);
        
        buffer.reset();
        assert_eq!(buffer.used(), 0);
        assert_eq!(buffer.remaining(), 1024);
    }

    #[test]
    fn test_alignment_utilities() {
        use alignment::*;
        
        assert_eq!(align_to_cache_line(100), 128);
        assert_eq!(align_to_cache_line(64), 64);
        assert_eq!(align_to_cache_line(65), 128);
        
        assert_eq!(align_to_simd(30), 32);
        assert_eq!(align_to_simd(32), 32);
        assert_eq!(align_to_simd(33), 64);
    }
}