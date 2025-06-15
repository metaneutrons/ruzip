//! Thread configuration for parallel operations

use std::num::NonZeroUsize;

/// Configuration for threading behavior
#[derive(Debug, Clone)]
pub struct ThreadConfig {
    /// Number of threads to use (None = auto-detect)
    pub thread_count: Option<NonZeroUsize>,
    /// Chunk size for parallel processing
    pub chunk_size: usize,
    /// Memory limit per thread in bytes
    pub memory_limit_per_thread: usize,
    /// Enable work stealing
    pub work_stealing: bool,
    /// Thread stack size
    pub stack_size: Option<usize>,
}

impl Default for ThreadConfig {
    fn default() -> Self {
        Self {
            thread_count: None, // Auto-detect
            chunk_size: 64 * 1024, // 64KB chunks
            memory_limit_per_thread: 128 * 1024 * 1024, // 128MB per thread
            work_stealing: true,
            stack_size: None, // Use system default
        }
    }
}

impl ThreadConfig {
    /// Create a new thread configuration
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Set the number of threads
    pub fn with_thread_count(mut self, count: usize) -> Self {
        self.thread_count = NonZeroUsize::new(count);
        self
    }
    
    /// Set the chunk size for processing
    pub fn with_chunk_size(mut self, size: usize) -> Self {
        self.chunk_size = size; // Allow any size for testing, validation will catch invalid values
        self
    }
    
    /// Set memory limit per thread
    pub fn with_memory_limit(mut self, limit: usize) -> Self {
        self.memory_limit_per_thread = limit;
        self
    }
    
    /// Disable work stealing
    pub fn without_work_stealing(mut self) -> Self {
        self.work_stealing = false;
        self
    }
    
    /// Set custom stack size
    pub fn with_stack_size(mut self, size: usize) -> Self {
        self.stack_size = Some(size);
        self
    }
    
    /// Get effective thread count (auto-detect if None)
    pub fn effective_thread_count(&self) -> usize {
        self.thread_count
            .map(|n| n.get())
            .unwrap_or_else(|| {
                // Use 75% of available cores, minimum 1, maximum 16
                (num_cpus::get() * 3 / 4).max(1).min(16)
            })
    }
    
    /// Calculate optimal chunk size based on input size and thread count
    pub fn optimal_chunk_size(&self, total_size: usize) -> usize {
        let thread_count = self.effective_thread_count();
        let ideal_chunks_per_thread = 4; // More chunks = better load balancing
        let total_chunks = thread_count * ideal_chunks_per_thread;
        
        if total_size == 0 {
            return self.chunk_size;
        }
        
        let calculated_chunk_size = total_size / total_chunks;
        
        // For very small inputs, use absolute minimum
        if total_size < 4096 {
            return 1024;
        }
        
        // Ensure chunk size is within reasonable bounds
        calculated_chunk_size
            .max(self.chunk_size / 4) // Not too small
            .min(self.chunk_size * 4) // Not too large
            .max(1024) // Absolute minimum 1KB
    }
    
    /// Validate configuration settings
    pub fn validate(&self) -> Result<(), String> {
        if self.chunk_size < 1024 {
            return Err("Chunk size must be at least 1024 bytes".to_string());
        }
        
        if self.memory_limit_per_thread < 1024 * 1024 {
            return Err("Memory limit per thread must be at least 1MB".to_string());
        }
        
        if let Some(count) = self.thread_count {
            if count.get() > 64 {
                return Err("Thread count cannot exceed 64".to_string());
            }
        }
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = ThreadConfig::default();
        assert!(config.work_stealing);
        assert!(config.thread_count.is_none());
        assert_eq!(config.chunk_size, 64 * 1024);
    }
    
    #[test]
    fn test_effective_thread_count() {
        let config = ThreadConfig::new();
        let count = config.effective_thread_count();
        assert!(count >= 1 && count <= 16);
        
        let config_with_threads = ThreadConfig::new().with_thread_count(4);
        assert_eq!(config_with_threads.effective_thread_count(), 4);
    }
    
    #[test]
    fn test_optimal_chunk_size() {
        let config = ThreadConfig::new().with_thread_count(4);
        
        // Test with large input
        let chunk_size = config.optimal_chunk_size(1_000_000);
        assert!(chunk_size >= 1024);
        
        // Test with small input
        let chunk_size = config.optimal_chunk_size(1000);
        assert_eq!(chunk_size, 1024); // Should be absolute minimum
    }
    
    #[test]
    fn test_validation() {
        let valid_config = ThreadConfig::new();
        assert!(valid_config.validate().is_ok());
        
        let invalid_config = ThreadConfig::new().with_chunk_size(512);
        assert!(invalid_config.validate().is_err());
    }
}