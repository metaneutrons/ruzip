//! Threading module for parallel compression operations
//! 
//! This module provides multi-threaded compression capabilities using Rayon
//! for work-stealing parallelism and high-performance I/O operations.

pub mod pool;
pub mod pipeline;
pub mod progress;
pub mod config;

pub use pool::ThreadPool;
pub use pipeline::ParallelPipeline;
pub use progress::ThreadSafeProgress;
pub use config::ThreadConfig;

use crate::error::RuzipError;

/// Result type for threading operations
pub type ThreadResult<T> = Result<T, RuzipError>;

/// Trait for parallel processing operations
pub trait ParallelProcessor: Send + Sync {
    type Input: Send;
    type Output: Send;
    
    /// Process input in parallel chunks
    fn process_parallel(&self, input: Vec<Self::Input>) -> ThreadResult<Vec<Self::Output>>;
    
    /// Get optimal chunk size for processing
    fn optimal_chunk_size(&self) -> usize;
}

/// Threading statistics for performance monitoring
#[derive(Debug, Clone)]
pub struct ThreadStats {
    pub threads_used: usize,
    pub chunks_processed: usize,
    pub total_items: usize,
    pub elapsed_ms: u64,
    pub throughput_mb_per_sec: f64,
}

impl ThreadStats {
    pub fn new() -> Self {
        Self {
            threads_used: 0,
            chunks_processed: 0,
            total_items: 0,
            elapsed_ms: 0,
            throughput_mb_per_sec: 0.0,
        }
    }
    
    pub fn calculate_throughput(&mut self, bytes_processed: u64) {
        if self.elapsed_ms > 0 {
            self.throughput_mb_per_sec = (bytes_processed as f64) / (self.elapsed_ms as f64 / 1000.0) / 1_048_576.0;
        }
    }
}