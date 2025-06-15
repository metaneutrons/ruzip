//! Parallel processing pipeline for compression operations

use super::{ThreadPool, ThreadSafeProgress, ThreadConfig, ThreadResult, ThreadStats};
use std::time::Instant;

/// Parallel compression pipeline
pub struct ParallelPipeline {
    thread_pool: ThreadPool,
    progress: Option<ThreadSafeProgress>,
}

/// Input chunk for parallel processing
#[derive(Clone)]
pub struct ProcessingChunk {
    pub data: Vec<u8>,
    pub chunk_id: usize,
    pub file_path: Option<String>,
    pub offset: u64,
}

/// Result of processing a chunk
#[derive(Clone)]
pub struct ChunkResult {
    pub compressed_data: Vec<u8>,
    pub chunk_id: usize,
    pub original_size: usize,
    pub compressed_size: usize,
    pub compression_ratio: f64,
    pub processing_time_ms: u64,
}

/// Pipeline statistics
#[derive(Debug, Clone)]
pub struct PipelineStats {
    pub total_chunks: usize,
    pub total_input_bytes: u64,
    pub total_output_bytes: u64,
    pub total_processing_time_ms: u64,
    pub average_compression_ratio: f64,
    pub throughput_mb_per_sec: f64,
    pub thread_efficiency: f64,
    pub thread_stats: ThreadStats,
}

impl ParallelPipeline {
    /// Create a new parallel pipeline
    pub fn new(config: ThreadConfig) -> ThreadResult<Self> {
        let thread_pool = ThreadPool::new(config)?;
        
        Ok(Self {
            thread_pool,
            progress: None,
        })
    }

    /// Create a pipeline with progress tracking
    pub fn with_progress(mut self, total_bytes: u64) -> Self {
        self.progress = Some(ThreadSafeProgress::new(total_bytes));
        self
    }

    /// Create a pipeline with silent progress tracking
    pub fn with_silent_progress(mut self, total_bytes: u64) -> Self {
        self.progress = Some(ThreadSafeProgress::new_silent(total_bytes));
        self
    }

    /// Process data in parallel chunks
    pub fn process_chunks(&self, chunks: Vec<ProcessingChunk>) -> ThreadResult<Vec<ChunkResult>> {
        if chunks.is_empty() {
            return Ok(Vec::new());
        }

        let _start_time = Instant::now();
        let _total_input_bytes: u64 = chunks.iter().map(|c| c.data.len() as u64).sum();

        // Set up progress tracking
        if let Some(ref progress) = self.progress {
            progress.set_message("Processing chunks...");
        }

        // Process chunks in parallel using simple threading
        let progress_clone = self.progress.clone();
        let results = self.thread_pool.try_parallel_map(chunks, move |chunk| {
            Self::process_single_chunk(chunk, progress_clone.as_ref())
        })?;

        // Sort results by chunk_id to maintain order
        let mut sorted_results = results;
        sorted_results.sort_by_key(|r| r.chunk_id);

        // Update final progress
        if let Some(ref progress) = self.progress {
            progress.finish_with_message("Processing completed");
        }

        Ok(sorted_results)
    }

    /// Process a single file in parallel chunks
    pub fn process_file(&self, file_data: Vec<u8>, file_path: String) -> ThreadResult<Vec<ChunkResult>> {
        let chunk_size = self.thread_pool.config().optimal_chunk_size(file_data.len());
        let chunks = self.split_into_chunks(file_data, chunk_size, Some(file_path));
        self.process_chunks(chunks)
    }

    /// Process multiple files in parallel
    pub fn process_files(&self, files: Vec<(String, Vec<u8>)>) -> ThreadResult<Vec<Vec<ChunkResult>>> {
        let _total_bytes: u64 = files.iter().map(|(_, data)| data.len() as u64).sum();
        
        if let Some(ref progress) = self.progress {
            progress.set_message("Processing multiple files...");
        }

        let file_chunks: Vec<_> = files.into_iter()
            .enumerate()
            .map(|(file_idx, (path, data))| {
                let chunk_size = self.thread_pool.config().optimal_chunk_size(data.len());
                let mut chunks = self.split_into_chunks(data, chunk_size, Some(path));
                // Adjust chunk IDs to be globally unique
                for chunk in &mut chunks {
                    chunk.chunk_id += file_idx * 10000; // Simple way to avoid ID conflicts
                }
                chunks
            })
            .collect();

        // Flatten all chunks and process in parallel
        let all_chunks: Vec<_> = file_chunks.into_iter().flatten().collect();
        let all_results = self.process_chunks(all_chunks)?;

        // Group results back by file
        let mut file_results = Vec::new();
        let mut current_file_results = Vec::new();
        let mut current_file_idx = 0;

        for result in all_results {
            let file_idx = result.chunk_id / 10000;
            if file_idx != current_file_idx {
                if !current_file_results.is_empty() {
                    file_results.push(current_file_results);
                    current_file_results = Vec::new();
                }
                current_file_idx = file_idx;
            }
            current_file_results.push(result);
        }
        
        if !current_file_results.is_empty() {
            file_results.push(current_file_results);
        }

        Ok(file_results)
    }

    /// Process a single chunk
    fn process_single_chunk(
        chunk: ProcessingChunk,
        progress: Option<&ThreadSafeProgress>,
    ) -> ThreadResult<ChunkResult> {
        let start_time = Instant::now();
        let original_size = chunk.data.len();

        // For now, just simulate compression by copying the data
        // In a full implementation, this would use the compression engine
        let compressed_data = chunk.data.clone();
        let compressed_size = compressed_data.len();
        let compression_ratio = if original_size > 0 {
            compressed_size as f64 / original_size as f64
        } else {
            1.0
        };

        let processing_time = start_time.elapsed();

        // Update progress
        if let Some(progress) = progress {
            progress.inc(original_size as u64);
        }

        Ok(ChunkResult {
            compressed_data,
            chunk_id: chunk.chunk_id,
            original_size,
            compressed_size,
            compression_ratio,
            processing_time_ms: processing_time.as_millis() as u64,
        })
    }

    /// Split data into processing chunks
    fn split_into_chunks(&self, data: Vec<u8>, chunk_size: usize, file_path: Option<String>) -> Vec<ProcessingChunk> {
        let mut chunks = Vec::new();
        let mut offset = 0u64;

        for (chunk_id, chunk_data) in data.chunks(chunk_size).enumerate() {
            chunks.push(ProcessingChunk {
                data: chunk_data.to_vec(),
                chunk_id,
                file_path: file_path.clone(),
                offset,
            });
            offset += chunk_data.len() as u64;
        }

        chunks
    }

    /// Get pipeline statistics
    pub fn get_stats(&self, results: &[ChunkResult]) -> PipelineStats {
        if results.is_empty() {
            return PipelineStats {
                total_chunks: 0,
                total_input_bytes: 0,
                total_output_bytes: 0,
                total_processing_time_ms: 0,
                average_compression_ratio: 1.0,
                throughput_mb_per_sec: 0.0,
                thread_efficiency: 0.0,
                thread_stats: ThreadStats::new(),
            };
        }

        let total_chunks = results.len();
        let total_input_bytes: u64 = results.iter().map(|r| r.original_size as u64).sum();
        let total_output_bytes: u64 = results.iter().map(|r| r.compressed_size as u64).sum();
        let total_processing_time_ms: u64 = results.iter().map(|r| r.processing_time_ms).sum();

        let average_compression_ratio = if total_input_bytes > 0 {
            total_output_bytes as f64 / total_input_bytes as f64
        } else {
            1.0
        };

        let throughput_mb_per_sec = if total_processing_time_ms > 0 {
            (total_input_bytes as f64) / (total_processing_time_ms as f64 / 1000.0) / 1_048_576.0
        } else {
            0.0
        };

        // Calculate thread efficiency (actual speedup vs theoretical maximum)
        let sequential_time_estimate = total_processing_time_ms;
        let parallel_time = results.iter().map(|r| r.processing_time_ms).max().unwrap_or(0);
        let thread_efficiency = if parallel_time > 0 && sequential_time_estimate > 0 {
            let actual_speedup = sequential_time_estimate as f64 / parallel_time as f64;
            let max_speedup = self.thread_pool.thread_count() as f64;
            (actual_speedup / max_speedup).min(1.0)
        } else {
            0.0
        };

        let mut thread_stats = ThreadStats::new();
        thread_stats.threads_used = self.thread_pool.thread_count();
        thread_stats.chunks_processed = total_chunks;
        thread_stats.total_items = total_chunks;
        thread_stats.elapsed_ms = parallel_time;
        thread_stats.calculate_throughput(total_input_bytes);

        PipelineStats {
            total_chunks,
            total_input_bytes,
            total_output_bytes,
            total_processing_time_ms,
            average_compression_ratio,
            throughput_mb_per_sec,
            thread_efficiency,
            thread_stats,
        }
    }

    /// Get progress information
    pub fn get_progress(&self) -> Option<crate::threading::progress::ProgressInfo> {
        self.progress.as_ref().and_then(|p| p.get_progress())
    }

    /// Get thread pool configuration
    pub fn config(&self) -> &ThreadConfig {
        self.thread_pool.config()
    }

    /// Get number of threads being used
    pub fn thread_count(&self) -> usize {
        self.thread_pool.thread_count()
    }
}

/// Builder for creating parallel pipelines
pub struct PipelineBuilder {
    config: ThreadConfig,
    progress_total: Option<u64>,
    silent_progress: bool,
}

impl PipelineBuilder {
    pub fn new() -> Self {
        Self {
            config: ThreadConfig::default(),
            progress_total: None,
            silent_progress: false,
        }
    }

    pub fn with_config(mut self, config: ThreadConfig) -> Self {
        self.config = config;
        self
    }

    pub fn with_progress(mut self, total_bytes: u64) -> Self {
        self.progress_total = Some(total_bytes);
        self.silent_progress = false;
        self
    }

    pub fn with_silent_progress(mut self, total_bytes: u64) -> Self {
        self.progress_total = Some(total_bytes);
        self.silent_progress = true;
        self
    }

    pub fn build(self) -> ThreadResult<ParallelPipeline> {
        let mut pipeline = ParallelPipeline::new(self.config)?;

        if let Some(total) = self.progress_total {
            pipeline = if self.silent_progress {
                pipeline.with_silent_progress(total)
            } else {
                pipeline.with_progress(total)
            };
        }

        Ok(pipeline)
    }
}

impl Default for PipelineBuilder {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_pipeline_creation() {
        let config = ThreadConfig::new().with_thread_count(2);
        let pipeline = ParallelPipeline::new(config).unwrap();
        assert_eq!(pipeline.thread_count(), 2);
    }

    #[test]
    fn test_chunk_processing() {
        let config = ThreadConfig::new().with_thread_count(2);
        let pipeline = ParallelPipeline::new(config).unwrap();

        let chunks = vec![
            ProcessingChunk {
                data: b"Hello, world!".to_vec(),
                chunk_id: 0,
                file_path: None,
                offset: 0,
            },
            ProcessingChunk {
                data: b"This is a test.".to_vec(),
                chunk_id: 1,
                file_path: None,
                offset: 13,
            },
        ];

        let results = pipeline.process_chunks(chunks).unwrap();
        assert_eq!(results.len(), 2);
        assert_eq!(results[0].chunk_id, 0);
        assert_eq!(results[1].chunk_id, 1);
    }

    #[test]
    fn test_pipeline_builder() {
        let pipeline = PipelineBuilder::new()
            .with_config(ThreadConfig::new().with_thread_count(4))
            .with_silent_progress(1000)
            .build()
            .unwrap();

        assert_eq!(pipeline.thread_count(), 4);
    }

    #[test]
    fn test_file_processing() {
        let config = ThreadConfig::new().with_thread_count(2);
        let pipeline = ParallelPipeline::new(config).unwrap();

        let file_data = b"This is test data that will be split into chunks for parallel processing.".to_vec();
        let results = pipeline.process_file(file_data, "test.txt".to_string()).unwrap();
        
        assert!(!results.is_empty());
        
        // Verify chunk ordering
        for (i, result) in results.iter().enumerate() {
            assert_eq!(result.chunk_id, i);
        }
    }

    #[test]
    fn test_stats_calculation() {
        let config = ThreadConfig::new().with_thread_count(2);
        let pipeline = ParallelPipeline::new(config).unwrap();

        let results = vec![
            ChunkResult {
                compressed_data: vec![1, 2, 3],
                chunk_id: 0,
                original_size: 10,
                compressed_size: 3,
                compression_ratio: 0.3,
                processing_time_ms: 100,
            },
            ChunkResult {
                compressed_data: vec![4, 5, 6, 7],
                chunk_id: 1,
                original_size: 20,
                compressed_size: 4,
                compression_ratio: 0.2,
                processing_time_ms: 200,
            },
        ];

        let stats = pipeline.get_stats(&results);
        assert_eq!(stats.total_chunks, 2);
        assert_eq!(stats.total_input_bytes, 30);
        assert_eq!(stats.total_output_bytes, 7);
        assert!((stats.average_compression_ratio - (7.0 / 30.0)).abs() < 0.001);
    }
}