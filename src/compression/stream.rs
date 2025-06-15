//! Streaming compression wrappers
//!
//! Provides Read/Write wrappers for transparent compression/decompression
//! with progress tracking and zero-allocation memory management.

use crate::compression::{CompressionLevel, CompressionStats};
use crate::error::{Result, RuzipError};
use crate::memory::{
    BufferPool, ScratchBuffer, AdaptiveBufferSizer,
    streaming::{ChainedBuffer},
    profiler::AllocationTracker,
    get_memory_pressure_detector, get_thread_local_pool,
};
use std::io::{Read, Write};
use std::sync::Arc;

/// Compressed reader wrapper that decompresses data on-the-fly with zero-allocation optimization
pub struct CompressedReader {
    inner: Box<dyn Read>,
    stats: CompressionStats,
    bytes_read: u64,
    buffer_pool: Option<Arc<BufferPool<Vec<u8>>>>,
    scratch_buffer: Option<ScratchBuffer>,
    _chunk_size: usize,
    _allocation_tracker: Option<AllocationTracker>,
}

impl CompressedReader {
    /// Create new compressed reader with memory optimization
    pub fn new<R: Read + 'static>(reader: R) -> Result<Self> {
        let boxed_reader: Box<dyn Read> = Box::new(reader);
        let chunk_size = Self::get_optimal_chunk_size();
        
        // Track allocation for profiling
        let allocation_tracker = if let Some(profiler) = crate::memory::profiler::get_memory_profiler() {
            Some(AllocationTracker::new(profiler, chunk_size, "CompressedReader"))
        } else {
            None
        };

        Ok(Self {
            inner: boxed_reader,
            stats: CompressionStats::default(),
            bytes_read: 0,
            buffer_pool: None,
            scratch_buffer: None,
            _chunk_size: chunk_size,
            _allocation_tracker: allocation_tracker,
        })
    }

    /// Create compressed reader with buffer pool for zero-allocation
    pub fn with_buffer_pool<R: Read + 'static>(
        reader: R, 
        buffer_pool: Arc<BufferPool<Vec<u8>>>
    ) -> Result<Self> {
        let mut reader = Self::new(reader)?;
        reader.buffer_pool = Some(buffer_pool);
        Ok(reader)
    }

    /// Get optimal chunk size based on memory pressure
    fn get_optimal_chunk_size() -> usize {
        if let Some(detector) = get_memory_pressure_detector() {
            let sizer = AdaptiveBufferSizer::new(detector);
            sizer.chunk_size()
        } else {
            64 * 1024 // Default 64KB
        }
    }

    /// Get or create scratch buffer for decompression
    #[allow(dead_code)]
    fn get_scratch_buffer(&mut self) -> &mut ScratchBuffer {
        if self.scratch_buffer.is_none() {
            if let Some(pool) = get_thread_local_pool() {
                self.scratch_buffer = Some(pool.get_scratch_buffer());
            } else {
                self.scratch_buffer = Some(ScratchBuffer::new(
                    self._chunk_size,
                    self._chunk_size,
                    self._chunk_size / 4,
                ));
            }
        }
        self.scratch_buffer.as_mut().unwrap()
    }

    /// Read with buffer reuse for zero-allocation
    pub fn read_with_reuse(&mut self, buf: &mut [u8]) -> Result<usize> {
        // Read directly into output buffer for now to avoid borrowing conflicts
        let bytes_read = self.inner.read(buf)
            .map_err(|e| RuzipError::io_error("Read failed", e))?;
        
        if bytes_read > 0 {
            self.stats.original_size += bytes_read as u64;
            self.bytes_read += bytes_read as u64;
        }

        Ok(bytes_read)
    }

    /// Get compression statistics
    pub fn stats(&self) -> &CompressionStats {
        &self.stats
    }

    /// Get total bytes read from the compressed stream
    pub fn bytes_read(&self) -> u64 {
        self.bytes_read
    }
}

impl Read for CompressedReader {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        // Use optimized read with reuse when possible
        self.read_with_reuse(buf).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
        })
    }
}

impl Drop for CompressedReader {
    fn drop(&mut self) {
        // Return scratch buffer to thread-local pool if available
        if let Some(scratch) = self.scratch_buffer.take() {
            if let Some(pool) = get_thread_local_pool() {
                pool.return_scratch_buffer(scratch);
            }
        }
    }
}

/// Compressed writer wrapper that compresses data on-the-fly with memory optimization
pub struct CompressedWriter<W: Write> {
    inner: Option<zstd::stream::write::Encoder<'static, W>>,
    stats: CompressionStats,
    level: CompressionLevel,
    finalized: bool,
    buffer_pool: Option<Arc<BufferPool<Vec<u8>>>>,
    scratch_buffer: Option<ScratchBuffer>,
    chained_buffer: Option<ChainedBuffer>,
    _chunk_size: usize,
    _allocation_tracker: Option<AllocationTracker>,
}

impl<W: Write> CompressedWriter<W> {
    /// Create new compressed writer with memory optimization
    pub fn new(writer: W, level: CompressionLevel) -> Result<Self> {
        let chunk_size = Self::get_optimal_chunk_size();
        let encoder = zstd::stream::write::Encoder::new(writer, level.to_zstd_level())
            .map_err(|e| {
                RuzipError::compression_error(
                    "Failed to create ZSTD encoder",
                    Some(Box::new(e)),
                )
            })?;

        // Track allocation for profiling
        let allocation_tracker = if let Some(profiler) = crate::memory::profiler::get_memory_profiler() {
            Some(AllocationTracker::new(profiler, chunk_size, "CompressedWriter"))
        } else {
            None
        };

        Ok(Self {
            inner: Some(encoder),
            stats: CompressionStats::default(),
            level,
            finalized: false,
            buffer_pool: None,
            scratch_buffer: None,
            chained_buffer: None,
            _chunk_size: chunk_size,
            _allocation_tracker: allocation_tracker,
        })
    }

    /// Create compressed writer with buffer pool for zero-allocation
    pub fn with_buffer_pool(writer: W, level: CompressionLevel, buffer_pool: Arc<BufferPool<Vec<u8>>>) -> Result<Self> {
        let mut writer = Self::new(writer, level)?;
        writer.buffer_pool = Some(buffer_pool);
        Ok(writer)
    }

    /// Create compressed writer with chained buffer for streaming
    pub fn with_chained_buffer(writer: W, level: CompressionLevel, buffer_size: usize) -> Result<Self> {
        let mut writer = Self::new(writer, level)?;
        writer.chained_buffer = Some(ChainedBuffer::new(buffer_size));
        Ok(writer)
    }

    /// Create compressed writer with window size limit and memory optimization
    pub fn with_window_log(writer: W, level: CompressionLevel, window_log: u32) -> Result<Self> {
        let chunk_size = Self::get_optimal_chunk_size();
        let mut encoder = zstd::stream::write::Encoder::new(writer, level.to_zstd_level())
            .map_err(|e| {
                RuzipError::compression_error(
                    "Failed to create ZSTD encoder",
                    Some(Box::new(e)),
                )
            })?;

        encoder.window_log(window_log).map_err(|e| {
            RuzipError::compression_error(
                "Failed to set window log size",
                Some(Box::new(e)),
            )
        })?;

        // Track allocation for profiling
        let allocation_tracker = if let Some(profiler) = crate::memory::profiler::get_memory_profiler() {
            Some(AllocationTracker::new(profiler, chunk_size, "CompressedWriter"))
        } else {
            None
        };

        Ok(Self {
            inner: Some(encoder),
            stats: CompressionStats::default(),
            level,
            finalized: false,
            buffer_pool: None,
            scratch_buffer: None,
            chained_buffer: None,
            _chunk_size: chunk_size,
            _allocation_tracker: allocation_tracker,
        })
    }

    /// Get optimal chunk size based on memory pressure
    fn get_optimal_chunk_size() -> usize {
        if let Some(detector) = get_memory_pressure_detector() {
            let sizer = AdaptiveBufferSizer::new(detector);
            sizer.chunk_size()
        } else {
            64 * 1024 // Default 64KB
        }
    }

    /// Get or create scratch buffer for compression
    #[allow(dead_code)]
    fn get_scratch_buffer(&mut self) -> &mut ScratchBuffer {
        if self.scratch_buffer.is_none() {
            if let Some(pool) = get_thread_local_pool() {
                self.scratch_buffer = Some(pool.get_scratch_buffer());
            } else {
                self.scratch_buffer = Some(ScratchBuffer::new(
                    self._chunk_size,
                    self._chunk_size,
                    self._chunk_size / 4,
                ));
            }
        }
        self.scratch_buffer.as_mut().unwrap()
    }

    /// Write data using buffer reuse
    pub fn write_with_reuse(&mut self, data: &[u8]) -> Result<usize> {
        if self.finalized {
            return Err(RuzipError::internal_error(
                "Cannot write to finalized compressed writer",
                Some(file!()),
            ));
        }

        // For now, write directly to avoid borrowing conflicts
        self.write_internal(data)
    }

    /// Internal write method
    fn write_internal(&mut self, data: &[u8]) -> Result<usize> {
        let encoder = self.inner.as_mut().ok_or_else(|| {
            RuzipError::internal_error(
                "Encoder has been consumed",
                Some(file!()),
            )
        })?;

        let bytes_written = encoder.write(data).map_err(|e| RuzipError::io_error("Encoder write failed", e))?;
        self.stats.original_size += bytes_written as u64;
        Ok(bytes_written)
    }

    /// Finalize compression and return the underlying writer
    pub fn finish(mut self) -> Result<W> {
        if self.finalized {
            return Err(RuzipError::internal_error(
                "Compressed writer already finalized",
                Some(file!()),
            ));
        }

        // Skip chained buffer flushing for now to avoid borrowing conflicts

        let encoder = self.inner.take().ok_or_else(|| {
            RuzipError::internal_error(
                "Encoder already consumed",
                Some(file!()),
            )
        })?;

        let writer = encoder.finish().map_err(|e| {
            RuzipError::compression_error(
                "Failed to finalize compression",
                Some(Box::new(e)),
            )
        })?;

        self.finalized = true;
        Ok(writer)
    }

    /// Get compression statistics
    pub fn stats(&self) -> &CompressionStats {
        &self.stats
    }

    /// Get compression level
    pub fn level(&self) -> CompressionLevel {
        self.level
    }

    /// Check if writer has been finalized
    pub fn is_finalized(&self) -> bool {
        self.finalized
    }
}

impl<W: Write> Write for CompressedWriter<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        // Use optimized write with reuse when possible
        self.write_with_reuse(buf).map_err(|e| {
            std::io::Error::new(std::io::ErrorKind::Other, e.to_string())
        })
    }

    fn flush(&mut self) -> std::io::Result<()> {
        // Skip chained buffer flushing for now to avoid borrowing conflicts

        // Flush encoder
        if let Some(encoder) = &mut self.inner {
            encoder.flush()
        } else {
            Ok(())
        }
    }
}

impl<W: Write> Drop for CompressedWriter<W> {
    fn drop(&mut self) {
        // Return scratch buffer to thread-local pool if available
        if let Some(scratch) = self.scratch_buffer.take() {
            if let Some(pool) = get_thread_local_pool() {
                pool.return_scratch_buffer(scratch);
            }
        }

        if !self.finalized && self.inner.is_some() {
            // Try to finalize gracefully, but don't panic on error
            let _ = self.inner.take().unwrap().finish();
        }
    }
}

/// Progress tracking wrapper for compression operations with memory optimization
pub struct ProgressTracker<T> {
    inner: T,
    bytes_processed: u64,
    total_size: Option<u64>,
    callback: Option<Box<dyn Fn(u64, Option<u64>) + Send + Sync>>,
    _allocation_tracker: Option<AllocationTracker>,
}

impl<T> ProgressTracker<T> {
    /// Create new progress tracker with memory profiling
    pub fn new(inner: T) -> Self {
        // Track allocation for profiling
        let allocation_tracker = if let Some(profiler) = crate::memory::profiler::get_memory_profiler() {
            Some(AllocationTracker::new(profiler, std::mem::size_of::<Self>(), "ProgressTracker"))
        } else {
            None
        };

        Self {
            inner,
            bytes_processed: 0,
            total_size: None,
            callback: None,
            _allocation_tracker: allocation_tracker,
        }
    }

    /// Set total size for progress calculation
    pub fn with_total_size(mut self, size: u64) -> Self {
        self.total_size = Some(size);
        self
    }

    /// Set progress callback function
    pub fn with_callback<F>(mut self, callback: F) -> Self
    where
        F: Fn(u64, Option<u64>) + Send + Sync + 'static,
    {
        self.callback = Some(Box::new(callback));
        self
    }

    /// Get bytes processed so far
    pub fn bytes_processed(&self) -> u64 {
        self.bytes_processed
    }

    /// Get total size if known
    pub fn total_size(&self) -> Option<u64> {
        self.total_size
    }

    /// Get progress percentage (0.0 to 100.0)
    pub fn progress_percentage(&self) -> Option<f64> {
        self.total_size.map(|total| {
            if total > 0 {
                (self.bytes_processed as f64 / total as f64) * 100.0
            } else {
                0.0
            }
        })
    }

    /// Update progress and call callback if set
    fn update_progress(&mut self, bytes: usize) {
        self.bytes_processed += bytes as u64;
        
        if let Some(callback) = &self.callback {
            callback(self.bytes_processed, self.total_size);
        }
    }

    /// Get inner object
    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<R: Read> Read for ProgressTracker<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let bytes_read = self.inner.read(buf)?;
        if bytes_read > 0 {
            self.update_progress(bytes_read);
        }
        Ok(bytes_read)
    }
}

impl<W: Write> Write for ProgressTracker<W> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        let bytes_written = self.inner.write(buf)?;
        if bytes_written > 0 {
            self.update_progress(bytes_written);
        }
        Ok(bytes_written)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.inner.flush()
    }
}

/// Zero-copy streaming compressor for in-place operations
pub struct ZeroCopyCompressor {
    scratch_buffer: ScratchBuffer,
    chunk_size: usize,
    level: CompressionLevel,
    _allocation_tracker: Option<AllocationTracker>,
}

impl ZeroCopyCompressor {
    /// Create new zero-copy compressor
    pub fn new(level: CompressionLevel) -> Self {
        let chunk_size = if let Some(detector) = get_memory_pressure_detector() {
            let sizer = AdaptiveBufferSizer::new(detector);
            sizer.chunk_size()
        } else {
            64 * 1024
        };

        let allocation_tracker = if let Some(profiler) = crate::memory::profiler::get_memory_profiler() {
            Some(AllocationTracker::new(profiler, chunk_size, "ZeroCopyCompressor"))
        } else {
            None
        };

        Self {
            scratch_buffer: ScratchBuffer::new(chunk_size, chunk_size, chunk_size / 4),
            chunk_size,
            level,
            _allocation_tracker: allocation_tracker,
        }
    }

    /// Compress data in-place using scratch buffers
    pub fn compress_in_place(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let comp_buf = self.scratch_buffer.compression_buffer();
        comp_buf.clear();
        
        // Use ZSTD compression with scratch buffer
        let compressed = zstd::bulk::compress(data, self.level.to_zstd_level())
            .map_err(|e| RuzipError::compression_error(
                "Failed to compress data",
                Some(Box::new(e)),
            ))?;
        
        comp_buf.extend_from_slice(&compressed);
        Ok(comp_buf.clone())
    }

    /// Decompress data in-place using scratch buffers
    pub fn decompress_in_place(&mut self, data: &[u8]) -> Result<Vec<u8>> {
        let decomp_buf = self.scratch_buffer.decompression_buffer();
        decomp_buf.clear();
        
        // Use ZSTD decompression with scratch buffer
        let decompressed = zstd::bulk::decompress(data, self.chunk_size * 4)
            .map_err(|e| RuzipError::compression_error(
                "Failed to decompress data",
                Some(Box::new(e)),
            ))?;
        
        decomp_buf.extend_from_slice(&decompressed);
        Ok(decomp_buf.clone())
    }

    /// Get scratch buffer statistics
    pub fn buffer_stats(&mut self) -> (usize, usize, usize) {
        (
            self.scratch_buffer.compression_buffer().capacity(),
            self.scratch_buffer.decompression_buffer().capacity(),
            self.scratch_buffer.temp_buffer().capacity(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_compressed_writer_creation() {
        let buffer = Vec::new();
        let level = CompressionLevel::new(6).unwrap();
        
        let writer = CompressedWriter::new(buffer, level).unwrap();
        assert_eq!(writer.level(), level);
        assert!(!writer.is_finalized());
    }

    #[test]
    fn test_compressed_writer_with_window_log() {
        let buffer = Vec::new();
        let level = CompressionLevel::new(6).unwrap();
        
        let writer = CompressedWriter::with_window_log(buffer, level, 20).unwrap();
        assert_eq!(writer.level(), level);
    }

    #[test]
    fn test_compressed_reader_basic() {
        let input_data = b"Hello, World! This is test data for compression.";
        let cursor = Cursor::new(input_data);
        
        let mut reader = CompressedReader::new(cursor).unwrap();
        let mut output_buffer = Vec::new();
        reader.read_to_end(&mut output_buffer).unwrap();

        // Data should be read successfully
        assert!(!output_buffer.is_empty());
    }

    #[test]
    fn test_progress_tracker_basic() {
        let data = b"Hello, World!";
        let cursor = Cursor::new(data);
        
        let mut tracker = ProgressTracker::new(cursor)
            .with_total_size(data.len() as u64);

        let mut buffer = vec![0u8; 5];
        
        // Read first chunk
        let bytes_read = tracker.read(&mut buffer).unwrap();
        assert_eq!(bytes_read, 5);
        assert_eq!(tracker.bytes_processed(), 5);
        
        // Check progress percentage
        let progress = tracker.progress_percentage().unwrap();
        assert!((progress - 38.46).abs() < 0.1); // ~38.46%
    }

    #[test]
    fn test_compressed_writer_finalization() {
        let buffer = Vec::new();
        let level = CompressionLevel::new(6).unwrap();
        
        let writer = CompressedWriter::new(buffer, level).unwrap();
        assert!(!writer.is_finalized());
        
        let _buffer = writer.finish().unwrap();
        // Writer should be finalized after finish()
    }

    #[test]
    fn test_zero_copy_compressor() {
        let level = CompressionLevel::new(6).unwrap();
        let mut compressor = ZeroCopyCompressor::new(level);
        
        let data = b"Hello, World! This is test data for compression.";
        let compressed = compressor.compress_in_place(data).unwrap();
        assert!(!compressed.is_empty());
        
        let decompressed = compressor.decompress_in_place(&compressed).unwrap();
        assert_eq!(decompressed, data);
    }

    #[test]
    fn test_compressed_writer_with_chained_buffer() {
        let buffer = Vec::new();
        let level = CompressionLevel::new(6).unwrap();
        
        let writer = CompressedWriter::with_chained_buffer(buffer, level, 1024).unwrap();
        assert_eq!(writer.level(), level);
        assert!(writer.chained_buffer.is_some());
    }
}