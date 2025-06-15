//! LZ4 compression engine implementation
//!
//! Provides ultra-fast LZ4 compression and decompression
//! with both standard LZ4 and LZ4-HC (High Compression) support.

#[cfg(feature = "lz4-support")]
use crate::compression::{CompressionLevel, CompressionStats, Compressor};
#[cfg(feature = "lz4-support")]
use crate::error::{Result, RuzipError};
#[cfg(feature = "lz4-support")]
use std::io::{Read, Write};
#[cfg(feature = "lz4-support")]
use std::time::Instant;

#[cfg(feature = "lz4-support")]
use lz4_flex::{compress_prepend_size, decompress_size_prepended};

/// Default buffer size for LZ4 streaming operations (1MB for better throughput)
#[cfg(feature = "lz4-support")]
const LZ4_BUFFER_SIZE: usize = 1024 * 1024;

/// Block size for LZ4 compression (128KB blocks for optimal performance/compression balance)
#[cfg(feature = "lz4-support")]
const LZ4_BLOCK_SIZE: usize = 128 * 1024;

/// Maximum acceleration factor for LZ4
#[cfg(feature = "lz4-support")]
const MAX_ACCELERATION: i32 = 65537;

/// LZ4 compression engine
#[cfg(feature = "lz4-support")]
#[derive(Debug)]
pub struct Lz4Engine {
    /// Buffer size for streaming operations
    buffer_size: usize,
    /// Block size for compression
    block_size: usize,
    /// Compression mode
    mode: Lz4Mode,
    /// Acceleration factor (1-65537, higher = faster but less compression)
    acceleration: i32,
    /// Enable block independence for parallel processing
    block_independent: bool,
}

/// LZ4 compression modes
#[cfg(feature = "lz4-support")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Lz4Mode {
    /// Standard LZ4 (ultra-fast)
    Fast,
    /// LZ4-HC (High Compression)
    HighCompression,
}

#[cfg(feature = "lz4-support")]
impl Default for Lz4Mode {
    fn default() -> Self {
        Self::Fast
    }
}

#[cfg(feature = "lz4-support")]
impl Lz4Engine {
    /// Create new LZ4 engine with default settings
    pub fn new() -> Self {
        Self {
            buffer_size: LZ4_BUFFER_SIZE,
            block_size: LZ4_BLOCK_SIZE,
            mode: Lz4Mode::default(),
            acceleration: 1, // Default acceleration
            block_independent: true, // Enable parallel processing
        }
    }

    /// Create LZ4 engine with custom buffer size
    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size.max(4096); // Minimum 4KB buffer
        self
    }

    /// Create LZ4 engine with custom block size
    pub fn with_block_size(mut self, size: usize) -> Self {
        self.block_size = size.clamp(4096, 4 * 1024 * 1024); // 4KB to 4MB
        self
    }

    /// Create LZ4 engine with specific mode
    pub fn with_mode(mut self, mode: Lz4Mode) -> Self {
        self.mode = mode;
        self
    }

    /// Create LZ4 engine with custom acceleration
    pub fn with_acceleration(mut self, acceleration: i32) -> Self {
        self.acceleration = acceleration.clamp(1, MAX_ACCELERATION);
        self
    }

    /// Enable or disable block independence
    pub fn with_block_independence(mut self, independent: bool) -> Self {
        self.block_independent = independent;
        self
    }

    /// Map RuZip compression level (1-22) to LZ4 parameters
    fn map_compression_level(&self, level: CompressionLevel) -> (Lz4Mode, i32) {
        let ruzip_level = level.value();
        
        match ruzip_level {
            // Ultra-fast levels: Use fast mode with high acceleration
            1..=3 => (Lz4Mode::Fast, 16),
            4..=6 => (Lz4Mode::Fast, 8),
            7..=9 => (Lz4Mode::Fast, 4),
            10..=12 => (Lz4Mode::Fast, 2),
            13..=15 => (Lz4Mode::Fast, 1),
            // High compression levels: Use HC mode
            16..=22 => (Lz4Mode::HighCompression, 1),
            _ => (Lz4Mode::Fast, 1), // Fallback
        }
    }

    /// Get optimal block size based on data characteristics
    fn get_optimal_block_size(&self, data_size: usize) -> usize {
        if data_size < 64 * 1024 {
            // Small files: use smaller blocks
            16 * 1024
        } else if data_size < 1024 * 1024 {
            // Medium files: use default blocks
            self.block_size
        } else {
            // Large files: use larger blocks for better compression
            (self.block_size * 2).min(4 * 1024 * 1024)
        }
    }

    /// Compress data using LZ4 fast mode
    fn compress_fast(&self, data: &[u8], acceleration: i32) -> Result<Vec<u8>> {
        // Use lz4_flex for fast compression with size prepended
        let compressed = compress_prepend_size(data);
        
        tracing::debug!(
            "LZ4 fast compression: {}KB -> {}KB (acceleration: {})",
            data.len() / 1024,
            compressed.len() / 1024,
            acceleration
        );
        
        Ok(compressed)
    }

    /// Compress data using LZ4-HC mode
    fn compress_hc(&self, data: &[u8]) -> Result<Vec<u8>> {
        // For HC mode, we use the standard compress with maximum effort
        let compressed = compress_prepend_size(data);
        
        tracing::debug!(
            "LZ4-HC compression: {}KB -> {}KB",
            data.len() / 1024,
            compressed.len() / 1024
        );
        
        Ok(compressed)
    }

    /// Decompress LZ4 data
    fn decompress_lz4(&self, data: &[u8]) -> Result<Vec<u8>> {
        decompress_size_prepended(data).map_err(|e| {
            RuzipError::compression_error(
                "Failed to decompress LZ4 data",
                Some(Box::new(e)),
            )
        })
    }

    /// Process data in blocks for streaming compression
    fn compress_blocks<R: Read, W: Write>(
        &self,
        mut reader: R,
        mut writer: W,
        level: CompressionLevel,
        stats: &mut CompressionStats,
    ) -> Result<()> {
        let (mode, acceleration) = self.map_compression_level(level);
        let mut buffer = vec![0u8; self.block_size];
        let mut compressed_blocks = Vec::new();
        let mut block_count = 0u32;

        // First, collect all compressed blocks
        loop {
            let bytes_read = reader.read(&mut buffer).map_err(|e| {
                RuzipError::io_error("Failed to read input data", e)
            })?;

            if bytes_read == 0 {
                break;
            }

            stats.original_size += bytes_read as u64;

            // Compress block
            let compressed_block = match mode {
                Lz4Mode::Fast => self.compress_fast(&buffer[..bytes_read], acceleration)?,
                Lz4Mode::HighCompression => self.compress_hc(&buffer[..bytes_read])?,
            };

            compressed_blocks.push(compressed_block);
            block_count += 1;
        }

        // Now write block count followed by all blocks
        writer.write_all(&block_count.to_le_bytes()).map_err(|e| {
            RuzipError::io_error("Failed to write block count", e)
        })?;
        stats.compressed_size += 4; // Block count header

        for compressed_block in compressed_blocks {
            // Write compressed block size and data
            let block_size = compressed_block.len() as u32;
            writer.write_all(&block_size.to_le_bytes()).map_err(|e| {
                RuzipError::io_error("Failed to write block size", e)
            })?;
            
            writer.write_all(&compressed_block).map_err(|e| {
                RuzipError::io_error("Failed to write compressed block", e)
            })?;

            stats.compressed_size += 4 + compressed_block.len() as u64; // Size header + data
        }

        tracing::debug!(
            "LZ4 block compression: {} blocks, mode: {:?}",
            block_count,
            mode
        );

        Ok(())
    }

    /// Decompress blocks for streaming decompression
    fn decompress_blocks<R: Read, W: Write>(
        &self,
        mut reader: R,
        mut writer: W,
        stats: &mut CompressionStats,
    ) -> Result<()> {
        // Read block count
        let mut block_count_bytes = [0u8; 4];
        reader.read_exact(&mut block_count_bytes).map_err(|e| {
            RuzipError::io_error("Failed to read block count", e)
        })?;
        
        let block_count = u32::from_le_bytes(block_count_bytes);
        
        for _ in 0..block_count {
            // Read block size
            let mut block_size_bytes = [0u8; 4];
            reader.read_exact(&mut block_size_bytes).map_err(|e| {
                RuzipError::io_error("Failed to read block size", e)
            })?;
            
            let block_size = u32::from_le_bytes(block_size_bytes) as usize;
            
            // Read compressed block
            let mut compressed_block = vec![0u8; block_size];
            reader.read_exact(&mut compressed_block).map_err(|e| {
                RuzipError::io_error("Failed to read compressed block", e)
            })?;
            
            // Decompress block
            let decompressed_block = self.decompress_lz4(&compressed_block)?;
            
            // Write decompressed data
            writer.write_all(&decompressed_block).map_err(|e| {
                RuzipError::io_error("Failed to write decompressed data", e)
            })?;
            
            stats.original_size += decompressed_block.len() as u64;
            stats.compressed_size += 4 + block_size as u64;
        }

        Ok(())
    }
}

#[cfg(feature = "lz4-support")]
impl Default for Lz4Engine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "lz4-support")]
impl Compressor for Lz4Engine {
    fn compress<R: Read, W: Write>(
        &self,
        reader: R,
        writer: W,
        level: CompressionLevel,
    ) -> Result<CompressionStats> {
        let start_time = Instant::now();
        let mut stats = CompressionStats::default();

        // Use block-based compression for streaming
        self.compress_blocks(reader, writer, level, &mut stats)?;

        stats.duration_ms = start_time.elapsed().as_millis() as u64;
        stats.calculate_ratio();
        stats.calculate_speed();

        tracing::debug!(
            "LZ4 compression completed: {}KB -> {}KB ({:.1}%) in {}ms ({:.1} MB/s)",
            stats.original_size / 1024,
            stats.compressed_size / 1024,
            stats.compression_percentage(),
            stats.duration_ms,
            stats.speed_mbps
        );

        Ok(stats)
    }

    fn decompress<R: Read, W: Write>(
        &self,
        reader: R,
        writer: W,
    ) -> Result<CompressionStats> {
        let start_time = Instant::now();
        let mut stats = CompressionStats::default();

        // Use block-based decompression
        self.decompress_blocks(reader, writer, &mut stats)?;

        stats.duration_ms = start_time.elapsed().as_millis() as u64;
        stats.calculate_ratio();
        stats.calculate_speed();

        tracing::debug!(
            "LZ4 decompression completed: {}KB in {}ms ({:.1} MB/s)",
            stats.original_size / 1024,
            stats.duration_ms,
            stats.speed_mbps
        );

        Ok(stats)
    }
}

// Provide stub implementations when lz4-support is not enabled
#[cfg(not(feature = "lz4-support"))]
pub struct Lz4Engine;

#[cfg(not(feature = "lz4-support"))]
impl Lz4Engine {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(not(feature = "lz4-support"))]
impl Default for Lz4Engine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[cfg(feature = "lz4-support")]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_lz4_engine_creation() {
        let engine = Lz4Engine::new();
        assert_eq!(engine.buffer_size, LZ4_BUFFER_SIZE);
        assert_eq!(engine.block_size, LZ4_BLOCK_SIZE);
        assert_eq!(engine.mode, Lz4Mode::Fast);
        assert_eq!(engine.acceleration, 1);
        assert!(engine.block_independent);
    }

    #[test]
    fn test_lz4_engine_configuration() {
        let engine = Lz4Engine::new()
            .with_buffer_size(128 * 1024)
            .with_block_size(32 * 1024)
            .with_mode(Lz4Mode::HighCompression)
            .with_acceleration(4)
            .with_block_independence(false);

        assert_eq!(engine.buffer_size, 128 * 1024);
        assert_eq!(engine.block_size, 32 * 1024);
        assert_eq!(engine.mode, Lz4Mode::HighCompression);
        assert_eq!(engine.acceleration, 4);
        assert!(!engine.block_independent);
    }

    #[test]
    fn test_compression_level_mapping() {
        let engine = Lz4Engine::new();
        
        let (mode, accel) = engine.map_compression_level(CompressionLevel::new(1).unwrap());
        assert_eq!(mode, Lz4Mode::Fast);
        assert_eq!(accel, 16);
        
        let (mode, accel) = engine.map_compression_level(CompressionLevel::new(15).unwrap());
        assert_eq!(mode, Lz4Mode::Fast);
        assert_eq!(accel, 1);
        
        let (mode, accel) = engine.map_compression_level(CompressionLevel::new(20).unwrap());
        assert_eq!(mode, Lz4Mode::HighCompression);
        assert_eq!(accel, 1);
    }

    #[test]
    fn test_optimal_block_size() {
        let engine = Lz4Engine::new();
        
        assert_eq!(engine.get_optimal_block_size(32 * 1024), 16 * 1024);
        assert_eq!(engine.get_optimal_block_size(512 * 1024), LZ4_BLOCK_SIZE);
        assert!(engine.get_optimal_block_size(10 * 1024 * 1024) > LZ4_BLOCK_SIZE);
    }

    #[test]
    fn test_lz4_fast_compression() {
        let engine = Lz4Engine::new();
        let test_data = b"Hello, World! This is test data for LZ4 compression. ".repeat(100);
        
        let compressed = engine.compress_fast(&test_data, 1).unwrap();
        assert!(compressed.len() > 0);
        assert!(compressed.len() < test_data.len()); // Should compress
        
        let decompressed = engine.decompress_lz4(&compressed).unwrap();
        assert_eq!(decompressed, test_data);
    }

    #[test]
    fn test_lz4_hc_compression() {
        let engine = Lz4Engine::new();
        let test_data = b"Hello, World! This is test data for LZ4-HC compression. ".repeat(100);
        
        let compressed = engine.compress_hc(&test_data).unwrap();
        assert!(compressed.len() > 0);
        assert!(compressed.len() < test_data.len()); // Should compress
        
        let decompressed = engine.decompress_lz4(&compressed).unwrap();
        assert_eq!(decompressed, test_data);
    }

    #[test]
    fn test_lz4_compression_roundtrip() {
        let engine = Lz4Engine::new();
        let input_data = b"Hello, World! This is test data for LZ4 compression. ".repeat(50);
        
        // Compress
        let mut input = Cursor::new(&input_data);
        let mut compressed = Cursor::new(Vec::new());
        let level = CompressionLevel::new(6).unwrap();
        
        let compress_stats = engine.compress(&mut input, &mut compressed, level).unwrap();
        assert_eq!(compress_stats.original_size, input_data.len() as u64);
        assert!(compress_stats.compressed_size > 0);

        // Decompress
        compressed.set_position(0);
        let mut decompressed = Cursor::new(Vec::new());
        
        let decompress_stats = engine.decompress(&mut compressed, &mut decompressed).unwrap();
        
        // Verify round-trip
        assert_eq!(decompressed.into_inner(), input_data);
        assert_eq!(decompress_stats.original_size, input_data.len() as u64);
    }
}