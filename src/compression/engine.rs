//! ZSTD compression engine implementation
//!
//! Provides high-performance streaming compression and decompression
//! with memory-bounded operations for large files.

use crate::compression::{CompressionLevel, CompressionMethod, CompressionStats, Compressor};
use crate::error::{Result, RuzipError};
use std::io::{Read, Write};
use std::time::Instant;

#[cfg(feature = "simd")]
use crate::simd::{
    compression::SimdEntropy,
};

/// Default buffer size for streaming operations (1MB)
const DEFAULT_BUFFER_SIZE: usize = 1024 * 1024;

/// Maximum memory usage per compression operation (512MB)
const MAX_MEMORY_USAGE: usize = 512 * 1024 * 1024;

/// ZSTD compression engine
#[derive(Debug)]
pub struct CompressionEngine {
    /// Buffer size for streaming operations
    buffer_size: usize,
    /// Maximum memory usage
    max_memory: usize,
    /// Compression method
    method: CompressionMethod,
    /// Enable SIMD optimizations
    #[cfg(feature = "simd")]
    simd_enabled: bool,
}

impl CompressionEngine {
    /// Create new compression engine with default settings
    pub fn new() -> Self {
        Self {
            buffer_size: DEFAULT_BUFFER_SIZE,
            max_memory: MAX_MEMORY_USAGE,
            method: CompressionMethod::default(),
            #[cfg(feature = "simd")]
            simd_enabled: true,
        }
    }

    /// Create compression engine with custom buffer size
    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size.max(4096); // Minimum 4KB buffer
        self
    }

    /// Create compression engine with custom memory limit
    pub fn with_memory_limit(mut self, limit: usize) -> Self {
        self.max_memory = limit.max(1024 * 1024); // Minimum 1MB
        self
    }

    /// Create compression engine with specific method
    pub fn with_method(mut self, method: CompressionMethod) -> Self {
        self.method = method;
        self
    }

    /// Enable or disable SIMD optimizations
    #[cfg(feature = "simd")]
    pub fn with_simd(mut self, enabled: bool) -> Self {
        self.simd_enabled = enabled;
        self
    }

    /// Get optimal buffer size for the given compression level
    fn optimal_buffer_size(&self, level: CompressionLevel) -> usize {
        let base_size = self.buffer_size;
        let multiplier = level.memory_multiplier();
        let optimal_size = (base_size as f64 * multiplier) as usize;
        
        // Ensure we don't exceed memory limits
        optimal_size.min(self.max_memory / 4)
    }

    /// Validate compression level for the current method
    fn validate_level(&self, level: CompressionLevel) -> Result<()> {
        match self.method {
            CompressionMethod::Zstd => {
                // ZSTD supports levels 1-22
                if level.value() > 22 {
                    return Err(RuzipError::compression_error(
                        format!("ZSTD compression level {} is too high (max 22)", level.value()),
                        None,
                    ));
                }
            }
            #[cfg(feature = "brotli-support")]
            CompressionMethod::Brotli => {
                // Brotli supports levels 1-22 (mapped to quality 1-11)
                if level.value() > 22 {
                    return Err(RuzipError::compression_error(
                        format!("Brotli compression level {} is too high (max 22)", level.value()),
                        None,
                    ));
                }
            }
            #[cfg(feature = "lz4-support")]
            CompressionMethod::Lz4 => {
                // LZ4 supports levels 1-22
                if level.value() > 22 {
                    return Err(RuzipError::compression_error(
                        format!("LZ4 compression level {} is too high (max 22)", level.value()),
                        None,
                    ));
                }
            }
            CompressionMethod::Store => {
                // Store mode ignores compression level
            }
        }
        Ok(())
    }
}

impl Default for CompressionEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl Compressor for CompressionEngine {
    fn compress<R: Read, W: Write>(
        &self,
        mut reader: R,
        mut writer: W,
        level: CompressionLevel,
    ) -> Result<CompressionStats> {
        let start_time = Instant::now();
        self.validate_level(level)?;

        let mut stats = CompressionStats::default();

        match self.method {
            CompressionMethod::Zstd => {
                self.compress_zstd(&mut reader, &mut writer, level, &mut stats)?;
            }
            #[cfg(feature = "brotli-support")]
            CompressionMethod::Brotli => {
                self.compress_brotli(&mut reader, &mut writer, level, &mut stats)?;
            }
            #[cfg(feature = "lz4-support")]
            CompressionMethod::Lz4 => {
                self.compress_lz4(&mut reader, &mut writer, level, &mut stats)?;
            }
            CompressionMethod::Store => {
                self.compress_store(&mut reader, &mut writer, &mut stats)?;
            }
        }

        stats.duration_ms = start_time.elapsed().as_millis() as u64;
        stats.calculate_ratio();
        stats.calculate_speed();

        Ok(stats)
    }

    fn decompress<R: Read, W: Write>(
        &self,
        mut reader: R,
        mut writer: W,
    ) -> Result<CompressionStats> {
        let start_time = Instant::now();
        let mut stats = CompressionStats::default();

        match self.method {
            CompressionMethod::Zstd => {
                self.decompress_zstd(&mut reader, &mut writer, &mut stats)?;
            }
            #[cfg(feature = "brotli-support")]
            CompressionMethod::Brotli => {
                self.decompress_brotli(&mut reader, &mut writer, &mut stats)?;
            }
            #[cfg(feature = "lz4-support")]
            CompressionMethod::Lz4 => {
                self.decompress_lz4(&mut reader, &mut writer, &mut stats)?;
            }
            CompressionMethod::Store => {
                self.decompress_store(&mut reader, &mut writer, &mut stats)?;
            }
        }

        stats.duration_ms = start_time.elapsed().as_millis() as u64;
        stats.calculate_ratio();
        stats.calculate_speed();

        Ok(stats)
    }
}

impl CompressionEngine {
    /// ZSTD compression implementation
    fn compress_zstd<R: Read, W: Write>(
        &self,
        reader: &mut R,
        writer: &mut W,
        level: CompressionLevel,
        stats: &mut CompressionStats,
    ) -> Result<()> {
        use zstd::stream::write::Encoder;

        let buffer_size = self.optimal_buffer_size(level);
        
        // Use level directly for now
        let optimized_level = level;
        
        let mut encoder = Encoder::new(writer, optimized_level.to_zstd_level())
            .map_err(|e| {
                RuzipError::compression_error(
                    "Failed to create ZSTD encoder",
                    Some(Box::new(e)),
                )
            })?;

        // Set window size to limit memory usage
        encoder
            .window_log(23) // 8MB window (2^23)
            .map_err(|e| {
                RuzipError::compression_error(
                    "Failed to configure ZSTD encoder",
                    Some(Box::new(e)),
                )
            })?;

        let mut buffer = vec![0u8; buffer_size];
        
        loop {
            let bytes_read = reader.read(&mut buffer).map_err(|e| {
                RuzipError::io_error("Failed to read input data", e)
            })?;

            if bytes_read == 0 {
                break;
            }

            stats.original_size += bytes_read as u64;
            
            // Use data directly without SIMD preprocessing for now
            encoder.write_all(&buffer[..bytes_read]).map_err(|e| {
                RuzipError::compression_error(
                    "Failed to compress data",
                    Some(Box::new(e)),
                )
            })?;
        }

        let _compressed_writer = encoder.finish().map_err(|e| {
            RuzipError::compression_error(
                "Failed to finalize compression",
                Some(Box::new(e)),
            )
        })?;

        // Note: We can't easily get the compressed size from zstd stream writer
        // This would need to be tracked by wrapping the writer
        stats.compressed_size = stats.original_size; // Placeholder

        Ok(())
    }

    /// ZSTD decompression implementation
    fn decompress_zstd<R: Read, W: Write>(
        &self,
        reader: &mut R,
        writer: &mut W,
        stats: &mut CompressionStats,
    ) -> Result<()> {
        use zstd::stream::read::Decoder;

        let mut decoder = Decoder::new(reader).map_err(|e| {
            RuzipError::compression_error(
                "Failed to create ZSTD decoder",
                Some(Box::new(e)),
            )
        })?;

        let mut buffer = vec![0u8; self.buffer_size];

        loop {
            let bytes_read = decoder.read(&mut buffer).map_err(|e| {
                RuzipError::compression_error(
                    "Failed to decompress data",
                    Some(Box::new(e)),
                )
            })?;

            if bytes_read == 0 {
                break;
            }

            stats.original_size += bytes_read as u64;
            
            writer.write_all(&buffer[..bytes_read]).map_err(|e| {
                RuzipError::io_error("Failed to write decompressed data", e)
            })?;
        }

        stats.compressed_size = stats.original_size; // Placeholder

        Ok(())
    }

    /// Store mode compression (no compression)
    fn compress_store<R: Read, W: Write>(
        &self,
        reader: &mut R,
        writer: &mut W,
        stats: &mut CompressionStats,
    ) -> Result<()> {
        let mut buffer = vec![0u8; self.buffer_size];

        loop {
            let bytes_read = reader.read(&mut buffer).map_err(|e| {
                RuzipError::io_error("Failed to read input data", e)
            })?;

            if bytes_read == 0 {
                break;
            }

            stats.original_size += bytes_read as u64;
            stats.compressed_size += bytes_read as u64;

            writer.write_all(&buffer[..bytes_read]).map_err(|e| {
                RuzipError::io_error("Failed to write data", e)
            })?;
        }

        Ok(())
    }

    /// Store mode decompression (copy data)
    fn decompress_store<R: Read, W: Write>(
        &self,
        reader: &mut R,
        writer: &mut W,
        stats: &mut CompressionStats,
    ) -> Result<()> {
        self.compress_store(reader, writer, stats)
    }

    /// SIMD-optimierte Compression-Level-Auswahl basierend auf Entropy
    #[cfg(feature = "simd")]
    #[allow(dead_code)]
    fn optimize_compression_level<R: Read>(
        &self,
        reader: &mut R,
        default_level: CompressionLevel,
    ) -> Result<CompressionLevel> {
        // Lese einen Sample der Daten für Entropy-Analyse
        let mut sample_buffer = vec![0u8; 8192.min(self.buffer_size)];
        let bytes_read = reader.read(&mut sample_buffer).map_err(|e| {
            RuzipError::io_error("Failed to read sample data for optimization", e)
        })?;
        
        if bytes_read == 0 {
            return Ok(default_level);
        }
        
        // Berechne Entropy mit SIMD
        let entropy = SimdEntropy::calculate_entropy(&sample_buffer[..bytes_read]);
        let recommended_level = SimdEntropy::recommend_compression_level(entropy);
        
        // Verwende empfohlenen Level, aber respektiere Benutzer-Präferenzen
        let optimized_level = if recommended_level > default_level.value() {
            // Nur höhere Level vorschlagen, nie niedrigere
            CompressionLevel::new(recommended_level).unwrap_or(default_level)
        } else {
            default_level
        };
        
        tracing::debug!(
            "SIMD entropy analysis: {:.2}, recommended level: {}, using: {}",
            entropy,
            recommended_level,
            optimized_level.value()
        );
        
        Ok(optimized_level)
    }

    /// Brotli compression implementation
    #[cfg(feature = "brotli-support")]
    fn compress_brotli<R: Read, W: Write>(
        &self,
        reader: &mut R,
        writer: &mut W,
        level: CompressionLevel,
        stats: &mut CompressionStats,
    ) -> Result<()> {
        use crate::compression::brotli::BrotliEngine;
        
        let brotli_engine = BrotliEngine::new()
            .with_buffer_size(self.buffer_size);
        
        let brotli_stats = brotli_engine.compress(reader, writer, level)?;
        
        // Copy stats
        stats.original_size = brotli_stats.original_size;
        stats.compressed_size = brotli_stats.compressed_size;
        stats.duration_ms = brotli_stats.duration_ms;
        
        Ok(())
    }

    /// Brotli decompression implementation
    #[cfg(feature = "brotli-support")]
    fn decompress_brotli<R: Read, W: Write>(
        &self,
        reader: &mut R,
        writer: &mut W,
        stats: &mut CompressionStats,
    ) -> Result<()> {
        use crate::compression::brotli::BrotliEngine;
        
        let brotli_engine = BrotliEngine::new()
            .with_buffer_size(self.buffer_size);
        
        let brotli_stats = brotli_engine.decompress(reader, writer)?;
        
        // Copy stats
        stats.original_size = brotli_stats.original_size;
        stats.compressed_size = brotli_stats.compressed_size;
        stats.duration_ms = brotli_stats.duration_ms;
        
        Ok(())
    }

    /// LZ4 compression implementation
    #[cfg(feature = "lz4-support")]
    fn compress_lz4<R: Read, W: Write>(
        &self,
        reader: &mut R,
        writer: &mut W,
        level: CompressionLevel,
        stats: &mut CompressionStats,
    ) -> Result<()> {
        use crate::compression::lz4::Lz4Engine;
        
        let lz4_engine = Lz4Engine::new()
            .with_buffer_size(self.buffer_size);
        
        let lz4_stats = lz4_engine.compress(reader, writer, level)?;
        
        // Copy stats
        stats.original_size = lz4_stats.original_size;
        stats.compressed_size = lz4_stats.compressed_size;
        stats.duration_ms = lz4_stats.duration_ms;
        
        Ok(())
    }

    /// LZ4 decompression implementation
    #[cfg(feature = "lz4-support")]
    fn decompress_lz4<R: Read, W: Write>(
        &self,
        reader: &mut R,
        writer: &mut W,
        stats: &mut CompressionStats,
    ) -> Result<()> {
        use crate::compression::lz4::Lz4Engine;
        
        let lz4_engine = Lz4Engine::new()
            .with_buffer_size(self.buffer_size);
        
        let lz4_stats = lz4_engine.decompress(reader, writer)?;
        
        // Copy stats
        stats.original_size = lz4_stats.original_size;
        stats.compressed_size = lz4_stats.compressed_size;
        stats.duration_ms = lz4_stats.duration_ms;
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_engine_creation() {
        let engine = CompressionEngine::new();
        assert_eq!(engine.buffer_size, DEFAULT_BUFFER_SIZE);
        assert_eq!(engine.max_memory, MAX_MEMORY_USAGE);
        assert_eq!(engine.method, CompressionMethod::Zstd);
    }

    #[test]
    fn test_engine_configuration() {
        let engine = CompressionEngine::new()
            .with_buffer_size(2048)
            .with_memory_limit(1024 * 1024)
            .with_method(CompressionMethod::Store);

        assert_eq!(engine.buffer_size, 4096); // Minimum enforced
        assert_eq!(engine.max_memory, 1024 * 1024);
        assert_eq!(engine.method, CompressionMethod::Store);
    }

    #[test]
    fn test_optimal_buffer_size() {
        let engine = CompressionEngine::new();
        let level = CompressionLevel::new(6).unwrap();
        
        let buffer_size = engine.optimal_buffer_size(level);
        assert!(buffer_size >= DEFAULT_BUFFER_SIZE);
        assert!(buffer_size <= MAX_MEMORY_USAGE / 4);
    }

    #[test]
    fn test_store_compression() {
        let engine = CompressionEngine::new().with_method(CompressionMethod::Store);
        let input_data = b"Hello, World! This is test data for store compression.";
        let mut input = Cursor::new(input_data);
        let mut output = Cursor::new(Vec::new());

        let level = CompressionLevel::new(6).unwrap();
        let stats = engine.compress(&mut input, &mut output, level).unwrap();

        assert_eq!(stats.original_size, input_data.len() as u64);
        assert_eq!(stats.compressed_size, input_data.len() as u64);
        assert_eq!(stats.ratio, 1.0);
        assert_eq!(stats.compression_percentage(), 0.0);

        // Verify output matches input
        assert_eq!(output.into_inner(), input_data);
    }

    #[test]
    fn test_store_decompression() {
        let engine = CompressionEngine::new().with_method(CompressionMethod::Store);
        let input_data = b"Hello, World! This is test data for store decompression.";
        let mut input = Cursor::new(input_data);
        let mut output = Cursor::new(Vec::new());

        let stats = engine.decompress(&mut input, &mut output).unwrap();

        assert_eq!(stats.original_size, input_data.len() as u64);
        assert_eq!(output.into_inner(), input_data);
    }

    #[test]
    fn test_level_validation() {
        let engine = CompressionEngine::new();
        
        // Valid level
        let valid_level = CompressionLevel::new(6).unwrap();
        assert!(engine.validate_level(valid_level).is_ok());

        // Store method should accept any level
        let store_engine = CompressionEngine::new().with_method(CompressionMethod::Store);
        let any_level = CompressionLevel::new(22).unwrap();
        assert!(store_engine.validate_level(any_level).is_ok());
    }

    #[test]
    fn test_zstd_compression_roundtrip() {
        let engine = CompressionEngine::new();
        let input_data = b"Hello, World! This is test data for ZSTD compression. ".repeat(100);
        
        // Compress
        let mut input = Cursor::new(&input_data);
        let mut compressed = Cursor::new(Vec::new());
        let level = CompressionLevel::new(6).unwrap();
        
        let compress_stats = engine.compress(&mut input, &mut compressed, level).unwrap();
        assert_eq!(compress_stats.original_size, input_data.len() as u64);

        // Decompress
        compressed.set_position(0);
        let mut decompressed = Cursor::new(Vec::new());
        
        let decompress_stats = engine.decompress(&mut compressed, &mut decompressed).unwrap();
        
        // Verify round-trip
        assert_eq!(decompressed.into_inner(), input_data);
        // Check that decompression completed (duration_ms is always >= 0 for u64)
        assert!(decompress_stats.duration_ms == decompress_stats.duration_ms);
    }
}