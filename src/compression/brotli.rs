//! Brotli compression engine implementation
//!
//! Provides high-performance Brotli compression and decompression
//! optimized for text and web content with streaming support.

#[cfg(feature = "brotli-support")]
use crate::compression::{CompressionLevel, CompressionStats, Compressor};
#[cfg(feature = "brotli-support")]
use crate::error::{Result, RuzipError};
#[cfg(feature = "brotli-support")]
use std::io::{Read, Write};
#[cfg(feature = "brotli-support")]
use std::time::Instant;

#[cfg(feature = "brotli-support")]
use brotli::{CompressorReader, Decompressor};

/// Default buffer size for Brotli streaming operations (64KB)
#[cfg(feature = "brotli-support")]
const BROTLI_BUFFER_SIZE: usize = 64 * 1024;

/// Maximum window size for Brotli (24 = 16MB)
#[cfg(feature = "brotli-support")]
const MAX_WINDOW_SIZE: u32 = 24;

/// Brotli compression engine
#[cfg(feature = "brotli-support")]
#[derive(Debug)]
pub struct BrotliEngine {
    /// Buffer size for streaming operations
    buffer_size: usize,
    /// Brotli quality level (1-11)
    quality: u32,
    /// Window size (10-24, representing 1KB to 16MB)
    window_size: u32,
    /// Compression mode
    mode: BrotliMode,
}

/// Brotli compression modes
#[cfg(feature = "brotli-support")]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BrotliMode {
    /// Generic mode (default)
    Generic,
    /// Text mode (optimized for UTF-8 text)
    Text,
    /// Font mode (optimized for WOFF fonts)
    Font,
}

#[cfg(feature = "brotli-support")]
impl Default for BrotliMode {
    fn default() -> Self {
        Self::Generic
    }
}

#[cfg(feature = "brotli-support")]
impl BrotliEngine {
    /// Create new Brotli engine with default settings
    pub fn new() -> Self {
        Self {
            buffer_size: BROTLI_BUFFER_SIZE,
            quality: 6, // Balanced quality
            window_size: 23, // 8MB window for better compression on larger files
            mode: BrotliMode::default(),
        }
    }

    /// Create Brotli engine with custom buffer size
    pub fn with_buffer_size(mut self, size: usize) -> Self {
        self.buffer_size = size.max(4096); // Minimum 4KB buffer
        self
    }

    /// Create Brotli engine with custom quality (1-11)
    pub fn with_quality(mut self, quality: u32) -> Self {
        self.quality = quality.clamp(1, 11);
        self
    }

    /// Create Brotli engine with custom window size (10-24)
    pub fn with_window_size(mut self, window_size: u32) -> Self {
        self.window_size = window_size.clamp(10, MAX_WINDOW_SIZE);
        self
    }

    /// Create Brotli engine with specific mode
    pub fn with_mode(mut self, mode: BrotliMode) -> Self {
        self.mode = mode;
        self
    }

    /// Map RuZip compression level (1-22) to Brotli quality (1-11)
    fn map_compression_level(&self, level: CompressionLevel) -> u32 {
        let ruzip_level = level.value();
        
        // Map RuZip levels 1-22 to Brotli quality 1-11
        match ruzip_level {
            1..=2 => 1,   // Fastest
            3..=4 => 2,
            5..=6 => 3,
            7..=8 => 4,
            9..=10 => 5,
            11..=12 => 6, // Default balanced
            13..=14 => 7,
            15..=16 => 8,
            17..=18 => 9,
            19..=20 => 10,
            21..=22 => 11, // Maximum compression
            _ => 6, // Fallback to balanced
        }
    }

    /// Detect optimal Brotli mode based on data characteristics
    fn detect_optimal_mode(&self, data_sample: &[u8]) -> BrotliMode {
        if data_sample.len() < 256 {
            return self.mode;
        }

        // Check for UTF-8 text patterns
        if self.is_likely_text(data_sample) {
            return BrotliMode::Text;
        }

        // Check for font signatures (WOFF, TTF, OTF)
        if self.is_likely_font(data_sample) {
            return BrotliMode::Font;
        }

        // Default to generic mode
        BrotliMode::Generic
    }

    /// Check if data is likely UTF-8 text
    fn is_likely_text(&self, data: &[u8]) -> bool {
        // Check for valid UTF-8 and common text patterns
        if let Ok(text) = std::str::from_utf8(data) {
            let printable_chars = text.chars()
                .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
                .count();
            
            // If more than 80% are printable ASCII characters, likely text
            printable_chars as f64 / text.chars().count() as f64 > 0.8
        } else {
            false
        }
    }

    /// Check if data is likely a font file
    fn is_likely_font(&self, data: &[u8]) -> bool {
        if data.len() < 4 {
            return false;
        }

        // Check for font file signatures
        matches!(
            &data[0..4],
            b"wOFF" | b"wOF2" | // WOFF fonts
            b"\x00\x01\x00\x00" | // TTF
            b"OTTO" | // OTF
            b"true" | b"typ1" // Other font formats
        )
    }

    /// Get Brotli encoder parameters
    fn get_encoder_params(&self, quality: u32, _mode: BrotliMode) -> brotli::enc::BrotliEncoderParams {
        let mut params = brotli::enc::BrotliEncoderParams::default();
        params.quality = quality as i32;
        params.lgwin = self.window_size as i32;
        
        // Note: Mode setting is not available in this version of brotli crate
        // We'll use the default generic mode
        
        params
    }
}

#[cfg(feature = "brotli-support")]
impl Default for BrotliEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(feature = "brotli-support")]
impl Compressor for BrotliEngine {
    fn compress<R: Read, W: Write>(
        &self,
        mut reader: R,
        mut writer: W,
        level: CompressionLevel,
    ) -> Result<CompressionStats> {
        let start_time = Instant::now();
        let mut stats = CompressionStats::default();

        // Map compression level to Brotli quality
        let quality = self.map_compression_level(level);

        // Read a sample for mode detection
        let mut sample_buffer = vec![0u8; 4096.min(self.buffer_size)];
        let sample_size = reader.read(&mut sample_buffer).map_err(|e| {
            RuzipError::io_error("Failed to read sample for Brotli mode detection", e)
        })?;

        // Detect optimal mode
        let optimal_mode = if sample_size > 0 {
            self.detect_optimal_mode(&sample_buffer[..sample_size])
        } else {
            self.mode
        };

        // Get encoder parameters
        let params = self.get_encoder_params(quality, optimal_mode);

        // Create Brotli compressor with all input data
        let mut input_data = Vec::new();
        
        // Add sample data back
        if sample_size > 0 {
            input_data.extend_from_slice(&sample_buffer[..sample_size]);
            stats.original_size += sample_size as u64;
        }

        // Read remaining data
        let mut buffer = vec![0u8; self.buffer_size];
        loop {
            let bytes_read = reader.read(&mut buffer).map_err(|e| {
                RuzipError::io_error("Failed to read input data", e)
            })?;

            if bytes_read == 0 {
                break;
            }

            input_data.extend_from_slice(&buffer[..bytes_read]);
            stats.original_size += bytes_read as u64;
        }

        // Compress all data at once for optimal Brotli performance
        let mut compressed_data = Vec::new();
        let mut compressor = CompressorReader::with_params(
            std::io::Cursor::new(&input_data),
            self.buffer_size,
            &params,
        );

        compressor.read_to_end(&mut compressed_data).map_err(|e| {
            RuzipError::compression_error(
                "Failed to compress data with Brotli",
                Some(Box::new(e)),
            )
        })?;

        // Write compressed data
        writer.write_all(&compressed_data).map_err(|e| {
            RuzipError::io_error("Failed to write compressed data", e)
        })?;

        stats.compressed_size = compressed_data.len() as u64;
        stats.duration_ms = start_time.elapsed().as_millis() as u64;
        stats.calculate_ratio();
        stats.calculate_speed();

        tracing::debug!(
            "Brotli compression: {}KB -> {}KB ({:.1}%) in {}ms, mode: {:?}, quality: {}",
            stats.original_size / 1024,
            stats.compressed_size / 1024,
            stats.compression_percentage(),
            stats.duration_ms,
            optimal_mode,
            quality
        );

        Ok(stats)
    }

    fn decompress<R: Read, W: Write>(
        &self,
        mut reader: R,
        mut writer: W,
    ) -> Result<CompressionStats> {
        let start_time = Instant::now();
        let mut stats = CompressionStats::default();

        // Read all compressed data first
        let mut compressed_data = Vec::new();
        reader.read_to_end(&mut compressed_data).map_err(|e| {
            RuzipError::io_error("Failed to read compressed data", e)
        })?;

        // Decompress using brotli
        let _decompressed_data: Vec<u8> = Vec::new();
        let mut decompressor = Decompressor::new(&compressed_data[..], compressed_data.len());
        
        let mut buffer = vec![0u8; self.buffer_size];
        loop {
            match decompressor.read(&mut buffer) {
                Ok(0) => break, // EOF
                Ok(bytes_read) => {
                    stats.original_size += bytes_read as u64;
                    writer.write_all(&buffer[..bytes_read]).map_err(|e| {
                        RuzipError::io_error("Failed to write decompressed data", e)
                    })?;
                }
                Err(e) => {
                    return Err(RuzipError::compression_error(
                        "Failed to decompress Brotli data",
                        Some(Box::new(e)),
                    ));
                }
            }
        }

        stats.compressed_size = stats.original_size; // Placeholder for decompression
        stats.duration_ms = start_time.elapsed().as_millis() as u64;
        stats.calculate_ratio();
        stats.calculate_speed();

        tracing::debug!(
            "Brotli decompression: {}KB in {}ms",
            stats.original_size / 1024,
            stats.duration_ms
        );

        Ok(stats)
    }
}

// Provide stub implementations when brotli-support is not enabled
#[cfg(not(feature = "brotli-support"))]
pub struct BrotliEngine;

#[cfg(not(feature = "brotli-support"))]
impl BrotliEngine {
    pub fn new() -> Self {
        Self
    }
}

#[cfg(not(feature = "brotli-support"))]
impl Default for BrotliEngine {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
#[cfg(feature = "brotli-support")]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_brotli_engine_creation() {
        let engine = BrotliEngine::new();
        assert_eq!(engine.buffer_size, BROTLI_BUFFER_SIZE);
        assert_eq!(engine.quality, 6);
        assert_eq!(engine.window_size, 23);
        assert_eq!(engine.mode, BrotliMode::Generic);
    }

    #[test]
    fn test_brotli_engine_configuration() {
        let engine = BrotliEngine::new()
            .with_buffer_size(32768)
            .with_quality(9)
            .with_window_size(20)
            .with_mode(BrotliMode::Text);

        assert_eq!(engine.buffer_size, 32768);
        assert_eq!(engine.quality, 9);
        assert_eq!(engine.window_size, 20);
        assert_eq!(engine.mode, BrotliMode::Text);
    }

    #[test]
    fn test_compression_level_mapping() {
        let engine = BrotliEngine::new();
        
        assert_eq!(engine.map_compression_level(CompressionLevel::new(1).unwrap()), 1);
        assert_eq!(engine.map_compression_level(CompressionLevel::new(6).unwrap()), 3);
        assert_eq!(engine.map_compression_level(CompressionLevel::new(12).unwrap()), 6);
        assert_eq!(engine.map_compression_level(CompressionLevel::new(22).unwrap()), 11);
    }

    #[test]
    fn test_text_detection() {
        let engine = BrotliEngine::new();
        
        let text_data = b"Hello, World! This is a test string with UTF-8 content.";
        assert!(engine.is_likely_text(text_data));
        
        let binary_data = &[0xFF, 0xFE, 0x00, 0x01, 0x80, 0x90];
        assert!(!engine.is_likely_text(binary_data));
    }

    #[test]
    fn test_font_detection() {
        let engine = BrotliEngine::new();
        
        let woff_data = b"wOFF\x00\x01\x00\x00";
        assert!(engine.is_likely_font(woff_data));
        
        let ttf_data = b"\x00\x01\x00\x00\x00\x0C";
        assert!(engine.is_likely_font(ttf_data));
        
        let text_data = b"Hello, World!";
        assert!(!engine.is_likely_font(text_data));
    }

    #[test]
    fn test_mode_detection() {
        let engine = BrotliEngine::new();
        
        let text_data = b"This is a long text string that should be detected as text content for Brotli compression optimization. This text needs to be longer than 256 characters to trigger the text detection algorithm properly. So we add more content here to make sure it meets the minimum length requirement for proper mode detection in the Brotli compression engine.";
        assert_eq!(engine.detect_optimal_mode(text_data), BrotliMode::Text);
        
        let woff_data = b"wOFF\x00\x01\x00\x00\x12\x34\x56\x78";
        let mut woff_extended = woff_data.to_vec();
        woff_extended.resize(300, 0); // Make it large enough for detection
        assert_eq!(engine.detect_optimal_mode(&woff_extended), BrotliMode::Font);
    }

    #[test]
    fn test_brotli_compression_roundtrip() {
        let engine = BrotliEngine::new();
        let input_data = b"Hello, World! This is test data for Brotli compression. ".repeat(50);
        
        // Compress
        let mut input = Cursor::new(&input_data);
        let mut compressed = Cursor::new(Vec::new());
        let level = CompressionLevel::new(6).unwrap();
        
        let compress_stats = engine.compress(&mut input, &mut compressed, level).unwrap();
        assert_eq!(compress_stats.original_size, input_data.len() as u64);
        assert!(compress_stats.compressed_size > 0);
        assert!(compress_stats.compressed_size < input_data.len() as u64); // Should compress

        // Decompress
        compressed.set_position(0);
        let mut decompressed = Cursor::new(Vec::new());
        
        let decompress_stats = engine.decompress(&mut compressed, &mut decompressed).unwrap();
        
        // Verify round-trip
        assert_eq!(decompressed.into_inner(), input_data);
        assert_eq!(decompress_stats.original_size, input_data.len() as u64);
    }
}