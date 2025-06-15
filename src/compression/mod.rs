//! Compression engine for RuZip
//!
//! This module provides streaming compression and decompression capabilities
//! with ZSTD as the primary compression algorithm.

pub mod engine;
pub mod level;
pub mod stream;
pub mod brotli;
pub mod lz4;
pub mod adaptive;

use crate::error::Result;
use std::io::{Read, Write};

pub use engine::CompressionEngine;
pub use level::CompressionLevel;
pub use stream::{CompressedReader, CompressedWriter};
pub use brotli::BrotliEngine;
pub use lz4::Lz4Engine;
pub use adaptive::{AdaptiveCompressionEngine, CompressionAlgorithm, FileType, PerformanceProfile};

/// Compression method enum
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionMethod {
    /// ZSTD compression (default)
    Zstd,
    /// Brotli compression (web-optimized)
    #[cfg(feature = "brotli-support")]
    Brotli,
    /// LZ4 compression (ultra-fast)
    #[cfg(feature = "lz4-support")]
    Lz4,
    /// Store without compression
    Store,
}

impl CompressionMethod {
    /// Convert from algorithm ID to compression method
    pub fn from_id(id: u8) -> Result<Self> {
        match id {
            0 => Ok(Self::Zstd),
            1 => Ok(Self::Store),
            #[cfg(feature = "brotli-support")]
            2 => Ok(Self::Brotli),
            #[cfg(not(feature = "brotli-support"))]
            2 => Err(crate::error::RuzipError::compression_error(
                "Brotli compression not available in this build. Cannot extract files compressed with Brotli. You can list and delete these files, but extraction requires a build with brotli-support feature.".to_string(),
                None,
            )),
            #[cfg(feature = "lz4-support")]
            3 => Ok(Self::Lz4),
            #[cfg(not(feature = "lz4-support"))]
            3 => Err(crate::error::RuzipError::compression_error(
                "LZ4 compression not available in this build. Cannot extract files compressed with LZ4. You can list and delete these files, but extraction requires a build with lz4-support feature.".to_string(),
                None,
            )),
            _ => Err(crate::error::RuzipError::compression_error(
                format!("Unknown compression algorithm ID: {}. This archive was created with a newer version of RuZip. You can list and delete files, but extraction requires an updated version with support for this algorithm.", id),
                None,
            )),
        }
    }

    /// Convert compression method to algorithm ID
    pub fn to_id(&self) -> u8 {
        match self {
            Self::Zstd => 0,
            Self::Store => 1,
            #[cfg(feature = "brotli-support")]
            Self::Brotli => 2,
            #[cfg(feature = "lz4-support")]
            Self::Lz4 => 3,
        }
    }

    /// Get human-readable name
    pub fn name(&self) -> &'static str {
        match self {
            Self::Zstd => "ZSTD",
            Self::Store => "Store",
            #[cfg(feature = "brotli-support")]
            Self::Brotli => "Brotli",
            #[cfg(feature = "lz4-support")]
            Self::Lz4 => "LZ4",
        }
    }

    /// Check if algorithm ID is supported for decompression
    pub fn is_decompression_supported(id: u8) -> bool {
        match id {
            0 | 1 => true, // ZSTD and Store always supported
            #[cfg(feature = "brotli-support")]
            2 => true,
            #[cfg(not(feature = "brotli-support"))]
            2 => false,
            #[cfg(feature = "lz4-support")]
            3 => true,
            #[cfg(not(feature = "lz4-support"))]
            3 => false,
            _ => false, // Unknown algorithms
        }
    }

    /// Get algorithm name from ID (even if not supported)
    pub fn algorithm_name_from_id(id: u8) -> String {
        match id {
            0 => "ZSTD".to_string(),
            1 => "Store".to_string(),
            2 => "Brotli".to_string(),
            3 => "LZ4".to_string(),
            _ => format!("Unknown-{}", id),
        }
    }
}

impl Default for CompressionMethod {
    fn default() -> Self {
        Self::Zstd
    }
}

/// Compression statistics
#[derive(Debug, Clone, Default)]
pub struct CompressionStats {
    /// Original data size in bytes
    pub original_size: u64,
    /// Compressed data size in bytes  
    pub compressed_size: u64,
    /// Compression ratio (compressed_size / original_size)
    pub ratio: f64,
    /// Compression speed in MB/s
    pub speed_mbps: f64,
    /// Time taken in milliseconds
    pub duration_ms: u64,
}

impl CompressionStats {
    /// Calculate compression ratio
    pub fn calculate_ratio(&mut self) {
        if self.original_size > 0 {
            self.ratio = self.compressed_size as f64 / self.original_size as f64;
        }
    }

    /// Calculate compression speed
    pub fn calculate_speed(&mut self) {
        if self.duration_ms > 0 {
            let duration_secs = self.duration_ms as f64 / 1000.0;
            let mb_processed = self.original_size as f64 / (1024.0 * 1024.0);
            self.speed_mbps = mb_processed / duration_secs;
        }
    }

    /// Get compression percentage (100% - ratio * 100%)
    pub fn compression_percentage(&self) -> f64 {
        (1.0 - self.ratio) * 100.0
    }
}

/// Trait for compression/decompression operations
pub trait Compressor {
    /// Compress data from reader to writer
    fn compress<R: Read, W: Write>(
        &self,
        reader: R,
        writer: W,
        level: CompressionLevel,
    ) -> Result<CompressionStats>;

    /// Decompress data from reader to writer
    fn decompress<R: Read, W: Write>(&self, reader: R, writer: W) -> Result<CompressionStats>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_stats_ratio() {
        let mut stats = CompressionStats {
            original_size: 1000,
            compressed_size: 600,
            ..Default::default()
        };
        
        stats.calculate_ratio();
        assert_eq!(stats.ratio, 0.6);
        assert_eq!(stats.compression_percentage(), 40.0);
    }

    #[test]
    fn test_compression_stats_speed() {
        let mut stats = CompressionStats {
            original_size: 10 * 1024 * 1024, // 10 MB
            duration_ms: 1000, // 1 second
            ..Default::default()
        };
        
        stats.calculate_speed();
        assert_eq!(stats.speed_mbps, 10.0);
    }

    #[test]
    fn test_compression_method_default() {
        assert_eq!(CompressionMethod::default(), CompressionMethod::Zstd);
    }
}