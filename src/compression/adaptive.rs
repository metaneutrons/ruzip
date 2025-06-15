//! Adaptive compression engine implementation
//!
//! Provides intelligent algorithm selection based on file type,
//! size, and content characteristics for optimal compression.

use crate::compression::{CompressionLevel, CompressionStats, Compressor};
use crate::error::{Result, RuzipError};
use std::io::{Read, Write, Seek, SeekFrom};

#[cfg(feature = "brotli-support")]
use crate::compression::brotli::BrotliEngine;
#[cfg(feature = "lz4-support")]
use crate::compression::lz4::Lz4Engine;
use crate::compression::engine::CompressionEngine;

/// File type detection for compression algorithm selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileType {
    /// Plain text files (UTF-8, ASCII)
    Text,
    /// Structured text (JSON, XML, YAML, etc.)
    StructuredText,
    /// Source code files
    SourceCode,
    /// Binary executable files
    Binary,
    /// Already compressed archives
    Archive,
    /// Audio files (MP3, FLAC, etc.)
    Audio,
    /// Video files (MP4, AVI, etc.)
    Video,
    /// Image files (JPEG, PNG, etc.)
    Image,
    /// Database files
    Database,
    /// Unknown file type
    Unknown,
}

/// Compression algorithm selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompressionAlgorithm {
    /// ZSTD compression (default, balanced)
    Zstd,
    /// Brotli compression (web-optimized, best for text)
    #[cfg(feature = "brotli-support")]
    Brotli,
    /// LZ4 compression (ultra-fast)
    #[cfg(feature = "lz4-support")]
    Lz4,
    /// Store without compression
    Store,
}

impl Default for CompressionAlgorithm {
    fn default() -> Self {
        Self::Zstd
    }
}

/// Performance profile for compression selection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PerformanceProfile {
    /// Prioritize speed over compression ratio
    Fast,
    /// Balance between speed and compression
    Balanced,
    /// Prioritize compression ratio over speed
    Maximum,
}

impl Default for PerformanceProfile {
    fn default() -> Self {
        Self::Balanced
    }
}

/// Adaptive compression engine
#[derive(Debug)]
pub struct AdaptiveCompressionEngine {
    /// Performance profile
    profile: PerformanceProfile,
    /// Sample size for analysis (bytes)
    sample_size: usize,
    /// Minimum file size for compression (bytes)
    min_compression_size: usize,
    /// Enable entropy analysis
    entropy_analysis: bool,
    /// Fallback algorithm when detection fails
    fallback_algorithm: CompressionAlgorithm,
}

impl AdaptiveCompressionEngine {
    /// Create new adaptive compression engine
    pub fn new() -> Self {
        Self {
            profile: PerformanceProfile::default(),
            sample_size: 8192, // 8KB sample
            min_compression_size: 1024, // Don't compress files < 1KB
            entropy_analysis: true,
            fallback_algorithm: CompressionAlgorithm::default(),
        }
    }

    /// Set performance profile
    pub fn with_profile(mut self, profile: PerformanceProfile) -> Self {
        self.profile = profile;
        self
    }

    /// Set sample size for analysis
    pub fn with_sample_size(mut self, size: usize) -> Self {
        self.sample_size = size.clamp(1024, 64 * 1024); // 1KB to 64KB
        self
    }

    /// Set minimum file size for compression
    pub fn with_min_compression_size(mut self, size: usize) -> Self {
        self.min_compression_size = size;
        self
    }

    /// Enable or disable entropy analysis
    pub fn with_entropy_analysis(mut self, enabled: bool) -> Self {
        self.entropy_analysis = enabled;
        self
    }

    /// Set fallback algorithm
    pub fn with_fallback_algorithm(mut self, algorithm: CompressionAlgorithm) -> Self {
        self.fallback_algorithm = algorithm;
        self
    }

    /// Detect file type from magic bytes and content analysis
    pub fn detect_file_type(&self, data: &[u8]) -> FileType {
        if data.len() < 4 {
            return FileType::Unknown;
        }

        // Check magic bytes for known file types
        match &data[0..4] {
            // Archive formats
            b"PK\x03\x04" | b"PK\x05\x06" => return FileType::Archive, // ZIP
            b"Rar!" => return FileType::Archive, // RAR
            b"\x1f\x8b\x08\x00" => return FileType::Archive, // GZIP
            b"BZh" if data.len() > 3 => return FileType::Archive, // BZIP2
            b"\xfd7zXZ" => return FileType::Archive, // XZ
            b"7z\xbc\xaf" => return FileType::Archive, // 7Z
            
            // Image formats
            b"\xff\xd8\xff\xe0" | b"\xff\xd8\xff\xe1" | b"\xff\xd8\xff\xdb" => return FileType::Image, // JPEG variants
            b"\x89PNG" => return FileType::Image, // PNG
            b"GIF8" => return FileType::Image, // GIF
            b"RIFF" if data.len() > 8 && &data[8..12] == b"WEBP" => return FileType::Image, // WebP
            b"BM" if data.len() > 2 => return FileType::Image, // BMP
            
            // Audio formats
            b"ID3" | b"\xff\xfb" | b"\xff\xf3" | b"\xff\xf2" => return FileType::Audio, // MP3
            b"fLaC" => return FileType::Audio, // FLAC
            b"OggS" => return FileType::Audio, // OGG
            b"RIFF" if data.len() > 8 && &data[8..12] == b"WAVE" => return FileType::Audio, // WAV
            
            // Video formats
            b"\x00\x00\x00" if data.len() > 8 && &data[4..8] == b"ftyp" => return FileType::Video, // MP4
            b"RIFF" if data.len() > 8 && &data[8..12] == b"AVI " => return FileType::Video, // AVI
            b"\x1a\x45\xdf\xa3" => return FileType::Video, // MKV
            
            // Executable formats
            b"MZ" if data.len() > 2 => return FileType::Binary, // Windows PE
            b"\x7fELF" => return FileType::Binary, // Linux ELF
            b"\xfe\xed\xfa" | b"\xce\xfa\xed\xfe" => return FileType::Binary, // Mach-O
            
            _ => {}
        }

        // Content-based detection for text files
        self.detect_text_type(data)
    }

    /// Detect text-based file types
    fn detect_text_type(&self, data: &[u8]) -> FileType {
        // Try to parse as UTF-8
        let text = match std::str::from_utf8(data) {
            Ok(s) => s,
            Err(_) => return FileType::Binary,
        };

        // Check for structured text formats
        let trimmed = text.trim_start();
        
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            return FileType::StructuredText; // Likely JSON
        }
        
        if trimmed.starts_with('<') {
            return FileType::StructuredText; // Likely XML/HTML
        }
        
        if trimmed.starts_with("---") || text.contains(":\n") || text.contains(": ") {
            return FileType::StructuredText; // Likely YAML
        }

        // Check for source code patterns
        if self.is_source_code(text) {
            return FileType::SourceCode;
        }

        // Check if it's mostly printable text
        let printable_ratio = text.chars()
            .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
            .count() as f64 / text.chars().count() as f64;

        if printable_ratio > 0.8 {
            FileType::Text
        } else {
            FileType::Binary
        }
    }

    /// Check if text content looks like source code
    fn is_source_code(&self, text: &str) -> bool {
        let code_indicators = [
            "function", "class", "import", "export", "const", "let", "var",
            "def ", "fn ", "if ", "else", "for ", "while ", "return", "public", "private",
            "#include", "#define", "struct", "enum", "typedef", "namespace",
            "package", "interface", "extends", "implements", "println!",
        ];

        let indicator_count = code_indicators.iter()
            .filter(|&indicator| text.contains(indicator))
            .count();

        // Check for common code patterns
        let has_braces = text.contains('{') && text.contains('}');
        let has_semicolons = text.contains(';');
        let has_parentheses = text.contains('(') && text.contains(')');

        // If we find code indicators or common code patterns, likely source code
        indicator_count >= 1 || (has_braces && (has_semicolons || has_parentheses))
    }

    /// Calculate entropy of data sample
    pub fn calculate_entropy(&self, data: &[u8]) -> f64 {
        if data.is_empty() {
            return 0.0;
        }

        let mut counts = [0u32; 256];
        for &byte in data {
            counts[byte as usize] += 1;
        }

        let len = data.len() as f64;
        let mut entropy = 0.0;

        for &count in &counts {
            if count > 0 {
                let p = count as f64 / len;
                entropy -= p * p.log2();
            }
        }

        entropy
    }

    /// Select optimal compression algorithm
    pub fn select_algorithm(
        &self,
        file_type: FileType,
        file_size: u64,
        entropy: Option<f64>,
    ) -> CompressionAlgorithm {
        // Don't compress very small files
        if file_size < self.min_compression_size as u64 {
            return CompressionAlgorithm::Store;
        }

        // Check entropy if available
        if let Some(entropy_value) = entropy {
            // High entropy (> 7.5) indicates already compressed/encrypted data
            if entropy_value > 7.5 {
                return CompressionAlgorithm::Store;
            }
        }

        match self.profile {
            PerformanceProfile::Fast => self.select_fast_algorithm(file_type, file_size),
            PerformanceProfile::Balanced => self.select_balanced_algorithm(file_type, file_size),
            PerformanceProfile::Maximum => self.select_maximum_algorithm(file_type, file_size),
        }
    }

    /// Select algorithm optimized for speed
    fn select_fast_algorithm(&self, file_type: FileType, _file_size: u64) -> CompressionAlgorithm {
        match file_type {
            FileType::Archive | FileType::Audio | FileType::Video | FileType::Image => {
                CompressionAlgorithm::Store // Already compressed
            }
            _ => {
                #[cfg(feature = "lz4-support")]
                {
                    CompressionAlgorithm::Lz4 // Ultra-fast for everything else
                }
                #[cfg(not(feature = "lz4-support"))]
                {
                    CompressionAlgorithm::Zstd
                }
            }
        }
    }

    /// Select algorithm with balanced speed/compression
    fn select_balanced_algorithm(&self, file_type: FileType, file_size: u64) -> CompressionAlgorithm {
        match file_type {
            FileType::Archive | FileType::Audio | FileType::Video | FileType::Image => {
                CompressionAlgorithm::Store // Already compressed
            }
            FileType::Text | FileType::StructuredText | FileType::SourceCode => {
                #[cfg(feature = "brotli-support")]
                {
                    CompressionAlgorithm::Brotli // Excellent for text
                }
                #[cfg(not(feature = "brotli-support"))]
                {
                    CompressionAlgorithm::Zstd
                }
            }
            FileType::Binary | FileType::Database => {
                if file_size < 1024 * 1024 {
                    // Small binary files: use LZ4 for speed
                    #[cfg(feature = "lz4-support")]
                    {
                        CompressionAlgorithm::Lz4
                    }
                    #[cfg(not(feature = "lz4-support"))]
                    {
                        CompressionAlgorithm::Zstd
                    }
                } else {
                    // Large binary files: use ZSTD for balance
                    CompressionAlgorithm::Zstd
                }
            }
            FileType::Unknown => self.fallback_algorithm,
        }
    }

    /// Select algorithm optimized for maximum compression
    fn select_maximum_algorithm(&self, file_type: FileType, _file_size: u64) -> CompressionAlgorithm {
        match file_type {
            FileType::Archive | FileType::Audio | FileType::Video | FileType::Image => {
                CompressionAlgorithm::Store // Already compressed
            }
            FileType::Text | FileType::StructuredText | FileType::SourceCode => {
                #[cfg(feature = "brotli-support")]
                {
                    CompressionAlgorithm::Brotli // Best compression for text
                }
                #[cfg(not(feature = "brotli-support"))]
                {
                    CompressionAlgorithm::Zstd
                }
            }
            _ => CompressionAlgorithm::Zstd, // ZSTD for everything else
        }
    }

    /// Analyze data and select optimal compression strategy
    pub fn analyze_and_select<R: Read + Seek>(
        &self,
        reader: &mut R,
        file_size: u64,
    ) -> Result<(CompressionAlgorithm, FileType, Option<f64>)> {
        // Read sample for analysis
        let sample_size = self.sample_size.min(file_size as usize);
        let mut sample = vec![0u8; sample_size];
        
        let bytes_read = reader.read(&mut sample).map_err(|e| {
            RuzipError::io_error("Failed to read sample for analysis", e)
        })?;
        
        sample.truncate(bytes_read);
        
        // Reset reader position
        reader.seek(SeekFrom::Start(0)).map_err(|e| {
            RuzipError::io_error("Failed to reset reader position", e)
        })?;

        // Detect file type
        let file_type = self.detect_file_type(&sample);

        // Calculate entropy if enabled
        let entropy = if self.entropy_analysis && !sample.is_empty() {
            Some(self.calculate_entropy(&sample))
        } else {
            None
        };

        // Select algorithm
        let algorithm = self.select_algorithm(file_type, file_size, entropy);

        tracing::debug!(
            "Adaptive analysis: type={:?}, size={}KB, entropy={:?}, algorithm={:?}",
            file_type,
            file_size / 1024,
            entropy,
            algorithm
        );

        Ok((algorithm, file_type, entropy))
    }

    /// Compress using the selected algorithm
    fn compress_with_algorithm<R: Read, W: Write>(
        &self,
        algorithm: CompressionAlgorithm,
        reader: R,
        writer: W,
        level: CompressionLevel,
    ) -> Result<CompressionStats> {
        match algorithm {
            CompressionAlgorithm::Zstd => {
                let engine = CompressionEngine::new();
                engine.compress(reader, writer, level)
            }
            #[cfg(feature = "brotli-support")]
            CompressionAlgorithm::Brotli => {
                let engine = BrotliEngine::new();
                engine.compress(reader, writer, level)
            }
            #[cfg(feature = "lz4-support")]
            CompressionAlgorithm::Lz4 => {
                let engine = Lz4Engine::new();
                engine.compress(reader, writer, level)
            }
            CompressionAlgorithm::Store => {
                let engine = CompressionEngine::new()
                    .with_method(crate::compression::CompressionMethod::Store);
                engine.compress(reader, writer, level)
            }
        }
    }

    /// Decompress using the selected algorithm
    fn decompress_with_algorithm<R: Read, W: Write>(
        &self,
        algorithm: CompressionAlgorithm,
        reader: R,
        writer: W,
    ) -> Result<CompressionStats> {
        match algorithm {
            CompressionAlgorithm::Zstd => {
                let engine = CompressionEngine::new();
                engine.decompress(reader, writer)
            }
            #[cfg(feature = "brotli-support")]
            CompressionAlgorithm::Brotli => {
                let engine = BrotliEngine::new();
                engine.decompress(reader, writer)
            }
            #[cfg(feature = "lz4-support")]
            CompressionAlgorithm::Lz4 => {
                let engine = Lz4Engine::new();
                engine.decompress(reader, writer)
            }
            CompressionAlgorithm::Store => {
                let engine = CompressionEngine::new()
                    .with_method(crate::compression::CompressionMethod::Store);
                engine.decompress(reader, writer)
            }
        }
    }
}

impl Default for AdaptiveCompressionEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl Compressor for AdaptiveCompressionEngine {
    fn compress<R: Read, W: Write>(
        &self,
        reader: R,
        writer: W,
        level: CompressionLevel,
    ) -> Result<CompressionStats> {
        // For non-seekable readers, use fallback algorithm
        let algorithm = self.fallback_algorithm;
        
        tracing::debug!(
            "Adaptive compression using fallback algorithm: {:?}",
            algorithm
        );
        
        self.compress_with_algorithm(algorithm, reader, writer, level)
    }

    fn decompress<R: Read, W: Write>(
        &self,
        reader: R,
        writer: W,
    ) -> Result<CompressionStats> {
        // For decompression, we need to detect the algorithm from the data
        // This would typically be stored in the archive header
        // For now, use ZSTD as fallback
        self.decompress_with_algorithm(CompressionAlgorithm::Zstd, reader, writer)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_file_type_detection() {
        let engine = AdaptiveCompressionEngine::new();
        
        // Test text detection
        let text_data = b"Hello, World! This is plain text.";
        assert_eq!(engine.detect_file_type(text_data), FileType::Text);
        
        // Test JSON detection
        let json_data = b"{ \"key\": \"value\" }";
        assert_eq!(engine.detect_file_type(json_data), FileType::StructuredText);
        
        // Test ZIP detection
        let zip_data = b"PK\x03\x04\x14\x00\x00\x00";
        assert_eq!(engine.detect_file_type(zip_data), FileType::Archive);
        
        // Test JPEG detection
        let jpeg_data = b"\xff\xd8\xff\xe0\x00\x10JFIF";
        assert_eq!(engine.detect_file_type(jpeg_data), FileType::Image);
    }

    #[test]
    fn test_entropy_calculation() {
        let engine = AdaptiveCompressionEngine::new();
        
        // Low entropy (repeated data)
        let low_entropy_data = vec![0u8; 1000];
        let entropy = engine.calculate_entropy(&low_entropy_data);
        assert!(entropy < 1.0);
        
        // High entropy (random data)
        let high_entropy_data: Vec<u8> = (0..=255).cycle().take(1000).collect();
        let entropy = engine.calculate_entropy(&high_entropy_data);
        assert!(entropy > 6.0);
    }

    #[test]
    fn test_algorithm_selection() {
        let engine = AdaptiveCompressionEngine::new().with_profile(PerformanceProfile::Balanced);
        
        // Text should prefer Brotli (if available) or ZSTD
        let algorithm = engine.select_algorithm(FileType::Text, 10000, Some(4.0));
        #[cfg(feature = "brotli-support")]
        assert_eq!(algorithm, CompressionAlgorithm::Brotli);
        #[cfg(not(feature = "brotli-support"))]
        assert_eq!(algorithm, CompressionAlgorithm::Zstd);
        
        // Already compressed files should be stored
        let algorithm = engine.select_algorithm(FileType::Archive, 10000, Some(7.8));
        assert_eq!(algorithm, CompressionAlgorithm::Store);
        
        // High entropy data should be stored
        let algorithm = engine.select_algorithm(FileType::Binary, 10000, Some(7.9));
        assert_eq!(algorithm, CompressionAlgorithm::Store);
    }

    #[test]
    fn test_performance_profiles() {
        #[cfg(feature = "lz4-support")]
        let fast_engine = AdaptiveCompressionEngine::new().with_profile(PerformanceProfile::Fast);
        let max_engine = AdaptiveCompressionEngine::new().with_profile(PerformanceProfile::Maximum);
        
        // Fast profile should prefer LZ4 for binary data
        #[cfg(feature = "lz4-support")]
        {
            let fast_algo = fast_engine.select_algorithm(FileType::Binary, 10000, Some(4.0));
            assert_eq!(fast_algo, CompressionAlgorithm::Lz4);
        }
        
        // Maximum profile should prefer ZSTD/Brotli
        let max_algo = max_engine.select_algorithm(FileType::Binary, 10000, Some(4.0));
        assert_eq!(max_algo, CompressionAlgorithm::Zstd);
    }

    #[test]
    fn test_source_code_detection() {
        let engine = AdaptiveCompressionEngine::new();
        
        let rust_code = b"fn main() {\n    println!(\"Hello, world!\");\n}";
        assert_eq!(engine.detect_file_type(rust_code), FileType::SourceCode);
        
        let js_code = b"function hello() {\n    return \"Hello, world!\";\n}";
        assert_eq!(engine.detect_file_type(js_code), FileType::SourceCode);
        
        let plain_text = b"This is just plain text without code keywords.";
        assert_eq!(engine.detect_file_type(plain_text), FileType::Text);
    }
}