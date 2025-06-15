//! Archive format definitions and version management
//!
//! Defines the RuZip archive format specification, version compatibility,
//! and format evolution management.

use crate::error::{Result, RuzipError};
use serde::{Deserialize, Serialize};

/// Archive format specification
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ArchiveFormat {
    /// Format version
    pub version: FormatVersion,
    /// Format capabilities
    pub capabilities: FormatCapabilities,
    /// Format limitations
    pub limitations: FormatLimitations,
}

/// Format version information
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct FormatVersion {
    /// Major version
    pub major: u8,
    /// Minor version  
    pub minor: u8,
}

/// Format capabilities
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatCapabilities {
    /// Supported compression methods
    pub compression_methods: Vec<CompressionMethodSpec>,
    /// Maximum compression level
    pub max_compression_level: u8,
    /// Supports encryption
    pub encryption: bool,
    /// Supports digital signatures
    pub signatures: bool,
    /// Supports extended metadata
    pub extended_metadata: bool,
    /// Supports streaming operations
    pub streaming: bool,
    /// Supports partial extraction
    pub partial_extraction: bool,
}

/// Format limitations
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FormatLimitations {
    /// Maximum archive size in bytes
    pub max_archive_size: u64,
    /// Maximum number of entries
    pub max_entries: u64,
    /// Maximum entry size in bytes
    pub max_entry_size: u64,
    /// Maximum path length
    pub max_path_length: usize,
    /// Maximum filename length
    pub max_filename_length: usize,
}

/// Compression method specification
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompressionMethodSpec {
    /// Method identifier
    pub id: u8,
    /// Method name
    pub name: String,
    /// Minimum supported level
    pub min_level: u8,
    /// Maximum supported level
    pub max_level: u8,
    /// Memory efficiency
    pub memory_efficient: bool,
    /// Speed category
    pub speed_category: String,
}

impl FormatVersion {
    /// Current format version
    pub const CURRENT: Self = Self { major: 1, minor: 0 };
    
    /// Minimum supported version
    pub const MIN_SUPPORTED: Self = Self { major: 1, minor: 0 };

    /// Create new format version
    pub fn new(major: u8, minor: u8) -> Self {
        Self { major, minor }
    }

    /// Check if this version is compatible with another
    pub fn is_compatible_with(&self, other: &FormatVersion) -> bool {
        // Same major version is compatible
        self.major == other.major
    }

    /// Check if this version supports reading the other version
    pub fn can_read(&self, other: &FormatVersion) -> bool {
        // Can read same or older minor versions of same major
        self.major == other.major && self.minor >= other.minor
    }

    /// Check if this version can write in the other version's format
    pub fn can_write(&self, other: &FormatVersion) -> bool {
        // Can only write exact version match
        self == other
    }

    /// Get version as u16 (major << 8 | minor)
    pub fn as_u16(&self) -> u16 {
        (self.major as u16) << 8 | (self.minor as u16)
    }

    /// Create version from u16
    pub fn from_u16(value: u16) -> Self {
        Self {
            major: (value >> 8) as u8,
            minor: (value & 0xFF) as u8,
        }
    }
}

impl std::fmt::Display for FormatVersion {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}.{}", self.major, self.minor)
    }
}

impl ArchiveFormat {
    /// Get current format specification
    pub fn current() -> Self {
        Self {
            version: FormatVersion::CURRENT,
            capabilities: FormatCapabilities::current(),
            limitations: FormatLimitations::current(),
        }
    }

    /// Get format for specific version
    pub fn for_version(version: FormatVersion) -> Result<Self> {
        match version {
            FormatVersion { major: 1, minor: 0 } => Ok(Self::v1_0()),
            _ => Err(RuzipError::invalid_version(
                version.as_u16(),
                FormatVersion::MIN_SUPPORTED.as_u16(),
                FormatVersion::CURRENT.as_u16(),
            )),
        }
    }

    /// Version 1.0 format specification
    fn v1_0() -> Self {
        Self {
            version: FormatVersion::new(1, 0),
            capabilities: FormatCapabilities {
                compression_methods: vec![
                    CompressionMethodSpec {
                        id: 0,
                        name: "ZSTD".to_string(),
                        min_level: 1,
                        max_level: 22,
                        memory_efficient: true,
                        speed_category: "balanced".to_string(),
                    },
                    CompressionMethodSpec {
                        id: 1,
                        name: "Store".to_string(),
                        min_level: 0,
                        max_level: 0,
                        memory_efficient: true,
                        speed_category: "fastest".to_string(),
                    },
                ],
                max_compression_level: 22,
                encryption: true, // Now supported with crypto integration
                signatures: true, // Now supported with crypto integration
                extended_metadata: true,
                streaming: true,
                partial_extraction: true,
            },
            limitations: FormatLimitations::current(),
        }
    }

    /// Validate if a compression method is supported
    pub fn supports_compression_method(&self, method_id: u8) -> bool {
        self.capabilities.compression_methods
            .iter()
            .any(|spec| spec.id == method_id)
    }

    /// Get compression method specification
    pub fn get_compression_method(&self, method_id: u8) -> Option<&CompressionMethodSpec> {
        self.capabilities.compression_methods
            .iter()
            .find(|spec| spec.id == method_id)
    }

    /// Validate compression level for method
    pub fn validate_compression_level(&self, method_id: u8, level: u8) -> Result<()> {
        let spec = self.get_compression_method(method_id)
            .ok_or_else(|| RuzipError::archive_format_error(
                format!("Unsupported compression method: {}", method_id),
                None,
            ))?;

        if level < spec.min_level || level > spec.max_level {
            return Err(RuzipError::archive_format_error(
                format!(
                    "Compression level {} out of range for {}: [{}, {}]",
                    level, spec.name, spec.min_level, spec.max_level
                ),
                None,
            ));
        }

        Ok(())
    }

    /// Check if archive size is within limits
    pub fn validate_archive_size(&self, size: u64) -> Result<()> {
        if size > self.limitations.max_archive_size {
            return Err(RuzipError::archive_format_error(
                format!(
                    "Archive size {} exceeds maximum: {}",
                    size, self.limitations.max_archive_size
                ),
                None,
            ));
        }
        Ok(())
    }

    /// Check if entry count is within limits
    pub fn validate_entry_count(&self, count: u64) -> Result<()> {
        if count > self.limitations.max_entries {
            return Err(RuzipError::archive_format_error(
                format!(
                    "Entry count {} exceeds maximum: {}",
                    count, self.limitations.max_entries
                ),
                None,
            ));
        }
        Ok(())
    }

    /// Check if path length is within limits
    pub fn validate_path_length(&self, path: &str) -> Result<()> {
        if path.len() > self.limitations.max_path_length {
            return Err(RuzipError::archive_format_error(
                format!(
                    "Path length {} exceeds maximum: {}",
                    path.len(), self.limitations.max_path_length
                ),
                Some(path.to_string()),
            ));
        }
        Ok(())
    }
}

impl FormatCapabilities {
    /// Current format capabilities
    fn current() -> Self {
        Self {
            compression_methods: vec![
                CompressionMethodSpec {
                    id: 0,
                    name: "ZSTD".to_string(),
                    min_level: 1,
                    max_level: 22,
                    memory_efficient: true,
                    speed_category: "balanced".to_string(),
                },
                CompressionMethodSpec {
                    id: 1,
                    name: "Store".to_string(),
                    min_level: 0,
                    max_level: 0,
                    memory_efficient: true,
                    speed_category: "fastest".to_string(),
                },
            ],
            max_compression_level: 22,
            encryption: true,
            signatures: true,
            extended_metadata: true,
            streaming: true,
            partial_extraction: true,
        }
    }
}

impl FormatLimitations {
    /// Current format limitations
    fn current() -> Self {
        Self {
            max_archive_size: crate::archive::MAX_ARCHIVE_SIZE,
            max_entries: crate::archive::MAX_ENTRIES,
            max_entry_size: 1024 * 1024 * 1024 * 1024, // 1TB per entry
            max_path_length: 4096,
            max_filename_length: 255,
        }
    }
}

/// Format detection utilities
pub mod detection {
    use super::*;
    use std::io::{Read, Seek, SeekFrom};

    /// Detect archive format from reader
    pub fn detect_format<R: Read + Seek>(mut reader: R) -> Result<FormatVersion> {
        reader.seek(SeekFrom::Start(0))?;
        
        // Read magic bytes
        let mut magic = [0u8; 4];
        reader.read_exact(&mut magic).map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                RuzipError::archive_too_short("Reading magic bytes".to_string(), 4, 3) // Indicate less than 4
            } else {
                RuzipError::io_error("Failed to read magic bytes", e)
            }
        })?;

        if &magic != crate::archive::RUZIP_MAGIC {
            return Err(RuzipError::header_parse_error(format!(
                "Invalid magic bytes. Expected {:?}, found {:?}",
                crate::archive::RUZIP_MAGIC, magic
            )));
        }

        // Read version
        let mut version_bytes = [0u8; 2];
        reader.read_exact(&mut version_bytes).map_err(|e| {
            if e.kind() == std::io::ErrorKind::UnexpectedEof {
                RuzipError::archive_too_short("Reading version bytes".to_string(), 2, 1) // Indicate less than 2
            } else {
                RuzipError::io_error("Failed to read version bytes", e)
            }
        })?;

        let version_u16 = u16::from_le_bytes(version_bytes);
        let version = FormatVersion::from_u16(version_u16);

        // Validate version is supported for reading
        if !FormatVersion::CURRENT.can_read(&version) {
             return Err(RuzipError::invalid_version(
                version.as_u16(),
                FormatVersion::MIN_SUPPORTED.as_u16(),
                FormatVersion::CURRENT.as_u16(),
            ));
        }

        Ok(version)
    }

    /// Check if reader contains a valid RuZip archive
    pub fn is_ruzip_archive<R: Read + Seek>(reader: R) -> bool {
        detect_format(reader).is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_format_version() {
        let version = FormatVersion::new(1, 0);
        assert_eq!(version.major, 1);
        assert_eq!(version.minor, 0);
        assert_eq!(format!("{}", version), "1.0");
        
        assert_eq!(version.as_u16(), 0x0100);
        assert_eq!(FormatVersion::from_u16(0x0100), version);
    }

    #[test]
    fn test_version_compatibility() {
        let v1_0 = FormatVersion::new(1, 0);
        let v1_1 = FormatVersion::new(1, 1);
        let v2_0 = FormatVersion::new(2, 0);

        // Same major version is compatible
        assert!(v1_0.is_compatible_with(&v1_1));
        assert!(v1_1.is_compatible_with(&v1_0));
        assert!(!v1_0.is_compatible_with(&v2_0));

        // Can read same or older minor versions
        assert!(v1_1.can_read(&v1_0));
        assert!(v1_0.can_read(&v1_0));
        assert!(!v1_0.can_read(&v1_1));

        // Can only write exact version
        assert!(v1_0.can_write(&v1_0));
        assert!(!v1_0.can_write(&v1_1));
    }

    #[test]
    fn test_archive_format() {
        let format = ArchiveFormat::current();
        assert_eq!(format.version, FormatVersion::CURRENT);
        
        // Test compression method support
        assert!(format.supports_compression_method(0)); // ZSTD
        assert!(format.supports_compression_method(1)); // Store
        assert!(!format.supports_compression_method(2)); // Unknown

        // Test compression level validation
        assert!(format.validate_compression_level(0, 6).is_ok());
        assert!(format.validate_compression_level(0, 23).is_err());
        assert!(format.validate_compression_level(1, 0).is_ok());
        assert!(format.validate_compression_level(1, 1).is_err());
    }

    #[test]
    fn test_format_limits() {
        let format = ArchiveFormat::current();
        
        // Test archive size validation
        assert!(format.validate_archive_size(1024).is_ok());
        assert!(format.validate_archive_size(format.limitations.max_archive_size + 1).is_err());

        // Test entry count validation
        assert!(format.validate_entry_count(100).is_ok());
        assert!(format.validate_entry_count(format.limitations.max_entries + 1).is_err());

        // Test path length validation
        assert!(format.validate_path_length("short/path").is_ok());
        let long_path = "a".repeat(format.limitations.max_path_length + 1);
        assert!(format.validate_path_length(&long_path).is_err());
    }

    #[test]
    fn test_format_detection() {
        // Test valid magic bytes
        let mut valid_data = Vec::new();
        valid_data.extend_from_slice(crate::archive::RUZIP_MAGIC);
        valid_data.extend_from_slice(&FormatVersion::CURRENT.as_u16().to_le_bytes());
        
        let cursor = Cursor::new(&valid_data);
        let detected = detection::detect_format(cursor).unwrap();
        assert_eq!(detected, FormatVersion::CURRENT);

        // Test invalid magic bytes
        let invalid_data = b"TEST";
        let cursor = Cursor::new(invalid_data);
        assert!(detection::detect_format(cursor).is_err());
    }

    #[test]
    fn test_compression_method_spec() {
        let format = ArchiveFormat::current();
        
        let zstd_spec = format.get_compression_method(0).unwrap();
        assert_eq!(zstd_spec.name, "ZSTD");
        assert_eq!(zstd_spec.min_level, 1);
        assert_eq!(zstd_spec.max_level, 22);
        
        let store_spec = format.get_compression_method(1).unwrap();
        assert_eq!(store_spec.name, "Store");
        assert_eq!(store_spec.min_level, 0);
        assert_eq!(store_spec.max_level, 0);
    }
}