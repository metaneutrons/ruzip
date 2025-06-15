//! Archive header structure and serialization
//!
//! Defines the binary format for RuZip archive headers with
//! version compatibility and integrity checks.

use crate::archive::{RUZIP_MAGIC, CURRENT_VERSION};
use crate::error::{Result, RuzipError};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};

/// Archive header structure (fixed size: 64 bytes)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveHeader {
    /// Magic bytes "RUZIP" (4 bytes)
    pub magic: [u8; 4],
    /// Format version (2 bytes)
    pub version: u16,
    /// Header size in bytes (2 bytes)
    pub header_size: u16,
    /// Compression method (1 byte)
    pub compression_method: u8,
    /// Compression level (1 byte)
    pub compression_level: u8,
    /// Archive flags (2 bytes)
    pub flags: ArchiveFlags,
    /// Number of entries (8 bytes)
    pub entry_count: u64,
    /// Total uncompressed size (8 bytes)
    pub uncompressed_size: u64,
    /// Total compressed size (8 bytes)
    pub compressed_size: u64,
    /// Archive creation timestamp (8 bytes)
    pub created_at: u64,
    /// Archive modification timestamp (8 bytes)
    pub modified_at: u64,
    /// Entry table offset (8 bytes)
    pub entry_table_offset: u64,
    /// Header checksum CRC32 (4 bytes)
    pub header_checksum: u32,
    /// Crypto metadata offset (8 bytes) - 0 if no crypto
    pub crypto_metadata_offset: u64,
    /// Signature metadata offset (8 bytes) - 0 if no signatures
    pub signature_metadata_offset: u64,
    /// Reserved bytes for future use (0 bytes to keep size at 80)
    pub reserved: [u8; 0],
}

/// Archive flags bitfield
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveFlags(u16);

impl ArchiveFlags {
    /// No special flags
    pub const NONE: Self = Self(0);
    /// Archive has integrity checksums
    pub const HAS_CHECKSUMS: Self = Self(1 << 0);
    /// Archive is encrypted
    pub const ENCRYPTED: Self = Self(1 << 1);
    /// Archive is signed
    pub const SIGNED: Self = Self(1 << 2);
    /// Archive preserves permissions
    pub const PRESERVE_PERMISSIONS: Self = Self(1 << 3);
    /// Archive preserves timestamps
    pub const PRESERVE_TIMESTAMPS: Self = Self(1 << 4);
    /// Archive is compressed
    pub const COMPRESSED: Self = Self(1 << 5);
    /// Archive has extended metadata
    pub const EXTENDED_METADATA: Self = Self(1 << 6);

    /// Create new flags from raw value
    pub fn new(value: u16) -> Self {
        Self(value)
    }

    /// Get raw flag value
    pub fn value(&self) -> u16 {
        self.0
    }

    /// Check if flag is set
    pub fn has_flag(&self, flag: ArchiveFlags) -> bool {
        (self.0 & flag.0) != 0
    }

    /// Set a flag
    pub fn set_flag(&mut self, flag: ArchiveFlags) {
        self.0 |= flag.0;
    }

    /// Clear a flag
    pub fn clear_flag(&mut self, flag: ArchiveFlags) {
        self.0 &= !flag.0;
    }

    /// Toggle a flag
    pub fn toggle_flag(&mut self, flag: ArchiveFlags) {
        self.0 ^= flag.0;
    }

    /// Create flags with multiple flags set
    pub fn with_flags(flags: &[ArchiveFlags]) -> Self {
        let mut result = Self::NONE;
        for flag in flags {
            result.set_flag(*flag);
        }
        result
    }
}

impl Default for ArchiveFlags {
    fn default() -> Self {
        Self::NONE
    }
}

impl std::fmt::Display for ArchiveFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut flags = Vec::new();
        
        if self.has_flag(Self::HAS_CHECKSUMS) {
            flags.push("checksums");
        }
        if self.has_flag(Self::ENCRYPTED) {
            flags.push("encrypted");
        }
        if self.has_flag(Self::SIGNED) {
            flags.push("signed");
        }
        if self.has_flag(Self::PRESERVE_PERMISSIONS) {
            flags.push("permissions");
        }
        if self.has_flag(Self::PRESERVE_TIMESTAMPS) {
            flags.push("timestamps");
        }
        if self.has_flag(Self::COMPRESSED) {
            flags.push("compressed");
        }
        if self.has_flag(Self::EXTENDED_METADATA) {
            flags.push("extended");
        }

        if flags.is_empty() {
            write!(f, "none")
        } else {
            write!(f, "{}", flags.join(","))
        }
    }
}

impl ArchiveHeader {
    /// Header size in bytes
    pub const SIZE: usize = 80;

    /// Create new archive header
    pub fn new() -> Self {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            magic: *RUZIP_MAGIC,
            version: CURRENT_VERSION,
            header_size: Self::SIZE as u16,
            compression_method: 0, // ZSTD
            compression_level: 6,  // Default level
            flags: ArchiveFlags::default(),
            entry_count: 0,
            uncompressed_size: 0,
            compressed_size: 0,
            created_at: now,
            modified_at: now,
            entry_table_offset: 0, // Will be set when writing entry table
            header_checksum: 0, // Will be calculated when serializing
            crypto_metadata_offset: 0, // Will be set if crypto is used
            signature_metadata_offset: 0, // Will be set if signatures are used
            reserved: [],
        }
    }

    /// Create header with compression settings
    pub fn with_compression(
        method: crate::compression::CompressionMethod,
        level: crate::compression::CompressionLevel,
    ) -> Self {
        let mut header = Self::new();
        
        header.compression_method = match method {
            crate::compression::CompressionMethod::Zstd => 0,
            #[cfg(feature = "brotli-support")]
            crate::compression::CompressionMethod::Brotli => 2,
            #[cfg(feature = "lz4-support")]
            crate::compression::CompressionMethod::Lz4 => 3,
            crate::compression::CompressionMethod::Store => 1,
        };
        
        header.compression_level = level.value();
        
        if matches!(method, crate::compression::CompressionMethod::Zstd) {
            header.flags.set_flag(ArchiveFlags::COMPRESSED);
        }
        
        header
    }

    /// Validate header magic and version
    pub fn validate(&self) -> Result<()> {
        // Check magic bytes
        if &self.magic != RUZIP_MAGIC {
            return Err(RuzipError::archive_format_error(
                "Invalid archive magic bytes",
                Some(format!("Expected {:?}, found {:?}", RUZIP_MAGIC, self.magic)),
            ));
        }

        // Check version compatibility
        if self.version < crate::archive::MIN_SUPPORTED_VERSION {
            return Err(RuzipError::archive_format_error(
                format!("Unsupported archive version {}", self.version),
                Some(format!("Minimum supported version is {}", crate::archive::MIN_SUPPORTED_VERSION)),
            ));
        }

        // Check header size
        if self.header_size as usize != Self::SIZE {
            return Err(RuzipError::archive_format_error(
                format!("Invalid header size {}", self.header_size),
                Some(format!("Expected size {}", Self::SIZE)),
            ));
        }

        // Validate entry count
        if self.entry_count > crate::archive::MAX_ENTRIES {
            return Err(RuzipError::archive_format_error(
                format!("Too many entries: {}", self.entry_count),
                Some(format!("Maximum allowed: {}", crate::archive::MAX_ENTRIES)),
            ));
        }

        // Validate sizes
        if self.compressed_size > crate::archive::MAX_ARCHIVE_SIZE {
            return Err(RuzipError::archive_format_error(
                "Archive too large",
                Some(format!("Size: {} bytes", self.compressed_size)),
            ));
        }

        Ok(())
    }

    /// Calculate header checksum (excluding the checksum field itself)
    pub fn calculate_checksum(&self) -> u32 {
        let mut header_copy = self.clone();
        header_copy.header_checksum = 0;
        
        let serialized = bincode::serialize(&header_copy).unwrap_or_default();
        crc32fast::hash(&serialized)
    }

    /// Update checksum field
    pub fn update_checksum(&mut self) {
        self.header_checksum = self.calculate_checksum();
    }

    /// Verify header checksum
    pub fn verify_checksum(&self) -> Result<()> {
        let calculated = self.calculate_checksum();
        if calculated != self.header_checksum {
            return Err(RuzipError::archive_format_error(
                "Header checksum mismatch",
                Some(format!("Expected {}, found {}", calculated, self.header_checksum)),
            ));
        }
        Ok(())
    }

    /// Serialize header to binary format
    pub fn serialize<W: Write>(&mut self, mut writer: W) -> Result<()> {
        // Update checksum before serializing
        self.update_checksum();

        let serialized = bincode::serialize(self).map_err(|e| {
            RuzipError::archive_format_error(
                "Failed to serialize header",
                Some(e.to_string()),
            )
        })?;

        // Ensure exact size
        if serialized.len() != Self::SIZE {
            return Err(RuzipError::archive_format_error(
                format!("Serialized header size mismatch: {} != {}", serialized.len(), Self::SIZE),
                None,
            ));
        }

        writer.write_all(&serialized).map_err(|e| {
            RuzipError::io_error("Failed to write header", e)
        })?;

        Ok(())
    }

    /// Deserialize header from binary format
    pub fn deserialize<R: Read>(mut reader: R) -> Result<Self> {
        let mut buffer = vec![0u8; Self::SIZE];
        reader.read_exact(&mut buffer).map_err(|e| {
            RuzipError::io_error("Failed to read header", e)
        })?;

        let header: Self = bincode::deserialize(&buffer).map_err(|e| {
            RuzipError::archive_format_error(
                "Failed to deserialize header",
                Some(e.to_string()),
            )
        })?;

        // Validate and verify checksum
        header.validate()?;
        header.verify_checksum()?;

        Ok(header)
    }

    /// Update modification time
    pub fn touch(&mut self) {
        self.modified_at = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
    }

    /// Get compression ratio
    pub fn compression_ratio(&self) -> f64 {
        if self.uncompressed_size > 0 {
            self.compressed_size as f64 / self.uncompressed_size as f64
        } else {
            1.0
        }
    }
}

impl Default for ArchiveHeader {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_archive_flags() {
        let mut flags = ArchiveFlags::NONE;
        assert!(!flags.has_flag(ArchiveFlags::COMPRESSED));
        
        flags.set_flag(ArchiveFlags::COMPRESSED);
        assert!(flags.has_flag(ArchiveFlags::COMPRESSED));
        
        flags.clear_flag(ArchiveFlags::COMPRESSED);
        assert!(!flags.has_flag(ArchiveFlags::COMPRESSED));
        
        flags.toggle_flag(ArchiveFlags::ENCRYPTED);
        assert!(flags.has_flag(ArchiveFlags::ENCRYPTED));
    }

    #[test]
    fn test_archive_flags_with_multiple() {
        let flags = ArchiveFlags::with_flags(&[
            ArchiveFlags::COMPRESSED,
            ArchiveFlags::HAS_CHECKSUMS,
            ArchiveFlags::PRESERVE_TIMESTAMPS,
        ]);
        
        assert!(flags.has_flag(ArchiveFlags::COMPRESSED));
        assert!(flags.has_flag(ArchiveFlags::HAS_CHECKSUMS));
        assert!(flags.has_flag(ArchiveFlags::PRESERVE_TIMESTAMPS));
        assert!(!flags.has_flag(ArchiveFlags::ENCRYPTED));
    }

    #[test]
    fn test_archive_flags_display() {
        let flags = ArchiveFlags::with_flags(&[
            ArchiveFlags::COMPRESSED,
            ArchiveFlags::ENCRYPTED,
        ]);
        
        let display = format!("{}", flags);
        assert!(display.contains("compressed"));
        assert!(display.contains("encrypted"));
    }

    #[test]
    fn test_header_creation() {
        let header = ArchiveHeader::new();
        assert_eq!(header.magic, *RUZIP_MAGIC);
        assert_eq!(header.version, CURRENT_VERSION);
        assert_eq!(header.header_size, ArchiveHeader::SIZE as u16);
        assert!(header.created_at > 0);
    }

    #[test]
    fn test_header_with_compression() {
        let level = crate::compression::CompressionLevel::new(12).unwrap();
        let header = ArchiveHeader::with_compression(
            crate::compression::CompressionMethod::Zstd,
            level,
        );
        
        assert_eq!(header.compression_method, 0); // ZSTD
        assert_eq!(header.compression_level, 12);
        assert!(header.flags.has_flag(ArchiveFlags::COMPRESSED));
    }

    #[test]
    fn test_header_validation() {
        let mut header = ArchiveHeader::new();
        assert!(header.validate().is_ok());
        
        // Test invalid magic
        header.magic = [b'T', b'E', b'S', b'T'];
        assert!(header.validate().is_err());
        header.magic = *RUZIP_MAGIC;
        
        // Test invalid version
        header.version = 0;
        assert!(header.validate().is_err());
        header.version = CURRENT_VERSION;
        
        // Test too many entries
        header.entry_count = crate::archive::MAX_ENTRIES + 1;
        assert!(header.validate().is_err());
    }

    #[test]
    fn test_header_checksum() {
        let mut header = ArchiveHeader::new();
        let original_checksum = header.calculate_checksum();
        
        header.update_checksum();
        assert_eq!(header.header_checksum, original_checksum);
        assert!(header.verify_checksum().is_ok());
        
        // Corrupt checksum
        header.header_checksum += 1;
        assert!(header.verify_checksum().is_err());
    }

    #[test]
    fn test_header_serialization() {
        let mut header = ArchiveHeader::new();
        header.entry_count = 42;
        header.uncompressed_size = 1000;
        header.compressed_size = 600;
        
        // Update checksum manually
        header.update_checksum();
        
        // Serialize using bincode directly (like the serialize method does internally)
        let mut buffer = Vec::new();
        let serialized = bincode::serialize(&header).unwrap();
        buffer.extend_from_slice(&serialized);
        assert_eq!(buffer.len(), ArchiveHeader::SIZE);
        
        // Deserialize
        let cursor = Cursor::new(&buffer);
        let deserialized = ArchiveHeader::deserialize(cursor).unwrap();
        
        assert_eq!(deserialized.entry_count, 42);
        assert_eq!(deserialized.uncompressed_size, 1000);
        assert_eq!(deserialized.compressed_size, 600);
        assert_eq!(deserialized.header_checksum, header.header_checksum);
    }

    #[test]
    fn test_header_touch() {
        let mut header = ArchiveHeader::new();
        let original_time = header.modified_at;
        
        // Sleep to ensure different timestamp
        std::thread::sleep(std::time::Duration::from_secs(1));
        header.touch();
        
        assert!(header.modified_at > original_time);
    }

    #[test]
    fn test_compression_ratio() {
        let mut header = ArchiveHeader::new();
        header.uncompressed_size = 1000;
        header.compressed_size = 600;
        
        assert_eq!(header.compression_ratio(), 0.6);
        
        // Test with zero uncompressed size
        header.uncompressed_size = 0;
        assert_eq!(header.compression_ratio(), 1.0);
    }
}