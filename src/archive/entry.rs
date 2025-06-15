//! File entry structures and metadata handling
//!
//! Defines the format for storing file information within archives,
//! including metadata preservation and permissions handling.

use crate::error::{Result, RuzipError};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

/// File entry in archive
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileEntry {
    /// File path within archive (normalized)
    pub path: String,
    /// Entry type
    pub entry_type: EntryType,
    /// File metadata
    pub metadata: FileMetadata,
    /// Compressed data offset in archive
    pub data_offset: u64,
    /// Compressed data size
    pub compressed_size: u64,
    /// Uncompressed data size
    pub uncompressed_size: u64,
    /// Compression method used
    pub compression_method: u8,
    /// File checksum (SHA-256)
    pub checksum: Option<[u8; 32]>,
    /// Entry flags
    pub flags: EntryFlags,
    /// Digital signature (if signed)
    pub signature: Option<EntrySignature>,
    /// Extended attributes for future use
    pub extensions: std::collections::HashMap<String, Vec<u8>>,
}

// Use the existing DigitalSignature enum from crypto module
use crate::crypto::types::DigitalSignature;

/// Digital signature for individual file entry
/// Note: The signature covers the entire entry data including metadata,
/// making it tamper-evident. The signer identity is part of the signed data.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntrySignature {
    /// Signature timestamp (part of signed data)
    pub timestamp: u64,
    /// Signature algorithm (using existing crypto types)
    pub algorithm: DigitalSignature,
    /// Signature bytes
    pub signature: Vec<u8>,
    /// Public key or certificate (for verification)
    pub public_key: Vec<u8>,
}

/// Type of archive entry
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum EntryType {
    /// Regular file
    File,
    /// Directory
    Directory,
    /// Symbolic link
    Symlink,
    /// Hard link
    Hardlink,
}

/// File metadata structure
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FileMetadata {
    /// File size in bytes
    pub size: u64,
    /// File permissions (Unix-style)
    pub permissions: u32,
    /// Creation time (Unix timestamp)
    pub created_at: u64,
    /// Modification time (Unix timestamp)
    pub modified_at: u64,
    /// Access time (Unix timestamp)
    pub accessed_at: u64,
    /// User ID (Unix)
    pub uid: Option<u32>,
    /// Group ID (Unix)
    pub gid: Option<u32>,
    /// Device ID (for device files)
    pub device_id: Option<u64>,
    /// Inode number (Unix)
    pub inode: Option<u64>,
    /// Number of hard links
    pub nlink: Option<u64>,
    /// Symlink target (for symlinks)
    pub symlink_target: Option<String>,
}

/// Entry flags bitfield
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryFlags(u32);

// DigitalSignature already has these methods in crypto/types.rs
// No need to reimplement them here

impl EntryFlags {
    /// No special flags
    pub const NONE: Self = Self(0);
    /// Entry is encrypted
    pub const ENCRYPTED: Self = Self(1 << 0);
    /// Entry has extended attributes
    pub const EXTENDED_ATTRS: Self = Self(1 << 1);
    /// Entry is sparse file (TODO: Implement sparse file detection and optimization)
    /// Sparse files have large regions of zeros that can be stored efficiently
    /// by the filesystem. This flag enables special handling during compression
    /// and extraction to preserve sparse characteristics.
    pub const SPARSE: Self = Self(1 << 2);
    /// Entry is read-only
    pub const READONLY: Self = Self(1 << 3);
    /// Entry is hidden
    pub const HIDDEN: Self = Self(1 << 4);
    /// Entry is system file
    pub const SYSTEM: Self = Self(1 << 5);
    /// Entry has custom permissions
    pub const CUSTOM_PERMISSIONS: Self = Self(1 << 6);
    /// Entry is digitally signed
    pub const SIGNED: Self = Self(1 << 7);

    /// Create new flags
    pub fn new(value: u32) -> Self {
        Self(value)
    }

    /// Get raw value
    pub fn value(&self) -> u32 {
        self.0
    }

    /// Check if flag is set
    pub fn has_flag(&self, flag: EntryFlags) -> bool {
        (self.0 & flag.0) != 0
    }

    /// Set a flag
    pub fn set_flag(&mut self, flag: EntryFlags) {
        self.0 |= flag.0;
    }

    /// Clear a flag
    pub fn clear_flag(&mut self, flag: EntryFlags) {
        self.0 &= !flag.0;
    }
}

impl Default for EntryFlags {
    fn default() -> Self {
        Self::NONE
    }
}

impl FileEntry {
    /// Create new file entry from filesystem path
    pub fn from_path<P: AsRef<Path>>(
        path: P,
        archive_path: String,
        preserve_metadata: bool,
    ) -> Result<Self> {
        let path = path.as_ref();
        let metadata = fs::metadata(path).map_err(|e| {
            RuzipError::io_error(
                format!("Failed to get metadata for: {}", path.display()),
                e,
            )
        })?;

        let entry_type = if metadata.is_file() {
            EntryType::File
        } else if metadata.is_dir() {
            EntryType::Directory
        } else if metadata.file_type().is_symlink() {
            EntryType::Symlink
        } else {
            EntryType::File // Default for unknown types
        };

        let file_metadata = if preserve_metadata {
            FileMetadata::from_std_metadata(&metadata, path)?
        } else {
            FileMetadata::minimal(&metadata)
        };

        Ok(Self {
            path: archive_path,
            entry_type,
            metadata: file_metadata,
            data_offset: 0, // Will be set when writing
            compressed_size: 0, // Will be set when compressing
            uncompressed_size: metadata.len(),
            compression_method: 0, // ZSTD by default
            checksum: None, // Will be calculated if needed
            flags: EntryFlags::default(),
            signature: None,
            extensions: std::collections::HashMap::new(),
        })
    }

    /// Create directory entry
    pub fn directory(path: String, preserve_metadata: bool) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let metadata = if preserve_metadata {
            FileMetadata {
                size: 0,
                permissions: 0o755, // Default directory permissions
                created_at: now,
                modified_at: now,
                accessed_at: now,
                uid: None,
                gid: None,
                device_id: None,
                inode: None,
                nlink: None,
                symlink_target: None,
            }
        } else {
            FileMetadata::empty()
        };

        Self {
            path,
            entry_type: EntryType::Directory,
            metadata,
            data_offset: 0,
            compressed_size: 0,
            uncompressed_size: 0,
            compression_method: 1, // Store (no compression for directories)
            checksum: None,
            flags: EntryFlags::default(),
            signature: None,
            extensions: std::collections::HashMap::new(),
        }
    }

    /// Normalize archive path (use forward slashes, remove leading slash)
    pub fn normalize_path<P: AsRef<Path>>(path: P) -> String {
        let path_str = path.as_ref().to_string_lossy();
        let normalized = path_str.replace('\\', "/");
        
        // Remove leading slash
        if normalized.starts_with('/') {
            normalized[1..].to_string()
        } else {
            normalized
        }
    }

    /// Get file extension
    pub fn extension(&self) -> Option<&str> {
        Path::new(&self.path)
            .extension()
            .and_then(|ext| ext.to_str())
    }

    /// Get file name
    pub fn filename(&self) -> Option<&str> {
        Path::new(&self.path)
            .file_name()
            .and_then(|name| name.to_str())
    }

    /// Get parent directory path
    pub fn parent_path(&self) -> Option<String> {
        Path::new(&self.path)
            .parent()
            .map(|p| p.to_string_lossy().to_string())
    }

    /// Check if entry is a file
    pub fn is_file(&self) -> bool {
        matches!(self.entry_type, EntryType::File)
    }

    /// Check if entry is a directory
    pub fn is_directory(&self) -> bool {
        matches!(self.entry_type, EntryType::Directory)
    }

    /// Check if entry is a symlink
    pub fn is_symlink(&self) -> bool {
        matches!(self.entry_type, EntryType::Symlink)
    }

    /// Get compression ratio
    pub fn compression_ratio(&self) -> f64 {
        if self.uncompressed_size > 0 {
            self.compressed_size as f64 / self.uncompressed_size as f64
        } else {
            1.0
        }
    }

    /// Validate entry data
    pub fn validate(&self) -> Result<()> {
        // Check path is not empty
        if self.path.is_empty() {
            return Err(RuzipError::archive_format_error(
                "Entry path cannot be empty",
                None,
            ));
        }

        // Check for path traversal attempts
        if self.path.contains("..") {
            return Err(RuzipError::archive_format_error(
                "Entry path contains path traversal",
                Some(self.path.clone()),
            ));
        }

        // Check for absolute paths
        if self.path.starts_with('/') || (cfg!(windows) && self.path.contains(':')) {
            return Err(RuzipError::archive_format_error(
                "Entry path should be relative",
                Some(self.path.clone()),
            ));
        }

        // Validate sizes
        if self.entry_type == EntryType::File && self.uncompressed_size == 0 && self.compressed_size > 0 {
            return Err(RuzipError::archive_format_error(
                "File has compressed data but zero uncompressed size",
                Some(self.path.clone()),
            ));
        }

        Ok(())
    }

    /// Add digital signature to entry
    pub fn add_signature(&mut self, signature: EntrySignature) {
        self.signature = Some(signature);
        self.flags.set_flag(EntryFlags::SIGNED);
    }

    /// Remove digital signature from entry
    pub fn remove_signature(&mut self) {
        self.signature = None;
        self.flags.clear_flag(EntryFlags::SIGNED);
    }

    /// Check if entry is signed
    pub fn is_signed(&self) -> bool {
        self.flags.has_flag(EntryFlags::SIGNED) && self.signature.is_some()
    }

    /// Add extension data
    pub fn add_extension(&mut self, name: String, data: Vec<u8>) {
        self.extensions.insert(name, data);
        if !self.extensions.is_empty() {
            self.flags.set_flag(EntryFlags::EXTENDED_ATTRS);
        }
    }

    /// Get extension data
    pub fn get_extension(&self, name: &str) -> Option<&Vec<u8>> {
        self.extensions.get(name)
    }

    /// Remove extension
    pub fn remove_extension(&mut self, name: &str) -> Option<Vec<u8>> {
        let result = self.extensions.remove(name);
        if self.extensions.is_empty() {
            self.flags.clear_flag(EntryFlags::EXTENDED_ATTRS);
        }
        result
    }

    /// Check if entry has extensions
    pub fn has_extensions(&self) -> bool {
        self.flags.has_flag(EntryFlags::EXTENDED_ATTRS) && !self.extensions.is_empty()
    }

    /// Check if compression algorithm is supported for extraction
    pub fn can_extract(&self) -> bool {
        crate::compression::CompressionMethod::is_decompression_supported(self.compression_method)
    }

    /// Get compression algorithm name
    pub fn compression_algorithm_name(&self) -> String {
        crate::compression::CompressionMethod::algorithm_name_from_id(self.compression_method)
    }

    /// Create signature for entry data
    pub fn create_signature(&self, algorithm: DigitalSignature, _private_key: &[u8]) -> Result<EntrySignature> {
        // This is a placeholder - real implementation would use proper crypto library
        // like ring, ed25519-dalek, or rsa crate
        let _signed_data = self.get_signable_data()?;
        
        // Placeholder signature - real implementation would sign the data
        let signature = vec![0u8; 64]; // Placeholder
        let public_key = vec![0u8; 32]; // Placeholder - derive from private_key
        
        Ok(EntrySignature {
            algorithm,
            signature,
            public_key,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        })
    }

    /// Get data that should be signed (excludes signature field itself)
    fn get_signable_data(&self) -> Result<Vec<u8>> {
        // Create a copy without signature for signing
        let signable_entry = FileEntry {
            signature: None,
            ..self.clone()
        };
        
        // Serialize to get consistent byte representation
        bincode::serialize(&signable_entry).map_err(|e| {
            RuzipError::archive_format_error(
                format!("Failed to serialize entry for signing: {}", e),
                Some(self.path.clone()),
            )
        })
    }

    /// Verify signature
    pub fn verify_signature(&self) -> Result<bool> {
        if let Some(ref sig) = self.signature {
            let _signed_data = self.get_signable_data()?;
            
            // TODO: Implement actual signature verification with crypto library
            // This would verify sig.signature against signed_data using sig.public_key
            // The signature itself contains the hash information - no separate hash needed
            // For now, just check that signature exists
            Ok(!sig.signature.is_empty())
        } else {
            Ok(true) // No signature to verify
        }
    }
}

impl FileMetadata {
    /// Create metadata from std::fs::Metadata
    #[cfg(unix)]
    pub fn from_std_metadata(metadata: &fs::Metadata, path: &Path) -> Result<Self> {
        use std::os::unix::fs::MetadataExt;

        let created_at = metadata
            .created()
            .unwrap_or(UNIX_EPOCH)
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let modified_at = metadata
            .modified()
            .unwrap_or(UNIX_EPOCH)
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let accessed_at = metadata
            .accessed()
            .unwrap_or(UNIX_EPOCH)
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let symlink_target = if metadata.file_type().is_symlink() {
            fs::read_link(path)
                .ok()
                .map(|p| p.to_string_lossy().to_string())
        } else {
            None
        };

        Ok(Self {
            size: metadata.len(),
            permissions: metadata.mode(),
            created_at,
            modified_at,
            accessed_at,
            uid: Some(metadata.uid()),
            gid: Some(metadata.gid()),
            device_id: Some(metadata.dev()),
            inode: Some(metadata.ino()),
            nlink: Some(metadata.nlink()),
            symlink_target,
        })
    }

    /// Create metadata from std::fs::Metadata (Windows)
    #[cfg(windows)]
    pub fn from_std_metadata(metadata: &fs::Metadata, path: &Path) -> Result<Self> {
        use std::os::windows::fs::MetadataExt;

        let created_at = metadata
            .created()
            .unwrap_or(UNIX_EPOCH)
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let modified_at = metadata
            .modified()
            .unwrap_or(UNIX_EPOCH)
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let accessed_at = metadata
            .accessed()
            .unwrap_or(UNIX_EPOCH)
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Convert Windows attributes to Unix-style permissions
        let mut permissions = 0o644; // Default file permissions
        if metadata.file_attributes() & 0x10 != 0 {
            permissions = 0o755; // Directory
        }
        if metadata.file_attributes() & 0x01 != 0 {
            permissions &= !0o200; // Read-only
        }

        let symlink_target = if metadata.file_type().is_symlink() {
            fs::read_link(path)
                .ok()
                .map(|p| p.to_string_lossy().to_string())
        } else {
            None
        };

        Ok(Self {
            size: metadata.len(),
            permissions,
            created_at,
            modified_at,
            accessed_at,
            uid: None, // Not available on Windows
            gid: None, // Not available on Windows
            device_id: None,
            inode: None,
            nlink: None,
            symlink_target,
        })
    }

    /// Create minimal metadata (just size and timestamps)
    pub fn minimal(metadata: &fs::Metadata) -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let modified_at = metadata
            .modified()
            .unwrap_or(UNIX_EPOCH)
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            size: metadata.len(),
            permissions: if metadata.is_dir() { 0o755 } else { 0o644 },
            created_at: now,
            modified_at,
            accessed_at: now,
            uid: None,
            gid: None,
            device_id: None,
            inode: None,
            nlink: None,
            symlink_target: None,
        }
    }

    /// Create empty metadata
    pub fn empty() -> Self {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        Self {
            size: 0,
            permissions: 0o644,
            created_at: now,
            modified_at: now,
            accessed_at: now,
            uid: None,
            gid: None,
            device_id: None,
            inode: None,
            nlink: None,
            symlink_target: None,
        }
    }

    /// Check if metadata has Unix-specific fields
    pub fn has_unix_metadata(&self) -> bool {
        self.uid.is_some() || self.gid.is_some() || self.inode.is_some()
    }

    /// Get permissions as octal string
    pub fn permissions_octal(&self) -> String {
        format!("{:o}", self.permissions)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    use std::fs;

    #[test]
    fn test_entry_type_matching() {
        assert!(matches!(EntryType::File, EntryType::File));
        assert!(matches!(EntryType::Directory, EntryType::Directory));
        assert!(matches!(EntryType::Symlink, EntryType::Symlink));
    }

    #[test]
    fn test_entry_flags() {
        let mut flags = EntryFlags::NONE;
        assert!(!flags.has_flag(EntryFlags::ENCRYPTED));
        
        flags.set_flag(EntryFlags::ENCRYPTED);
        assert!(flags.has_flag(EntryFlags::ENCRYPTED));
        
        flags.clear_flag(EntryFlags::ENCRYPTED);
        assert!(!flags.has_flag(EntryFlags::ENCRYPTED));
    }

    #[test]
    fn test_normalize_path() {
        assert_eq!(FileEntry::normalize_path("file.txt"), "file.txt");
        assert_eq!(FileEntry::normalize_path("/file.txt"), "file.txt");
        assert_eq!(FileEntry::normalize_path("dir\\file.txt"), "dir/file.txt");
        assert_eq!(FileEntry::normalize_path("./dir/../file.txt"), "./dir/../file.txt");
    }

    #[test]
    fn test_directory_entry() {
        let entry = FileEntry::directory("test/dir".to_string(), true);
        assert!(entry.is_directory());
        assert_eq!(entry.path, "test/dir");
        assert_eq!(entry.entry_type, EntryType::Directory);
        assert_eq!(entry.compression_method, 1); // Store
    }

    #[test]
    fn test_file_entry_from_path() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        fs::write(&test_file, b"Hello, World!").unwrap();

        let entry = FileEntry::from_path(
            &test_file,
            "test.txt".to_string(),
            true,
        ).unwrap();

        assert!(entry.is_file());
        assert_eq!(entry.path, "test.txt");
        assert_eq!(entry.uncompressed_size, 13);
        assert_eq!(entry.entry_type, EntryType::File);
    }

    #[test]
    fn test_entry_validation() {
        let mut entry = FileEntry::directory("valid/path".to_string(), false);
        assert!(entry.validate().is_ok());

        // Test empty path
        entry.path = String::new();
        assert!(entry.validate().is_err());

        // Test path traversal
        entry.path = "../../../etc/passwd".to_string();
        assert!(entry.validate().is_err());

        // Test absolute path
        entry.path = "/absolute/path".to_string();
        assert!(entry.validate().is_err());
    }

    #[test]
    fn test_entry_properties() {
        let entry = FileEntry::directory("dir/subdir/file.txt".to_string(), false);
        
        assert_eq!(entry.filename(), Some("file.txt"));
        assert_eq!(entry.extension(), Some("txt"));
        assert_eq!(entry.parent_path(), Some("dir/subdir".to_string()));
    }

    #[test]
    fn test_compression_ratio() {
        let mut entry = FileEntry::directory("test".to_string(), false);
        entry.uncompressed_size = 1000;
        entry.compressed_size = 600;
        
        assert_eq!(entry.compression_ratio(), 0.6);
        
        // Test zero uncompressed size
        entry.uncompressed_size = 0;
        assert_eq!(entry.compression_ratio(), 1.0);
    }

    #[test]
    fn test_file_metadata_minimal() {
        let temp_dir = TempDir::new().unwrap();
        let test_file = temp_dir.path().join("test.txt");
        fs::write(&test_file, b"test").unwrap();
        
        let metadata = fs::metadata(&test_file).unwrap();
        let file_metadata = FileMetadata::minimal(&metadata);
        
        assert_eq!(file_metadata.size, 4);
        assert_eq!(file_metadata.permissions, 0o644);
        assert!(!file_metadata.has_unix_metadata());
    }

    #[test]
    fn test_permissions_octal() {
        let metadata = FileMetadata {
            permissions: 0o755,
            ..FileMetadata::empty()
        };
        
        assert_eq!(metadata.permissions_octal(), "755");
    }
}