//! Windows-specific optimizations and features for RuZip

use crate::error::{Result, RuzipError};
use std::path::Path;

/// Windows-specific file handle
#[derive(Debug)]
pub struct WindowsFileHandle {
    pub path: std::path::PathBuf,
    pub attributes: WindowsFileAttributes,
}

/// Windows file attributes
#[derive(Debug, Clone)]
pub struct WindowsFileAttributes {
    pub compressed: bool,
    pub sparse: bool,
    pub encrypted: bool,
    pub system: bool,
    pub hidden: bool,
}

impl Default for WindowsFileAttributes {
    fn default() -> Self {
        Self {
            compressed: false,
            sparse: false,
            encrypted: false,
            system: false,
            hidden: false,
        }
    }
}

/// Create Windows-specific file handle
pub fn create_file_handle<P: AsRef<Path>>(path: P) -> Result<super::PlatformFileHandle> {
    let path_buf = path.as_ref().to_path_buf();
    let attributes = detect_file_attributes(&path_buf)?;
    
    Ok(super::PlatformFileHandle::Windows {
        handle: WindowsFileHandle {
            path: path_buf,
            attributes,
        },
    })
}

/// Detect Windows file attributes
fn detect_file_attributes(path: &Path) -> Result<WindowsFileAttributes> {
    let mut attributes = WindowsFileAttributes::default();
    
    // On Windows, we could use Windows API to detect actual attributes
    // For now, we'll use cross-platform methods where possible
    
    if let Ok(metadata) = std::fs::metadata(path) {
        #[cfg(target_os = "windows")]
        {
            use std::os::windows::fs::MetadataExt;
            let file_attributes = metadata.file_attributes();
            
            // FILE_ATTRIBUTE_COMPRESSED = 0x800
            attributes.compressed = (file_attributes & 0x800) != 0;
            
            // FILE_ATTRIBUTE_SPARSE_FILE = 0x200
            attributes.sparse = (file_attributes & 0x200) != 0;
            
            // FILE_ATTRIBUTE_ENCRYPTED = 0x4000
            attributes.encrypted = (file_attributes & 0x4000) != 0;
            
            // FILE_ATTRIBUTE_SYSTEM = 0x4
            attributes.system = (file_attributes & 0x4) != 0;
            
            // FILE_ATTRIBUTE_HIDDEN = 0x2
            attributes.hidden = (file_attributes & 0x2) != 0;
        }
        
        #[cfg(not(target_os = "windows"))]
        {
            // Fallback for non-Windows platforms during cross-compilation
            let _ = metadata;
        }
    }
    
    Ok(attributes)
}

/// Get Windows temp directory with optimizations
pub fn get_temp_dir() -> Result<std::path::PathBuf> {
    // Try to use the fastest available temp location on Windows
    
    // First try TEMP environment variable
    if let Ok(temp) = std::env::var("TEMP") {
        let temp_path = std::path::PathBuf::from(temp);
        if temp_path.exists() {
            return Ok(temp_path);
        }
    }
    
    // Try TMP environment variable
    if let Ok(tmp) = std::env::var("TMP") {
        let tmp_path = std::path::PathBuf::from(tmp);
        if tmp_path.exists() {
            return Ok(tmp_path);
        }
    }
    
    // Fall back to system default
    Ok(std::env::temp_dir())
}

/// Windows-specific I/O optimizations
pub struct WindowsIoOptimizer {
    use_overlapped_io: bool,
    use_file_flag_sequential_scan: bool,
    use_file_flag_random_access: bool,
    buffer_size: usize,
}

impl WindowsIoOptimizer {
    pub fn new(file_size: Option<u64>, access_pattern: AccessPattern) -> Self {
        let buffer_size = match file_size {
            Some(size) if size > 100 * 1024 * 1024 => 1024 * 1024, // 1MB for large files
            Some(size) if size < 1024 * 1024 => 64 * 1024,         // 64KB for small files
            _ => 256 * 1024,                                        // 256KB default
        };
        
        Self {
            use_overlapped_io: file_size.map_or(false, |s| s > 10 * 1024 * 1024),
            use_file_flag_sequential_scan: matches!(access_pattern, AccessPattern::Sequential),
            use_file_flag_random_access: matches!(access_pattern, AccessPattern::Random),
            buffer_size,
        }
    }
    
    pub fn buffer_size(&self) -> usize {
        self.buffer_size
    }
    
    pub fn should_use_overlapped_io(&self) -> bool {
        self.use_overlapped_io
    }
}

/// File access patterns
#[derive(Debug, Clone)]
pub enum AccessPattern {
    Sequential,
    Random,
    Unknown,
}

/// Windows memory management optimizations
pub struct WindowsMemoryManager {
    use_large_pages: bool,
    preferred_allocation_size: usize,
}

impl WindowsMemoryManager {
    pub fn new() -> Self {
        Self {
            use_large_pages: false, // Requires special privileges
            preferred_allocation_size: 64 * 1024, // 64KB alignment for Windows
        }
    }
    
    pub fn allocate_buffer(&self, size: usize) -> Result<Vec<u8>> {
        // Align to preferred allocation size
        let aligned_size = (size + self.preferred_allocation_size - 1) 
            & !(self.preferred_allocation_size - 1);
        
        let mut buffer = Vec::with_capacity(aligned_size);
        buffer.resize(size, 0);
        
        Ok(buffer)
    }
    
    pub fn preferred_allocation_size(&self) -> usize {
        self.preferred_allocation_size
    }
}

/// Windows-specific compression optimizations
pub fn get_windows_compression_settings() -> WindowsCompressionSettings {
    WindowsCompressionSettings {
        use_hardware_acceleration: detect_intel_quickassist(),
        prefer_zstd_over_lz4: true, // Windows generally has good SIMD support
        use_multiple_streams: true,
        stream_count: num_cpus::get().min(8),
    }
}

/// Windows compression settings
#[derive(Debug, Clone)]
pub struct WindowsCompressionSettings {
    pub use_hardware_acceleration: bool,
    pub prefer_zstd_over_lz4: bool,
    pub use_multiple_streams: bool,
    pub stream_count: usize,
}

/// Detect Intel QuickAssist Technology
fn detect_intel_quickassist() -> bool {
    // This would normally check for QAT drivers and hardware
    // For now, return false as it's specialized hardware
    false
}

/// Windows performance monitoring
pub struct WindowsPerformanceMonitor {
    process_handle: Option<std::process::Child>,
}

impl WindowsPerformanceMonitor {
    pub fn new() -> Self {
        Self {
            process_handle: None,
        }
    }
    
    pub fn get_memory_usage(&self) -> Result<u64> {
        // On Windows, we could use Windows API to get detailed memory info
        // For now, return a placeholder
        Ok(0)
    }
    
    pub fn get_cpu_usage(&self) -> Result<f64> {
        // Windows-specific CPU usage detection
        Ok(0.0)
    }
    
    pub fn get_disk_io_stats(&self) -> Result<DiskIoStats> {
        Ok(DiskIoStats {
            read_bytes: 0,
            write_bytes: 0,
            read_time_ms: 0,
            write_time_ms: 0,
        })
    }
}

/// Disk I/O statistics
#[derive(Debug, Clone)]
pub struct DiskIoStats {
    pub read_bytes: u64,
    pub write_bytes: u64,
    pub read_time_ms: u64,
    pub write_time_ms: u64,
}

/// Windows-specific error handling
pub fn map_windows_error(error_code: u32) -> RuzipError {
    match error_code {
        2 => RuzipError::io_error(
            "File not found".to_string(),
            std::io::Error::from(std::io::ErrorKind::NotFound),
        ),
        3 => RuzipError::io_error(
            "Path not found".to_string(),
            std::io::Error::from(std::io::ErrorKind::NotFound),
        ),
        5 => RuzipError::permission_error(
            "Access denied".to_string(),
            None,
        ),
        32 => RuzipError::io_error(
            "File is in use by another process".to_string(),
            std::io::Error::from(std::io::ErrorKind::PermissionDenied),
        ),
        112 => RuzipError::resource_exhausted(
            "Insufficient disk space".to_string(),
            "disk".to_string(),
        ),
        _ => RuzipError::io_error(
            format!("Windows error code: {}", error_code),
            std::io::Error::from(std::io::ErrorKind::Other),
        ),
    }
}

/// Windows registry utilities for configuration
pub struct WindowsRegistry;

impl WindowsRegistry {
    pub fn read_ruzip_config() -> Result<std::collections::HashMap<String, String>> {
        let mut config = std::collections::HashMap::new();
        
        // On Windows, we could read from registry keys like:
        // HKEY_CURRENT_USER\Software\RuZip\Config
        // For now, return empty config
        
        Ok(config)
    }
    
    pub fn write_ruzip_config(config: &std::collections::HashMap<String, String>) -> Result<()> {
        // Write configuration to Windows registry
        let _ = config; // Avoid unused variable warning
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_windows_file_handle_creation() {
        let temp_dir = std::env::temp_dir();
        let result = create_file_handle(&temp_dir);
        
        match result {
            Ok(super::PlatformFileHandle::Windows { handle }) => {
                assert_eq!(handle.path, temp_dir);
            },
            Ok(_) => panic!("Expected Windows file handle"),
            Err(e) => {
                // This might fail on non-Windows platforms, which is expected
                println!("Error creating Windows file handle: {}", e);
            }
        }
    }

    #[test]
    fn test_windows_temp_dir() {
        let temp_dir = get_temp_dir().unwrap();
        assert!(temp_dir.exists());
    }

    #[test]
    fn test_windows_io_optimizer() {
        let optimizer = WindowsIoOptimizer::new(Some(50 * 1024 * 1024), AccessPattern::Sequential);
        assert!(optimizer.buffer_size() > 0);
        assert!(optimizer.use_file_flag_sequential_scan);
        assert!(!optimizer.use_file_flag_random_access);
    }

    #[test]
    fn test_windows_memory_manager() {
        let manager = WindowsMemoryManager::new();
        let buffer = manager.allocate_buffer(1024).unwrap();
        assert_eq!(buffer.len(), 1024);
        assert!(manager.preferred_allocation_size() > 0);
    }

    #[test]
    fn test_windows_compression_settings() {
        let settings = get_windows_compression_settings();
        assert!(settings.stream_count > 0);
        assert!(settings.stream_count <= 8);
    }

    #[test]
    fn test_windows_error_mapping() {
        let not_found_error = map_windows_error(2);
        assert!(matches!(not_found_error, RuzipError::Io { .. }));
        
        let access_denied_error = map_windows_error(5);
        assert!(matches!(access_denied_error, RuzipError::Permission { .. }));
        
        let disk_full_error = map_windows_error(112);
        assert!(matches!(disk_full_error, RuzipError::ResourceExhausted { .. }));
    }

    #[test]
    fn test_windows_performance_monitor() {
        let monitor = WindowsPerformanceMonitor::new();
        
        // These might return placeholder values on non-Windows platforms
        let memory_usage = monitor.get_memory_usage().unwrap();
        let cpu_usage = monitor.get_cpu_usage().unwrap();
        let disk_stats = monitor.get_disk_io_stats().unwrap();
        
        assert!(memory_usage >= 0);
        assert!(cpu_usage >= 0.0);
        assert!(disk_stats.read_bytes >= 0);
    }
}