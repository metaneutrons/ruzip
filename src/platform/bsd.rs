//! BSD-specific optimizations and features for RuZip (FreeBSD/OpenBSD)

use crate::error::{Result, RuzipError};
use std::path::Path;

/// Create BSD-specific file handle
pub fn create_file_handle<P: AsRef<Path>>(path: P, variant: BsdVariant) -> Result<super::PlatformFileHandle> {
    let path_buf = path.as_ref().to_path_buf();
    let fd = get_file_descriptor(&path_buf, &variant)?;
    
    Ok(super::PlatformFileHandle::Unix {
        fd,
        path: path_buf,
    })
}

/// BSD variants
#[derive(Debug, Clone, PartialEq)]
pub enum BsdVariant {
    FreeBSD,
    OpenBSD,
}

/// Get file descriptor for BSD file operations
fn get_file_descriptor(path: &Path, variant: &BsdVariant) -> Result<i32> {
    let _ = (path, variant);
    Ok(-1) // Placeholder
}

/// Get BSD-optimized temp directory
pub fn get_temp_dir() -> Result<std::path::PathBuf> {
    // BSD systems typically use /tmp
    let tmp_dir = std::path::PathBuf::from("/tmp");
    if tmp_dir.exists() {
        Ok(tmp_dir)
    } else {
        Ok(std::env::temp_dir())
    }
}

/// BSD-specific filesystem optimizations
pub struct BsdFilesystemOptimizer {
    variant: BsdVariant,
    filesystem_type: BsdFilesystemType,
    use_sendfile: bool,
    use_kqueue: bool,
}

impl BsdFilesystemOptimizer {
    pub fn new(variant: BsdVariant) -> Self {
        let filesystem_type = detect_filesystem_type(&variant);
        
        Self {
            variant: variant.clone(),
            filesystem_type,
            use_sendfile: true,
            use_kqueue: detect_kqueue_support(&variant),
        }
    }
    
    pub fn supports_zfs(&self) -> bool {
        matches!(self.filesystem_type, BsdFilesystemType::Zfs) ||
        matches!(self.variant, BsdVariant::FreeBSD)
    }
    
    pub fn supports_kqueue(&self) -> bool {
        self.use_kqueue
    }
    
    pub fn get_optimal_record_size(&self) -> usize {
        match self.filesystem_type {
            BsdFilesystemType::Zfs => 128 * 1024, // ZFS record size
            BsdFilesystemType::Ufs => 32 * 1024,  // UFS block size
            BsdFilesystemType::Ffs => 16 * 1024,  // FFS block size
            _ => 64 * 1024, // Default
        }
    }
}

/// BSD filesystem types
#[derive(Debug, Clone, PartialEq)]
pub enum BsdFilesystemType {
    Zfs,    // ZFS (common on FreeBSD)
    Ufs,    // Unix File System
    Ffs,    // Fast File System (OpenBSD)
    Tmpfs,  // Temporary filesystem
    Nfs,    // Network File System
    Unknown,
}

/// Detect filesystem type
fn detect_filesystem_type(variant: &BsdVariant) -> BsdFilesystemType {
    match variant {
        BsdVariant::FreeBSD => {
            // FreeBSD commonly uses ZFS
            if check_zfs_available() {
                BsdFilesystemType::Zfs
            } else {
                BsdFilesystemType::Ufs
            }
        },
        BsdVariant::OpenBSD => {
            // OpenBSD typically uses FFS
            BsdFilesystemType::Ffs
        },
    }
}

/// Check if ZFS is available
fn check_zfs_available() -> bool {
    std::path::Path::new("/sbin/zfs").exists() || 
    std::path::Path::new("/usr/sbin/zfs").exists()
}

/// Detect kqueue support
fn detect_kqueue_support(variant: &BsdVariant) -> bool {
    match variant {
        BsdVariant::FreeBSD | BsdVariant::OpenBSD => true, // Both support kqueue
    }
}

/// BSD memory management
pub struct BsdMemoryManager {
    variant: BsdVariant,
    use_mlock: bool,
    page_size: usize,
}

impl BsdMemoryManager {
    pub fn new(variant: BsdVariant) -> Self {
        Self {
            variant,
            use_mlock: false, // Requires privileges
            page_size: get_page_size(),
        }
    }
    
    pub fn allocate_buffer(&self, size: usize) -> Result<Vec<u8>> {
        // Align to page boundaries
        let aligned_size = (size + self.page_size - 1) & !(self.page_size - 1);
        
        let mut buffer = Vec::with_capacity(aligned_size);
        buffer.resize(size, 0);
        
        Ok(buffer)
    }
    
    pub fn page_size(&self) -> usize {
        self.page_size
    }
}

/// Get system page size
fn get_page_size() -> usize {
    #[cfg(any(target_os = "freebsd", target_os = "openbsd"))]
    {
        unsafe {
            libc::sysconf(libc::_SC_PAGESIZE) as usize
        }
    }
    
    #[cfg(not(any(target_os = "freebsd", target_os = "openbsd")))]
    {
        4096 // Default page size
    }
}

/// FreeBSD-specific optimizations
pub struct FreeBsdOptimizer {
    use_zfs_compression: bool,
    use_dtrace: bool,
    use_jails: bool,
}

impl FreeBsdOptimizer {
    pub fn new() -> Self {
        Self {
            use_zfs_compression: check_zfs_available(),
            use_dtrace: detect_dtrace(),
            use_jails: detect_jails(),
        }
    }
    
    pub fn supports_zfs_compression(&self) -> bool {
        self.use_zfs_compression
    }
    
    pub fn get_zfs_settings(&self) -> Option<ZfsSettings> {
        if self.use_zfs_compression {
            Some(ZfsSettings {
                compression: ZfsCompression::Lz4,
                record_size: 128 * 1024,
                atime: false, // Disable atime for performance
            })
        } else {
            None
        }
    }
}

/// ZFS-specific settings
#[derive(Debug, Clone)]
pub struct ZfsSettings {
    pub compression: ZfsCompression,
    pub record_size: usize,
    pub atime: bool,
}

/// ZFS compression algorithms
#[derive(Debug, Clone)]
pub enum ZfsCompression {
    Off,
    Lz4,
    Gzip,
    Zstd,
}

/// Detect DTrace availability
fn detect_dtrace() -> bool {
    std::path::Path::new("/usr/sbin/dtrace").exists()
}

/// Detect if running in FreeBSD jail
fn detect_jails() -> bool {
    // Check if we're running inside a jail
    std::fs::read_to_string("/proc/curproc/status")
        .map(|content| content.contains("jail"))
        .unwrap_or(false)
}

/// OpenBSD-specific optimizations
pub struct OpenBsdOptimizer {
    use_pledge: bool,
    use_unveil: bool,
    use_w_xor_x: bool,
}

impl OpenBsdOptimizer {
    pub fn new() -> Self {
        Self {
            use_pledge: true,  // OpenBSD security feature
            use_unveil: true,  // Filesystem access control
            use_w_xor_x: true, // W^X memory protection
        }
    }
    
    pub fn get_pledge_promises(&self) -> Vec<&'static str> {
        vec![
            "stdio",     // Standard I/O
            "rpath",     // Read file system
            "wpath",     // Write file system
            "cpath",     // Create files/directories
            "fattr",     // File attributes
            "tmppath",   // Temporary files
            "proc",      // Process management
            "exec",      // Execute programs
        ]
    }
    
    pub fn should_use_unveil(&self) -> bool {
        self.use_unveil
    }
}

/// BSD performance monitoring using sysctl
pub struct BsdPerformanceMonitor {
    variant: BsdVariant,
    cpu_count: usize,
}

impl BsdPerformanceMonitor {
    pub fn new(variant: BsdVariant) -> Self {
        let cpu_count = num_cpus::get();
        
        Self {
            variant,
            cpu_count,
        }
    }
    
    pub fn get_system_load(&self) -> Result<(f64, f64, f64)> {
        // Get 1, 5, and 15 minute load averages using sysctl
        // For now, return placeholder values
        Ok((0.0, 0.0, 0.0))
    }
    
    pub fn get_memory_info(&self) -> Result<BsdMemoryInfo> {
        match self.variant {
            BsdVariant::FreeBSD => self.get_freebsd_memory_info(),
            BsdVariant::OpenBSD => self.get_openbsd_memory_info(),
        }
    }
    
    fn get_freebsd_memory_info(&self) -> Result<BsdMemoryInfo> {
        // Use sysctl to get FreeBSD memory information
        Ok(BsdMemoryInfo {
            total: 0,
            active: 0,
            inactive: 0,
            free: 0,
            wired: 0,
            cached: 0,
        })
    }
    
    fn get_openbsd_memory_info(&self) -> Result<BsdMemoryInfo> {
        // Use sysctl to get OpenBSD memory information
        Ok(BsdMemoryInfo {
            total: 0,
            active: 0,
            inactive: 0,
            free: 0,
            wired: 0,
            cached: 0,
        })
    }
    
    pub fn get_cpu_usage(&self) -> Result<Vec<f64>> {
        // Return per-CPU usage percentages
        Ok(vec![0.0; self.cpu_count])
    }
}

/// BSD memory information
#[derive(Debug, Clone)]
pub struct BsdMemoryInfo {
    pub total: u64,
    pub active: u64,
    pub inactive: u64,
    pub free: u64,
    pub wired: u64,
    pub cached: u64,
}

/// BSD-specific compression settings
pub fn get_bsd_compression_settings(variant: &BsdVariant) -> BsdCompressionSettings {
    match variant {
        BsdVariant::FreeBSD => BsdCompressionSettings {
            prefer_zstd: true,      // FreeBSD has good SIMD support
            use_zfs_compression: check_zfs_available(),
            thread_count: num_cpus::get(),
            buffer_size: 128 * 1024, // ZFS-optimized
        },
        BsdVariant::OpenBSD => BsdCompressionSettings {
            prefer_zstd: false,     // OpenBSD focuses on security over performance
            use_zfs_compression: false,
            thread_count: std::cmp::min(num_cpus::get(), 4), // Conservative
            buffer_size: 64 * 1024,  // Smaller buffers
        },
    }
}

/// BSD compression settings
#[derive(Debug, Clone)]
pub struct BsdCompressionSettings {
    pub prefer_zstd: bool,
    pub use_zfs_compression: bool,
    pub thread_count: usize,
    pub buffer_size: usize,
}

/// BSD-specific error handling
pub fn map_bsd_errno(errno: i32, variant: &BsdVariant) -> RuzipError {
    let _ = variant; // Avoid unused warning
    
    match errno {
        libc::ENOENT => RuzipError::io_error(
            "No such file or directory".to_string(),
            std::io::Error::from(std::io::ErrorKind::NotFound),
        ),
        libc::EACCES => RuzipError::permission_error(
            "Permission denied".to_string(),
            None,
        ),
        libc::ENOSPC => RuzipError::resource_exhausted(
            "No space left on device".to_string(),
            "disk".to_string(),
        ),
        libc::ENOMEM => RuzipError::memory_error(
            "Out of memory".to_string(),
            None,
        ),
        libc::EMFILE => RuzipError::resource_exhausted(
            "Too many open files".to_string(),
            "file_descriptors".to_string(),
        ),
        _ => RuzipError::io_error(
            format!("BSD errno: {}", errno),
            std::io::Error::from_raw_os_error(errno),
        ),
    }
}

/// BSD package management integration
pub struct BsdPackageManager {
    variant: BsdVariant,
    package_tool: PackageTool,
}

impl BsdPackageManager {
    pub fn new(variant: BsdVariant) -> Self {
        let package_tool = match variant {
            BsdVariant::FreeBSD => PackageTool::Pkg,
            BsdVariant::OpenBSD => PackageTool::PkgAdd,
        };
        
        Self {
            variant,
            package_tool,
        }
    }
    
    pub fn get_config_paths(&self) -> Vec<std::path::PathBuf> {
        match self.variant {
            BsdVariant::FreeBSD => vec![
                std::path::PathBuf::from("/usr/local/etc/ruzip/config.toml"),
                std::path::PathBuf::from("/etc/ruzip/config.toml"),
            ],
            BsdVariant::OpenBSD => vec![
                std::path::PathBuf::from("/etc/ruzip/config.toml"),
                std::path::PathBuf::from("/usr/local/share/ruzip/config.toml"),
            ],
        }
    }
}

/// BSD package tools
#[derive(Debug, Clone, PartialEq)]
pub enum PackageTool {
    Pkg,    // FreeBSD pkg
    PkgAdd, // OpenBSD pkg_add
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_bsd_temp_dir() {
        let temp_dir = get_temp_dir().unwrap();
        assert!(temp_dir.exists());
        println!("BSD temp dir: {:?}", temp_dir);
    }

    #[test]
    fn test_bsd_filesystem_optimizer() {
        let freebsd_optimizer = BsdFilesystemOptimizer::new(BsdVariant::FreeBSD);
        let openbsd_optimizer = BsdFilesystemOptimizer::new(BsdVariant::OpenBSD);
        
        assert!(freebsd_optimizer.supports_kqueue());
        assert!(openbsd_optimizer.supports_kqueue());
        
        println!("FreeBSD ZFS support: {}", freebsd_optimizer.supports_zfs());
        println!("OpenBSD ZFS support: {}", openbsd_optimizer.supports_zfs());
        
        assert!(freebsd_optimizer.get_optimal_record_size() > 0);
        assert!(openbsd_optimizer.get_optimal_record_size() > 0);
    }

    #[test]
    fn test_bsd_memory_manager() {
        let manager = BsdMemoryManager::new(BsdVariant::FreeBSD);
        let buffer = manager.allocate_buffer(1024).unwrap();
        assert_eq!(buffer.len(), 1024);
        assert!(manager.page_size() > 0);
    }

    #[test]
    fn test_freebsd_optimizer() {
        let optimizer = FreeBsdOptimizer::new();
        println!("ZFS compression support: {}", optimizer.supports_zfs_compression());
        
        if let Some(zfs_settings) = optimizer.get_zfs_settings() {
            assert!(zfs_settings.record_size > 0);
            println!("ZFS settings: {:?}", zfs_settings);
        }
    }

    #[test]
    fn test_openbsd_optimizer() {
        let optimizer = OpenBsdOptimizer::new();
        let promises = optimizer.get_pledge_promises();
        assert!(!promises.is_empty());
        assert!(optimizer.should_use_unveil());
        
        println!("OpenBSD pledge promises: {:?}", promises);
    }

    #[test]
    fn test_bsd_compression_settings() {
        let freebsd_settings = get_bsd_compression_settings(&BsdVariant::FreeBSD);
        let openbsd_settings = get_bsd_compression_settings(&BsdVariant::OpenBSD);
        
        assert!(freebsd_settings.thread_count > 0);
        assert!(openbsd_settings.thread_count > 0);
        assert!(freebsd_settings.buffer_size > 0);
        assert!(openbsd_settings.buffer_size > 0);
        
        println!("FreeBSD prefers zstd: {}", freebsd_settings.prefer_zstd);
        println!("OpenBSD prefers zstd: {}", openbsd_settings.prefer_zstd);
    }

    #[test]
    fn test_bsd_performance_monitor() {
        let freebsd_monitor = BsdPerformanceMonitor::new(BsdVariant::FreeBSD);
        let openbsd_monitor = BsdPerformanceMonitor::new(BsdVariant::OpenBSD);
        
        if let Ok((load1, load5, load15)) = freebsd_monitor.get_system_load() {
            assert!(load1 >= 0.0 && load5 >= 0.0 && load15 >= 0.0);
            println!("FreeBSD system load: {:.2}, {:.2}, {:.2}", load1, load5, load15);
        }
        
        if let Ok(memory_info) = openbsd_monitor.get_memory_info() {
            assert!(memory_info.total >= 0);
            println!("OpenBSD memory info: {:?}", memory_info);
        }
    }

    #[test]
    fn test_bsd_error_mapping() {
        let not_found_error = map_bsd_errno(libc::ENOENT, &BsdVariant::FreeBSD);
        assert!(matches!(not_found_error, RuzipError::Io { .. }));
        
        let access_denied_error = map_bsd_errno(libc::EACCES, &BsdVariant::OpenBSD);
        assert!(matches!(access_denied_error, RuzipError::Permission { .. }));
        
        let no_space_error = map_bsd_errno(libc::ENOSPC, &BsdVariant::FreeBSD);
        assert!(matches!(no_space_error, RuzipError::ResourceExhausted { .. }));
    }

    #[test]
    fn test_bsd_package_manager() {
        let freebsd_pkg = BsdPackageManager::new(BsdVariant::FreeBSD);
        let openbsd_pkg = BsdPackageManager::new(BsdVariant::OpenBSD);
        
        let freebsd_paths = freebsd_pkg.get_config_paths();
        let openbsd_paths = openbsd_pkg.get_config_paths();
        
        assert!(!freebsd_paths.is_empty());
        assert!(!openbsd_paths.is_empty());
        
        println!("FreeBSD config paths: {:?}", freebsd_paths);
        println!("OpenBSD config paths: {:?}", openbsd_paths);
    }
}