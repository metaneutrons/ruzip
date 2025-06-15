//! Linux-specific optimizations and features for RuZip

use crate::error::{Result, RuzipError};
use std::path::Path;

/// Create Linux-specific file handle
pub fn create_file_handle<P: AsRef<Path>>(path: P) -> Result<super::PlatformFileHandle> {
    let path_buf = path.as_ref().to_path_buf();
    let fd = get_file_descriptor(&path_buf)?;
    
    Ok(super::PlatformFileHandle::Unix {
        fd,
        path: path_buf,
    })
}

/// Get file descriptor for Linux file operations
fn get_file_descriptor(path: &Path) -> Result<i32> {
    let _ = path;
    Ok(-1) // Placeholder
}

/// Get Linux-optimized temp directory
pub fn get_temp_dir() -> Result<std::path::PathBuf> {
    // Linux typically uses /tmp, but check for tmpfs
    let tmpfs_paths = ["/dev/shm", "/tmp", "/var/tmp"];
    
    for path in &tmpfs_paths {
        let tmp_path = std::path::PathBuf::from(path);
        if tmp_path.exists() && is_tmpfs(path).unwrap_or(false) {
            return Ok(tmp_path);
        }
    }
    
    Ok(std::env::temp_dir())
}

/// Check if a path is mounted as tmpfs (memory filesystem)
fn is_tmpfs(path: &str) -> Result<bool> {
    // Read /proc/mounts to check if path is tmpfs
    if let Ok(mounts) = std::fs::read_to_string("/proc/mounts") {
        for line in mounts.lines() {
            if line.contains(path) && line.contains("tmpfs") {
                return Ok(true);
            }
        }
    }
    Ok(false)
}

/// Linux-specific I/O optimizations
pub struct LinuxIoOptimizer {
    use_io_uring: bool,
    use_aio: bool,
    use_splice: bool,
    use_sendfile: bool,
    preferred_block_size: usize,
}

impl LinuxIoOptimizer {
    pub fn new() -> Self {
        Self {
            use_io_uring: detect_io_uring(),
            use_aio: true,
            use_splice: true,
            use_sendfile: true,
            preferred_block_size: detect_optimal_block_size(),
        }
    }
    
    pub fn supports_io_uring(&self) -> bool {
        self.use_io_uring
    }
    
    pub fn supports_splice(&self) -> bool {
        self.use_splice
    }
    
    pub fn preferred_block_size(&self) -> usize {
        self.preferred_block_size
    }
}

/// Detect if io_uring is available
fn detect_io_uring() -> bool {
    // Check if io_uring is available (Linux 5.1+)
    std::path::Path::new("/proc/sys/kernel/io_uring_disabled").exists()
}

/// Detect optimal block size for the system
fn detect_optimal_block_size() -> usize {
    // Try to read from /sys/block/*/queue/optimal_io_size
    if let Ok(entries) = std::fs::read_dir("/sys/block") {
        for entry in entries.flatten() {
            let optimal_io_path = entry.path().join("queue/optimal_io_size");
            if let Ok(size_str) = std::fs::read_to_string(&optimal_io_path) {
                if let Ok(size) = size_str.trim().parse::<usize>() {
                    if size > 0 {
                        return size;
                    }
                }
            }
        }
    }
    
    // Default to 64KB if detection fails
    64 * 1024
}

/// Linux memory management with huge pages support
pub struct LinuxMemoryManager {
    use_huge_pages: bool,
    huge_page_size: usize,
    use_madvise: bool,
}

impl LinuxMemoryManager {
    pub fn new() -> Self {
        Self {
            use_huge_pages: detect_huge_pages(),
            huge_page_size: get_huge_page_size(),
            use_madvise: true,
        }
    }
    
    pub fn allocate_buffer(&self, size: usize) -> Result<Vec<u8>> {
        let mut buffer = Vec::with_capacity(size);
        buffer.resize(size, 0);
        
        // Use madvise hints for better performance
        if self.use_madvise && size > 1024 * 1024 {
            self.apply_madvise_hints(&buffer)?;
        }
        
        Ok(buffer)
    }
    
    fn apply_madvise_hints(&self, buffer: &[u8]) -> Result<()> {
        let _ = buffer;
        // Apply madvise() hints like MADV_SEQUENTIAL, MADV_WILLNEED, etc.
        Ok(())
    }
    
    pub fn supports_huge_pages(&self) -> bool {
        self.use_huge_pages
    }
}

/// Detect if huge pages are available
fn detect_huge_pages() -> bool {
    std::path::Path::new("/proc/meminfo").exists() &&
    std::fs::read_to_string("/proc/meminfo")
        .map(|content| content.contains("HugePages_Total"))
        .unwrap_or(false)
}

/// Get huge page size from /proc/meminfo
fn get_huge_page_size() -> usize {
    if let Ok(meminfo) = std::fs::read_to_string("/proc/meminfo") {
        for line in meminfo.lines() {
            if line.starts_with("Hugepagesize:") {
                if let Some(size_str) = line.split_whitespace().nth(1) {
                    if let Ok(size_kb) = size_str.parse::<usize>() {
                        return size_kb * 1024; // Convert KB to bytes
                    }
                }
            }
        }
    }
    
    2 * 1024 * 1024 // Default 2MB huge pages
}

/// Linux distribution-specific optimizations
pub struct LinuxDistributionOptimizer {
    distribution: super::LinuxDistribution,
    package_manager: PackageManager,
    init_system: InitSystem,
}

impl LinuxDistributionOptimizer {
    pub fn new(distribution: super::LinuxDistribution) -> Self {
        let package_manager = detect_package_manager(&distribution);
        let init_system = detect_init_system();
        
        Self {
            distribution,
            package_manager,
            init_system,
        }
    }
    
    pub fn get_config_paths(&self) -> Vec<std::path::PathBuf> {
        match self.distribution {
            super::LinuxDistribution::Ubuntu | super::LinuxDistribution::Debian => {
                vec![
                    std::path::PathBuf::from("/etc/ruzip/config.toml"),
                    std::path::PathBuf::from("/usr/share/ruzip/config.toml"),
                ]
            },
            super::LinuxDistribution::RedHat | super::LinuxDistribution::CentOS | super::LinuxDistribution::Fedora => {
                vec![
                    std::path::PathBuf::from("/etc/ruzip/config.toml"),
                    std::path::PathBuf::from("/usr/share/ruzip/config.toml"),
                ]
            },
            super::LinuxDistribution::ArchLinux => {
                vec![
                    std::path::PathBuf::from("/etc/ruzip/config.toml"),
                    std::path::PathBuf::from("/usr/share/ruzip/config.toml"),
                ]
            },
            super::LinuxDistribution::Alpine => {
                vec![
                    std::path::PathBuf::from("/etc/ruzip/config.toml"),
                ]
            },
            _ => {
                vec![
                    std::path::PathBuf::from("/etc/ruzip/config.toml"),
                ]
            }
        }
    }
    
    pub fn get_preferred_compression(&self) -> &'static str {
        match self.distribution {
            super::LinuxDistribution::Alpine => "lz4", // Alpine prefers speed
            super::LinuxDistribution::ArchLinux => "zstd", // Arch users often prefer latest tech
            _ => "zstd", // Default to zstd for most distributions
        }
    }
}

/// Linux package managers
#[derive(Debug, Clone, PartialEq)]
pub enum PackageManager {
    Apt,     // Debian/Ubuntu
    Yum,     // RHEL/CentOS
    Dnf,     // Fedora
    Pacman,  // Arch Linux
    Apk,     // Alpine Linux
    Zypper,  // openSUSE
    Unknown,
}

/// Linux init systems
#[derive(Debug, Clone, PartialEq)]
pub enum InitSystem {
    Systemd,
    OpenRC,
    SysVInit,
    Upstart,
    Unknown,
}

/// Detect package manager for the distribution
fn detect_package_manager(distribution: &super::LinuxDistribution) -> PackageManager {
    match distribution {
        super::LinuxDistribution::Ubuntu | super::LinuxDistribution::Debian => PackageManager::Apt,
        super::LinuxDistribution::RedHat | super::LinuxDistribution::CentOS => PackageManager::Yum,
        super::LinuxDistribution::Fedora => PackageManager::Dnf,
        super::LinuxDistribution::ArchLinux => PackageManager::Pacman,
        super::LinuxDistribution::Alpine => PackageManager::Apk,
        super::LinuxDistribution::SUSE => PackageManager::Zypper,
        _ => PackageManager::Unknown,
    }
}

/// Detect init system
fn detect_init_system() -> InitSystem {
    if std::path::Path::new("/run/systemd/system").exists() {
        InitSystem::Systemd
    } else if std::path::Path::new("/sbin/openrc").exists() {
        InitSystem::OpenRC
    } else if std::path::Path::new("/sbin/upstart").exists() {
        InitSystem::Upstart
    } else if std::path::Path::new("/sbin/init").exists() {
        InitSystem::SysVInit
    } else {
        InitSystem::Unknown
    }
}

/// Linux performance monitoring using /proc and /sys
pub struct LinuxPerformanceMonitor {
    proc_stat: Option<ProcStat>,
    proc_meminfo: Option<ProcMeminfo>,
}

#[derive(Debug, Clone)]
pub struct ProcStat {
    pub user: u64,
    pub nice: u64,
    pub system: u64,
    pub idle: u64,
    pub iowait: u64,
}

#[derive(Debug, Clone)]
pub struct ProcMeminfo {
    pub total: u64,
    pub free: u64,
    pub available: u64,
    pub buffers: u64,
    pub cached: u64,
}

impl LinuxPerformanceMonitor {
    pub fn new() -> Self {
        Self {
            proc_stat: None,
            proc_meminfo: None,
        }
    }
    
    pub fn update(&mut self) -> Result<()> {
        self.proc_stat = Some(self.read_proc_stat()?);
        self.proc_meminfo = Some(self.read_proc_meminfo()?);
        Ok(())
    }
    
    fn read_proc_stat(&self) -> Result<ProcStat> {
        let stat_content = std::fs::read_to_string("/proc/stat")
            .map_err(|e| RuzipError::io_error("Failed to read /proc/stat", e))?;
        
        if let Some(cpu_line) = stat_content.lines().next() {
            let parts: Vec<&str> = cpu_line.split_whitespace().collect();
            if parts.len() >= 6 {
                return Ok(ProcStat {
                    user: parts[1].parse().unwrap_or(0),
                    nice: parts[2].parse().unwrap_or(0),
                    system: parts[3].parse().unwrap_or(0),
                    idle: parts[4].parse().unwrap_or(0),
                    iowait: parts[5].parse().unwrap_or(0),
                });
            }
        }
        
        Err(RuzipError::internal_error("Failed to parse /proc/stat", Some("linux_perf_monitor")))
    }
    
    fn read_proc_meminfo(&self) -> Result<ProcMeminfo> {
        let meminfo_content = std::fs::read_to_string("/proc/meminfo")
            .map_err(|e| RuzipError::io_error("Failed to read /proc/meminfo", e))?;
        
        let mut meminfo = ProcMeminfo {
            total: 0,
            free: 0,
            available: 0,
            buffers: 0,
            cached: 0,
        };
        
        for line in meminfo_content.lines() {
            if let Some((key, value)) = line.split_once(':') {
                let value_kb: u64 = value.trim()
                    .split_whitespace()
                    .next()
                    .and_then(|v| v.parse().ok())
                    .unwrap_or(0);
                let value_bytes = value_kb * 1024;
                
                match key.trim() {
                    "MemTotal" => meminfo.total = value_bytes,
                    "MemFree" => meminfo.free = value_bytes,
                    "MemAvailable" => meminfo.available = value_bytes,
                    "Buffers" => meminfo.buffers = value_bytes,
                    "Cached" => meminfo.cached = value_bytes,
                    _ => {}
                }
            }
        }
        
        Ok(meminfo)
    }
    
    pub fn get_cpu_usage_percent(&self) -> f64 {
        if let Some(stat) = &self.proc_stat {
            let total = stat.user + stat.nice + stat.system + stat.idle + stat.iowait;
            if total > 0 {
                let active = stat.user + stat.nice + stat.system;
                return (active as f64 / total as f64) * 100.0;
            }
        }
        0.0
    }
    
    pub fn get_memory_usage_percent(&self) -> f64 {
        if let Some(meminfo) = &self.proc_meminfo {
            if meminfo.total > 0 {
                let used = meminfo.total - meminfo.available;
                return (used as f64 / meminfo.total as f64) * 100.0;
            }
        }
        0.0
    }
    
    pub fn get_iowait_percent(&self) -> f64 {
        if let Some(stat) = &self.proc_stat {
            let total = stat.user + stat.nice + stat.system + stat.idle + stat.iowait;
            if total > 0 {
                return (stat.iowait as f64 / total as f64) * 100.0;
            }
        }
        0.0
    }
}

/// Linux-specific error handling
pub fn map_linux_errno(errno: i32) -> RuzipError {
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
        libc::EAGAIN => RuzipError::io_error(
            "Resource temporarily unavailable".to_string(),
            std::io::Error::from(std::io::ErrorKind::WouldBlock),
        ),
        _ => RuzipError::io_error(
            format!("Linux errno: {}", errno),
            std::io::Error::from_raw_os_error(errno),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_linux_temp_dir() {
        let temp_dir = get_temp_dir().unwrap();
        assert!(temp_dir.exists());
        println!("Linux temp dir: {:?}", temp_dir);
    }

    #[test]
    fn test_linux_io_optimizer() {
        let optimizer = LinuxIoOptimizer::new();
        assert!(optimizer.preferred_block_size() > 0);
        println!("IO_uring support: {}", optimizer.supports_io_uring());
        println!("Splice support: {}", optimizer.supports_splice());
    }

    #[test]
    fn test_linux_memory_manager() {
        let manager = LinuxMemoryManager::new();
        let buffer = manager.allocate_buffer(1024).unwrap();
        assert_eq!(buffer.len(), 1024);
        println!("Huge pages support: {}", manager.supports_huge_pages());
    }

    #[test]
    fn test_linux_distribution_optimizer() {
        let optimizer = LinuxDistributionOptimizer::new(super::super::LinuxDistribution::Ubuntu);
        let config_paths = optimizer.get_config_paths();
        assert!(!config_paths.is_empty());
        
        let compression = optimizer.get_preferred_compression();
        assert!(!compression.is_empty());
        println!("Preferred compression: {}", compression);
    }

    #[test]
    fn test_init_system_detection() {
        let init_system = detect_init_system();
        println!("Detected init system: {:?}", init_system);
    }

    #[test]
    fn test_linux_performance_monitor() {
        let mut monitor = LinuxPerformanceMonitor::new();
        
        if monitor.update().is_ok() {
            let cpu_usage = monitor.get_cpu_usage_percent();
            let memory_usage = monitor.get_memory_usage_percent();
            let iowait = monitor.get_iowait_percent();
            
            assert!(cpu_usage >= 0.0 && cpu_usage <= 100.0);
            assert!(memory_usage >= 0.0 && memory_usage <= 100.0);
            assert!(iowait >= 0.0 && iowait <= 100.0);
            
            println!("CPU: {:.1}%, Memory: {:.1}%, IO Wait: {:.1}%", 
                     cpu_usage, memory_usage, iowait);
        }
    }

    #[test]
    fn test_linux_error_mapping() {
        let not_found_error = map_linux_errno(libc::ENOENT);
        assert!(matches!(not_found_error, RuzipError::Io { .. }));
        
        let access_denied_error = map_linux_errno(libc::EACCES);
        assert!(matches!(access_denied_error, RuzipError::Permission { .. }));
        
        let no_space_error = map_linux_errno(libc::ENOSPC);
        assert!(matches!(no_space_error, RuzipError::ResourceExhausted { .. }));
    }
}