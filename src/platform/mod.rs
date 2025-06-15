//! Cross-platform compatibility layer for RuZip
//!
//! Provides platform-specific optimizations and abstractions for:
//! - Windows-specific features
//! - macOS-specific optimizations  
//! - Linux distribution-specific features
//! - FreeBSD/OpenBSD support

use crate::error::{Result, RuzipError};
use std::path::Path;

pub mod windows;
pub mod macos;
pub mod linux;
pub mod bsd;

/// Platform-specific configuration and capabilities
#[derive(Debug, Clone)]
pub struct PlatformInfo {
    pub os_type: OsType,
    pub architecture: Architecture,
    pub capabilities: PlatformCapabilities,
    pub optimizations: PlatformOptimizations,
}

/// Operating system types
#[derive(Debug, Clone, PartialEq)]
pub enum OsType {
    Windows,
    MacOS,
    Linux { distribution: LinuxDistribution },
    FreeBSD,
    OpenBSD,
    Unknown,
}

/// CPU architectures
#[derive(Debug, Clone, PartialEq)]
pub enum Architecture {
    X86_64,
    Aarch64,
    X86,
    Unknown,
}

/// Linux distributions
#[derive(Debug, Clone, PartialEq)]
pub enum LinuxDistribution {
    Ubuntu,
    Debian,
    RedHat,
    CentOS,
    Fedora,
    ArchLinux,
    Alpine,
    SUSE,
    Unknown,
}

/// Platform-specific capabilities
#[derive(Debug, Clone)]
pub struct PlatformCapabilities {
    /// Supports memory mapping
    pub memory_mapping: bool,
    /// Supports sparse files
    pub sparse_files: bool,
    /// Supports file system compression
    pub fs_compression: bool,
    /// Supports extended attributes
    pub extended_attributes: bool,
    /// Supports symbolic links
    pub symbolic_links: bool,
    /// Supports hard links
    pub hard_links: bool,
    /// Supports file locking
    pub file_locking: bool,
    /// Supports asynchronous I/O
    pub async_io: bool,
    /// Supports SIMD instructions
    pub simd_support: SimdSupport,
    /// Maximum path length
    pub max_path_length: usize,
}

/// SIMD instruction set support
#[derive(Debug, Clone)]
pub struct SimdSupport {
    pub sse2: bool,
    pub sse3: bool,
    pub ssse3: bool,
    pub sse4_1: bool,
    pub sse4_2: bool,
    pub avx: bool,
    pub avx2: bool,
    pub avx512: bool,
    pub neon: bool, // ARM NEON
}

/// Platform-specific optimizations
#[derive(Debug, Clone)]
pub struct PlatformOptimizations {
    /// Preferred I/O buffer size
    pub preferred_buffer_size: usize,
    /// Number of I/O threads to use
    pub io_thread_count: usize,
    /// Use memory mapping for large files
    pub use_memory_mapping: bool,
    /// Use sparse file optimization
    pub use_sparse_files: bool,
    /// Preferred compression algorithm
    pub preferred_compression: String,
    /// Enable platform-specific acceleration
    pub hardware_acceleration: bool,
}

impl Default for PlatformCapabilities {
    fn default() -> Self {
        Self {
            memory_mapping: true,
            sparse_files: true,
            fs_compression: false,
            extended_attributes: true,
            symbolic_links: true,
            hard_links: true,
            file_locking: true,
            async_io: true,
            simd_support: SimdSupport::default(),
            max_path_length: 4096,
        }
    }
}

impl Default for SimdSupport {
    fn default() -> Self {
        Self {
            sse2: false,
            sse3: false,
            ssse3: false,
            sse4_1: false,
            sse4_2: false,
            avx: false,
            avx2: false,
            avx512: false,
            neon: false,
        }
    }
}

impl Default for PlatformOptimizations {
    fn default() -> Self {
        Self {
            preferred_buffer_size: 64 * 1024, // 64KB
            io_thread_count: num_cpus::get(),
            use_memory_mapping: false,
            use_sparse_files: false,
            preferred_compression: "zstd".to_string(),
            hardware_acceleration: false,
        }
    }
}

/// Platform abstraction layer
pub struct PlatformLayer {
    info: PlatformInfo,
}

impl PlatformLayer {
    /// Initialize platform layer with auto-detection
    pub fn new() -> Result<Self> {
        let info = detect_platform_info()?;
        Ok(Self { info })
    }

    /// Get platform information
    pub fn info(&self) -> &PlatformInfo {
        &self.info
    }

    /// Get optimal buffer size for I/O operations
    pub fn optimal_buffer_size(&self, file_size: Option<u64>) -> usize {
        match file_size {
            Some(size) if size > 100 * 1024 * 1024 => {
                // Large files (>100MB): use larger buffers
                std::cmp::min(self.info.optimizations.preferred_buffer_size * 4, 1024 * 1024)
            },
            Some(size) if size < 1024 * 1024 => {
                // Small files (<1MB): use smaller buffers
                std::cmp::max(self.info.optimizations.preferred_buffer_size / 4, 4096)
            },
            _ => self.info.optimizations.preferred_buffer_size,
        }
    }

    /// Check if memory mapping should be used for a file
    pub fn should_use_memory_mapping(&self, file_size: u64) -> bool {
        self.info.capabilities.memory_mapping &&
        self.info.optimizations.use_memory_mapping &&
        file_size > 1024 * 1024 && // Only for files > 1MB
        file_size < 2u64.pow(32) // Avoid very large files on 32-bit systems
    }

    /// Get number of I/O threads for parallel operations
    pub fn io_thread_count(&self) -> usize {
        match self.info.os_type {
            OsType::Windows => {
                // Windows handles I/O differently, use fewer threads
                std::cmp::min(self.info.optimizations.io_thread_count, 4)
            },
            _ => self.info.optimizations.io_thread_count,
        }
    }

    /// Create platform-specific file handle
    pub fn create_file_handle<P: AsRef<Path>>(&self, path: P) -> Result<PlatformFileHandle> {
        match self.info.os_type {
            OsType::Windows => windows::create_file_handle(path),
            OsType::MacOS => macos::create_file_handle(path),
            OsType::Linux { .. } => linux::create_file_handle(path),
            OsType::FreeBSD => bsd::create_file_handle(path, BsdVariant::FreeBSD),
            OsType::OpenBSD => bsd::create_file_handle(path, BsdVariant::OpenBSD),
            _ => {
                // Generic implementation
                Ok(PlatformFileHandle::Generic {
                    path: path.as_ref().to_path_buf(),
                })
            }
        }
    }

    /// Get preferred compression algorithm for this platform
    pub fn preferred_compression(&self) -> &str {
        // Platform-specific compression preferences
        match self.info.os_type {
            OsType::Windows => {
                // Windows often benefits from faster compression
                if self.info.capabilities.simd_support.avx2 {
                    "zstd"
                } else {
                    "lz4"
                }
            },
            OsType::MacOS => {
                // macOS has good SIMD support, use high-quality compression
                "zstd"
            },
            OsType::Linux { .. } => {
                // Linux varies, use adaptive approach
                if self.info.capabilities.simd_support.avx2 {
                    "zstd"
                } else {
                    "zstd"
                }
            },
            _ => "zstd",
        }
    }

    /// Check if hardware acceleration is available
    pub fn has_hardware_acceleration(&self) -> bool {
        self.info.optimizations.hardware_acceleration &&
        (self.info.capabilities.simd_support.avx2 || 
         self.info.capabilities.simd_support.neon)
    }

    /// Get platform-specific temporary directory
    pub fn temp_dir(&self) -> Result<std::path::PathBuf> {
        match self.info.os_type {
            OsType::Windows => windows::get_temp_dir(),
            OsType::MacOS => macos::get_temp_dir(),
            OsType::Linux { .. } => linux::get_temp_dir(),
            OsType::FreeBSD | OsType::OpenBSD => bsd::get_temp_dir(),
            _ => Ok(std::env::temp_dir()),
        }
    }
}

/// Platform-specific file handle
#[derive(Debug)]
pub enum PlatformFileHandle {
    Windows {
        handle: windows::WindowsFileHandle,
    },
    Unix {
        fd: i32,
        path: std::path::PathBuf,
    },
    Generic {
        path: std::path::PathBuf,
    },
}

/// BSD variant for FreeBSD/OpenBSD support
#[derive(Debug, Clone, PartialEq)]
pub enum BsdVariant {
    FreeBSD,
    OpenBSD,
}

/// Detect current platform information
pub fn detect_platform_info() -> Result<PlatformInfo> {
    let os_type = detect_os_type()?;
    let architecture = detect_architecture();
    let capabilities = detect_capabilities(&os_type, &architecture)?;
    let optimizations = determine_optimizations(&os_type, &architecture, &capabilities);

    Ok(PlatformInfo {
        os_type,
        architecture,
        capabilities,
        optimizations,
    })
}

/// Detect operating system type
fn detect_os_type() -> Result<OsType> {
    #[cfg(target_os = "windows")]
    return Ok(OsType::Windows);

    #[cfg(target_os = "macos")]
    return Ok(OsType::MacOS);

    #[cfg(target_os = "linux")]
    {
        let distribution = detect_linux_distribution()?;
        return Ok(OsType::Linux { distribution });
    }

    #[cfg(target_os = "freebsd")]
    return Ok(OsType::FreeBSD);

    #[cfg(target_os = "openbsd")]
    return Ok(OsType::OpenBSD);

    #[cfg(not(any(
        target_os = "windows",
        target_os = "macos", 
        target_os = "linux",
        target_os = "freebsd",
        target_os = "openbsd"
    )))]
    return Ok(OsType::Unknown);
}

/// Detect Linux distribution
#[cfg(target_os = "linux")]
fn detect_linux_distribution() -> Result<LinuxDistribution> {
    // Try to read /etc/os-release
    match std::fs::read_to_string("/etc/os-release") {
        Ok(content) => {
            if content.contains("Ubuntu") {
                Ok(LinuxDistribution::Ubuntu)
            } else if content.contains("Debian") {
                Ok(LinuxDistribution::Debian)
            } else if content.contains("Red Hat") || content.contains("RHEL") {
                Ok(LinuxDistribution::RedHat)
            } else if content.contains("CentOS") {
                Ok(LinuxDistribution::CentOS)
            } else if content.contains("Fedora") {
                Ok(LinuxDistribution::Fedora)
            } else if content.contains("Arch") {
                Ok(LinuxDistribution::ArchLinux)
            } else if content.contains("Alpine") {
                Ok(LinuxDistribution::Alpine)
            } else if content.contains("SUSE") {
                Ok(LinuxDistribution::SUSE)
            } else {
                Ok(LinuxDistribution::Unknown)
            }
        },
        Err(_) => Ok(LinuxDistribution::Unknown),
    }
}

#[cfg(not(target_os = "linux"))]
fn detect_linux_distribution() -> Result<LinuxDistribution> {
    Ok(LinuxDistribution::Unknown)
}

/// Detect CPU architecture
fn detect_architecture() -> Architecture {
    #[cfg(target_arch = "x86_64")]
    return Architecture::X86_64;

    #[cfg(target_arch = "aarch64")]
    return Architecture::Aarch64;

    #[cfg(target_arch = "x86")]
    return Architecture::X86;

    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64", target_arch = "x86")))]
    return Architecture::Unknown;
}

/// Detect platform capabilities
fn detect_capabilities(os_type: &OsType, architecture: &Architecture) -> Result<PlatformCapabilities> {
    let mut caps = PlatformCapabilities::default();

    // Platform-specific capability detection
    match os_type {
        OsType::Windows => {
            caps.max_path_length = 32767; // Windows supports long paths with proper configuration
            caps.fs_compression = true; // NTFS compression
        },
        OsType::MacOS => {
            caps.max_path_length = 1024; // macOS path limit
            caps.fs_compression = true; // APFS compression
        },
        OsType::Linux { distribution } => {
            caps.max_path_length = 4096; // Linux path limit
            caps.fs_compression = match distribution {
                LinuxDistribution::Ubuntu | LinuxDistribution::Debian => true, // Often has Btrfs/ZFS
                _ => false,
            };
        },
        OsType::FreeBSD => {
            caps.max_path_length = 1024;
            caps.fs_compression = true; // ZFS compression
        },
        OsType::OpenBSD => {
            caps.max_path_length = 1024;
            caps.fs_compression = false;
        },
        OsType::Unknown => {
            caps.max_path_length = 256; // Conservative default
        },
    }

    // Detect SIMD support
    caps.simd_support = detect_simd_support(architecture);

    Ok(caps)
}

/// Detect SIMD instruction support
fn detect_simd_support(architecture: &Architecture) -> SimdSupport {
    let mut simd = SimdSupport::default();

    match architecture {
        Architecture::X86_64 | Architecture::X86 => {
            // Use std::arch to detect x86 features
            #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
            {
                if std::arch::is_x86_feature_detected!("sse2") {
                    simd.sse2 = true;
                }
                if std::arch::is_x86_feature_detected!("sse3") {
                    simd.sse3 = true;
                }
                if std::arch::is_x86_feature_detected!("ssse3") {
                    simd.ssse3 = true;
                }
                if std::arch::is_x86_feature_detected!("sse4.1") {
                    simd.sse4_1 = true;
                }
                if std::arch::is_x86_feature_detected!("sse4.2") {
                    simd.sse4_2 = true;
                }
                if std::arch::is_x86_feature_detected!("avx") {
                    simd.avx = true;
                }
                if std::arch::is_x86_feature_detected!("avx2") {
                    simd.avx2 = true;
                }
                if std::arch::is_x86_feature_detected!("avx512f") {
                    simd.avx512 = true;
                }
            }
        },
        Architecture::Aarch64 => {
            // ARM NEON is standard on AArch64
            simd.neon = true;
        },
        _ => {
            // Unknown architecture, no SIMD support assumed
        }
    }

    simd
}

/// Determine optimal platform optimizations
fn determine_optimizations(
    os_type: &OsType,
    architecture: &Architecture,
    capabilities: &PlatformCapabilities,
) -> PlatformOptimizations {
    let mut opts = PlatformOptimizations::default();

    // Adjust buffer size based on platform
    match os_type {
        OsType::Windows => {
            // Windows benefits from larger buffers
            opts.preferred_buffer_size = 128 * 1024;
            opts.io_thread_count = std::cmp::min(num_cpus::get(), 6);
        },
        OsType::MacOS => {
            // macOS optimized for SSD performance
            opts.preferred_buffer_size = 64 * 1024;
            opts.use_memory_mapping = true;
        },
        OsType::Linux { .. } => {
            // Linux scales well with multiple threads
            opts.io_thread_count = num_cpus::get();
            opts.use_sparse_files = true;
        },
        OsType::FreeBSD => {
            // FreeBSD with ZFS benefits from specific optimizations
            opts.preferred_buffer_size = 128 * 1024;
            opts.use_sparse_files = true;
        },
        _ => {
            // Conservative defaults for unknown platforms
            opts.preferred_buffer_size = 32 * 1024;
            opts.io_thread_count = std::cmp::min(num_cpus::get(), 4);
        }
    }

    // Enable hardware acceleration if supported
    opts.hardware_acceleration = capabilities.simd_support.avx2 || capabilities.simd_support.neon;

    // Adjust for architecture
    match architecture {
        Architecture::Aarch64 => {
            // ARM processors often benefit from smaller buffers
            opts.preferred_buffer_size = std::cmp::min(opts.preferred_buffer_size, 32 * 1024);
        },
        _ => {}
    }

    opts
}

impl Default for PlatformLayer {
    fn default() -> Self {
        Self::new().unwrap_or_else(|_| Self {
            info: PlatformInfo {
                os_type: OsType::Unknown,
                architecture: Architecture::Unknown,
                capabilities: PlatformCapabilities::default(),
                optimizations: PlatformOptimizations::default(),
            },
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_platform_detection() {
        let info = detect_platform_info().unwrap();
        
        // Should detect some OS type
        assert_ne!(info.os_type, OsType::Unknown);
        
        // Should detect some architecture
        assert_ne!(info.architecture, Architecture::Unknown);
        
        println!("Detected platform: {:?}", info.os_type);
        println!("Architecture: {:?}", info.architecture);
        println!("SIMD support: {:?}", info.capabilities.simd_support);
    }

    #[test]
    fn test_platform_layer() {
        let platform = PlatformLayer::new().unwrap();
        
        assert!(platform.optimal_buffer_size(None) > 0);
        assert!(platform.io_thread_count() > 0);
        
        let large_file_buffer = platform.optimal_buffer_size(Some(100 * 1024 * 1024));
        let small_file_buffer = platform.optimal_buffer_size(Some(1024));
        
        // Large files should use larger buffers
        assert!(large_file_buffer >= small_file_buffer);
    }

    #[test]
    fn test_memory_mapping_decision() {
        let platform = PlatformLayer::new().unwrap();
        
        // Small files should not use memory mapping
        assert!(!platform.should_use_memory_mapping(1024));
        
        // Large files might use memory mapping (depends on platform capabilities)
        let use_mmap = platform.should_use_memory_mapping(10 * 1024 * 1024);
        println!("Memory mapping for 10MB file: {}", use_mmap);
    }
}