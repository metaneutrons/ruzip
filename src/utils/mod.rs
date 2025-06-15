//! Utility modules for RuZip
//!
//! This module contains various utility functions and types used throughout
//! the RuZip application.

pub mod config;
pub mod logging;

pub use config::*;
pub use logging::*;

/// Version information for the application
pub fn version_info() -> VersionInfo {
    VersionInfo {
        name: env!("CARGO_PKG_NAME").to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        authors: env!("CARGO_PKG_AUTHORS").to_string(),
        description: env!("CARGO_PKG_DESCRIPTION").to_string(),
        homepage: env!("CARGO_PKG_HOMEPAGE").to_string(),
        repository: env!("CARGO_PKG_REPOSITORY").to_string(),
        license: env!("CARGO_PKG_LICENSE").to_string(),
        rust_version: "Unknown".to_string(),
        target: std::env::consts::ARCH.to_string(),
    }
}

/// Complete version information structure
#[derive(Debug, Clone, PartialEq)]
pub struct VersionInfo {
    pub name: String,
    pub version: String,
    pub authors: String,
    pub description: String,
    pub homepage: String,
    pub repository: String,
    pub license: String,
    pub rust_version: String,
    pub target: String,
}

impl std::fmt::Display for VersionInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        writeln!(f, "{} {}", self.name, self.version)?;
        writeln!(f, "Authors: {}", self.authors)?;
        writeln!(f, "Description: {}", self.description)?;
        writeln!(f, "Homepage: {}", self.homepage)?;
        writeln!(f, "Repository: {}", self.repository)?;
        writeln!(f, "License: {}", self.license)?;
        writeln!(f, "Built with Rust: {}", self.rust_version)?;
        write!(f, "Target: {}", self.target)
    }
}

/// Format file size in human-readable format
pub fn format_size(bytes: u64) -> String {
    const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB", "PB"];
    const THRESHOLD: f64 = 1024.0;

    if bytes == 0 {
        return "0 B".to_string();
    }

    let bytes_f = bytes as f64;
    let unit_index = (bytes_f.log10() / THRESHOLD.log10()).floor() as usize;
    let unit_index = unit_index.min(UNITS.len() - 1);

    let size = bytes_f / THRESHOLD.powi(unit_index as i32);
    
    if unit_index == 0 {
        format!("{} {}", bytes, UNITS[unit_index])
    } else if size >= 10.0 {
        format!("{:.0} {}", size, UNITS[unit_index])
    } else {
        format!("{:.1} {}", size, UNITS[unit_index])
    }
}

/// Format duration in human-readable format
pub fn format_duration(duration: std::time::Duration) -> String {
    let total_seconds = duration.as_secs();
    let millis = duration.subsec_millis();

    if total_seconds == 0 {
        if millis == 0 {
            return format!("{}μs", duration.subsec_micros());
        } else {
            return format!("{}ms", millis);
        }
    }

    let hours = total_seconds / 3600;
    let minutes = (total_seconds % 3600) / 60;
    let seconds = total_seconds % 60;

    if hours > 0 {
        format!("{}h {}m {}s", hours, minutes, seconds)
    } else if minutes > 0 {
        format!("{}m {}s", minutes, seconds)
    } else {
        format!("{}.{:03}s", seconds, millis)
    }
}

/// Calculate compression ratio as a percentage
pub fn compression_ratio(original_size: u64, compressed_size: u64) -> f64 {
    if original_size == 0 {
        return 0.0;
    }
    
    let saved = original_size as f64 - compressed_size as f64;
    (saved / original_size as f64) * 100.0
}

/// Calculate compression speed in MB/s
pub fn compression_speed(bytes: u64, duration: std::time::Duration) -> f64 {
    if duration.is_zero() {
        return 0.0;
    }
    
    let seconds = duration.as_secs_f64();
    let megabytes = bytes as f64 / (1024.0 * 1024.0);
    megabytes / seconds
}

/// Validate file path for archive operations
pub fn validate_archive_path<P: AsRef<std::path::Path>>(path: P) -> crate::error::Result<()> {
    let path = path.as_ref();
    
    // Check for null bytes
    if path.to_string_lossy().contains('\0') {
        return Err(crate::error::RuzipError::invalid_input(
            "Path contains null bytes",
            Some(path.display().to_string()),
        ));
    }
    
    // Check for excessively long paths
    if path.as_os_str().len() > 4096 {
        return Err(crate::error::RuzipError::invalid_input(
            "Path is too long (>4096 characters)",
            Some(path.display().to_string()),
        ));
    }
    
    // Check for invalid characters on Windows
    #[cfg(target_os = "windows")]
    {
        let invalid_chars = ['<', '>', ':', '"', '|', '?', '*'];
        let path_str = path.to_string_lossy();
        
        for &ch in &invalid_chars {
            if path_str.contains(ch) {
                return Err(crate::error::RuzipError::invalid_input(
                    format!("Path contains invalid character: '{}'", ch),
                    Some(path.display().to_string()),
                ));
            }
        }
        
        // Check for reserved names on Windows
        let reserved_names = [
            "CON", "PRN", "AUX", "NUL",
            "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8", "COM9",
            "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
        ];
        
        if let Some(filename) = path.file_name() {
            let filename_upper = filename.to_string_lossy().to_uppercase();
            if reserved_names.contains(&filename_upper.as_str()) {
                return Err(crate::error::RuzipError::invalid_input(
                    format!("Path uses reserved name: {}", filename.to_string_lossy()),
                    Some(path.display().to_string()),
                ));
            }
        }
    }
    
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn test_format_size() {
        assert_eq!(format_size(0), "0 B");
        assert_eq!(format_size(512), "512 B");
        assert_eq!(format_size(1024), "1.0 KB");
        assert_eq!(format_size(1536), "1.5 KB");
        assert_eq!(format_size(1048576), "1.0 MB");
        assert_eq!(format_size(1073741824), "1.0 GB");
        assert_eq!(format_size(10485760), "10 MB");
    }

    #[test]
    fn test_format_duration() {
        assert_eq!(format_duration(Duration::from_micros(500)), "500μs");
        assert_eq!(format_duration(Duration::from_millis(250)), "250ms");
        assert_eq!(format_duration(Duration::from_secs(1)), "1.000s");
        assert_eq!(format_duration(Duration::from_secs(65)), "1m 5s");
        assert_eq!(format_duration(Duration::from_secs(3661)), "1h 1m 1s");
    }

    #[test]
    fn test_compression_ratio() {
        assert_eq!(compression_ratio(1000, 500), 50.0);
        assert_eq!(compression_ratio(1000, 250), 75.0);
        assert_eq!(compression_ratio(1000, 1200), -20.0); // Expansion
        assert_eq!(compression_ratio(0, 100), 0.0); // Edge case
    }

    #[test]
    fn test_compression_speed() {
        let speed = compression_speed(1048576, Duration::from_secs(1)); // 1MB in 1s
        assert!((speed - 1.0).abs() < 0.01); // ~1 MB/s
        
        let speed = compression_speed(10485760, Duration::from_millis(500)); // 10MB in 0.5s
        assert!((speed - 20.0).abs() < 0.1); // ~20 MB/s
        
        assert_eq!(compression_speed(1000, Duration::ZERO), 0.0);
    }

    #[test]
    fn test_validate_archive_path_valid() {
        assert!(validate_archive_path("normal/path/file.txt").is_ok());
        assert!(validate_archive_path("file.txt").is_ok());
        assert!(validate_archive_path("../relative/path").is_ok());
    }

    #[test]
    fn test_validate_archive_path_invalid() {
        // Null byte
        assert!(validate_archive_path("path\0with\0null").is_err());
        
        // Too long path
        let long_path = "a".repeat(5000);
        assert!(validate_archive_path(long_path).is_err());
    }

    #[test]
    #[cfg(target_os = "windows")]
    fn test_validate_archive_path_windows() {
        // Invalid characters
        assert!(validate_archive_path("file<name").is_err());
        assert!(validate_archive_path("file>name").is_err());
        assert!(validate_archive_path("file:name").is_err());
        assert!(validate_archive_path("file\"name").is_err());
        assert!(validate_archive_path("file|name").is_err());
        assert!(validate_archive_path("file?name").is_err());
        assert!(validate_archive_path("file*name").is_err());
        
        // Reserved names
        assert!(validate_archive_path("CON").is_err());
        assert!(validate_archive_path("PRN").is_err());
        assert!(validate_archive_path("COM1").is_err());
        assert!(validate_archive_path("LPT1").is_err());
    }

    #[test]
    fn test_version_info() {
        let info = version_info();
        assert!(!info.name.is_empty());
        assert!(!info.version.is_empty());
        
        let display = format!("{}", info);
        assert!(display.contains(&info.name));
        assert!(display.contains(&info.version));
    }
}