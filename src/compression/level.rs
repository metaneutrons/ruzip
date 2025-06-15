//! Compression level mapping for different algorithms
//!
//! This module provides unified compression level handling across
//! different compression algorithms with proper validation.

use crate::error::{Result, RuzipError};
use std::fmt;

/// Compression level wrapper with validation
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CompressionLevel(u8);

impl CompressionLevel {
    /// Minimum compression level
    pub const MIN: u8 = 1;
    /// Maximum compression level  
    pub const MAX: u8 = 22;
    /// Default compression level
    pub const DEFAULT: u8 = 6;
    /// Fast compression level
    pub const FAST: u8 = 3;
    /// Best compression level
    pub const BEST: u8 = 22;

    /// Create new compression level with validation
    pub fn new(level: u8) -> Result<Self> {
        if level < Self::MIN || level > Self::MAX {
            return Err(RuzipError::invalid_input(
                format!(
                    "Compression level {} is out of range [{}, {}]",
                    level,
                    Self::MIN,
                    Self::MAX
                ),
                Some(level.to_string()),
            ));
        }
        Ok(Self(level))
    }

    /// Create compression level without validation (for internal use)
    pub(crate) fn new_unchecked(level: u8) -> Self {
        Self(level)
    }

    /// Get the raw level value
    pub fn value(&self) -> u8 {
        self.0
    }

    /// Map to ZSTD compression level (1-22)
    pub fn to_zstd_level(&self) -> i32 {
        self.0 as i32
    }

    /// Get compression speed category
    pub fn speed_category(&self) -> SpeedCategory {
        match self.0 {
            1..=3 => SpeedCategory::Fast,
            4..=9 => SpeedCategory::Normal,
            10..=15 => SpeedCategory::Good,
            16..=22 => SpeedCategory::Best,
            _ => unreachable!(), // Constructor ensures valid range
        }
    }

    /// Estimate compression ratio multiplier
    pub fn estimated_ratio_multiplier(&self) -> f64 {
        match self.0 {
            1..=3 => 0.8,   // Fast: ~20% compression
            4..=9 => 0.6,   // Normal: ~40% compression  
            10..=15 => 0.4, // Good: ~60% compression
            16..=22 => 0.3, // Best: ~70% compression
            _ => unreachable!(),
        }
    }

    /// Get memory usage multiplier
    pub fn memory_multiplier(&self) -> f64 {
        match self.0 {
            1..=3 => 1.0,   // Fast: baseline memory
            4..=9 => 2.0,   // Normal: 2x memory
            10..=15 => 4.0, // Good: 4x memory
            16..=22 => 8.0, // Best: 8x memory
            _ => unreachable!(),
        }
    }
}

impl Default for CompressionLevel {
    fn default() -> Self {
        Self::new_unchecked(Self::DEFAULT)
    }
}

impl fmt::Display for CompressionLevel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

impl TryFrom<u8> for CompressionLevel {
    type Error = RuzipError;

    fn try_from(value: u8) -> Result<Self> {
        Self::new(value)
    }
}

impl From<CompressionLevel> for u8 {
    fn from(level: CompressionLevel) -> Self {
        level.0
    }
}

/// Compression speed categories
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SpeedCategory {
    /// Fast compression, lower ratio
    Fast,
    /// Normal compression, balanced
    Normal,
    /// Good compression, higher ratio
    Good,
    /// Best compression, highest ratio
    Best,
}

impl fmt::Display for SpeedCategory {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SpeedCategory::Fast => write!(f, "fast"),
            SpeedCategory::Normal => write!(f, "normal"),
            SpeedCategory::Good => write!(f, "good"),
            SpeedCategory::Best => write!(f, "best"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_level_validation() {
        // Valid levels
        assert!(CompressionLevel::new(1).is_ok());
        assert!(CompressionLevel::new(6).is_ok());
        assert!(CompressionLevel::new(22).is_ok());

        // Invalid levels
        assert!(CompressionLevel::new(0).is_err());
        assert!(CompressionLevel::new(23).is_err());
        assert!(CompressionLevel::new(255).is_err());
    }

    #[test]
    fn test_compression_level_default() {
        let default_level = CompressionLevel::default();
        assert_eq!(default_level.value(), CompressionLevel::DEFAULT);
    }

    #[test]
    fn test_compression_level_conversions() {
        let level = CompressionLevel::new(6).unwrap();
        
        // Test ZSTD mapping
        assert_eq!(level.to_zstd_level(), 6);
        
        // Test u8 conversion
        let level_u8: u8 = level.into();
        assert_eq!(level_u8, 6);
        
        // Test try_from
        let level_from_u8 = CompressionLevel::try_from(6).unwrap();
        assert_eq!(level_from_u8, level);
    }

    #[test]
    fn test_speed_categories() {
        assert_eq!(CompressionLevel::new(1).unwrap().speed_category(), SpeedCategory::Fast);
        assert_eq!(CompressionLevel::new(6).unwrap().speed_category(), SpeedCategory::Normal);
        assert_eq!(CompressionLevel::new(12).unwrap().speed_category(), SpeedCategory::Good);
        assert_eq!(CompressionLevel::new(22).unwrap().speed_category(), SpeedCategory::Best);
    }

    #[test]
    fn test_ratio_multipliers() {
        let fast_level = CompressionLevel::new(3).unwrap();
        let best_level = CompressionLevel::new(22).unwrap();
        
        assert!(fast_level.estimated_ratio_multiplier() > best_level.estimated_ratio_multiplier());
        assert_eq!(fast_level.estimated_ratio_multiplier(), 0.8);
        assert_eq!(best_level.estimated_ratio_multiplier(), 0.3);
    }

    #[test]
    fn test_memory_multipliers() {
        let fast_level = CompressionLevel::new(1).unwrap();
        let best_level = CompressionLevel::new(22).unwrap();
        
        assert!(fast_level.memory_multiplier() < best_level.memory_multiplier());
        assert_eq!(fast_level.memory_multiplier(), 1.0);
        assert_eq!(best_level.memory_multiplier(), 8.0);
    }

    #[test]
    fn test_display_format() {
        let level = CompressionLevel::new(6).unwrap();
        assert_eq!(format!("{}", level), "6");
        
        let category = SpeedCategory::Normal;
        assert_eq!(format!("{}", category), "normal");
    }
}