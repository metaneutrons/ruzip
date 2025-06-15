//! Command line argument parsing utilities
//!
//! This module provides additional parsing functionality for CLI arguments.

use crate::error::{Result, RuzipError};

/// Parse a string as a compression level (1-22)
pub fn parse_compression_level(s: &str) -> Result<u8> {
    let level: u8 = s.parse()
        .map_err(|_| RuzipError::invalid_input(
            format!("Invalid compression level: {}", s),
            Some(s.to_string()),
        ))?;
    
    if !(1..=22).contains(&level) {
        return Err(RuzipError::invalid_input(
            format!("Compression level must be between 1 and 22, got: {}", level),
            Some(s.to_string()),
        ));
    }
    
    Ok(level)
}

/// Parse a thread count string
pub fn parse_thread_count(s: &str) -> Result<u16> {
    let count: u16 = s.parse()
        .map_err(|_| RuzipError::invalid_input(
            format!("Invalid thread count: {}", s),
            Some(s.to_string()),
        ))?;
    
    Ok(count)
}

/// Validate a file path for CLI usage
pub fn validate_cli_path(path: &str) -> Result<()> {
    if path.is_empty() {
        return Err(RuzipError::invalid_input(
            "Path cannot be empty",
            Some(path.to_string()),
        ));
    }
    
    // Additional CLI-specific validation can go here
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_compression_level() {
        assert_eq!(parse_compression_level("1").unwrap(), 1);
        assert_eq!(parse_compression_level("22").unwrap(), 22);
        assert_eq!(parse_compression_level("9").unwrap(), 9);
        
        assert!(parse_compression_level("0").is_err());
        assert!(parse_compression_level("23").is_err());
        assert!(parse_compression_level("abc").is_err());
    }

    #[test]
    fn test_parse_thread_count() {
        assert_eq!(parse_thread_count("0").unwrap(), 0);
        assert_eq!(parse_thread_count("8").unwrap(), 8);
        assert_eq!(parse_thread_count("16").unwrap(), 16);
        
        assert!(parse_thread_count("abc").is_err());
    }

    #[test]
    fn test_validate_cli_path() {
        assert!(validate_cli_path("file.txt").is_ok());
        assert!(validate_cli_path("/path/to/file").is_ok());
        
        assert!(validate_cli_path("").is_err());
    }
}