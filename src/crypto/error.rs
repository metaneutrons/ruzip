//! Cryptographic error types for RuZip
//!
//! Comprehensive error handling for all cryptographic operations.

use thiserror::Error;

/// Comprehensive error type for cryptographic operations
#[derive(Error, Debug)]
pub enum CryptoError {
    /// Key derivation errors
    #[error("Key derivation failed: {message}")]
    KeyDerivation {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Encryption/decryption errors
    #[error("Encryption operation failed: {message}")]
    Encryption {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Decryption errors
    #[error("Decryption operation failed: {message}")]
    Decryption {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// I/O errors during cryptographic operations
    #[error("I/O error during crypto operation: {message}")]
    Io {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Digital signature errors
    #[error("Digital signature operation failed: {message}")]
    Signature {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Key generation errors
    #[error("Key generation failed: {message}")]
    KeyGeneration {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Invalid key format or size
    #[error("Invalid key: {message}")]
    InvalidKey {
        message: String,
        key_type: Option<String>,
    },

    /// Invalid cryptographic parameters
    #[error("Invalid crypto parameters: {message}")]
    InvalidParameters {
        message: String,
        parameter: Option<String>,
    },

    /// Authentication/verification failures
    #[error("Authentication failed: {message}")]
    Authentication {
        message: String,
        context: Option<String>,
    },

    /// Random number generation errors
    #[error("Random number generation failed: {message}")]
    RandomGeneration {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },

    /// Unsupported cryptographic operation
    #[error("Unsupported operation: {message}")]
    Unsupported {
        message: String,
        operation: String,
    },

    /// Internal cryptographic library errors
    #[error("Internal crypto error: {message}")]
    Internal {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

impl CryptoError {
    /// Create a new key derivation error
    pub fn key_derivation<S: Into<String>>(
        message: S,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self::KeyDerivation {
            message: message.into(),
            source,
        }
    }

    /// Create a new encryption error
    pub fn encryption<S: Into<String>>(
        message: S,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self::Encryption {
            message: message.into(),
            source,
        }
    }

    /// Create a new decryption error
    pub fn decryption<S: Into<String>>(
        message: S,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self::Decryption {
            message: message.into(),
            source,
        }
    }

    /// Create a new I/O error
    pub fn io<S: Into<String>>(
        message: S,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self::Io {
            message: message.into(),
            source,
        }
    }

    /// Create a new signature error
    pub fn signature<S: Into<String>>(
        message: S,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self::Signature {
            message: message.into(),
            source,
        }
    }

    /// Create a new key generation error
    pub fn key_generation<S: Into<String>>(
        message: S,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self::KeyGeneration {
            message: message.into(),
            source,
        }
    }

    /// Create a new invalid key error
    pub fn invalid_key<S: Into<String>>(message: S, key_type: Option<String>) -> Self {
        Self::InvalidKey {
            message: message.into(),
            key_type,
        }
    }

    /// Create a new invalid parameters error
    pub fn invalid_parameters<S: Into<String>>(message: S, parameter: Option<String>) -> Self {
        Self::InvalidParameters {
            message: message.into(),
            parameter,
        }
    }

    /// Create a new authentication error
    pub fn authentication<S: Into<String>>(message: S, context: Option<String>) -> Self {
        Self::Authentication {
            message: message.into(),
            context,
        }
    }

    /// Create a new random generation error
    pub fn random_generation<S: Into<String>>(
        message: S,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self::RandomGeneration {
            message: message.into(),
            source,
        }
    }

    /// Create a new unsupported operation error
    pub fn unsupported<S: Into<String>>(message: S, operation: String) -> Self {
        Self::Unsupported {
            message: message.into(),
            operation,
        }
    }

    /// Create a new internal error
    pub fn internal<S: Into<String>>(
        message: S,
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self::Internal {
            message: message.into(),
            source,
        }
    }

    /// Check if this error is recoverable
    pub fn is_recoverable(&self) -> bool {
        match self {
            CryptoError::KeyDerivation { .. } => false,
            CryptoError::Encryption { .. } => false,
            CryptoError::Decryption { .. } => false,
            CryptoError::Io { .. } => true, // I/O errors might be recoverable
            CryptoError::Signature { .. } => false,
            CryptoError::KeyGeneration { .. } => true, // Can retry with different parameters
            CryptoError::InvalidKey { .. } => false,
            CryptoError::InvalidParameters { .. } => false,
            CryptoError::Authentication { .. } => false,
            CryptoError::RandomGeneration { .. } => true, // Can retry
            CryptoError::Unsupported { .. } => false,
            CryptoError::Internal { .. } => false,
        }
    }

    /// Get error category for reporting
    pub fn category(&self) -> &'static str {
        match self {
            CryptoError::KeyDerivation { .. } => "key_derivation",
            CryptoError::Encryption { .. } => "encryption",
            CryptoError::Decryption { .. } => "decryption",
            CryptoError::Io { .. } => "io",
            CryptoError::Signature { .. } => "signature",
            CryptoError::KeyGeneration { .. } => "key_generation",
            CryptoError::InvalidKey { .. } => "invalid_key",
            CryptoError::InvalidParameters { .. } => "invalid_parameters",
            CryptoError::Authentication { .. } => "authentication",
            CryptoError::RandomGeneration { .. } => "random_generation",
            CryptoError::Unsupported { .. } => "unsupported",
            CryptoError::Internal { .. } => "internal",
        }
    }
}

/// Convert CryptoError to RuzipError
impl From<CryptoError> for crate::error::RuzipError {
    fn from(err: CryptoError) -> Self {
        crate::error::RuzipError::crypto_error(
            format!("Cryptographic operation failed: {}", err),
            Some(Box::new(err)),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_error_construction() {
        let err = CryptoError::invalid_key("Key too short", Some("AES-256".to_string()));
        assert_eq!(err.category(), "invalid_key");
        assert!(!err.is_recoverable());
    }

    #[test]
    fn test_crypto_error_recoverability() {
        let recoverable = CryptoError::key_generation("Failed to generate", None);
        assert!(recoverable.is_recoverable());

        let non_recoverable = CryptoError::authentication("Invalid signature", None);
        assert!(!non_recoverable.is_recoverable());
    }

    #[test]
    fn test_crypto_error_display() {
        let err = CryptoError::encryption("AES encryption failed", None);
        let display_str = format!("{}", err);
        assert!(display_str.contains("Encryption operation failed"));
        assert!(display_str.contains("AES encryption failed"));
    }

    #[test]
    fn test_conversion_to_ruzip_error() {
        let crypto_err = CryptoError::signature("Invalid signature", None);
        let ruzip_err: crate::error::RuzipError = crypto_err.into();
        assert_eq!(ruzip_err.category(), "crypto");
    }
}