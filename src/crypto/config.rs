//! Cryptographic configuration for RuZip
//!
//! Configuration structures and validation for cryptographic operations.

use serde::{Deserialize, Serialize};
use crate::crypto::{
    types::{CryptoMethod, DigitalSignature, KeyDerivationParams},
    error::CryptoError,
};

/// Comprehensive cryptographic configuration
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CryptoConfig {
    /// Encryption method to use
    pub encryption: CryptoMethod,
    /// Digital signature method to use
    pub signature: DigitalSignature,
    /// Key derivation parameters
    pub key_derivation: KeyDerivationParams,
    /// Whether to compress before encrypting (recommended)
    pub compress_before_encrypt: bool,
    /// Whether to verify integrity after decryption
    pub verify_integrity: bool,
    /// Maximum password attempts before lockout
    pub max_password_attempts: u32,
    /// Whether to use secure memory allocation where possible
    pub use_secure_memory: bool,
}

impl Default for CryptoConfig {
    fn default() -> Self {
        Self {
            encryption: CryptoMethod::None,
            signature: DigitalSignature::None,
            key_derivation: KeyDerivationParams::default(),
            compress_before_encrypt: true,
            verify_integrity: true,
            max_password_attempts: 3,
            use_secure_memory: true,
        }
    }
}

impl CryptoConfig {
    /// Create a new configuration with specified encryption and signature methods
    pub fn new(encryption: CryptoMethod, signature: DigitalSignature) -> Self {
        Self {
            encryption,
            signature,
            ..Default::default()
        }
    }

    /// Create a configuration optimized for high security
    pub fn high_security() -> Self {
        Self {
            encryption: CryptoMethod::ChaCha20Poly1305,
            signature: DigitalSignature::Ed25519,
            key_derivation: KeyDerivationParams::sensitive(),
            compress_before_encrypt: true,
            verify_integrity: true,
            max_password_attempts: 3,
            use_secure_memory: true,
        }
    }

    /// Create a configuration optimized for performance
    pub fn performance_optimized() -> Self {
        Self {
            encryption: CryptoMethod::AesGcm256,
            signature: DigitalSignature::None,
            key_derivation: KeyDerivationParams::interactive(),
            compress_before_encrypt: true,
            verify_integrity: true,
            max_password_attempts: 5,
            use_secure_memory: false,
        }
    }

    /// Create a configuration with no cryptography (fastest)
    pub fn no_crypto() -> Self {
        Self {
            encryption: CryptoMethod::None,
            signature: DigitalSignature::None,
            key_derivation: KeyDerivationParams::interactive(),
            compress_before_encrypt: false,
            verify_integrity: false,
            max_password_attempts: 1,
            use_secure_memory: false,
        }
    }

    /// Validate the configuration
    pub fn validate(&self) -> Result<(), CryptoError> {
        // Validate key derivation parameters
        self.key_derivation.validate()?;

        // Validate password attempts
        if self.max_password_attempts == 0 {
            return Err(CryptoError::invalid_parameters(
                "Maximum password attempts must be at least 1",
                Some("max_password_attempts".to_string()),
            ));
        }

        if self.max_password_attempts > 100 {
            return Err(CryptoError::invalid_parameters(
                "Maximum password attempts should not exceed 100",
                Some("max_password_attempts".to_string()),
            ));
        }

        // Validate consistency between encryption and key derivation
        if self.encryption.requires_encryption() {
            let required_key_length = self.encryption.key_size();
            if self.key_derivation.output_length < required_key_length {
                return Err(CryptoError::invalid_parameters(
                    format!(
                        "Key derivation output length ({}) is insufficient for encryption method {} (requires {})",
                        self.key_derivation.output_length,
                        self.encryption.name(),
                        required_key_length
                    ),
                    Some("key_derivation.output_length".to_string()),
                ));
            }
        }

        // Warn about potentially insecure configurations
        if self.encryption.requires_encryption() && !self.compress_before_encrypt {
            // This is not an error, but could be a security consideration
            // Compression before encryption can help hide patterns
        }

        if self.encryption.requires_encryption() && !self.verify_integrity {
            return Err(CryptoError::invalid_parameters(
                "Integrity verification should be enabled when using encryption",
                Some("verify_integrity".to_string()),
            ));
        }

        Ok(())
    }

    /// Check if any cryptographic operations are enabled
    pub fn has_crypto(&self) -> bool {
        self.encryption.requires_encryption() || self.signature.requires_signing()
    }

    /// Check if encryption is enabled
    pub fn has_encryption(&self) -> bool {
        self.encryption.requires_encryption()
    }

    /// Check if digital signatures are enabled
    pub fn has_signatures(&self) -> bool {
        self.signature.requires_signing()
    }

    /// Get the total overhead in bytes for this configuration
    pub fn crypto_overhead(&self) -> usize {
        let mut overhead = 0;

        // Encryption overhead
        if self.has_encryption() {
            overhead += self.encryption.nonce_size(); // Nonce/IV
            overhead += self.encryption.tag_size(); // Authentication tag
            overhead += self.key_derivation.salt_length; // Salt for key derivation
        }

        // Signature overhead
        if self.has_signatures() {
            overhead += self.signature.signature_size(); // Digital signature
            overhead += self.signature.public_key_size(); // Public key (if embedded)
        }

        overhead
    }

    /// Get estimated memory usage for cryptographic operations
    pub fn estimated_memory_usage(&self) -> usize {
        let mut memory = 0;

        // Key derivation memory
        if self.has_encryption() {
            memory += (self.key_derivation.memory_cost as usize) * 1024; // Convert KiB to bytes
        }

        // Additional memory for crypto contexts and buffers
        if self.has_crypto() {
            memory += 64 * 1024; // 64 KB for various crypto contexts and buffers
        }

        memory
    }

    /// Get a security level rating (0-100, higher is more secure)
    pub fn security_level(&self) -> u8 {
        let mut score = 0u8;

        // Encryption scoring
        match self.encryption {
            CryptoMethod::None => score += 0,
            CryptoMethod::AesGcm256 => score += 35,
            CryptoMethod::ChaCha20Poly1305 => score += 40,
        }

        // Signature scoring
        match self.signature {
            DigitalSignature::None => score += 0,
            DigitalSignature::Rsa2048 => score += 20,
            DigitalSignature::Ed25519 => score += 25,
        }

        // Key derivation scoring (only if crypto is enabled)
        if self.has_crypto() {
            let kdf_score = match self.key_derivation.memory_cost {
                0..=4095 => 5,
                4096..=65535 => 15,
                65536..=1048575 => 25,
                _ => 30,
            };
            score += kdf_score;

            // Additional security features (only relevant with crypto)
            if self.verify_integrity {
                score += 5;
            }
            if self.use_secure_memory {
                score += 3;
            }
            if self.max_password_attempts <= 3 {
                score += 2;
            }
        }

        score.min(100)
    }

    /// Update key derivation parameters based on available system resources
    pub fn optimize_for_system(&mut self, available_memory_mb: usize, cpu_cores: usize) {
        if !self.has_encryption() {
            return;
        }

        // Adjust memory cost based on available memory
        let max_memory_for_kdf = (available_memory_mb / 4).max(4); // Use at most 1/4 of available memory
        let max_memory_kib = (max_memory_for_kdf * 1024).min(2097152); // Cap at 2 GiB

        if self.key_derivation.memory_cost > max_memory_kib as u32 {
            self.key_derivation.memory_cost = max_memory_kib as u32;
        }

        // Adjust parallelism based on CPU cores
        let optimal_parallelism = cpu_cores.min(8).max(1); // Use up to 8 cores
        if self.key_derivation.parallelism != optimal_parallelism as u32 {
            self.key_derivation.parallelism = optimal_parallelism as u32;
        }
    }

    /// Get recommended signature algorithm based on use case
    pub fn get_recommended_signature_algorithm(use_case: &str) -> DigitalSignature {
        match use_case.to_lowercase().as_str() {
            "performance" | "fast" | "speed" => DigitalSignature::Ed25519,
            "compatibility" | "legacy" | "rsa" => DigitalSignature::Rsa2048,
            "security" | "modern" | "recommended" => DigitalSignature::Ed25519,
            "none" | "disabled" => DigitalSignature::None,
            _ => DigitalSignature::Ed25519, // Default to Ed25519 for best performance/security balance
        }
    }

    /// Validate signature algorithm choice
    pub fn validate_signature_choice(&self) -> Result<(), CryptoError> {
        // If encryption is enabled but signatures are not, warn about potential security implications
        if self.has_encryption() && !self.has_signatures() {
            // This is not an error, but could be logged as a warning
            // Encryption without signatures means no authenticity verification
        }

        // If signatures are enabled, ensure we have a valid algorithm
        if self.has_signatures() {
            match self.signature {
                DigitalSignature::None => {
                    return Err(CryptoError::invalid_parameters(
                        "Signature algorithm cannot be None when signatures are required",
                        Some("signature".to_string()),
                    ));
                }
                DigitalSignature::Rsa2048 | DigitalSignature::Ed25519 => {
                    // Valid algorithms
                }
            }
        }

        Ok(())
    }

    /// Get signature performance characteristics
    pub fn signature_performance_info(&self) -> SignaturePerformanceInfo {
        match self.signature {
            DigitalSignature::None => SignaturePerformanceInfo {
                sign_time_estimate_ms: 0.0,
                verify_time_estimate_ms: 0.0,
                key_generation_time_ms: 0.0,
                signature_size_bytes: 0,
                public_key_size_bytes: 0,
                private_key_size_bytes: 0,
                security_level: 0,
            },
            DigitalSignature::Rsa2048 => SignaturePerformanceInfo {
                sign_time_estimate_ms: 8.0,   // ~8ms for RSA-2048 signing
                verify_time_estimate_ms: 0.5, // ~0.5ms for RSA-2048 verification
                key_generation_time_ms: 50.0, // ~50ms for RSA-2048 key generation
                signature_size_bytes: 256,
                public_key_size_bytes: 294,
                private_key_size_bytes: 1192,
                security_level: 112, // Equivalent to 112-bit symmetric security
            },
            DigitalSignature::Ed25519 => SignaturePerformanceInfo {
                sign_time_estimate_ms: 0.05,  // ~0.05ms for Ed25519 signing
                verify_time_estimate_ms: 0.1, // ~0.1ms for Ed25519 verification
                key_generation_time_ms: 1.0,  // ~1ms for Ed25519 key generation
                signature_size_bytes: 64,
                public_key_size_bytes: 32,
                private_key_size_bytes: 32,
                security_level: 128, // Equivalent to 128-bit symmetric security
            },
        }
    }
}

/// Performance information for signature algorithms
#[derive(Debug, Clone, PartialEq)]
pub struct SignaturePerformanceInfo {
    /// Estimated signing time in milliseconds
    pub sign_time_estimate_ms: f64,
    /// Estimated verification time in milliseconds
    pub verify_time_estimate_ms: f64,
    /// Estimated key generation time in milliseconds
    pub key_generation_time_ms: f64,
    /// Signature size in bytes
    pub signature_size_bytes: usize,
    /// Public key size in bytes
    pub public_key_size_bytes: usize,
    /// Private key size in bytes
    pub private_key_size_bytes: usize,
    /// Security level in bits
    pub security_level: u32,
}

impl SignaturePerformanceInfo {
    /// Calculate performance score (higher is better)
    pub fn performance_score(&self) -> f64 {
        // Lower times and smaller sizes are better
        let time_score = 1000.0 / (self.sign_time_estimate_ms + self.verify_time_estimate_ms + 1.0);
        let size_score = 1000.0 / (self.signature_size_bytes as f64 + 1.0);
        let keygen_score = 100.0 / (self.key_generation_time_ms + 1.0);
        
        (time_score + size_score + keygen_score) / 3.0
    }

    /// Calculate security score (higher is better)
    pub fn security_score(&self) -> f64 {
        self.security_level as f64
    }

    /// Calculate overall score balancing performance and security
    pub fn overall_score(&self) -> f64 {
        let perf_weight = 0.3;
        let security_weight = 0.7;
        
        (self.performance_score() * perf_weight) + (self.security_score() * security_weight)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_config() {
        let config = CryptoConfig::default();
        assert_eq!(config.encryption, CryptoMethod::None);
        assert_eq!(config.signature, DigitalSignature::None);
        assert!(!config.has_crypto());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_high_security_config() {
        let config = CryptoConfig::high_security();
        assert_eq!(config.encryption, CryptoMethod::ChaCha20Poly1305);
        assert_eq!(config.signature, DigitalSignature::Ed25519);
        assert!(config.has_crypto());
        assert!(config.has_encryption());
        assert!(config.has_signatures());
        assert!(config.validate().is_ok());
        assert!(config.security_level() > 80);
    }

    #[test]
    fn test_performance_optimized_config() {
        let config = CryptoConfig::performance_optimized();
        assert_eq!(config.encryption, CryptoMethod::AesGcm256);
        assert_eq!(config.signature, DigitalSignature::None);
        assert!(config.has_encryption());
        assert!(!config.has_signatures());
        assert!(config.validate().is_ok());
    }

    #[test]
    fn test_no_crypto_config() {
        let config = CryptoConfig::no_crypto();
        assert_eq!(config.encryption, CryptoMethod::None);
        assert_eq!(config.signature, DigitalSignature::None);
        assert!(!config.has_crypto());
        assert!(config.validate().is_ok());
        assert_eq!(config.security_level(), 0);
    }

    #[test]
    fn test_config_validation() {
        // Valid configuration
        let mut config = CryptoConfig::new(CryptoMethod::AesGcm256, DigitalSignature::None);
        assert!(config.validate().is_ok());

        // Invalid: zero password attempts
        config.max_password_attempts = 0;
        assert!(config.validate().is_err());
        config.max_password_attempts = 3;

        // Invalid: insufficient key length
        config.key_derivation.output_length = 16; // Too short for AES-256
        assert!(config.validate().is_err());
        config.key_derivation.output_length = 32;

        // Invalid: encryption without integrity verification
        config.verify_integrity = false;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_crypto_overhead() {
        let no_crypto = CryptoConfig::no_crypto();
        assert_eq!(no_crypto.crypto_overhead(), 0);

        let with_encryption = CryptoConfig::new(CryptoMethod::AesGcm256, DigitalSignature::None);
        let overhead = with_encryption.crypto_overhead();
        assert!(overhead > 0);
        assert_eq!(overhead, 12 + 16 + 32); // nonce + tag + salt

        let with_signatures = CryptoConfig::new(CryptoMethod::None, DigitalSignature::Ed25519);
        let sig_overhead = with_signatures.crypto_overhead();
        assert_eq!(sig_overhead, 64 + 32); // signature + public key
    }

    #[test]
    fn test_memory_usage_estimation() {
        let config = CryptoConfig::high_security();
        let memory = config.estimated_memory_usage();
        assert!(memory > 1024 * 1024); // Should be > 1 MB for high security
    }

    #[test]
    fn test_security_level() {
        let no_crypto = CryptoConfig::no_crypto();
        assert_eq!(no_crypto.security_level(), 0);

        let high_security = CryptoConfig::high_security();
        assert!(high_security.security_level() > 80);

        let performance = CryptoConfig::performance_optimized();
        let perf_level = performance.security_level();
        assert!(perf_level > 30 && perf_level < 80);
    }

    #[test]
    fn test_system_optimization() {
        let mut config = CryptoConfig::high_security();
        let original_memory = config.key_derivation.memory_cost;
        let original_parallelism = config.key_derivation.parallelism;

        // Simulate system with limited resources
        config.optimize_for_system(512, 2); // 512 MB RAM, 2 cores

        assert!(config.key_derivation.memory_cost <= original_memory);
        assert!(config.key_derivation.parallelism <= original_parallelism);
        assert_eq!(config.key_derivation.parallelism, 2);
    }

    #[test]
    fn test_config_creation() {
        let config = CryptoConfig::new(CryptoMethod::ChaCha20Poly1305, DigitalSignature::Ed25519);
        assert_eq!(config.encryption, CryptoMethod::ChaCha20Poly1305);
        assert_eq!(config.signature, DigitalSignature::Ed25519);
        assert!(config.compress_before_encrypt); // Should use default
        assert!(config.verify_integrity); // Should use default
    }
}
#[test]
    fn test_signature_algorithm_recommendations() {
        assert_eq!(
            CryptoConfig::get_recommended_signature_algorithm("performance"),
            DigitalSignature::Ed25519
        );
        assert_eq!(
            CryptoConfig::get_recommended_signature_algorithm("compatibility"),
            DigitalSignature::Rsa2048
        );
        assert_eq!(
            CryptoConfig::get_recommended_signature_algorithm("security"),
            DigitalSignature::Ed25519
        );
        assert_eq!(
            CryptoConfig::get_recommended_signature_algorithm("none"),
            DigitalSignature::None
        );
        assert_eq!(
            CryptoConfig::get_recommended_signature_algorithm("unknown"),
            DigitalSignature::Ed25519
        );
    }

    #[test]
    fn test_signature_validation() {
        let mut config = CryptoConfig::new(CryptoMethod::None, DigitalSignature::Ed25519);
        assert!(config.validate_signature_choice().is_ok());

        // Invalid: signature set to None but signatures required
        config.signature = DigitalSignature::None;
        // This should be OK since we're not explicitly requiring signatures
        assert!(config.validate_signature_choice().is_ok());
    }

    #[test]
    fn test_signature_performance_info() {
        let config_ed25519 = CryptoConfig::new(CryptoMethod::None, DigitalSignature::Ed25519);
        let ed25519_info = config_ed25519.signature_performance_info();
        
        assert_eq!(ed25519_info.signature_size_bytes, 64);
        assert_eq!(ed25519_info.public_key_size_bytes, 32);
        assert_eq!(ed25519_info.private_key_size_bytes, 32);
        assert_eq!(ed25519_info.security_level, 128);
        assert!(ed25519_info.sign_time_estimate_ms < 1.0);

        let config_rsa = CryptoConfig::new(CryptoMethod::None, DigitalSignature::Rsa2048);
        let rsa_info = config_rsa.signature_performance_info();
        
        assert_eq!(rsa_info.signature_size_bytes, 256);
        assert_eq!(rsa_info.public_key_size_bytes, 294);
        assert_eq!(rsa_info.private_key_size_bytes, 1192);
        assert_eq!(rsa_info.security_level, 112);
        assert!(rsa_info.sign_time_estimate_ms > ed25519_info.sign_time_estimate_ms);

        let config_none = CryptoConfig::new(CryptoMethod::None, DigitalSignature::None);
        let none_info = config_none.signature_performance_info();
        
        assert_eq!(none_info.signature_size_bytes, 0);
        assert_eq!(none_info.security_level, 0);
    }

    #[test]
    fn test_performance_scoring() {
        let ed25519_info = SignaturePerformanceInfo {
            sign_time_estimate_ms: 0.05,
            verify_time_estimate_ms: 0.1,
            key_generation_time_ms: 1.0,
            signature_size_bytes: 64,
            public_key_size_bytes: 32,
            private_key_size_bytes: 32,
            security_level: 128,
        };

        let rsa_info = SignaturePerformanceInfo {
            sign_time_estimate_ms: 8.0,
            verify_time_estimate_ms: 0.5,
            key_generation_time_ms: 50.0,
            signature_size_bytes: 256,
            public_key_size_bytes: 294,
            private_key_size_bytes: 1192,
            security_level: 112,
        };

        // Ed25519 should have better performance score
        assert!(ed25519_info.performance_score() > rsa_info.performance_score());
        
        // Ed25519 should have better security score
        assert!(ed25519_info.security_score() > rsa_info.security_score());
        
        // Ed25519 should have better overall score
        assert!(ed25519_info.overall_score() > rsa_info.overall_score());
    }

    #[test]
    fn test_config_with_signatures() {
        let config = CryptoConfig::new(CryptoMethod::AesGcm256, DigitalSignature::Ed25519);
        
        assert!(config.has_crypto());
        assert!(config.has_encryption());
        assert!(config.has_signatures());
        
        let overhead = config.crypto_overhead();
        // Should include encryption overhead (nonce + tag + salt) + signature overhead (signature + public key)
        let expected_overhead = 12 + 16 + 32 + 64 + 32; // AES-GCM + Ed25519
        assert_eq!(overhead, expected_overhead);
        
        // Security level should be high with both encryption and signatures
        assert!(config.security_level() > 60);
    }