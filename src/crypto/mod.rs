//! Cryptographic module for RuZip
//!
//! Provides comprehensive cryptographic functionality including:
//! - Symmetric encryption (AES-GCM, ChaCha20-Poly1305)
//! - Digital signatures (RSA, Ed25519)
//! - Key derivation (Argon2)
//! - Secure memory handling
//!
//! This module serves as the foundation for all cryptographic operations
//! in RuZip, providing type-safe interfaces and secure defaults.

pub mod aes;
pub mod archive;
pub mod config;
pub mod error;
pub mod signature;
pub mod types;

// Re-export main types for convenience
pub use aes::AesGcmEngine;
pub use archive::{ArchiveCrypto, CryptoArchiveReader, CryptoArchiveWriter, CryptoMetadata};
pub use config::{CryptoConfig, SignaturePerformanceInfo};
pub use error::CryptoError;
pub use signature::{
    ArchiveSignature, DigitalSignatureEngine, Ed25519KeyPair, Ed25519SignatureEngine,
    KeyFormat, PrivateKey, PublicKey, RsaKeyPair, RsaSignatureEngine, SignatureBytes,
    SignatureKeyPair,
};
pub use types::{
    AesKey, CryptoMethod, DigitalSignature, EncryptedData, KeyDerivationParams, Nonce, SecureBytes,
};

/// Result type alias for cryptographic operations
pub type CryptoResult<T> = Result<T, CryptoError>;

/// Cryptographic constants and limits
pub mod constants {
    /// Maximum supported key size in bytes
    pub const MAX_KEY_SIZE: usize = 64;
    
    /// Maximum supported nonce/IV size in bytes
    pub const MAX_NONCE_SIZE: usize = 32;
    
    /// Maximum supported salt size in bytes
    pub const MAX_SALT_SIZE: usize = 64;
    
    /// Minimum supported salt size in bytes
    pub const MIN_SALT_SIZE: usize = 8;
    
    /// Maximum supported signature size in bytes
    pub const MAX_SIGNATURE_SIZE: usize = 512;
    
    /// Default buffer size for cryptographic operations
    pub const DEFAULT_BUFFER_SIZE: usize = 64 * 1024; // 64 KB
    
    /// Maximum memory cost for Argon2 in KiB (2 GiB)
    pub const MAX_ARGON2_MEMORY: u32 = 2 * 1024 * 1024;
    
    /// Minimum memory cost for Argon2 in KiB
    pub const MIN_ARGON2_MEMORY: u32 = 8;
    
    /// Maximum time cost for Argon2
    pub const MAX_ARGON2_TIME: u32 = 100;
    
    /// Minimum time cost for Argon2
    pub const MIN_ARGON2_TIME: u32 = 1;
    
    /// Maximum parallelism for Argon2
    pub const MAX_ARGON2_PARALLELISM: u32 = 16777215;
    
    /// Minimum parallelism for Argon2
    pub const MIN_ARGON2_PARALLELISM: u32 = 1;
}

/// Utility functions for cryptographic operations
pub mod utils {
    use super::{CryptoError, CryptoResult};
    use rand::{RngCore, CryptoRng};
    
    /// Generate cryptographically secure random bytes
    pub fn generate_random_bytes<R: RngCore + CryptoRng>(
        rng: &mut R,
        length: usize,
    ) -> CryptoResult<Vec<u8>> {
        if length == 0 {
            return Err(CryptoError::invalid_parameters(
                "Length must be greater than 0",
                Some("length".to_string()),
            ));
        }
        
        if length > super::constants::MAX_KEY_SIZE * 8 {
            return Err(CryptoError::invalid_parameters(
                format!("Length {} exceeds maximum allowed size", length),
                Some("length".to_string()),
            ));
        }
        
        let mut bytes = vec![0u8; length];
        rng.try_fill_bytes(&mut bytes)
            .map_err(|e| CryptoError::random_generation(
                "Failed to generate random bytes",
                Some(Box::new(e)),
            ))?;
        
        Ok(bytes)
    }
    
    /// Generate a cryptographically secure salt
    pub fn generate_salt<R: RngCore + CryptoRng>(
        rng: &mut R,
        length: usize,
    ) -> CryptoResult<Vec<u8>> {
        if length < super::constants::MIN_SALT_SIZE {
            return Err(CryptoError::invalid_parameters(
                format!("Salt length {} is below minimum {}", length, super::constants::MIN_SALT_SIZE),
                Some("length".to_string()),
            ));
        }
        
        if length > super::constants::MAX_SALT_SIZE {
            return Err(CryptoError::invalid_parameters(
                format!("Salt length {} exceeds maximum {}", length, super::constants::MAX_SALT_SIZE),
                Some("length".to_string()),
            ));
        }
        
        generate_random_bytes(rng, length)
    }
    
    /// Generate a cryptographically secure nonce/IV
    pub fn generate_nonce<R: RngCore + CryptoRng>(
        rng: &mut R,
        length: usize,
    ) -> CryptoResult<Vec<u8>> {
        if length == 0 {
            return Err(CryptoError::invalid_parameters(
                "Nonce length must be greater than 0",
                Some("length".to_string()),
            ));
        }
        
        if length > super::constants::MAX_NONCE_SIZE {
            return Err(CryptoError::invalid_parameters(
                format!("Nonce length {} exceeds maximum {}", length, super::constants::MAX_NONCE_SIZE),
                Some("length".to_string()),
            ));
        }
        
        generate_random_bytes(rng, length)
    }
    
    /// Constant-time comparison of byte slices
    pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
        if a.len() != b.len() {
            return false;
        }
        
        let mut result = 0u8;
        for (x, y) in a.iter().zip(b.iter()) {
            result |= x ^ y;
        }
        
        result == 0
    }
    
    /// Securely clear a mutable byte slice
    pub fn secure_clear(data: &mut [u8]) {
        use zeroize::Zeroize;
        data.zeroize();
    }
    
    /// Validate that a password meets minimum security requirements
    pub fn validate_password(password: &str) -> CryptoResult<()> {
        if password.is_empty() {
            return Err(CryptoError::invalid_parameters(
                "Password cannot be empty",
                Some("password".to_string()),
            ));
        }
        
        if password.len() < 8 {
            return Err(CryptoError::invalid_parameters(
                "Password must be at least 8 characters long",
                Some("password".to_string()),
            ));
        }
        
        if password.len() > 1024 {
            return Err(CryptoError::invalid_parameters(
                "Password is too long (maximum 1024 characters)",
                Some("password".to_string()),
            ));
        }
        
        // Check for basic character diversity
        let has_lower = password.chars().any(|c| c.is_lowercase());
        let has_upper = password.chars().any(|c| c.is_uppercase());
        let has_digit = password.chars().any(|c| c.is_ascii_digit());
        let has_special = password.chars().any(|c| !c.is_alphanumeric());
        
        let diversity_score = [has_lower, has_upper, has_digit, has_special]
            .iter()
            .map(|&b| if b { 1 } else { 0 })
            .sum::<i32>();
        
        if diversity_score < 2 {
            return Err(CryptoError::invalid_parameters(
                "Password should contain at least 2 of: lowercase, uppercase, digits, special characters",
                Some("password".to_string()),
            ));
        }
        
        Ok(())
    }
}

/// AES-GCM utility functions
pub mod aes_utils {
    use super::*;
    use rand::thread_rng;

    /// Generate a new AES-256 key
    pub fn generate_aes_key() -> CryptoResult<AesKey> {
        let mut rng = thread_rng();
        AesGcmEngine::generate_key(&mut rng)
    }

    /// Derive an AES key from password with default parameters
    pub fn derive_key_from_password(password: &str) -> CryptoResult<(AesKey, Vec<u8>)> {
        AesGcmEngine::derive_key_from_password(password, None, None)
    }

    /// Derive an AES key from password with interactive parameters (faster)
    pub fn derive_key_interactive(password: &str) -> CryptoResult<(AesKey, Vec<u8>)> {
        let params = types::KeyDerivationParams::interactive();
        AesGcmEngine::derive_key_from_password(password, None, Some(params))
    }

    /// Derive an AES key from password with sensitive parameters (more secure)
    pub fn derive_key_sensitive(password: &str) -> CryptoResult<(AesKey, Vec<u8>)> {
        let params = types::KeyDerivationParams::sensitive();
        AesGcmEngine::derive_key_from_password(password, None, Some(params))
    }

    /// Encrypt data with a password (convenience function)
    pub fn encrypt_with_password(
        data: &[u8],
        password: &str,
    ) -> CryptoResult<(EncryptedData, Vec<u8>)> {
        let (key, salt) = derive_key_from_password(password)?;
        let engine = AesGcmEngine::new(key)?;
        let encrypted = engine.encrypt(data)?;
        Ok((encrypted, salt))
    }

    /// Decrypt data with a password (convenience function)
    pub fn decrypt_with_password(
        encrypted_data: &EncryptedData,
        password: &str,
        salt: &[u8],
    ) -> CryptoResult<SecureBytes> {
        let (key, _) = AesGcmEngine::derive_key_from_password(password, Some(salt), None)?;
        let engine = AesGcmEngine::new(key)?;
        engine.decrypt(encrypted_data)
    }

    /// Get recommended key derivation parameters based on use case
    pub fn get_recommended_params(use_case: &str) -> types::KeyDerivationParams {
        match use_case.to_lowercase().as_str() {
            "interactive" | "fast" => types::KeyDerivationParams::interactive(),
            "sensitive" | "secure" | "high_security" => types::KeyDerivationParams::sensitive(),
            _ => types::KeyDerivationParams::default(),
        }
    }
}

/// Signature utility functions
pub mod signature_utils {
    use super::*;
    use rand::thread_rng;

    /// Generate a new key pair for the specified algorithm
    pub fn generate_keypair(algorithm: DigitalSignature) -> CryptoResult<SignatureKeyPair> {
        let mut rng = thread_rng();
        match algorithm {
            DigitalSignature::None => Err(CryptoError::invalid_parameters(
                "Cannot generate keypair for None algorithm",
                Some("algorithm".to_string()),
            )),
            DigitalSignature::Rsa2048 => RsaSignatureEngine::generate_keypair(&mut rng),
            DigitalSignature::Ed25519 => Ed25519SignatureEngine::generate_keypair(&mut rng),
        }
    }

    /// Sign data with the appropriate engine based on private key algorithm
    pub fn sign_data(data: &[u8], private_key: &PrivateKey) -> CryptoResult<SignatureBytes> {
        let mut rng = thread_rng();
        match private_key.algorithm() {
            DigitalSignature::None => Err(CryptoError::invalid_parameters(
                "Cannot sign with None algorithm",
                Some("algorithm".to_string()),
            )),
            DigitalSignature::Rsa2048 => {
                let engine = RsaSignatureEngine::new();
                engine.sign(data, private_key, &mut rng)
            }
            DigitalSignature::Ed25519 => {
                let engine = Ed25519SignatureEngine::new();
                engine.sign(data, private_key, &mut rng)
            }
        }
    }

    /// Verify a signature with the appropriate engine based on signature algorithm
    pub fn verify_signature(
        data: &[u8],
        signature: &SignatureBytes,
        public_key: &PublicKey,
    ) -> CryptoResult<bool> {
        // Ensure signature and public key algorithms match
        if signature.algorithm() != public_key.algorithm() {
            return Err(CryptoError::invalid_parameters(
                "Signature and public key algorithms do not match",
                Some("algorithm_mismatch".to_string()),
            ));
        }

        match signature.algorithm() {
            DigitalSignature::None => Err(CryptoError::invalid_parameters(
                "Cannot verify None algorithm signature",
                Some("algorithm".to_string()),
            )),
            DigitalSignature::Rsa2048 => {
                let engine = RsaSignatureEngine::new();
                engine.verify(data, signature, public_key)
            }
            DigitalSignature::Ed25519 => {
                let engine = Ed25519SignatureEngine::new();
                engine.verify(data, signature, public_key)
            }
        }
    }

    /// Export a public key in the specified format
    pub fn export_public_key(public_key: &PublicKey, format: KeyFormat) -> CryptoResult<Vec<u8>> {
        public_key.export(format)
    }

    /// Import a public key from the specified format
    pub fn import_public_key(
        data: &[u8],
        algorithm: DigitalSignature,
        format: KeyFormat,
    ) -> CryptoResult<PublicKey> {
        match format {
            KeyFormat::Raw => Ok(PublicKey::new(data.to_vec(), algorithm)),
            KeyFormat::Pem => {
                // Parse PEM format
                let pem_str = String::from_utf8(data.to_vec()).map_err(|_| {
                    CryptoError::invalid_parameters("Invalid UTF-8 in PEM data", Some("encoding".to_string()))
                })?;

                // Extract base64 content between headers
                let lines: Vec<&str> = pem_str.lines().collect();
                let mut in_key = false;
                let mut base64_content = String::new();

                for line in lines {
                    if line.contains("-----BEGIN") {
                        in_key = true;
                        continue;
                    }
                    if line.contains("-----END") {
                        break;
                    }
                    if in_key {
                        base64_content.push_str(line.trim());
                    }
                }

                // Decode base64 content
                let key_data = base64_decode(&base64_content).map_err(|_| {
                    CryptoError::invalid_parameters("Invalid base64 in PEM data", Some("base64".to_string()))
                })?;

                Ok(PublicKey::new(key_data, algorithm))
            }
            KeyFormat::Der => Ok(PublicKey::new(data.to_vec(), algorithm)),
        }
    }

    /// Create an archive signature for the given data
    pub fn create_archive_signature(
        data: &[u8],
        private_key: &PrivateKey,
        signer_id: Option<String>,
    ) -> CryptoResult<ArchiveSignature> {
        let signature_data = sign_data(data, private_key)?;
        let public_key = match private_key.algorithm() {
            DigitalSignature::Rsa2048 => {
                // For RSA, we need to derive the public key from the private key
                // This is a simplified approach - in practice, you'd store the public key separately
                return Err(CryptoError::invalid_parameters(
                    "RSA public key derivation from private key not implemented in this utility",
                    Some("rsa_key_derivation".to_string()),
                ));
            }
            DigitalSignature::Ed25519 => {
                // For Ed25519, we can derive the public key from the private key
                if private_key.len() != 32 {
                    return Err(CryptoError::invalid_key(
                        "Invalid Ed25519 private key size",
                        Some("key_size".to_string()),
                    ));
                }

                let mut key_bytes = [0u8; 32];
                key_bytes.copy_from_slice(private_key.as_bytes());
                let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
                let verifying_key = signing_key.verifying_key();
                let public_key_bytes = verifying_key.to_bytes().to_vec();

                PublicKey::new(public_key_bytes, DigitalSignature::Ed25519)
            }
            DigitalSignature::None => {
                return Err(CryptoError::invalid_parameters(
                    "Cannot create signature with None algorithm",
                    Some("algorithm".to_string()),
                ));
            }
        };

        Ok(ArchiveSignature::new(
            private_key.algorithm(),
            public_key,
            signature_data,
            signer_id,
        ))
    }

    /// Verify an archive signature
    pub fn verify_archive_signature(
        data: &[u8],
        archive_signature: &ArchiveSignature,
    ) -> CryptoResult<bool> {
        // First validate the archive signature structure
        archive_signature.validate()?;

        // Then verify the actual signature
        verify_signature(
            data,
            &archive_signature.signature_data,
            &archive_signature.public_key,
        )
    }

    /// Get the recommended signature algorithm for a given use case
    pub fn get_recommended_algorithm(use_case: &str) -> DigitalSignature {
        config::CryptoConfig::get_recommended_signature_algorithm(use_case)
    }

    /// Compare performance characteristics of different signature algorithms
    pub fn compare_algorithms() -> Vec<(DigitalSignature, SignaturePerformanceInfo)> {
        vec![
            (
                DigitalSignature::Ed25519,
                config::CryptoConfig::new(CryptoMethod::None, DigitalSignature::Ed25519)
                    .signature_performance_info(),
            ),
            (
                DigitalSignature::Rsa2048,
                config::CryptoConfig::new(CryptoMethod::None, DigitalSignature::Rsa2048)
                    .signature_performance_info(),
            ),
        ]
    }
}

// Simple base64 decoder for PEM parsing
fn base64_decode(input: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    let input = input.replace('\n', "").replace('\r', "").replace(' ', "");
    let mut result = Vec::new();
    let mut i = 0;
    
    while i < input.len() {
        if i + 4 > input.len() {
            break;
        }
        
        let chunk = &input[i..i + 4];
        let mut n = 0u32;
        let mut padding = 0;
        
        for (j, &c) in chunk.as_bytes().iter().enumerate() {
            if c == b'=' {
                padding += 1;
                continue;
            }
            
            let val = CHARS.iter().position(|&x| x == c)
                .ok_or("Invalid base64 character")?;
            n |= (val as u32) << (18 - j * 6);
        }
        
        result.push((n >> 16) as u8);
        if padding < 2 {
            result.push((n >> 8) as u8);
        }
        if padding < 1 {
            result.push(n as u8);
        }
        
        i += 4;
    }
    
    Ok(result)
}

/// Version information for the crypto module
pub const CRYPTO_VERSION: &str = "1.0.0";

/// Supported cryptographic algorithms and their identifiers
pub const SUPPORTED_ALGORITHMS: &[(&str, &str)] = &[
    ("aes-256-gcm", "AES-256 in GCM mode"),
    ("chacha20-poly1305", "ChaCha20-Poly1305 AEAD"),
    ("rsa-2048", "RSA with 2048-bit keys"),
    ("ed25519", "Ed25519 elliptic curve signatures"),
    ("argon2id", "Argon2id key derivation"),
];

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_module_exports() {
        // Test that all main types are accessible
        let _config = CryptoConfig::default();
        let _method = CryptoMethod::None;
        let _signature = DigitalSignature::None;
        let _params = KeyDerivationParams::default();
        let _secure = SecureBytes::new(vec![1, 2, 3]);
    }

    #[test]
    fn test_constants() {
        assert!(constants::MAX_KEY_SIZE > 0);
        assert!(constants::MIN_SALT_SIZE <= constants::MAX_SALT_SIZE);
        assert!(constants::MIN_ARGON2_MEMORY <= constants::MAX_ARGON2_MEMORY);
        assert!(constants::MIN_ARGON2_TIME <= constants::MAX_ARGON2_TIME);
        assert!(constants::MIN_ARGON2_PARALLELISM <= constants::MAX_ARGON2_PARALLELISM);
    }

    #[test]
    fn test_random_generation() {
        let mut rng = thread_rng();
        
        // Test random bytes generation
        let bytes = utils::generate_random_bytes(&mut rng, 32).unwrap();
        assert_eq!(bytes.len(), 32);
        
        // Test that two generations are different
        let bytes2 = utils::generate_random_bytes(&mut rng, 32).unwrap();
        assert_ne!(bytes, bytes2);
        
        // Test error cases
        assert!(utils::generate_random_bytes(&mut rng, 0).is_err());
        assert!(utils::generate_random_bytes(&mut rng, constants::MAX_KEY_SIZE * 10).is_err());
    }

    #[test]
    fn test_salt_generation() {
        let mut rng = thread_rng();
        
        // Test valid salt generation
        let salt = utils::generate_salt(&mut rng, 16).unwrap();
        assert_eq!(salt.len(), 16);
        
        // Test error cases
        assert!(utils::generate_salt(&mut rng, 4).is_err()); // Too short
        assert!(utils::generate_salt(&mut rng, 128).is_err()); // Too long
    }

    #[test]
    fn test_nonce_generation() {
        let mut rng = thread_rng();
        
        // Test valid nonce generation
        let nonce = utils::generate_nonce(&mut rng, 12).unwrap();
        assert_eq!(nonce.len(), 12);
        
        // Test error cases
        assert!(utils::generate_nonce(&mut rng, 0).is_err());
        assert!(utils::generate_nonce(&mut rng, 64).is_err()); // Too long
    }
    
    #[cfg(test)]
    mod aes_utils_tests {
        use super::aes_utils::*;
    
        #[test]
        fn test_generate_aes_key() {
            let key = generate_aes_key().unwrap();
            assert_eq!(key.len(), 32);
        }
    
        #[test]
        fn test_derive_key_from_password() {
            let password = "TestPassword123!";
            let (key, salt) = derive_key_from_password(password).unwrap();
            
            assert_eq!(key.len(), 32);
            assert!(salt.len() >= 8);
        }
    
        #[test]
        fn test_derive_key_interactive() {
            let password = "TestPassword123!";
            let (key, salt) = derive_key_interactive(password).unwrap();
            
            assert_eq!(key.len(), 32);
            assert!(salt.len() >= 8);
        }
    
        #[test]
        fn test_derive_key_sensitive() {
            let password = "TestPassword123!";
            let (key, salt) = derive_key_sensitive(password).unwrap();
            
            assert_eq!(key.len(), 32);
            assert!(salt.len() >= 8);
        }
    
        #[test]
        fn test_encrypt_decrypt_with_password() {
            let password = "TestPassword123!";
            let data = b"Hello, World! This is a test message.";
            
            // Encrypt
            let (encrypted, salt) = encrypt_with_password(data, password).unwrap();
            
            // Decrypt
            let decrypted = decrypt_with_password(&encrypted, password, &salt).unwrap();
            
            assert_eq!(data, decrypted.as_slice());
        }
    
        #[test]
        fn test_get_recommended_params() {
            let interactive = get_recommended_params("interactive");
            assert_eq!(interactive.memory_cost, 4096);
            
            let sensitive = get_recommended_params("sensitive");
            assert_eq!(sensitive.memory_cost, 1048576);
            
            let default = get_recommended_params("unknown");
            assert_eq!(default.memory_cost, 65536);
        }
    
        #[test]
        fn test_password_roundtrip_different_params() {
            let password = "TestPassword123!";
            let data = b"Test data for different parameters";
            
            // Test with interactive params
            let (key_interactive, salt_interactive) = derive_key_interactive(password).unwrap();
            let engine_interactive = super::AesGcmEngine::new(key_interactive).unwrap();
            let encrypted_interactive = engine_interactive.encrypt(data).unwrap();
            let decrypted_interactive = engine_interactive.decrypt(&encrypted_interactive).unwrap();
            assert_eq!(data, decrypted_interactive.as_slice());
            
            // Test with sensitive params
            let (key_sensitive, salt_sensitive) = derive_key_sensitive(password).unwrap();
            let engine_sensitive = super::AesGcmEngine::new(key_sensitive).unwrap();
            let encrypted_sensitive = engine_sensitive.encrypt(data).unwrap();
            let decrypted_sensitive = engine_sensitive.decrypt(&encrypted_sensitive).unwrap();
            assert_eq!(data, decrypted_sensitive.as_slice());
            
            // Keys should be different due to different salts
            assert_ne!(salt_interactive, salt_sensitive);
        }
    }

    #[test]
    fn test_constant_time_eq() {
        assert!(utils::constant_time_eq(b"hello", b"hello"));
        assert!(!utils::constant_time_eq(b"hello", b"world"));
        assert!(!utils::constant_time_eq(b"hello", b"hello world"));
        assert!(!utils::constant_time_eq(b"", b"hello"));
        assert!(utils::constant_time_eq(b"", b""));
    }

    #[test]
    fn test_secure_clear() {
        let mut data = vec![1, 2, 3, 4, 5];
        utils::secure_clear(&mut data);
        assert_eq!(data, vec![0, 0, 0, 0, 0]);
    }

    #[test]
    fn test_password_validation() {
        // Valid passwords
        assert!(utils::validate_password("Password123").is_ok());
        assert!(utils::validate_password("MySecure!Pass").is_ok());
        assert!(utils::validate_password("simple123").is_ok()); // 2 types: lower + digit
        
        // Invalid passwords
        assert!(utils::validate_password("").is_err()); // Empty
        assert!(utils::validate_password("short").is_err()); // Too short
        assert!(utils::validate_password("password").is_err()); // Only lowercase
        assert!(utils::validate_password("PASSWORD").is_err()); // Only uppercase
        assert!(utils::validate_password("12345678").is_err()); // Only digits
        
        // Test very long password
        let long_password = "a".repeat(1025);
        assert!(utils::validate_password(&long_password).is_err());
    }

    #[test]
    fn test_supported_algorithms() {
        assert!(!SUPPORTED_ALGORITHMS.is_empty());
        
        // Check that all algorithms have both ID and description
        for (id, desc) in SUPPORTED_ALGORITHMS {
            assert!(!id.is_empty());
            assert!(!desc.is_empty());
        }
    }

    #[test]
    fn test_crypto_result_type() {
        let success: CryptoResult<i32> = Ok(42);
        assert!(success.is_ok());
        
        let error: CryptoResult<i32> = Err(CryptoError::invalid_key("test", None));
        assert!(error.is_err());
    }
}
#[cfg(test)]
    mod signature_utils_tests {
        use super::signature_utils::*;
        use super::*;

        #[test]
        fn test_generate_keypair() {
            // Test Ed25519 keypair generation
            let ed25519_keypair = generate_keypair(DigitalSignature::Ed25519).unwrap();
            assert_eq!(ed25519_keypair.algorithm(), DigitalSignature::Ed25519);

            // Test RSA keypair generation
            let rsa_keypair = generate_keypair(DigitalSignature::Rsa2048).unwrap();
            assert_eq!(rsa_keypair.algorithm(), DigitalSignature::Rsa2048);

            // Test None algorithm should fail
            let none_result = generate_keypair(DigitalSignature::None);
            assert!(none_result.is_err());
        }

        #[test]
        fn test_sign_verify_data() {
            let keypair = generate_keypair(DigitalSignature::Ed25519).unwrap();
            let private_key = keypair.private_key().unwrap();
            let public_key = keypair.public_key().unwrap();
            let data = b"Test data for signing";

            // Sign the data
            let signature = sign_data(data, &private_key).unwrap();
            assert_eq!(signature.algorithm(), DigitalSignature::Ed25519);

            // Verify the signature
            let is_valid = verify_signature(data, &signature, &public_key).unwrap();
            assert!(is_valid);

            // Verify with wrong data should fail
            let wrong_data = b"Wrong data";
            let is_valid_wrong = verify_signature(wrong_data, &signature, &public_key).unwrap();
            assert!(!is_valid_wrong);
        }

        #[test]
        fn test_algorithm_mismatch() {
            let ed25519_keypair = generate_keypair(DigitalSignature::Ed25519).unwrap();
            let rsa_keypair = generate_keypair(DigitalSignature::Rsa2048).unwrap();

            let ed25519_private = ed25519_keypair.private_key().unwrap();
            let rsa_public = rsa_keypair.public_key().unwrap();
            let data = b"Test data";

            // Sign with Ed25519
            let ed25519_signature = sign_data(data, &ed25519_private).unwrap();

            // Try to verify with RSA public key should fail
            let result = verify_signature(data, &ed25519_signature, &rsa_public);
            assert!(result.is_err());
        }

        #[test]
        fn test_key_export_import() {
            let keypair = generate_keypair(DigitalSignature::Ed25519).unwrap();
            let public_key = keypair.public_key().unwrap();

            // Test raw format
            let exported_raw = export_public_key(&public_key, KeyFormat::Raw).unwrap();
            let imported_raw = import_public_key(&exported_raw, DigitalSignature::Ed25519, KeyFormat::Raw).unwrap();
            assert_eq!(public_key.as_bytes(), imported_raw.as_bytes());

            // Test PEM format
            let exported_pem = export_public_key(&public_key, KeyFormat::Pem).unwrap();
            let pem_str = String::from_utf8(exported_pem.clone()).unwrap();
            assert!(pem_str.contains("-----BEGIN PUBLIC KEY-----"));
            assert!(pem_str.contains("-----END PUBLIC KEY-----"));

            let imported_pem = import_public_key(&exported_pem, DigitalSignature::Ed25519, KeyFormat::Pem).unwrap();
            assert_eq!(public_key.as_bytes(), imported_pem.as_bytes());
        }

        #[test]
        fn test_archive_signature() {
            let keypair = generate_keypair(DigitalSignature::Ed25519).unwrap();
            let private_key = keypair.private_key().unwrap();
            let data = b"Archive data to be signed";

            // Create archive signature
            let archive_sig = create_archive_signature(data, &private_key, Some("test-signer".to_string())).unwrap();

            // Verify archive signature
            let is_valid = verify_archive_signature(data, &archive_sig).unwrap();
            assert!(is_valid);

            // Verify with wrong data should fail
            let wrong_data = b"Wrong archive data";
            let is_valid_wrong = verify_archive_signature(wrong_data, &archive_sig).unwrap();
            assert!(!is_valid_wrong);
        }

        #[test]
        fn test_algorithm_recommendations() {
            assert_eq!(get_recommended_algorithm("performance"), DigitalSignature::Ed25519);
            assert_eq!(get_recommended_algorithm("compatibility"), DigitalSignature::Rsa2048);
            assert_eq!(get_recommended_algorithm("security"), DigitalSignature::Ed25519);
            assert_eq!(get_recommended_algorithm("none"), DigitalSignature::None);
        }

        #[test]
        fn test_algorithm_comparison() {
            let comparisons = compare_algorithms();
            assert_eq!(comparisons.len(), 2);

            let ed25519_info = comparisons.iter().find(|(alg, _)| *alg == DigitalSignature::Ed25519).unwrap();
            let rsa_info = comparisons.iter().find(|(alg, _)| *alg == DigitalSignature::Rsa2048).unwrap();

            // Ed25519 should be faster
            assert!(ed25519_info.1.sign_time_estimate_ms < rsa_info.1.sign_time_estimate_ms);
            assert!(ed25519_info.1.verify_time_estimate_ms < rsa_info.1.verify_time_estimate_ms);

            // Ed25519 should have smaller signatures
            assert!(ed25519_info.1.signature_size_bytes < rsa_info.1.signature_size_bytes);
        }

        #[test]
        fn test_base64_decode() {
            let test_data = b"Hello, World!";
            let encoded = base64_encode(test_data);
            let decoded = super::base64_decode(&encoded).unwrap();
            assert_eq!(test_data, decoded.as_slice());
        }
    }

// Helper function for testing
#[cfg(test)]
fn base64_encode(input: &[u8]) -> String {
    use std::fmt::Write;
    const CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    
    let mut result = String::new();
    let mut i = 0;
    while i < input.len() {
        let b1 = input[i];
        let b2 = if i + 1 < input.len() { input[i + 1] } else { 0 };
        let b3 = if i + 2 < input.len() { input[i + 2] } else { 0 };
        
        let n = ((b1 as u32) << 16) | ((b2 as u32) << 8) | (b3 as u32);
        
        let _ = write!(result, "{}", CHARS[((n >> 18) & 63) as usize] as char);
        let _ = write!(result, "{}", CHARS[((n >> 12) & 63) as usize] as char);
        let _ = write!(result, "{}", if i + 1 < input.len() { CHARS[((n >> 6) & 63) as usize] as char } else { '=' });
        let _ = write!(result, "{}", if i + 2 < input.len() { CHARS[(n & 63) as usize] as char } else { '=' });
        
        i += 3;
    }
    result
}