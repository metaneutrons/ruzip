//! AES-256-GCM encryption implementation for RuZip
//!
//! Provides secure symmetric encryption using AES-256 in Galois/Counter Mode (GCM)
//! with automatic nonce generation and authentication.

use crate::crypto::{
    error::CryptoError,
    types::{AesKey, EncryptedData, KeyDerivationParams, Nonce, SecureBytes},
    utils, CryptoResult,
};
use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Key, Nonce as AesNonce,
};
use argon2::Argon2;
use rand::{CryptoRng, RngCore};
use std::time::Instant;
use zeroize::{Zeroize, ZeroizeOnDrop};

/// AES-256-GCM encryption engine
pub struct AesGcmEngine {
    cipher: Aes256Gcm,
    key: AesKey,
}

impl AesGcmEngine {
    /// Create a new AES-GCM engine with the provided key
    pub fn new(key: AesKey) -> CryptoResult<Self> {
        let cipher_key = Key::<Aes256Gcm>::from_slice(key.as_bytes());
        let cipher = Aes256Gcm::new(cipher_key);
        
        Ok(Self { cipher, key })
    }

    /// Create a new AES-GCM engine from raw key bytes
    pub fn from_key_bytes(key_bytes: &[u8]) -> CryptoResult<Self> {
        let key = AesKey::new(key_bytes.to_vec())?;
        Self::new(key)
    }

    /// Generate a new random AES key
    pub fn generate_key<R: RngCore + CryptoRng>(rng: &mut R) -> CryptoResult<AesKey> {
        let key_bytes = utils::generate_random_bytes(rng, 32)?;
        AesKey::new(key_bytes)
    }

    /// Derive an AES key from a password using Argon2id
    pub fn derive_key_from_password(
        password: &str,
        salt: Option<&[u8]>,
        params: Option<KeyDerivationParams>,
    ) -> CryptoResult<(AesKey, Vec<u8>)> {
        // Validate password
        utils::validate_password(password)?;

        let params = params.unwrap_or_else(|| KeyDerivationParams::default());
        params.validate()?;

        // Generate or use provided salt
        let salt_bytes = if let Some(salt) = salt {
            if salt.len() < 8 || salt.len() > 64 {
                return Err(CryptoError::invalid_parameters(
                    "Salt must be between 8 and 64 bytes",
                    Some("salt_length".to_string()),
                ));
            }
            salt.to_vec()
        } else {
            let mut rng = rand::thread_rng();
            utils::generate_salt(&mut rng, params.salt_length)?
        };

        let start_time = Instant::now();

        // Configure Argon2id
        let argon2_params = argon2::Params::new(
            params.memory_cost,
            params.time_cost,
            params.parallelism,
            Some(32), // Output length for AES-256
        )
        .map_err(|e| {
            CryptoError::key_derivation(
                format!("Invalid Argon2 parameters: {}", e),
                None,
            )
        })?;

        let argon2 = Argon2::new(
            argon2::Algorithm::Argon2id,
            argon2::Version::V0x13,
            argon2_params,
        );

        // Derive key directly using hash_password_into
        let mut key_bytes = [0u8; 32];
        argon2
            .hash_password_into(password.as_bytes(), &salt_bytes, &mut key_bytes)
            .map_err(|e| {
                CryptoError::key_derivation(
                    format!("Password hashing failed: {}", e),
                    None,
                )
            })?;

        let key = AesKey::new(key_bytes.to_vec())?;

        let duration = start_time.elapsed();
        tracing::debug!(
            "Key derivation completed in {:?} (memory: {}KB, time: {}, parallelism: {})",
            duration,
            params.memory_cost,
            params.time_cost,
            params.parallelism
        );

        Ok((key, salt_bytes))
    }

    /// Encrypt data with automatic nonce generation
    pub fn encrypt(&self, plaintext: &[u8]) -> CryptoResult<EncryptedData> {
        self.encrypt_with_rng(plaintext, &mut OsRng)
    }

    /// Encrypt data with a custom RNG for nonce generation
    pub fn encrypt_with_rng<R: RngCore + CryptoRng>(
        &self,
        plaintext: &[u8],
        rng: &mut R,
    ) -> CryptoResult<EncryptedData> {
        if plaintext.is_empty() {
            return Err(CryptoError::invalid_parameters(
                "Plaintext cannot be empty",
                Some("plaintext".to_string()),
            ));
        }

        // Generate random nonce
        let nonce_bytes = utils::generate_nonce(rng, 12)?;
        let mut nonce_array = [0u8; 12];
        nonce_array.copy_from_slice(&nonce_bytes);
        let nonce = Nonce::new(nonce_array);

        // Encrypt
        let aes_nonce = AesNonce::from_slice(nonce.as_bytes());
        let ciphertext_with_tag = self
            .cipher
            .encrypt(aes_nonce, plaintext)
            .map_err(|_| CryptoError::encryption("AES-GCM encryption failed", None))?;

        // Split ciphertext and tag
        if ciphertext_with_tag.len() < 16 {
            return Err(CryptoError::encryption(
                "Invalid ciphertext length",
                None,
            ));
        }

        let (ciphertext, tag_slice) = ciphertext_with_tag.split_at(ciphertext_with_tag.len() - 16);
        let mut tag = [0u8; 16];
        tag.copy_from_slice(tag_slice);

        Ok(EncryptedData::new(ciphertext.to_vec(), nonce, tag))
    }

    /// Decrypt data with authentication verification
    pub fn decrypt(&self, encrypted_data: &EncryptedData) -> CryptoResult<SecureBytes> {
        if encrypted_data.ciphertext().is_empty() {
            return Err(CryptoError::invalid_parameters(
                "Ciphertext cannot be empty",
                Some("ciphertext".to_string()),
            ));
        }

        // Reconstruct the full ciphertext with tag
        let mut ciphertext_with_tag = encrypted_data.ciphertext().to_vec();
        ciphertext_with_tag.extend_from_slice(encrypted_data.tag());

        // Decrypt and authenticate
        let aes_nonce = AesNonce::from_slice(encrypted_data.nonce().as_bytes());
        let plaintext = self
            .cipher
            .decrypt(aes_nonce, ciphertext_with_tag.as_slice())
            .map_err(|_| {
                CryptoError::decryption("AES-GCM decryption failed (authentication error)", None)
            })?;

        Ok(SecureBytes::new(plaintext))
    }

    /// Get the key used by this engine
    pub fn key(&self) -> &AesKey {
        &self.key
    }
}

impl Drop for AesGcmEngine {
    fn drop(&mut self) {
        // Key is automatically zeroized by AesKey's Drop implementation
    }
}

impl Zeroize for AesGcmEngine {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl ZeroizeOnDrop for AesGcmEngine {}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_key_generation() {
        let mut rng = thread_rng();
        let key = AesGcmEngine::generate_key(&mut rng).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_key_derivation() {
        let password = "TestPassword123!";
        let (key, salt) = AesGcmEngine::derive_key_from_password(password, None, None).unwrap();
        
        assert_eq!(key.len(), 32);
        assert!(salt.len() >= 8);

        // Test with same password and salt should produce same key
        let (key2, _) = AesGcmEngine::derive_key_from_password(password, Some(&salt), None).unwrap();
        assert_eq!(key.as_bytes(), key2.as_bytes());
    }

    #[test]
    fn test_key_derivation_with_custom_params() {
        let password = "TestPassword123!";
        let params = KeyDerivationParams::interactive();
        let (key, _) = AesGcmEngine::derive_key_from_password(password, None, Some(params)).unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_encryption_decryption_roundtrip() {
        let mut rng = thread_rng();
        let key = AesGcmEngine::generate_key(&mut rng).unwrap();
        let engine = AesGcmEngine::new(key).unwrap();

        let plaintext = b"Hello, World! This is a test message for AES-GCM encryption.";
        let encrypted = engine.encrypt(plaintext).unwrap();
        let decrypted = engine.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
        assert_eq!(encrypted.nonce().len(), 12);
        assert_eq!(encrypted.tag().len(), 16);
    }

    #[test]
    fn test_nonce_uniqueness() {
        let mut rng = thread_rng();
        let key = AesGcmEngine::generate_key(&mut rng).unwrap();
        let engine = AesGcmEngine::new(key).unwrap();

        let plaintext = b"Test message";
        let encrypted1 = engine.encrypt(plaintext).unwrap();
        let encrypted2 = engine.encrypt(plaintext).unwrap();

        // Nonces should be different
        assert_ne!(encrypted1.nonce(), encrypted2.nonce());
        
        // But both should decrypt to the same plaintext
        let decrypted1 = engine.decrypt(&encrypted1).unwrap();
        let decrypted2 = engine.decrypt(&encrypted2).unwrap();
        assert_eq!(decrypted1.as_slice(), decrypted2.as_slice());
        assert_eq!(plaintext, decrypted1.as_slice());
    }

    #[test]
    fn test_authentication_failure() {
        let mut rng = thread_rng();
        let key = AesGcmEngine::generate_key(&mut rng).unwrap();
        let engine = AesGcmEngine::new(key).unwrap();

        let plaintext = b"Test message";
        let mut encrypted = engine.encrypt(plaintext).unwrap();

        // Tamper with ciphertext
        encrypted.ciphertext[0] ^= 1;

        // Decryption should fail due to authentication error
        assert!(engine.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_tag_tampering() {
        let mut rng = thread_rng();
        let key = AesGcmEngine::generate_key(&mut rng).unwrap();
        let engine = AesGcmEngine::new(key).unwrap();

        let plaintext = b"Test message";
        let mut encrypted = engine.encrypt(plaintext).unwrap();

        // Tamper with authentication tag
        encrypted.tag[0] ^= 1;

        // Decryption should fail
        assert!(engine.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_empty_plaintext() {
        let mut rng = thread_rng();
        let key = AesGcmEngine::generate_key(&mut rng).unwrap();
        let engine = AesGcmEngine::new(key).unwrap();

        // Empty plaintext should be rejected
        assert!(engine.encrypt(b"").is_err());
    }

    #[test]
    fn test_large_data() {
        let mut rng = thread_rng();
        let key = AesGcmEngine::generate_key(&mut rng).unwrap();
        let engine = AesGcmEngine::new(key).unwrap();

        // Test with 1MB of data
        let plaintext = vec![0x42u8; 1024 * 1024];
        let encrypted = engine.encrypt(&plaintext).unwrap();
        let decrypted = engine.decrypt(&encrypted).unwrap();

        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_serialization_roundtrip() {
        let mut rng = thread_rng();
        let key = AesGcmEngine::generate_key(&mut rng).unwrap();
        let engine = AesGcmEngine::new(key).unwrap();

        let plaintext = b"Test serialization";
        let encrypted = engine.encrypt(plaintext).unwrap();
        
        // Serialize and deserialize
        let serialized = encrypted.to_bytes();
        let deserialized = EncryptedData::from_bytes(&serialized).unwrap();
        
        assert_eq!(encrypted, deserialized);
        
        // Decrypt deserialized data
        let decrypted = engine.decrypt(&deserialized).unwrap();
        assert_eq!(plaintext, decrypted.as_slice());
    }

    #[test]
    fn test_password_validation() {
        // Valid passwords
        assert!(AesGcmEngine::derive_key_from_password("Password123!", None, None).is_ok());
        
        // Invalid passwords
        assert!(AesGcmEngine::derive_key_from_password("", None, None).is_err());
        assert!(AesGcmEngine::derive_key_from_password("short", None, None).is_err());
        assert!(AesGcmEngine::derive_key_from_password("onlylowercase", None, None).is_err());
    }

    #[test]
    fn test_key_zeroization() {
        let mut rng = thread_rng();
        let mut key = AesGcmEngine::generate_key(&mut rng).unwrap();
        
        // Key should contain non-zero data
        assert!(key.as_bytes().iter().any(|&b| b != 0));
        
        // Zeroize the key
        key.zeroize();
        
        // Key should now be all zeros
        assert!(key.as_bytes().iter().all(|&b| b == 0));
    }

    #[test]
    fn test_performance_benchmark() {
        let mut rng = thread_rng();
        let key = AesGcmEngine::generate_key(&mut rng).unwrap();
        let engine = AesGcmEngine::new(key).unwrap();

        // Test with 10MB of data
        let plaintext = vec![0x42u8; 10 * 1024 * 1024];
        
        let start = Instant::now();
        let encrypted = engine.encrypt(&plaintext).unwrap();
        let encrypt_duration = start.elapsed();
        
        let start = Instant::now();
        let _decrypted = engine.decrypt(&encrypted).unwrap();
        let decrypt_duration = start.elapsed();
        
        println!("Encryption: {:.2} MB/s", 10.0 / encrypt_duration.as_secs_f64());
        println!("Decryption: {:.2} MB/s", 10.0 / decrypt_duration.as_secs_f64());
        
        // Performance should be reasonable (>5 MB/s on modern hardware)
        assert!(encrypt_duration.as_millis() < 5000); // Less than 5 seconds for 10MB
        assert!(decrypt_duration.as_millis() < 5000);
    }

    #[test]
    fn test_concurrent_operations() {
        use std::sync::Arc;
        use std::thread;

        let mut rng = thread_rng();
        let key = AesGcmEngine::generate_key(&mut rng).unwrap();
        let engine = Arc::new(AesGcmEngine::new(key).unwrap());

        let handles: Vec<_> = (0..4)
            .map(|i| {
                let engine = Arc::clone(&engine);
                thread::spawn(move || {
                    let plaintext = format!("Thread {} test message", i);
                    let encrypted = engine.encrypt(plaintext.as_bytes()).unwrap();
                    let decrypted = engine.decrypt(&encrypted).unwrap();
                    assert_eq!(plaintext.as_bytes(), decrypted.as_slice());
                })
            })
            .collect();

        for handle in handles {
            handle.join().unwrap();
        }
    }
}