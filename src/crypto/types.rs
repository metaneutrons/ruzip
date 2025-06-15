//! Cryptographic types and structures for RuZip
//!
//! Core types for encryption, key derivation, and digital signatures.

use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Supported cryptographic methods for encryption
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CryptoMethod {
    /// No encryption
    None,
    /// AES-256 in GCM mode
    AesGcm256,
    /// ChaCha20-Poly1305 AEAD
    ChaCha20Poly1305,
}

impl Default for CryptoMethod {
    fn default() -> Self {
        Self::None
    }
}

impl CryptoMethod {
    /// Get the key size in bytes for this method
    pub fn key_size(&self) -> usize {
        match self {
            CryptoMethod::None => 0,
            CryptoMethod::AesGcm256 => 32, // 256 bits
            CryptoMethod::ChaCha20Poly1305 => 32, // 256 bits
        }
    }

    /// Get the nonce/IV size in bytes for this method
    pub fn nonce_size(&self) -> usize {
        match self {
            CryptoMethod::None => 0,
            CryptoMethod::AesGcm256 => 12, // 96 bits for GCM
            CryptoMethod::ChaCha20Poly1305 => 12, // 96 bits
        }
    }

    /// Get the authentication tag size in bytes
    pub fn tag_size(&self) -> usize {
        match self {
            CryptoMethod::None => 0,
            CryptoMethod::AesGcm256 => 16, // 128 bits
            CryptoMethod::ChaCha20Poly1305 => 16, // 128 bits
        }
    }

    /// Check if this method requires encryption
    pub fn requires_encryption(&self) -> bool {
        !matches!(self, CryptoMethod::None)
    }

    /// Get a human-readable name for this method
    pub fn name(&self) -> &'static str {
        match self {
            CryptoMethod::None => "None",
            CryptoMethod::AesGcm256 => "AES-256-GCM",
            CryptoMethod::ChaCha20Poly1305 => "ChaCha20-Poly1305",
        }
    }
}

/// Supported digital signature algorithms
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum DigitalSignature {
    /// No digital signature
    None,
    /// RSA with 2048-bit keys and PKCS#1 v1.5 padding
    Rsa2048,
    /// Ed25519 elliptic curve signatures
    Ed25519,
}

impl Default for DigitalSignature {
    fn default() -> Self {
        Self::None
    }
}

impl DigitalSignature {
    /// Get the signature size in bytes
    pub fn signature_size(&self) -> usize {
        match self {
            DigitalSignature::None => 0,
            DigitalSignature::Rsa2048 => 256, // 2048 bits
            DigitalSignature::Ed25519 => 64, // 512 bits
        }
    }

    /// Get the public key size in bytes
    pub fn public_key_size(&self) -> usize {
        match self {
            DigitalSignature::None => 0,
            DigitalSignature::Rsa2048 => 294, // DER encoded
            DigitalSignature::Ed25519 => 32, // 256 bits
        }
    }

    /// Get the private key size in bytes (approximate)
    pub fn private_key_size(&self) -> usize {
        match self {
            DigitalSignature::None => 0,
            DigitalSignature::Rsa2048 => 1192, // DER encoded
            DigitalSignature::Ed25519 => 32, // 256 bits
        }
    }

    /// Check if this method requires signing
    pub fn requires_signing(&self) -> bool {
        !matches!(self, DigitalSignature::None)
    }

    /// Get a human-readable name for this method
    pub fn name(&self) -> &'static str {
        match self {
            DigitalSignature::None => "None",
            DigitalSignature::Rsa2048 => "RSA-2048",
            DigitalSignature::Ed25519 => "Ed25519",
        }
    }
}

/// Parameters for Argon2 key derivation
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyDerivationParams {
    /// Memory cost in KiB (default: 65536 = 64 MiB)
    pub memory_cost: u32,
    /// Time cost (iterations, default: 3)
    pub time_cost: u32,
    /// Parallelism (threads, default: 4)
    pub parallelism: u32,
    /// Salt length in bytes (default: 32)
    pub salt_length: usize,
    /// Output key length in bytes
    pub output_length: usize,
}

impl Default for KeyDerivationParams {
    fn default() -> Self {
        Self {
            memory_cost: 65536, // 64 MiB
            time_cost: 3,
            parallelism: 4,
            salt_length: 32,
            output_length: 32, // 256 bits
        }
    }
}

impl KeyDerivationParams {
    /// Create new parameters with custom values
    pub fn new(
        memory_cost: u32,
        time_cost: u32,
        parallelism: u32,
        salt_length: usize,
        output_length: usize,
    ) -> Self {
        Self {
            memory_cost,
            time_cost,
            parallelism,
            salt_length,
            output_length,
        }
    }

    /// Create parameters optimized for interactive use (faster)
    pub fn interactive() -> Self {
        Self {
            memory_cost: 4096, // 4 MiB
            time_cost: 3,
            parallelism: 1,
            salt_length: 16,
            output_length: 32,
        }
    }

    /// Create parameters optimized for sensitive data (slower, more secure)
    pub fn sensitive() -> Self {
        Self {
            memory_cost: 1048576, // 1 GiB
            time_cost: 4,
            parallelism: 8,
            salt_length: 32,
            output_length: 32,
        }
    }

    /// Validate the parameters
    pub fn validate(&self) -> Result<(), crate::crypto::error::CryptoError> {
        if self.memory_cost < 8 {
            return Err(crate::crypto::error::CryptoError::invalid_parameters(
                "Memory cost must be at least 8 KiB",
                Some("memory_cost".to_string()),
            ));
        }

        if self.time_cost < 1 {
            return Err(crate::crypto::error::CryptoError::invalid_parameters(
                "Time cost must be at least 1",
                Some("time_cost".to_string()),
            ));
        }

        if self.parallelism < 1 || self.parallelism > 16777215 {
            return Err(crate::crypto::error::CryptoError::invalid_parameters(
                "Parallelism must be between 1 and 16777215",
                Some("parallelism".to_string()),
            ));
        }

        if self.salt_length < 8 || self.salt_length > 64 {
            return Err(crate::crypto::error::CryptoError::invalid_parameters(
                "Salt length must be between 8 and 64 bytes",
                Some("salt_length".to_string()),
            ));
        }

        if self.output_length < 4 || self.output_length > 4294967295 {
            return Err(crate::crypto::error::CryptoError::invalid_parameters(
                "Output length must be between 4 and 4294967295 bytes",
                Some("output_length".to_string()),
            ));
        }

        Ok(())
    }
}

/// Secure byte container that automatically zeros memory on drop
#[derive(Clone, PartialEq, Eq)]
pub struct SecureBytes {
    data: Vec<u8>,
}

impl Zeroize for SecureBytes {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl ZeroizeOnDrop for SecureBytes {}

impl SecureBytes {
    /// Create a new SecureBytes container
    pub fn new(data: Vec<u8>) -> Self {
        Self { data }
    }

    /// Create a SecureBytes container with the specified capacity
    pub fn with_capacity(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
        }
    }

    /// Create a SecureBytes container filled with zeros
    pub fn zeros(len: usize) -> Self {
        Self {
            data: vec![0u8; len],
        }
    }

    /// Get the length of the data
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if the container is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Get a reference to the underlying data
    pub fn as_slice(&self) -> &[u8] {
        &self.data
    }

    /// Get a mutable reference to the underlying data
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        &mut self.data
    }

    /// Extend the container with additional data
    pub fn extend_from_slice(&mut self, other: &[u8]) {
        self.data.extend_from_slice(other);
    }

    /// Push a single byte
    pub fn push(&mut self, byte: u8) {
        self.data.push(byte);
    }

    /// Clear the container (zeros the memory)
    pub fn clear(&mut self) {
        self.data.zeroize();
        self.data.clear();
    }

    /// Convert to a Vec<u8> (consumes self)
    pub fn into_vec(self) -> Vec<u8> {
        self.data
    }
}

impl std::fmt::Debug for SecureBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecureBytes([REDACTED; {}])", self.data.len())
    }
}

impl From<Vec<u8>> for SecureBytes {
    fn from(data: Vec<u8>) -> Self {
        Self::new(data)
    }
}

impl From<&[u8]> for SecureBytes {
    fn from(data: &[u8]) -> Self {
        Self::new(data.to_vec())
    }
}

impl AsRef<[u8]> for SecureBytes {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

impl AsMut<[u8]> for SecureBytes {
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.data
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_crypto_method_properties() {
        assert_eq!(CryptoMethod::AesGcm256.key_size(), 32);
        assert_eq!(CryptoMethod::AesGcm256.nonce_size(), 12);
        assert_eq!(CryptoMethod::AesGcm256.tag_size(), 16);
        assert!(CryptoMethod::AesGcm256.requires_encryption());
        assert_eq!(CryptoMethod::AesGcm256.name(), "AES-256-GCM");

        assert!(!CryptoMethod::None.requires_encryption());
        assert_eq!(CryptoMethod::None.key_size(), 0);
    }

    #[test]
    fn test_digital_signature_properties() {
        assert_eq!(DigitalSignature::Ed25519.signature_size(), 64);
        assert_eq!(DigitalSignature::Ed25519.public_key_size(), 32);
        assert!(DigitalSignature::Ed25519.requires_signing());
        assert_eq!(DigitalSignature::Ed25519.name(), "Ed25519");

        assert!(!DigitalSignature::None.requires_signing());
        assert_eq!(DigitalSignature::None.signature_size(), 0);
    }

    #[test]
    fn test_key_derivation_params_validation() {
        let valid_params = KeyDerivationParams::default();
        assert!(valid_params.validate().is_ok());

        let invalid_params = KeyDerivationParams {
            memory_cost: 4, // Too low
            ..Default::default()
        };
        assert!(invalid_params.validate().is_err());

        let interactive = KeyDerivationParams::interactive();
        assert!(interactive.validate().is_ok());
        assert_eq!(interactive.memory_cost, 4096);

        let sensitive = KeyDerivationParams::sensitive();
        assert!(sensitive.validate().is_ok());
        assert_eq!(sensitive.memory_cost, 1048576);
    }

    #[test]
    fn test_secure_bytes() {
        let mut secure = SecureBytes::new(vec![1, 2, 3, 4]);
        assert_eq!(secure.len(), 4);
        assert!(!secure.is_empty());
        assert_eq!(secure.as_slice(), &[1, 2, 3, 4]);

        secure.push(5);
        assert_eq!(secure.len(), 5);

        secure.extend_from_slice(&[6, 7]);
        assert_eq!(secure.len(), 7);

        let zeros = SecureBytes::zeros(10);
        assert_eq!(zeros.len(), 10);
        assert_eq!(zeros.as_slice(), &[0u8; 10]);
    }

    #[test]
    fn test_secure_bytes_debug() {
        let secure = SecureBytes::new(vec![1, 2, 3, 4]);
        let debug_str = format!("{:?}", secure);
        assert!(debug_str.contains("REDACTED"));
        assert!(debug_str.contains("4"));
        assert!(!debug_str.contains("1"));
    }

    #[test]
    fn test_secure_bytes_conversions() {
        let data = vec![1, 2, 3, 4];
        let secure: SecureBytes = data.clone().into();
        assert_eq!(secure.as_slice(), &data);

        let slice_data: &[u8] = &[5, 6, 7, 8];
        let secure_from_slice: SecureBytes = slice_data.into();
        assert_eq!(secure_from_slice.as_slice(), slice_data);
    }

    #[test]
    fn test_defaults() {
        assert_eq!(CryptoMethod::default(), CryptoMethod::None);
        assert_eq!(DigitalSignature::default(), DigitalSignature::None);

        let default_params = KeyDerivationParams::default();
        assert_eq!(default_params.memory_cost, 65536);
        assert_eq!(default_params.time_cost, 3);
        assert_eq!(default_params.parallelism, 4);
    }
}

/// AES-256 key wrapper with automatic zeroization
#[derive(Clone, PartialEq, Eq)]
pub struct AesKey {
    key: SecureBytes,
}

impl Zeroize for AesKey {
    fn zeroize(&mut self) {
        self.key.zeroize();
    }
}

impl ZeroizeOnDrop for AesKey {}

impl AesKey {
    /// Create a new AES key from raw bytes
    pub fn new(key: Vec<u8>) -> Result<Self, crate::crypto::error::CryptoError> {
        if key.len() != 32 {
            return Err(crate::crypto::error::CryptoError::invalid_key(
                "AES key must be exactly 32 bytes (256 bits)",
                Some("key_length".to_string()),
            ));
        }
        Ok(Self {
            key: SecureBytes::new(key),
        })
    }

    /// Create a new AES key from a SecureBytes container
    pub fn from_secure_bytes(key: SecureBytes) -> Result<Self, crate::crypto::error::CryptoError> {
        if key.len() != 32 {
            return Err(crate::crypto::error::CryptoError::invalid_key(
                "AES key must be exactly 32 bytes (256 bits)",
                Some("key_length".to_string()),
            ));
        }
        Ok(Self { key })
    }

    /// Get the key as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        self.key.as_slice()
    }

    /// Get the key length in bytes
    pub fn len(&self) -> usize {
        self.key.len()
    }

    /// Check if the key is empty (should never be true for valid AES keys)
    pub fn is_empty(&self) -> bool {
        self.key.is_empty()
    }
}

impl std::fmt::Debug for AesKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "AesKey([REDACTED; 32])")
    }
}

/// AES-GCM nonce (96-bit)
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nonce {
    nonce: [u8; 12],
}

impl Nonce {
    /// Create a new nonce from raw bytes
    pub fn new(nonce: [u8; 12]) -> Self {
        Self { nonce }
    }

    /// Create a nonce from a slice
    pub fn from_slice(slice: &[u8]) -> Result<Self, crate::crypto::error::CryptoError> {
        if slice.len() != 12 {
            return Err(crate::crypto::error::CryptoError::invalid_parameters(
                "Nonce must be exactly 12 bytes (96 bits)",
                Some("nonce_length".to_string()),
            ));
        }
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(slice);
        Ok(Self { nonce })
    }

    /// Get the nonce as a byte slice
    pub fn as_bytes(&self) -> &[u8] {
        &self.nonce
    }

    /// Get the nonce as an array
    pub fn as_array(&self) -> &[u8; 12] {
        &self.nonce
    }

    /// Get the nonce length in bytes
    pub fn len(&self) -> usize {
        12
    }

    /// Check if the nonce is empty (should never be true)
    pub fn is_empty(&self) -> bool {
        false
    }
}

impl std::fmt::Debug for Nonce {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Nonce({})", hex::encode(&self.nonce))
    }
}

impl From<[u8; 12]> for Nonce {
    fn from(nonce: [u8; 12]) -> Self {
        Self::new(nonce)
    }
}

impl AsRef<[u8]> for Nonce {
    fn as_ref(&self) -> &[u8] {
        &self.nonce
    }
}

/// Encrypted data container with nonce and authentication tag
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EncryptedData {
    /// The encrypted ciphertext
    pub ciphertext: Vec<u8>,
    /// The nonce used for encryption
    pub nonce: Nonce,
    /// The authentication tag
    pub tag: [u8; 16],
}

impl EncryptedData {
    /// Create new encrypted data
    pub fn new(ciphertext: Vec<u8>, nonce: Nonce, tag: [u8; 16]) -> Self {
        Self {
            ciphertext,
            nonce,
            tag,
        }
    }

    /// Get the total size of the encrypted data (ciphertext + nonce + tag)
    pub fn total_size(&self) -> usize {
        self.ciphertext.len() + 12 + 16
    }

    /// Get the ciphertext length
    pub fn ciphertext_len(&self) -> usize {
        self.ciphertext.len()
    }

    /// Get the nonce
    pub fn nonce(&self) -> &Nonce {
        &self.nonce
    }

    /// Get the authentication tag
    pub fn tag(&self) -> &[u8; 16] {
        &self.tag
    }

    /// Get the ciphertext
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }

    /// Serialize to bytes (nonce + tag + ciphertext)
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut result = Vec::with_capacity(self.total_size());
        result.extend_from_slice(self.nonce.as_bytes());
        result.extend_from_slice(&self.tag);
        result.extend_from_slice(&self.ciphertext);
        result
    }

    /// Deserialize from bytes
    pub fn from_bytes(data: &[u8]) -> Result<Self, crate::crypto::error::CryptoError> {
        if data.len() < 28 {
            return Err(crate::crypto::error::CryptoError::invalid_parameters(
                "Encrypted data must be at least 28 bytes (12 nonce + 16 tag)",
                Some("data_length".to_string()),
            ));
        }

        let nonce = Nonce::from_slice(&data[0..12])?;
        let mut tag = [0u8; 16];
        tag.copy_from_slice(&data[12..28]);
        let ciphertext = data[28..].to_vec();

        Ok(Self::new(ciphertext, nonce, tag))
    }
}

impl std::fmt::Debug for EncryptedData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("EncryptedData")
            .field("ciphertext_len", &self.ciphertext.len())
            .field("nonce", &self.nonce)
            .field("tag", &hex::encode(&self.tag))
            .finish()
    }
}
/// Signature-specific types and wrappers
pub mod signature_types {
    
    /// Re-export signature types from the signature module
    pub use crate::crypto::signature::{
        ArchiveSignature, Ed25519KeyPair, KeyFormat, PrivateKey, PublicKey, 
        RsaKeyPair, SignatureBytes, SignatureKeyPair,
    };
}