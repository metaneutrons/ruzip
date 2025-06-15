//! Digital signature implementation for RuZip
//!
//! Provides RSA-2048-PSS and Ed25519 digital signature functionality
//! with secure key generation, signing, and verification.

use crate::crypto::{
    error::CryptoError,
    types::{DigitalSignature, SecureBytes},
    CryptoResult,
};
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::fmt;
use zeroize::{Zeroize, ZeroizeOnDrop};

// Re-export signature-related types
pub use ed25519_dalek::{Signature as Ed25519Signature, Signer, Verifier};
pub use rsa::{
    pkcs1v15::SigningKey as RsaSigningKey,
    pss::{BlindedSigningKey as RsaPssSigningKey, VerifyingKey as RsaPssVerifyingKey},
    signature::{RandomizedSigner, SignatureEncoding},
    RsaPrivateKey, RsaPublicKey,
};
pub use sha2::Sha256;

/// Maximum signature size across all supported algorithms
pub const MAX_SIGNATURE_SIZE: usize = 256; // RSA-2048 signatures

/// RSA key size in bits
pub const RSA_KEY_SIZE: usize = 2048;

/// Ed25519 signature size in bytes
pub const ED25519_SIGNATURE_SIZE: usize = 64;

/// RSA signature size in bytes
pub const RSA_SIGNATURE_SIZE: usize = 256;

/// Ed25519 public key size in bytes
pub const ED25519_PUBLIC_KEY_SIZE: usize = 32;

/// Ed25519 private key size in bytes
pub const ED25519_PRIVATE_KEY_SIZE: usize = 32;

/// Key formats for import/export
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyFormat {
    /// PEM format (Base64 encoded with headers)
    Pem,
    /// DER format (binary ASN.1)
    Der,
    /// Raw bytes (algorithm-specific)
    Raw,
}

impl Default for KeyFormat {
    fn default() -> Self {
        Self::Pem
    }
}

/// Signature bytes wrapper with size validation
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignatureBytes {
    data: Vec<u8>,
    algorithm: DigitalSignature,
}

impl SignatureBytes {
    /// Create new signature bytes with validation
    pub fn new(data: Vec<u8>, algorithm: DigitalSignature) -> CryptoResult<Self> {
        let expected_size = algorithm.signature_size();
        if data.len() != expected_size {
            return Err(CryptoError::invalid_parameters(
                format!(
                    "Invalid signature size for {}: expected {}, got {}",
                    algorithm.name(),
                    expected_size,
                    data.len()
                ),
                Some("signature_size".to_string()),
            ));
        }
        Ok(Self { data, algorithm })
    }

    /// Get signature data as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get the signature algorithm
    pub fn algorithm(&self) -> DigitalSignature {
        self.algorithm
    }

    /// Get signature length
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if signature is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
}

impl fmt::Debug for SignatureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "SignatureBytes({}, {} bytes)",
            self.algorithm.name(),
            self.data.len()
        )
    }
}

/// Public key wrapper with algorithm information
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicKey {
    data: Vec<u8>,
    algorithm: DigitalSignature,
}

impl PublicKey {
    /// Create new public key
    pub fn new(data: Vec<u8>, algorithm: DigitalSignature) -> Self {
        Self { data, algorithm }
    }

    /// Get key data as bytes
    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    /// Get the signature algorithm
    pub fn algorithm(&self) -> DigitalSignature {
        self.algorithm
    }

    /// Get key length
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if key is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Export key in specified format
    pub fn export(&self, format: KeyFormat) -> CryptoResult<Vec<u8>> {
        match format {
            KeyFormat::Raw => Ok(self.data.clone()),
            KeyFormat::Pem => {
                // For PEM format, we need to encode based on algorithm
                match self.algorithm {
                    DigitalSignature::Ed25519 => {
                        // Ed25519 keys are typically stored as raw bytes in PEM
                        let pem_data = format!(
                            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
                            base64::encode(&self.data)
                        );
                        Ok(pem_data.into_bytes())
                    }
                    DigitalSignature::Rsa2048 => {
                        // RSA keys should already be in DER format, convert to PEM
                        let pem_data = format!(
                            "-----BEGIN PUBLIC KEY-----\n{}\n-----END PUBLIC KEY-----\n",
                            base64::encode(&self.data)
                        );
                        Ok(pem_data.into_bytes())
                    }
                    DigitalSignature::None => Err(CryptoError::invalid_parameters(
                        "Cannot export key for None algorithm",
                        None,
                    )),
                }
            }
            KeyFormat::Der => {
                // For DER format, return as-is for RSA, encode for Ed25519
                match self.algorithm {
                    DigitalSignature::Rsa2048 => Ok(self.data.clone()),
                    DigitalSignature::Ed25519 => {
                        // Ed25519 keys need to be wrapped in DER structure
                        // This is a simplified implementation
                        Ok(self.data.clone())
                    }
                    DigitalSignature::None => Err(CryptoError::invalid_parameters(
                        "Cannot export key for None algorithm",
                        None,
                    )),
                }
            }
        }
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PublicKey({}, {} bytes)",
            self.algorithm.name(),
            self.data.len()
        )
    }
}

/// Private key wrapper with secure memory handling
#[derive(Clone, PartialEq, Eq)]
pub struct PrivateKey {
    data: SecureBytes,
    algorithm: DigitalSignature,
}

impl Zeroize for PrivateKey {
    fn zeroize(&mut self) {
        self.data.zeroize();
    }
}

impl ZeroizeOnDrop for PrivateKey {}

impl PrivateKey {
    /// Create new private key
    pub fn new(data: Vec<u8>, algorithm: DigitalSignature) -> Self {
        Self {
            data: SecureBytes::new(data),
            algorithm,
        }
    }

    /// Get key data as bytes
    pub fn as_bytes(&self) -> &[u8] {
        self.data.as_slice()
    }

    /// Get the signature algorithm
    pub fn algorithm(&self) -> DigitalSignature {
        self.algorithm
    }

    /// Get key length
    pub fn len(&self) -> usize {
        self.data.len()
    }

    /// Check if key is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Export key in specified format (use with caution)
    pub fn export(&self, format: KeyFormat) -> CryptoResult<SecureBytes> {
        match format {
            KeyFormat::Raw => Ok(SecureBytes::new(self.data.as_slice().to_vec())),
            KeyFormat::Pem => {
                // For PEM format, we need to encode based on algorithm
                match self.algorithm {
                    DigitalSignature::Ed25519 => {
                        let pem_data = format!(
                            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
                            base64::encode(self.data.as_slice())
                        );
                        Ok(SecureBytes::new(pem_data.into_bytes()))
                    }
                    DigitalSignature::Rsa2048 => {
                        let pem_data = format!(
                            "-----BEGIN PRIVATE KEY-----\n{}\n-----END PRIVATE KEY-----\n",
                            base64::encode(self.data.as_slice())
                        );
                        Ok(SecureBytes::new(pem_data.into_bytes()))
                    }
                    DigitalSignature::None => Err(CryptoError::invalid_parameters(
                        "Cannot export key for None algorithm",
                        None,
                    )),
                }
            }
            KeyFormat::Der => Ok(SecureBytes::new(self.data.as_slice().to_vec())),
        }
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "PrivateKey({}, [REDACTED; {}])",
            self.algorithm.name(),
            self.data.len()
        )
    }
}

/// Key pair container
#[derive(Debug, Clone)]
pub enum SignatureKeyPair {
    /// RSA key pair
    Rsa(RsaKeyPair),
    /// Ed25519 key pair
    Ed25519(Ed25519KeyPair),
}

impl SignatureKeyPair {
    /// Get the algorithm for this key pair
    pub fn algorithm(&self) -> DigitalSignature {
        match self {
            SignatureKeyPair::Rsa(_) => DigitalSignature::Rsa2048,
            SignatureKeyPair::Ed25519(_) => DigitalSignature::Ed25519,
        }
    }

    /// Get the public key
    pub fn public_key(&self) -> CryptoResult<PublicKey> {
        match self {
            SignatureKeyPair::Rsa(rsa_pair) => rsa_pair.public_key(),
            SignatureKeyPair::Ed25519(ed_pair) => ed_pair.public_key(),
        }
    }

    /// Get the private key
    pub fn private_key(&self) -> CryptoResult<PrivateKey> {
        match self {
            SignatureKeyPair::Rsa(rsa_pair) => rsa_pair.private_key(),
            SignatureKeyPair::Ed25519(ed_pair) => ed_pair.private_key(),
        }
    }
}

/// RSA key pair
#[derive(Debug, Clone)]
pub struct RsaKeyPair {
    private_key: RsaPrivateKey,
    public_key: RsaPublicKey,
}

impl RsaKeyPair {
    /// Create new RSA key pair
    pub fn new(private_key: RsaPrivateKey) -> Self {
        let public_key = private_key.to_public_key();
        Self {
            private_key,
            public_key,
        }
    }

    /// Get the public key
    pub fn public_key(&self) -> CryptoResult<PublicKey> {
        use rsa::pkcs8::EncodePublicKey;
        let der_bytes = self
            .public_key
            .to_public_key_der()
            .map_err(|e| CryptoError::key_generation("Failed to encode RSA public key", Some(Box::new(e))))?
            .as_bytes()
            .to_vec();
        Ok(PublicKey::new(der_bytes, DigitalSignature::Rsa2048))
    }

    /// Get the private key
    pub fn private_key(&self) -> CryptoResult<PrivateKey> {
        use rsa::pkcs8::EncodePrivateKey;
        let der_bytes = self
            .private_key
            .to_pkcs8_der()
            .map_err(|e| CryptoError::key_generation("Failed to encode RSA private key", Some(Box::new(e))))?
            .as_bytes()
            .to_vec();
        Ok(PrivateKey::new(der_bytes, DigitalSignature::Rsa2048))
    }

    /// Get reference to internal RSA private key
    pub fn rsa_private_key(&self) -> &RsaPrivateKey {
        &self.private_key
    }

    /// Get reference to internal RSA public key
    pub fn rsa_public_key(&self) -> &RsaPublicKey {
        &self.public_key
    }
}

/// Ed25519 key pair
#[derive(Debug, Clone)]
pub struct Ed25519KeyPair {
    signing_key: ed25519_dalek::SigningKey,
    verifying_key: ed25519_dalek::VerifyingKey,
}

impl Ed25519KeyPair {
    /// Create new Ed25519 key pair
    pub fn new(signing_key: ed25519_dalek::SigningKey) -> Self {
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Get the public key
    pub fn public_key(&self) -> CryptoResult<PublicKey> {
        let key_bytes = self.verifying_key.to_bytes().to_vec();
        Ok(PublicKey::new(key_bytes, DigitalSignature::Ed25519))
    }

    /// Get the private key
    pub fn private_key(&self) -> CryptoResult<PrivateKey> {
        let key_bytes = self.signing_key.to_bytes().to_vec();
        Ok(PrivateKey::new(key_bytes, DigitalSignature::Ed25519))
    }

    /// Get reference to internal signing key
    pub fn signing_key(&self) -> &ed25519_dalek::SigningKey {
        &self.signing_key
    }

    /// Get reference to internal verifying key
    pub fn verifying_key(&self) -> &ed25519_dalek::VerifyingKey {
        &self.verifying_key
    }
}

/// Archive signature containing all signature metadata
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArchiveSignature {
    /// Signature method used
    pub signature_method: DigitalSignature,
    /// Public key for verification
    pub public_key: PublicKey,
    /// Signature data
    pub signature_data: SignatureBytes,
    /// Timestamp when signature was created
    pub timestamp: u64,
    /// Optional signer identifier
    pub signer_id: Option<String>,
}

impl ArchiveSignature {
    /// Create new archive signature
    pub fn new(
        signature_method: DigitalSignature,
        public_key: PublicKey,
        signature_data: SignatureBytes,
        signer_id: Option<String>,
    ) -> Self {
        Self {
            signature_method,
            public_key,
            signature_data,
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
            signer_id,
        }
    }

    /// Verify that the signature components are consistent
    pub fn validate(&self) -> CryptoResult<()> {
        if self.signature_method != self.public_key.algorithm() {
            return Err(CryptoError::invalid_parameters(
                "Signature method does not match public key algorithm",
                Some("signature_method".to_string()),
            ));
        }

        if self.signature_method != self.signature_data.algorithm() {
            return Err(CryptoError::invalid_parameters(
                "Signature method does not match signature data algorithm",
                Some("signature_method".to_string()),
            ));
        }

        Ok(())
    }

    /// Get signature age in seconds
    pub fn age_seconds(&self) -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs()
            .saturating_sub(self.timestamp)
    }
}

/// Common interface for digital signature engines
pub trait DigitalSignatureEngine {
    /// Generate a new key pair
    fn generate_keypair<R: RngCore + CryptoRng>(rng: &mut R) -> CryptoResult<SignatureKeyPair>;

    /// Sign data with a private key
    fn sign<R: RngCore + CryptoRng>(
        &self,
        data: &[u8],
        private_key: &PrivateKey,
        rng: &mut R,
    ) -> CryptoResult<SignatureBytes>;

    /// Verify a signature with a public key
    fn verify(
        &self,
        data: &[u8],
        signature: &SignatureBytes,
        public_key: &PublicKey,
    ) -> CryptoResult<bool>;

    /// Get the algorithm this engine supports
    fn algorithm(&self) -> DigitalSignature;
}

/// RSA-2048-PSS signature engine
#[derive(Debug, Clone)]
pub struct RsaSignatureEngine;

impl RsaSignatureEngine {
    /// Create new RSA signature engine
    pub fn new() -> Self {
        Self
    }
}

impl Default for RsaSignatureEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl DigitalSignatureEngine for RsaSignatureEngine {
    fn generate_keypair<R: RngCore + CryptoRng>(rng: &mut R) -> CryptoResult<SignatureKeyPair> {
        let private_key = RsaPrivateKey::new(rng, RSA_KEY_SIZE).map_err(|e| {
            CryptoError::key_generation("Failed to generate RSA private key", Some(Box::new(e)))
        })?;

        Ok(SignatureKeyPair::Rsa(RsaKeyPair::new(private_key)))
    }

    fn sign<R: RngCore + CryptoRng>(
        &self,
        data: &[u8],
        private_key: &PrivateKey,
        rng: &mut R,
    ) -> CryptoResult<SignatureBytes> {
        if private_key.algorithm() != DigitalSignature::Rsa2048 {
            return Err(CryptoError::invalid_key(
                "Private key is not RSA-2048",
                Some("algorithm".to_string()),
            ));
        }

        // Parse the private key from DER format
        use rsa::pkcs8::DecodePrivateKey;
        let rsa_key = RsaPrivateKey::from_pkcs8_der(private_key.as_bytes()).map_err(|_e| {
            CryptoError::invalid_key("Failed to parse RSA private key", Some("rsa_private_key".to_string()))
        })?;

        // Create PSS signing key
        let signing_key = RsaPssSigningKey::<Sha256>::new(rsa_key);

        // Sign the data
        let signature = signing_key.sign_with_rng(rng, data);
        let signature_bytes = signature.to_bytes().to_vec();

        SignatureBytes::new(signature_bytes, DigitalSignature::Rsa2048)
    }

    fn verify(
        &self,
        data: &[u8],
        signature: &SignatureBytes,
        public_key: &PublicKey,
    ) -> CryptoResult<bool> {
        if signature.algorithm() != DigitalSignature::Rsa2048 {
            return Err(CryptoError::invalid_parameters(
                "Signature is not RSA-2048",
                Some("algorithm".to_string()),
            ));
        }

        if public_key.algorithm() != DigitalSignature::Rsa2048 {
            return Err(CryptoError::invalid_key(
                "Public key is not RSA-2048",
                Some("algorithm".to_string()),
            ));
        }

        // Parse the public key from DER format
        use rsa::pkcs8::DecodePublicKey;
        let rsa_key = RsaPublicKey::from_public_key_der(public_key.as_bytes()).map_err(|_e| {
            CryptoError::invalid_key("Failed to parse RSA public key", Some("rsa_public_key".to_string()))
        })?;

        // Create PSS verifying key
        let verifying_key = RsaPssVerifyingKey::<Sha256>::new(rsa_key);

        // Parse signature
        let signature = rsa::pss::Signature::try_from(signature.as_bytes()).map_err(|_e| {
            CryptoError::invalid_parameters("Invalid RSA signature format", Some("signature_format".to_string()))
        })?;

        // Verify the signature
        use rsa::signature::Verifier;
        match verifying_key.verify(data, &signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn algorithm(&self) -> DigitalSignature {
        DigitalSignature::Rsa2048
    }
}

/// Ed25519 signature engine
#[derive(Debug, Clone)]
pub struct Ed25519SignatureEngine;

impl Ed25519SignatureEngine {
    /// Create new Ed25519 signature engine
    pub fn new() -> Self {
        Self
    }
}

impl Default for Ed25519SignatureEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl DigitalSignatureEngine for Ed25519SignatureEngine {
    fn generate_keypair<R: RngCore + CryptoRng>(rng: &mut R) -> CryptoResult<SignatureKeyPair> {
        let mut key_bytes = [0u8; 32];
        rng.fill_bytes(&mut key_bytes);
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);
        Ok(SignatureKeyPair::Ed25519(Ed25519KeyPair::new(signing_key)))
    }

    fn sign<R: RngCore + CryptoRng>(
        &self,
        data: &[u8],
        private_key: &PrivateKey,
        _rng: &mut R, // Ed25519 signing is deterministic
    ) -> CryptoResult<SignatureBytes> {
        if private_key.algorithm() != DigitalSignature::Ed25519 {
            return Err(CryptoError::invalid_key(
                "Private key is not Ed25519",
                Some("algorithm".to_string()),
            ));
        }

        // Parse the private key
        if private_key.len() != ED25519_PRIVATE_KEY_SIZE {
            return Err(CryptoError::invalid_key(
                "Invalid Ed25519 private key size",
                Some("key_size".to_string()),
            ));
        }

        let mut key_bytes = [0u8; ED25519_PRIVATE_KEY_SIZE];
        key_bytes.copy_from_slice(private_key.as_bytes());
        let signing_key = ed25519_dalek::SigningKey::from_bytes(&key_bytes);

        // Sign the data
        let signature = signing_key.sign(data);
        let signature_bytes = signature.to_bytes().to_vec();

        SignatureBytes::new(signature_bytes, DigitalSignature::Ed25519)
    }

    fn verify(
        &self,
        data: &[u8],
        signature: &SignatureBytes,
        public_key: &PublicKey,
    ) -> CryptoResult<bool> {
        if signature.algorithm() != DigitalSignature::Ed25519 {
            return Err(CryptoError::invalid_parameters(
                "Signature is not Ed25519",
                Some("algorithm".to_string()),
            ));
        }

        if public_key.algorithm() != DigitalSignature::Ed25519 {
            return Err(CryptoError::invalid_key(
                "Public key is not Ed25519",
                Some("algorithm".to_string()),
            ));
        }

        // Parse the public key
        if public_key.len() != ED25519_PUBLIC_KEY_SIZE {
            return Err(CryptoError::invalid_key(
                "Invalid Ed25519 public key size",
                Some("key_size".to_string()),
            ));
        }

        let mut key_bytes = [0u8; ED25519_PUBLIC_KEY_SIZE];
        key_bytes.copy_from_slice(public_key.as_bytes());
        let verifying_key = ed25519_dalek::VerifyingKey::from_bytes(&key_bytes).map_err(|_e| {
            CryptoError::invalid_key("Invalid Ed25519 public key", Some("ed25519_public_key".to_string()))
        })?;

        // Parse signature
        if signature.len() != ED25519_SIGNATURE_SIZE {
            return Err(CryptoError::invalid_parameters(
                "Invalid Ed25519 signature size",
                Some("signature_size".to_string()),
            ));
        }

        let mut sig_bytes = [0u8; ED25519_SIGNATURE_SIZE];
        sig_bytes.copy_from_slice(signature.as_bytes());
        let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes);

        // Verify the signature
        match verifying_key.verify(data, &signature) {
            Ok(()) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    fn algorithm(&self) -> DigitalSignature {
        DigitalSignature::Ed25519
    }
}

// Add base64 dependency for PEM encoding
mod base64 {
    pub fn encode(input: &[u8]) -> String {
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::thread_rng;

    #[test]
    fn test_rsa_key_generation() {
        let mut rng = thread_rng();
        let keypair = RsaSignatureEngine::generate_keypair(&mut rng).unwrap();
        
        assert_eq!(keypair.algorithm(), DigitalSignature::Rsa2048);
        
        let public_key = keypair.public_key().unwrap();
        let private_key = keypair.private_key().unwrap();
        
        assert_eq!(public_key.algorithm(), DigitalSignature::Rsa2048);
        assert_eq!(private_key.algorithm(), DigitalSignature::Rsa2048);
        assert!(public_key.len() > 0);
        assert!(private_key.len() > 0);
    }

    #[test]
    fn test_ed25519_key_generation() {
        let mut rng = thread_rng();
        let keypair = Ed25519SignatureEngine::generate_keypair(&mut rng).unwrap();
        
        assert_eq!(keypair.algorithm(), DigitalSignature::Ed25519);
        
        let public_key = keypair.public_key().unwrap();
        let private_key = keypair.private_key().unwrap();
        
        assert_eq!(public_key.algorithm(), DigitalSignature::Ed25519);
        assert_eq!(private_key.algorithm(), DigitalSignature::Ed25519);
        assert_eq!(public_key.len(), ED25519_PUBLIC_KEY_SIZE);
        assert_eq!(private_key.len(), ED25519_PRIVATE_KEY_SIZE);
    }

    #[test]
    fn test_rsa_sign_verify_roundtrip() {
        let mut rng = thread_rng();
        let engine = RsaSignatureEngine::new();
        let keypair = RsaSignatureEngine::generate_keypair(&mut rng).unwrap();
        
        let public_key = keypair.public_key().unwrap();
        let private_key = keypair.private_key().unwrap();
        
        let data = b"Hello, World! This is a test message for RSA signing.";
        
        // Sign the data
        let signature = engine.sign(data, &private_key, &mut rng).unwrap();
        assert_eq!(signature.len(), RSA_SIGNATURE_SIZE);
        assert_eq!(signature.algorithm(), DigitalSignature::Rsa2048);
        
        // Verify the signature
        let is_valid = engine.verify(data, &signature, &public_key).unwrap();
        assert!(is_valid);
        
        // Verify with wrong data should fail
        let wrong_data = b"Wrong data";
        let is_valid_wrong = engine.verify(wrong_data, &signature, &public_key).unwrap();
        assert!(!is_valid_wrong);
    }

    #[test]
    fn test_ed25519_sign_verify_roundtrip() {
        let mut rng = thread_rng();
        let engine = Ed25519SignatureEngine::new();
        let keypair = Ed25519SignatureEngine::generate_keypair(&mut rng).unwrap();
        
        let public_key = keypair.public_key().unwrap();
        let private_key = keypair.private_key().unwrap();
        
        let data = b"Hello, World! This is a test message for Ed25519 signing.";
        
        // Sign the data
        let signature = engine.sign(data, &private_key, &mut rng).unwrap();
        assert_eq!(signature.len(), ED25519_SIGNATURE_SIZE);
        assert_eq!(signature.algorithm(), DigitalSignature::Ed25519);
        
        // Verify the signature
        let is_valid = engine.verify(data, &signature, &public_key).unwrap();
        assert!(is_valid);
        
        // Verify with wrong data should fail
        let wrong_data = b"Wrong data";
        let is_valid_wrong = engine.verify(wrong_data, &signature, &public_key).unwrap();
        assert!(!is_valid_wrong);
    }

    #[test]
    fn test_cross_algorithm_compatibility() {
        let mut rng = thread_rng();
        
        // Generate RSA and Ed25519 keypairs
        let rsa_keypair = RsaSignatureEngine::generate_keypair(&mut rng).unwrap();
        let ed25519_keypair = Ed25519SignatureEngine::generate_keypair(&mut rng).unwrap();
        
        let rsa_engine = RsaSignatureEngine::new();
        let ed25519_engine = Ed25519SignatureEngine::new();
        
        let data = b"Cross-compatibility test data";
        
        // RSA sign, Ed25519 verify should fail gracefully
        let rsa_private = rsa_keypair.private_key().unwrap();
        let ed25519_public = ed25519_keypair.public_key().unwrap();
        
        let rsa_signature = rsa_engine.sign(data, &rsa_private, &mut rng).unwrap();
        
        // This should return an error, not panic
        let result = ed25519_engine.verify(data, &rsa_signature, &ed25519_public);
        assert!(result.is_err());
    }

    #[test]
    fn test_signature_tampering_detection() {
        let mut rng = thread_rng();
        let engine = Ed25519SignatureEngine::new();
        let keypair = Ed25519SignatureEngine::generate_keypair(&mut rng).unwrap();
        
        let public_key = keypair.public_key().unwrap();
        let private_key = keypair.private_key().unwrap();
        let data = b"Important data that should not be tampered with";
        
        // Create valid signature
        let signature = engine.sign(data, &private_key, &mut rng).unwrap();
        
        // Verify original signature
        assert!(engine.verify(data, &signature, &public_key).unwrap());
        
        // Tamper with signature by modifying one byte
        let tampered_sig_data = {
            let mut sig_data = signature.as_bytes().to_vec();
            sig_data[0] ^= 0x01; // Flip one bit
            SignatureBytes::new(sig_data, DigitalSignature::Ed25519).unwrap()
        };
        
        // Verification should fail
        assert!(!engine.verify(data, &tampered_sig_data, &public_key).unwrap());
    }

    #[test]
    fn test_large_data_signing() {
        let mut rng = thread_rng();
        let engine = RsaSignatureEngine::new();
        let keypair = RsaSignatureEngine::generate_keypair(&mut rng).unwrap();
        
        let public_key = keypair.public_key().unwrap();
        let private_key = keypair.private_key().unwrap();
        
        // Create large data (1MB)
        let large_data = vec![0xAB; 1024 * 1024];
        
        // Sign and verify large data
        let signature = engine.sign(&large_data, &private_key, &mut rng).unwrap();
        let is_valid = engine.verify(&large_data, &signature, &public_key).unwrap();
        assert!(is_valid);
    }

    #[test]
    fn test_key_serialization() {
        let mut rng = thread_rng();
        let keypair = Ed25519SignatureEngine::generate_keypair(&mut rng).unwrap();
        
        let public_key = keypair.public_key().unwrap();
        let private_key = keypair.private_key().unwrap();
        
        // Test raw format export
        let pub_raw = public_key.export(KeyFormat::Raw).unwrap();
        let priv_raw = private_key.export(KeyFormat::Raw).unwrap();
        
        assert_eq!(pub_raw.len(), ED25519_PUBLIC_KEY_SIZE);
        assert_eq!(priv_raw.len(), ED25519_PRIVATE_KEY_SIZE);
        
        // Test PEM format export
        let pub_pem = public_key.export(KeyFormat::Pem).unwrap();
        let priv_pem = private_key.export(KeyFormat::Pem).unwrap();
        
        let pub_pem_str = String::from_utf8(pub_pem).unwrap();
        let priv_pem_str = String::from_utf8(priv_pem.as_slice().to_vec()).unwrap();
        
        assert!(pub_pem_str.contains("-----BEGIN PUBLIC KEY-----"));
        assert!(pub_pem_str.contains("-----END PUBLIC KEY-----"));
        assert!(priv_pem_str.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(priv_pem_str.contains("-----END PRIVATE KEY-----"));
    }

    #[test]
    fn test_archive_signature() {
        let mut rng = thread_rng();
        let keypair = Ed25519SignatureEngine::generate_keypair(&mut rng).unwrap();
        let engine = Ed25519SignatureEngine::new();
        
        let public_key = keypair.public_key().unwrap();
        let private_key = keypair.private_key().unwrap();
        let data = b"Archive data to be signed";
        
        // Create signature
        let signature_data = engine.sign(data, &private_key, &mut rng).unwrap();
        
        // Create archive signature
        let archive_sig = ArchiveSignature::new(
            DigitalSignature::Ed25519,
            public_key.clone(),
            signature_data,
            Some("test-signer".to_string()),
        );
        
        // Validate archive signature
        assert!(archive_sig.validate().is_ok());
        assert_eq!(archive_sig.signature_method, DigitalSignature::Ed25519);
        assert_eq!(archive_sig.signer_id, Some("test-signer".to_string()));
        assert!(archive_sig.timestamp > 0);
        assert_eq!(archive_sig.age_seconds(), 0); // Should be very recent
    }

    #[test]
    fn test_signature_bytes_validation() {
        // Valid Ed25519 signature
        let valid_ed25519_data = vec![0u8; ED25519_SIGNATURE_SIZE];
        let sig = SignatureBytes::new(valid_ed25519_data, DigitalSignature::Ed25519);
        assert!(sig.is_ok());
        
        // Invalid Ed25519 signature size
        let invalid_ed25519_data = vec![0u8; 32]; // Wrong size
        let sig = SignatureBytes::new(invalid_ed25519_data, DigitalSignature::Ed25519);
        assert!(sig.is_err());
        
        // Valid RSA signature
        let valid_rsa_data = vec![0u8; RSA_SIGNATURE_SIZE];
        let sig = SignatureBytes::new(valid_rsa_data, DigitalSignature::Rsa2048);
        assert!(sig.is_ok());
        
        // Invalid RSA signature size
        let invalid_rsa_data = vec![0u8; 128]; // Wrong size
        let sig = SignatureBytes::new(invalid_rsa_data, DigitalSignature::Rsa2048);
        assert!(sig.is_err());
    }

    #[test]
    fn test_performance_comparison() {
        use std::time::Instant;
        
        let mut rng = thread_rng();
        let data = b"Performance test data for signing benchmarks";
        
        // RSA performance
        let rsa_keypair = RsaSignatureEngine::generate_keypair(&mut rng).unwrap();
        let rsa_engine = RsaSignatureEngine::new();
        let rsa_private = rsa_keypair.private_key().unwrap();
        let rsa_public = rsa_keypair.public_key().unwrap();
        
        let rsa_sign_start = Instant::now();
        let rsa_signature = rsa_engine.sign(data, &rsa_private, &mut rng).unwrap();
        let rsa_sign_time = rsa_sign_start.elapsed();
        
        let rsa_verify_start = Instant::now();
        let rsa_valid = rsa_engine.verify(data, &rsa_signature, &rsa_public).unwrap();
        let rsa_verify_time = rsa_verify_start.elapsed();
        
        assert!(rsa_valid);
        
        // Ed25519 performance
        let ed25519_keypair = Ed25519SignatureEngine::generate_keypair(&mut rng).unwrap();
        let ed25519_engine = Ed25519SignatureEngine::new();
        let ed25519_private = ed25519_keypair.private_key().unwrap();
        let ed25519_public = ed25519_keypair.public_key().unwrap();
        
        let ed25519_sign_start = Instant::now();
        let ed25519_signature = ed25519_engine.sign(data, &ed25519_private, &mut rng).unwrap();
        let ed25519_sign_time = ed25519_sign_start.elapsed();
        
        let ed25519_verify_start = Instant::now();
        let ed25519_valid = ed25519_engine.verify(data, &ed25519_signature, &ed25519_public).unwrap();
        let ed25519_verify_time = ed25519_verify_start.elapsed();
        
        assert!(ed25519_valid);
        
        // Ed25519 should be faster than RSA for both signing and verification
        println!("RSA sign: {:?}, verify: {:?}", rsa_sign_time, rsa_verify_time);
        println!("Ed25519 sign: {:?}, verify: {:?}", ed25519_sign_time, ed25519_verify_time);
        
        // These are performance expectations, not hard requirements for the test
        // Ed25519 is typically much faster than RSA
        assert!(ed25519_sign_time < rsa_sign_time);
        assert!(ed25519_verify_time < rsa_verify_time);
    }

    #[test]
    fn test_thread_safety() {
        use std::sync::Arc;
        use std::thread;
        
        let mut rng = thread_rng();
        let keypair = Arc::new(Ed25519SignatureEngine::generate_keypair(&mut rng).unwrap());
        let engine = Arc::new(Ed25519SignatureEngine::new());
        
        let handles: Vec<_> = (0..4)
            .map(|i| {
                let keypair = Arc::clone(&keypair);
                let engine = Arc::clone(&engine);
                
                thread::spawn(move || {
                    let mut thread_rng = thread_rng();
                    let data = format!("Thread {} test data", i);
                    
                    let public_key = keypair.public_key().unwrap();
                    let private_key = keypair.private_key().unwrap();
                    
                    let signature = engine.sign(data.as_bytes(), &private_key, &mut thread_rng).unwrap();
                    let is_valid = engine.verify(data.as_bytes(), &signature, &public_key).unwrap();
                    
                    assert!(is_valid);
                    i
                })
            })
            .collect();
        
        for handle in handles {
            let result = handle.join().unwrap();
            assert!(result < 4);
        }
    }
}