//! Integration tests for cryptographic archive functionality
//!
//! Tests the complete end-to-end workflow of encrypted and signed archives.

use ruzip::crypto::{
    CryptoArchiveReader, CryptoArchiveWriter, CryptoConfig, CryptoMethod, DigitalSignature,
    KeyDerivationParams, signature_utils,
};
use ruzip::error::Result;
use ruzip::threading::ThreadConfig;
use std::io::Cursor;
use tempfile::TempDir;

#[test]
fn test_encrypted_archive_roundtrip() -> Result<()> {
    // Create test data
    let test_data = b"Hello, World! This is a test file for encryption.";
    let password = "TestPassword123!";
    
    // Create crypto config for encryption
    let crypto_config = CryptoConfig {
        encryption_method: CryptoMethod::AesGcm256,
        signature_method: DigitalSignature::None,
        key_derivation_params: KeyDerivationParams::interactive(), // Faster for tests
    };
    
    // Create encrypted archive
    let mut archive_data = Vec::new();
    {
        let writer = Cursor::new(&mut archive_data);
        let mut crypto_writer = CryptoArchiveWriter::new(
            writer,
            crypto_config.clone(),
            None, // No threading for simple test
        )?;
        
        // Initialize encryption
        crypto_writer.init_encryption(password)?;
        
        // Add test data
        crypto_writer.add_data("test.txt", test_data, None)?;
        
        // Finalize archive
        crypto_writer.finalize()?;
    }
    
    // Read and decrypt archive
    {
        let reader = Cursor::new(&archive_data);
        let mut crypto_reader = CryptoArchiveReader::new(reader)?;
        
        // Initialize decryption
        crypto_reader.init_decryption(password)?;
        
        // Load entries
        crypto_reader.load_entries()?;
        
        // Verify we have one entry
        assert_eq!(crypto_reader.entries().len(), 1);
        assert_eq!(crypto_reader.entries()[0].path, "test.txt");
        
        // Extract and verify data
        let extracted_data = crypto_reader.extract_file(0)?;
        assert_eq!(extracted_data, test_data);
    }
    
    Ok(())
}

#[test]
fn test_signed_archive_roundtrip() -> Result<()> {
    // Create test data
    let test_data = b"Hello, World! This is a test file for signing.";
    
    // Generate keypair for signing
    let keypair = signature_utils::generate_keypair(DigitalSignature::Ed25519)?;
    
    // Create crypto config for signing
    let crypto_config = CryptoConfig {
        encryption_method: CryptoMethod::None,
        signature_method: DigitalSignature::Ed25519,
        key_derivation_params: KeyDerivationParams::default(),
    };
    
    // Create signed archive
    let mut archive_data = Vec::new();
    {
        let writer = Cursor::new(&mut archive_data);
        let mut crypto_writer = CryptoArchiveWriter::new(
            writer,
            crypto_config.clone(),
            None,
        )?;
        
        // Initialize signing
        crypto_writer.init_signing(Box::new(keypair.clone()))?;
        
        // Add test data
        crypto_writer.add_data("test.txt", test_data, None)?;
        
        // Finalize archive
        crypto_writer.finalize()?;
    }
    
    // Read and verify archive
    {
        let reader = Cursor::new(&archive_data);
        let mut crypto_reader = CryptoArchiveReader::new(reader)?;
        
        // Initialize verification
        crypto_reader.init_verification(Box::new(keypair))?;
        
        // Load entries
        crypto_reader.load_entries()?;
        
        // Verify signature
        let is_valid = crypto_reader.verify_signature()?;
        assert!(is_valid);
        
        // Extract and verify data
        let extracted_data = crypto_reader.extract_file(0)?;
        assert_eq!(extracted_data, test_data);
    }
    
    Ok(())
}

#[test]
fn test_encrypted_and_signed_archive() -> Result<()> {
    // Create test data
    let test_data = b"Hello, World! This is a test file for encryption and signing.";
    let password = "TestPassword123!";
    
    // Generate keypair for signing
    let keypair = signature_utils::generate_keypair(DigitalSignature::Ed25519)?;
    
    // Create crypto config for both encryption and signing
    let crypto_config = CryptoConfig {
        encryption_method: CryptoMethod::AesGcm256,
        signature_method: DigitalSignature::Ed25519,
        key_derivation_params: KeyDerivationParams::interactive(),
    };
    
    // Create encrypted and signed archive
    let mut archive_data = Vec::new();
    {
        let writer = Cursor::new(&mut archive_data);
        let mut crypto_writer = CryptoArchiveWriter::new(
            writer,
            crypto_config.clone(),
            None,
        )?;
        
        // Initialize encryption and signing
        crypto_writer.init_encryption(password)?;
        crypto_writer.init_signing(Box::new(keypair.clone()))?;
        
        // Add test data
        crypto_writer.add_data("test.txt", test_data, None)?;
        
        // Finalize archive
        crypto_writer.finalize()?;
    }
    
    // Read, decrypt, and verify archive
    {
        let reader = Cursor::new(&archive_data);
        let mut crypto_reader = CryptoArchiveReader::new(reader)?;
        
        // Initialize decryption and verification
        crypto_reader.init_decryption(password)?;
        crypto_reader.init_verification(Box::new(keypair))?;
        
        // Load entries
        crypto_reader.load_entries()?;
        
        // Verify signature
        let is_valid = crypto_reader.verify_signature()?;
        assert!(is_valid);
        
        // Extract and verify data
        let extracted_data = crypto_reader.extract_file(0)?;
        assert_eq!(extracted_data, test_data);
    }
    
    Ok(())
}

#[test]
fn test_multiple_files_encrypted_archive() -> Result<()> {
    let password = "TestPassword123!";
    let test_files = vec![
        ("file1.txt", b"Content of file 1"),
        ("file2.txt", b"Content of file 2"),
        ("dir/file3.txt", b"Content of file 3 in subdirectory"),
    ];
    
    // Create crypto config
    let crypto_config = CryptoConfig {
        encryption_method: CryptoMethod::AesGcm256,
        signature_method: DigitalSignature::None,
        key_derivation_params: KeyDerivationParams::interactive(),
    };
    
    // Create encrypted archive with multiple files
    let mut archive_data = Vec::new();
    {
        let writer = Cursor::new(&mut archive_data);
        let mut crypto_writer = CryptoArchiveWriter::new(
            writer,
            crypto_config.clone(),
            None,
        )?;
        
        crypto_writer.init_encryption(password)?;
        
        // Add all test files
        for (path, content) in &test_files {
            crypto_writer.add_data(path, content, None)?;
        }
        
        crypto_writer.finalize()?;
    }
    
    // Read and verify all files
    {
        let reader = Cursor::new(&archive_data);
        let mut crypto_reader = CryptoArchiveReader::new(reader)?;
        
        crypto_reader.init_decryption(password)?;
        crypto_reader.load_entries()?;
        
        // Verify we have all entries
        assert_eq!(crypto_reader.entries().len(), test_files.len());
        
        // Extract and verify each file
        for (i, (expected_path, expected_content)) in test_files.iter().enumerate() {
            assert_eq!(crypto_reader.entries()[i].path, *expected_path);
            let extracted_data = crypto_reader.extract_file(i)?;
            assert_eq!(extracted_data, *expected_content);
        }
    }
    
    Ok(())
}

#[test]
fn test_wrong_password_fails() -> Result<()> {
    let correct_password = "CorrectPassword123!";
    let wrong_password = "WrongPassword123!";
    let test_data = b"Secret data";
    
    // Create encrypted archive
    let crypto_config = CryptoConfig {
        encryption_method: CryptoMethod::AesGcm256,
        signature_method: DigitalSignature::None,
        key_derivation_params: KeyDerivationParams::interactive(),
    };
    
    let mut archive_data = Vec::new();
    {
        let writer = Cursor::new(&mut archive_data);
        let mut crypto_writer = CryptoArchiveWriter::new(writer, crypto_config.clone(), None)?;
        crypto_writer.init_encryption(correct_password)?;
        crypto_writer.add_data("secret.txt", test_data, None)?;
        crypto_writer.finalize()?;
    }
    
    // Try to decrypt with wrong password
    {
        let reader = Cursor::new(&archive_data);
        let mut crypto_reader = CryptoArchiveReader::new(reader)?;
        
        // This should succeed (password validation happens during decryption)
        crypto_reader.init_decryption(wrong_password)?;
        crypto_reader.load_entries()?;
        
        // This should fail when trying to decrypt
        let result = crypto_reader.extract_file(0);
        assert!(result.is_err());
    }
    
    Ok(())
}

#[test]
fn test_performance_large_file() -> Result<()> {
    // Create a larger test file (1MB)
    let large_data = vec![0xAB; 1024 * 1024];
    let password = "TestPassword123!";
    
    let crypto_config = CryptoConfig {
        encryption_method: CryptoMethod::AesGcm256,
        signature_method: DigitalSignature::None,
        key_derivation_params: KeyDerivationParams::interactive(),
    };
    
    // Measure encryption time
    let start = std::time::Instant::now();
    
    let mut archive_data = Vec::new();
    {
        let writer = Cursor::new(&mut archive_data);
        let mut crypto_writer = CryptoArchiveWriter::new(writer, crypto_config.clone(), None)?;
        crypto_writer.init_encryption(password)?;
        crypto_writer.add_data("large_file.bin", &large_data, None)?;
        crypto_writer.finalize()?;
    }
    
    let encryption_time = start.elapsed();
    println!("Encryption of 1MB took: {:?}", encryption_time);
    
    // Measure decryption time
    let start = std::time::Instant::now();
    
    {
        let reader = Cursor::new(&archive_data);
        let mut crypto_reader = CryptoArchiveReader::new(reader)?;
        crypto_reader.init_decryption(password)?;
        crypto_reader.load_entries()?;
        let extracted_data = crypto_reader.extract_file(0)?;
        assert_eq!(extracted_data.len(), large_data.len());
    }
    
    let decryption_time = start.elapsed();
    println!("Decryption of 1MB took: {:?}", decryption_time);
    
    // Performance assertions (these are quite generous)
    assert!(encryption_time.as_millis() < 1000, "Encryption took too long: {:?}", encryption_time);
    assert!(decryption_time.as_millis() < 1000, "Decryption took too long: {:?}", decryption_time);
    
    Ok(())
}

#[test]
fn test_threading_integration() -> Result<()> {
    let password = "TestPassword123!";
    let test_files = (0..10).map(|i| {
        (format!("file_{}.txt", i), format!("Content of file {}", i).into_bytes())
    }).collect::<Vec<_>>();
    
    // Create crypto config with threading
    let crypto_config = CryptoConfig {
        encryption_method: CryptoMethod::AesGcm256,
        signature_method: DigitalSignature::None,
        key_derivation_params: KeyDerivationParams::interactive(),
    };
    
    let thread_config = ThreadConfig::new()
        .with_thread_count(4)
        .with_chunk_size(1024);
    
    // Create encrypted archive with threading
    let mut archive_data = Vec::new();
    {
        let writer = Cursor::new(&mut archive_data);
        let mut crypto_writer = CryptoArchiveWriter::new(
            writer,
            crypto_config.clone(),
            Some(thread_config),
        )?;
        
        crypto_writer.init_encryption(password)?;
        
        for (path, content) in &test_files {
            crypto_writer.add_data(path, content, None)?;
        }
        
        crypto_writer.finalize()?;
    }
    
    // Read and verify
    {
        let reader = Cursor::new(&archive_data);
        let mut crypto_reader = CryptoArchiveReader::new(reader)?;
        crypto_reader.init_decryption(password)?;
        crypto_reader.load_entries()?;
        
        assert_eq!(crypto_reader.entries().len(), test_files.len());
        
        for (i, (expected_path, expected_content)) in test_files.iter().enumerate() {
            assert_eq!(crypto_reader.entries()[i].path, *expected_path);
            let extracted_data = crypto_reader.extract_file(i)?;
            assert_eq!(extracted_data, *expected_content);
        }
    }
    
    Ok(())
}

#[test]
fn test_different_encryption_methods() -> Result<()> {
    let password = "TestPassword123!";
    let test_data = b"Test data for different encryption methods";
    
    let methods = vec![
        CryptoMethod::AesGcm256,
        CryptoMethod::ChaCha20Poly1305,
    ];
    
    for method in methods {
        let crypto_config = CryptoConfig {
            encryption_method: method,
            signature_method: DigitalSignature::None,
            key_derivation_params: KeyDerivationParams::interactive(),
        };
        
        // Create encrypted archive
        let mut archive_data = Vec::new();
        {
            let writer = Cursor::new(&mut archive_data);
            let mut crypto_writer = CryptoArchiveWriter::new(writer, crypto_config.clone(), None)?;
            crypto_writer.init_encryption(password)?;
            crypto_writer.add_data("test.txt", test_data, None)?;
            crypto_writer.finalize()?;
        }
        
        // Read and verify
        {
            let reader = Cursor::new(&archive_data);
            let mut crypto_reader = CryptoArchiveReader::new(reader)?;
            crypto_reader.init_decryption(password)?;
            crypto_reader.load_entries()?;
            
            let extracted_data = crypto_reader.extract_file(0)?;
            assert_eq!(extracted_data, test_data);
        }
    }
    
    Ok(())
}

#[test]
fn test_different_signature_algorithms() -> Result<()> {
    let test_data = b"Test data for different signature algorithms";
    
    let algorithms = vec![
        DigitalSignature::Ed25519,
        DigitalSignature::Rsa2048,
    ];
    
    for algorithm in algorithms {
        let keypair = signature_utils::generate_keypair(algorithm)?;
        
        let crypto_config = CryptoConfig {
            encryption_method: CryptoMethod::None,
            signature_method: algorithm,
            key_derivation_params: KeyDerivationParams::default(),
        };
        
        // Create signed archive
        let mut archive_data = Vec::new();
        {
            let writer = Cursor::new(&mut archive_data);
            let mut crypto_writer = CryptoArchiveWriter::new(writer, crypto_config.clone(), None)?;
            crypto_writer.init_signing(Box::new(keypair.clone()))?;
            crypto_writer.add_data("test.txt", test_data, None)?;
            crypto_writer.finalize()?;
        }
        
        // Read and verify
        {
            let reader = Cursor::new(&archive_data);
            let mut crypto_reader = CryptoArchiveReader::new(reader)?;
            crypto_reader.init_verification(Box::new(keypair))?;
            crypto_reader.load_entries()?;
            
            let is_valid = crypto_reader.verify_signature()?;
            assert!(is_valid);
            
            let extracted_data = crypto_reader.extract_file(0)?;
            assert_eq!(extracted_data, test_data);
        }
    }
    
    Ok(())
}

#[test]
fn test_backward_compatibility() -> Result<()> {
    // Test that unencrypted archives still work
    let test_data = b"Unencrypted test data";
    
    let crypto_config = CryptoConfig {
        encryption_method: CryptoMethod::None,
        signature_method: DigitalSignature::None,
        key_derivation_params: KeyDerivationParams::default(),
    };
    
    // Create unencrypted archive
    let mut archive_data = Vec::new();
    {
        let writer = Cursor::new(&mut archive_data);
        let mut crypto_writer = CryptoArchiveWriter::new(writer, crypto_config.clone(), None)?;
        crypto_writer.add_data("test.txt", test_data, None)?;
        crypto_writer.finalize()?;
    }
    
    // Read unencrypted archive
    {
        let reader = Cursor::new(&archive_data);
        let mut crypto_reader = CryptoArchiveReader::new(reader)?;
        crypto_reader.load_entries()?;
        
        let extracted_data = crypto_reader.extract_file(0)?;
        assert_eq!(extracted_data, test_data);
    }
    
    Ok(())
}