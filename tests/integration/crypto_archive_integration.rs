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
use crate::chaos::{
    fault_injection::{FaultInjector, FaultInjectingOperation, FaultType},
    ChaosTestConfig,
};

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

// ... (existing tests remain here) ...

#[tokio::test]
async fn test_encrypt_with_io_errors() -> Result<()> {
    let test_data = b"Data to be encrypted with I/O errors.";
    let password = "PasswordForIoErrorTest";

    let crypto_config = CryptoConfig {
        encryption_method: CryptoMethod::AesGcm256,
        signature_method: DigitalSignature::None,
        key_derivation_params: KeyDerivationParams::interactive(),
    };

    let config = ChaosTestConfig::default();
    let fault_injector = FaultInjector::new(config);
    fault_injector.enable_io_faults(1.0).await?; // 100% probability

    let mut archive_data = Vec::new();
    let cursor = Cursor::new(&mut archive_data);

    // CryptoArchiveWriter setup might involve I/O, but we're targeting add_data/finalize
    let mut crypto_writer_instance = CryptoArchiveWriter::new(
        cursor,
        crypto_config.clone(),
        None,
    )?;
    crypto_writer_instance.init_encryption(password)?;

    let crypto_writer_op = FaultInjectingOperation::new(&mut crypto_writer_instance, fault_injector.clone());

    // Attempt to add data, expecting an I/O error
    let add_data_result = crypto_writer_op.execute("crypto_add_data_io", |writer| {
        writer.add_data("test_io.txt", test_data, None)
    }).await;

    // If add_data didn't error (e.g., if fault injected only on flush/finalize), check finalize
    if add_data_result.is_ok() {
        let finalize_result = crypto_writer_op.execute("crypto_finalize_io", |writer| {
            writer.finalize()
        }).await;
        assert!(finalize_result.is_err(), "Expected I/O error during finalize if not in add_data");
        if let Err(e) = finalize_result {
            eprintln!("Successfully injected I/O error during finalize: {:?}", e);
            assert!(e.to_string().contains("Injected I/O error"));
        }
    } else {
        if let Err(e) = add_data_result {
            eprintln!("Successfully injected I/O error during add_data: {:?}", e);
            assert!(e.to_string().contains("Injected I/O error"));
        }
    }

    // Ensure one of them was an error
    assert!(add_data_result.is_err() || crypto_writer_op.execute("crypto_finalize_io_check", |writer| writer.finalize()).await.is_err(),
            "Expected an I/O error during encryption process (add_data or finalize)");

    Ok(())
}

#[tokio::test]
async fn test_encrypt_with_memory_errors() -> Result<()> {
    let test_data = b"Data to be encrypted with memory errors.";
    let password = "PasswordForMemoryErrorTest";

    let crypto_config = CryptoConfig {
        encryption_method: CryptoMethod::AesGcm256,
        signature_method: DigitalSignature::None,
        key_derivation_params: KeyDerivationParams::interactive(),
    };

    let config = ChaosTestConfig::default();
    let fault_injector = FaultInjector::new(config);
    fault_injector.enable_memory_faults(1.0).await?; // 100% probability

    let mut archive_data = Vec::new();
    let cursor = Cursor::new(&mut archive_data);

    let mut crypto_writer_instance = CryptoArchiveWriter::new(
        cursor,
        crypto_config.clone(),
        None,
    )?;
    crypto_writer_instance.init_encryption(password)?;

    let crypto_writer_op = FaultInjectingOperation::new(&mut crypto_writer_instance, fault_injector.clone());

    // Attempt to add data, expecting a memory error
    let add_data_result = crypto_writer_op.execute("crypto_add_data_mem", |writer| {
        futures::executor::block_on(fault_injector.maybe_inject_memory_exhaustion(1024 * 1024))?; // Simulate 1MB alloc
        writer.add_data("test_mem.txt", test_data, None)
    }).await;

    if add_data_result.is_ok() {
        let finalize_result = crypto_writer_op.execute("crypto_finalize_mem", |writer| {
            futures::executor::block_on(fault_injector.maybe_inject_memory_exhaustion(1024 * 1024))?; // Simulate 1MB alloc
            writer.finalize()
        }).await;
        assert!(finalize_result.is_err(), "Expected memory error during finalize if not in add_data");
        if let Err(e) = finalize_result {
            eprintln!("Successfully injected memory error during finalize: {:?}", e);
            assert!(e.to_string().contains("Injected memory exhaustion"));
        }
    } else {
        if let Err(e) = add_data_result {
            eprintln!("Successfully injected memory error during add_data: {:?}", e);
            assert!(e.to_string().contains("Injected memory exhaustion"));
        }
    }

    // Ensure one of them was an error
    let final_check_result = crypto_writer_op.execute("crypto_finalize_mem_check", |writer| {
        futures::executor::block_on(fault_injector.maybe_inject_memory_exhaustion(1024 * 1024))?;
        writer.finalize()
    }).await;
    assert!(add_data_result.is_err() || final_check_result.is_err(),
            "Expected a memory error during encryption process (add_data or finalize)");

    Ok(())
}

#[tokio::test]
async fn test_decrypt_with_io_errors() -> Result<()> {
    let test_data = b"Data for decrypt I/O error test.";
    let password = "PasswordForDecryptIo";

    // 1. Create a normally encrypted archive
    let crypto_config_create = CryptoConfig {
        encryption_method: CryptoMethod::AesGcm256,
        signature_method: DigitalSignature::None,
        key_derivation_params: KeyDerivationParams::interactive(),
    };
    let mut archive_data = Vec::new();
    {
        let writer_cursor = Cursor::new(&mut archive_data);
        let mut crypto_writer = CryptoArchiveWriter::new(writer_cursor, crypto_config_create, None)?;
        crypto_writer.init_encryption(password)?;
        crypto_writer.add_data("test_decrypt_io.txt", test_data, None)?;
        crypto_writer.finalize()?;
    }

    // 2. Setup FaultInjector for I/O errors
    let config = ChaosTestConfig::default();
    let fault_injector = FaultInjector::new(config);
    fault_injector.enable_io_faults(1.0).await?; // 100% probability

    // 3. Attempt to decrypt and extract with fault injection
    let reader_cursor = Cursor::new(&archive_data);
    let mut crypto_reader_instance = CryptoArchiveReader::new(reader_cursor)?;
    crypto_reader_instance.init_decryption(password)?;
    crypto_reader_instance.load_entries()?; // Assume this doesn't do heavy I/O that we are targeting

    assert_eq!(crypto_reader_instance.entries().len(), 1, "Should have one entry before extraction attempt");

    let crypto_reader_op = FaultInjectingOperation::new(&mut crypto_reader_instance, fault_injector.clone());

    let extract_result = crypto_reader_op.execute("crypto_extract_io", |reader| {
        reader.extract_file(0) // Attempt to extract the first file
    }).await;

    assert!(extract_result.is_err(), "Expected an I/O error during archive decryption/extraction");
    if let Err(e) = extract_result {
        eprintln!("Successfully injected I/O error during extraction: {:?}", e);
        assert!(e.to_string().contains("Injected I/O error"), "Error message mismatch for I/O fault");
    }

    Ok(())
}

#[tokio::test]
async fn test_decrypt_with_memory_errors() -> Result<()> {
    let test_data = b"Data for decrypt memory error test.";
    let password = "PasswordForDecryptMemory";

    // 1. Create a normally encrypted archive
    let crypto_config_create = CryptoConfig {
        encryption_method: CryptoMethod::AesGcm256,
        signature_method: DigitalSignature::None,
        key_derivation_params: KeyDerivationParams::interactive(),
    };
    let mut archive_data = Vec::new();
    {
        let writer_cursor = Cursor::new(&mut archive_data);
        let mut crypto_writer = CryptoArchiveWriter::new(writer_cursor, crypto_config_create, None)?;
        crypto_writer.init_encryption(password)?;
        crypto_writer.add_data("test_decrypt_mem.txt", test_data, None)?;
        crypto_writer.finalize()?;
    }

    // 2. Setup FaultInjector for memory errors
    let config = ChaosTestConfig::default();
    let fault_injector = FaultInjector::new(config);
    fault_injector.enable_memory_faults(1.0).await?; // 100% probability

    // 3. Attempt to decrypt and extract with fault injection
    let reader_cursor = Cursor::new(&archive_data);
    let mut crypto_reader_instance = CryptoArchiveReader::new(reader_cursor)?;
    crypto_reader_instance.init_decryption(password)?;
    crypto_reader_instance.load_entries()?;

    assert_eq!(crypto_reader_instance.entries().len(), 1, "Should have one entry before extraction attempt");

    let crypto_reader_op = FaultInjectingOperation::new(&mut crypto_reader_instance, fault_injector.clone());

    let extract_result = crypto_reader_op.execute("crypto_extract_mem", |reader| {
        futures::executor::block_on(fault_injector.maybe_inject_memory_exhaustion(1024 * 1024))?; // Simulate 1MB alloc
        reader.extract_file(0)
    }).await;

    assert!(extract_result.is_err(), "Expected a memory error during archive decryption/extraction");
    if let Err(e) = extract_result {
        eprintln!("Successfully injected memory error during extraction: {:?}", e);
        assert!(e.to_string().contains("Injected memory exhaustion"), "Error message mismatch for memory fault");
    }

    Ok(())
}

#[tokio::test]
async fn test_sign_with_io_errors() -> Result<()> {
    let test_data = b"Data to be signed with I/O errors.";
    let keypair = signature_utils::generate_keypair(DigitalSignature::Ed25519)?;

    let crypto_config = CryptoConfig {
        encryption_method: CryptoMethod::None,
        signature_method: DigitalSignature::Ed25519,
        key_derivation_params: KeyDerivationParams::default(),
    };

    let config = ChaosTestConfig::default();
    let fault_injector = FaultInjector::new(config);
    fault_injector.enable_io_faults(1.0).await?; // 100% probability

    let mut archive_data = Vec::new();
    let cursor = Cursor::new(&mut archive_data);

    let mut crypto_writer_instance = CryptoArchiveWriter::new(
        cursor,
        crypto_config.clone(),
        None,
    )?;
    crypto_writer_instance.init_signing(Box::new(keypair.clone()))?;

    let crypto_writer_op = FaultInjectingOperation::new(&mut crypto_writer_instance, fault_injector.clone());

    let add_data_result = crypto_writer_op.execute("crypto_sign_add_data_io", |writer| {
        writer.add_data("test_sign_io.txt", test_data, None)
    }).await;

    if add_data_result.is_ok() {
        let finalize_result = crypto_writer_op.execute("crypto_sign_finalize_io", |writer| {
            writer.finalize()
        }).await;
        assert!(finalize_result.is_err(), "Expected I/O error during finalize (signing) if not in add_data");
        if let Err(e) = finalize_result {
            eprintln!("Successfully injected I/O error during finalize (signing): {:?}", e);
            assert!(e.to_string().contains("Injected I/O error"));
        }
    } else {
         if let Err(e) = add_data_result {
            eprintln!("Successfully injected I/O error during add_data (signing): {:?}", e);
            assert!(e.to_string().contains("Injected I/O error"));
        }
    }

    let final_check_result = crypto_writer_op.execute("crypto_sign_finalize_io_check", |writer| writer.finalize()).await;
    assert!(add_data_result.is_err() || final_check_result.is_err(),
            "Expected an I/O error during signing process (add_data or finalize)");

    Ok(())
}

#[tokio::test]
async fn test_sign_with_memory_errors() -> Result<()> {
    let test_data = b"Data to be signed with memory errors.";
    let keypair = signature_utils::generate_keypair(DigitalSignature::Ed25519)?;

    let crypto_config = CryptoConfig {
        encryption_method: CryptoMethod::None,
        signature_method: DigitalSignature::Ed25519,
        key_derivation_params: KeyDerivationParams::default(),
    };

    let config = ChaosTestConfig::default();
    let fault_injector = FaultInjector::new(config);
    fault_injector.enable_memory_faults(1.0).await?; // 100% probability

    let mut archive_data = Vec::new();
    let cursor = Cursor::new(&mut archive_data);

    let mut crypto_writer_instance = CryptoArchiveWriter::new(
        cursor,
        crypto_config.clone(),
        None,
    )?;
    crypto_writer_instance.init_signing(Box::new(keypair.clone()))?;

    let crypto_writer_op = FaultInjectingOperation::new(&mut crypto_writer_instance, fault_injector.clone());

    let add_data_result = crypto_writer_op.execute("crypto_sign_add_data_mem", |writer| {
        futures::executor::block_on(fault_injector.maybe_inject_memory_exhaustion(1024 * 1024))?;
        writer.add_data("test_sign_mem.txt", test_data, None)
    }).await;

    if add_data_result.is_ok() {
        let finalize_result = crypto_writer_op.execute("crypto_sign_finalize_mem", |writer| {
            futures::executor::block_on(fault_injector.maybe_inject_memory_exhaustion(1024 * 1024))?;
            writer.finalize()
        }).await;
        assert!(finalize_result.is_err(), "Expected memory error during finalize (signing) if not in add_data");
        if let Err(e) = finalize_result {
            eprintln!("Successfully injected memory error during finalize (signing): {:?}", e);
            assert!(e.to_string().contains("Injected memory exhaustion"));
        }
    } else {
        if let Err(e) = add_data_result {
            eprintln!("Successfully injected memory error during add_data (signing): {:?}", e);
            assert!(e.to_string().contains("Injected memory exhaustion"));
        }
    }

    let final_check_result = crypto_writer_op.execute("crypto_sign_finalize_mem_check", |writer| {
        futures::executor::block_on(fault_injector.maybe_inject_memory_exhaustion(1024 * 1024))?;
        writer.finalize()
    }).await;
    assert!(add_data_result.is_err() || final_check_result.is_err(),
            "Expected a memory error during signing process (add_data or finalize)");

    Ok(())
}

#[tokio::test]
async fn test_verify_with_io_errors() -> Result<()> {
    let test_data = b"Data for signature verification I/O error test.";
    let keypair = signature_utils::generate_keypair(DigitalSignature::Ed25519)?;

    // 1. Create a normally signed archive
    let crypto_config_create = CryptoConfig {
        encryption_method: CryptoMethod::None,
        signature_method: DigitalSignature::Ed25519,
        key_derivation_params: KeyDerivationParams::default(),
    };
    let mut archive_data = Vec::new();
    {
        let writer_cursor = Cursor::new(&mut archive_data);
        let mut crypto_writer = CryptoArchiveWriter::new(writer_cursor, crypto_config_create, None)?;
        crypto_writer.init_signing(Box::new(keypair.clone()))?;
        crypto_writer.add_data("test_verify_io.txt", test_data, None)?;
        crypto_writer.finalize()?;
    }

    // 2. Setup FaultInjector for I/O errors
    let config = ChaosTestConfig::default();
    let fault_injector = FaultInjector::new(config);
    fault_injector.enable_io_faults(1.0).await?; // 100% probability

    // 3. Attempt to verify with fault injection
    let reader_cursor = Cursor::new(&archive_data);
    let mut crypto_reader_instance = CryptoArchiveReader::new(reader_cursor)?;
    crypto_reader_instance.init_verification(Box::new(keypair))?;
    crypto_reader_instance.load_entries()?; // Assumed not the target for I/O fault in this test

    let crypto_reader_op = FaultInjectingOperation::new(&mut crypto_reader_instance, fault_injector.clone());

    let verify_result = crypto_reader_op.execute("crypto_verify_sig_io", |reader| {
        reader.verify_signature()
    }).await;

    // verify_signature itself returns Result<bool>, so an injected I/O error makes it Result<Result<bool>> -> Err
    // Or, if the error is inside verify_signature's logic before returning bool, it might be Err(RuzipError)
    assert!(verify_result.is_err(), "Expected an I/O error during signature verification");
    if let Err(e) = verify_result {
        eprintln!("Successfully injected I/O error during verification: {:?}", e);
        assert!(e.to_string().contains("Injected I/O error"), "Error message mismatch for I/O fault");
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

#[tokio::test]
async fn test_verify_with_memory_errors() -> Result<()> {
    let test_data = b"Data for signature verification memory error test.";
    let keypair = signature_utils::generate_keypair(DigitalSignature::Ed25519)?;

    // 1. Create a normally signed archive
    let crypto_config_create = CryptoConfig {
        encryption_method: CryptoMethod::None,
        signature_method: DigitalSignature::Ed25519,
        key_derivation_params: KeyDerivationParams::default(),
    };
    let mut archive_data = Vec::new();
    {
        let writer_cursor = Cursor::new(&mut archive_data);
        let mut crypto_writer = CryptoArchiveWriter::new(writer_cursor, crypto_config_create, None)?;
        crypto_writer.init_signing(Box::new(keypair.clone()))?;
        crypto_writer.add_data("test_verify_mem.txt", test_data, None)?;
        crypto_writer.finalize()?;
    }

    // 2. Setup FaultInjector for memory errors
    let config = ChaosTestConfig::default();
    let fault_injector = FaultInjector::new(config);
    fault_injector.enable_memory_faults(1.0).await?; // 100% probability

    // 3. Attempt to verify with fault injection
    let reader_cursor = Cursor::new(&archive_data);
    let mut crypto_reader_instance = CryptoArchiveReader::new(reader_cursor)?;
    crypto_reader_instance.init_verification(Box::new(keypair))?;
    crypto_reader_instance.load_entries()?;

    let crypto_reader_op = FaultInjectingOperation::new(&mut crypto_reader_instance, fault_injector.clone());

    let verify_result = crypto_reader_op.execute("crypto_verify_sig_mem", |reader| {
        futures::executor::block_on(fault_injector.maybe_inject_memory_exhaustion(1024 * 1024))?;
        reader.verify_signature()
    }).await;

    assert!(verify_result.is_err(), "Expected a memory error during signature verification");
    if let Err(e) = verify_result {
        eprintln!("Successfully injected memory error during verification: {:?}", e);
        assert!(e.to_string().contains("Injected memory exhaustion"), "Error message mismatch for memory fault");
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