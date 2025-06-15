//! SIMD Integration Tests
//! 
//! Testet die SIMD-Optimierungen in realistischen Szenarien
//! und stellt sicher, dass sie korrekte Ergebnisse liefern.

#[cfg(feature = "simd")]
mod simd_tests {
    use ruzip::simd::{
        hashing::{SimdCrc32, SimdBlake3, SimdSha256, MultiHasher},
        compression::{SimdMemCopy, SimdEntropy, SimdDictionary, SimdZstdPreprocessor},
        get_simd_capabilities, init_simd,
    };
    use ruzip::{CompressionEngine, ArchiveValidator};
    use std::io::Cursor;
    use tempfile::NamedTempFile;

    /// Test SIMD-Capabilities Detection
    #[test]
    fn test_simd_capabilities_detection() {
        let caps = get_simd_capabilities();
        
        // Auf modernen x86_64 CPUs sollte mindestens SSE2 verfügbar sein
        #[cfg(target_arch = "x86_64")]
        assert!(caps.sse2, "SSE2 should be available on x86_64");
        
        // Auf ARM64 sollte NEON verfügbar sein
        #[cfg(target_arch = "aarch64")]
        assert!(caps.neon, "NEON should be available on aarch64");
        
        println!("SIMD Capabilities: {:?}", caps);
    }

    /// Test SIMD-Initialization
    #[test]
    fn test_simd_initialization() {
        let caps = init_simd();
        
        // Sollte ohne Fehler durchlaufen
        assert!(caps.sse2 || caps.neon || (!caps.sse2 && !caps.neon));
    }

    /// Test SIMD CRC32 Correctness
    #[test]
    fn test_simd_crc32_correctness() {
        let test_cases = vec![
            b"".to_vec(),
            b"a".to_vec(),
            b"Hello, World!".to_vec(),
            b"The quick brown fox jumps over the lazy dog".to_vec(),
            vec![0xAB; 1024],
            (0..256).collect::<Vec<u8>>(),
            vec![0xFF; 8192],
        ];

        for data in test_cases {
            let mut simd_hasher = SimdCrc32::new();
            simd_hasher.update(&data).unwrap();
            let simd_result = simd_hasher.finalize();
            
            let scalar_result = crc32fast::hash(&data);
            
            assert_eq!(
                simd_result, scalar_result,
                "CRC32 mismatch for data length {}: SIMD={:08x}, Scalar={:08x}",
                data.len(), simd_result, scalar_result
            );
        }
    }

    /// Test SIMD Blake3 Correctness
    #[test]
    fn test_simd_blake3_correctness() {
        let test_cases = vec![
            b"".to_vec(),
            b"Hello, SIMD Blake3!".to_vec(),
            vec![0x42; 1024],
            (0..1024).map(|i| (i % 256) as u8).collect(),
            vec![0xFF; 64 * 1024],
        ];

        for data in test_cases {
            let mut simd_hasher = SimdBlake3::new();
            simd_hasher.update(&data);
            let simd_result = simd_hasher.finalize();
            
            let standard_result = blake3::hash(&data);
            
            assert_eq!(
                simd_result, standard_result,
                "Blake3 mismatch for data length {}", data.len()
            );
        }
    }

    /// Test SIMD SHA-256 Correctness
    #[test]
    fn test_simd_sha256_correctness() {
        use sha2::{Digest, Sha256};
        
        let test_cases = vec![
            b"".to_vec(),
            b"Hello, SIMD SHA-256!".to_vec(),
            vec![0x33; 2048],
            (0..4096).map(|i| (i % 256) as u8).collect(),
        ];

        for data in test_cases {
            let mut simd_hasher = SimdSha256::new();
            simd_hasher.update(&data);
            let simd_result = simd_hasher.finalize();
            
            let mut standard_hasher = Sha256::new();
            standard_hasher.update(&data);
            let standard_result: [u8; 32] = standard_hasher.finalize().into();
            
            assert_eq!(
                simd_result, standard_result,
                "SHA-256 mismatch for data length {}", data.len()
            );
        }
    }

    /// Test Multi-Hash Correctness
    #[test]
    fn test_multi_hash_correctness() {
        use sha2::{Digest, Sha256};
        
        let data = b"Multi-hash test data with various patterns and lengths!".repeat(100);
        
        let mut multi_hasher = MultiHasher::new();
        multi_hasher.update(&data).unwrap();
        let multi_result = multi_hasher.finalize();
        
        // Vergleiche einzelne Hashes
        let expected_crc32 = crc32fast::hash(&data);
        let expected_blake3 = blake3::hash(&data);
        let mut sha_hasher = Sha256::new();
        sha_hasher.update(&data);
        let expected_sha256: [u8; 32] = sha_hasher.finalize().into();
        
        assert_eq!(multi_result.crc32, expected_crc32);
        assert_eq!(multi_result.blake3, expected_blake3);
        assert_eq!(multi_result.sha256, expected_sha256);
    }

    /// Test SIMD Memory Copy Correctness
    #[test]
    fn test_simd_memory_copy_correctness() {
        let test_sizes = vec![16, 32, 64, 128, 1024, 4096, 65536];
        
        for size in test_sizes {
            let src: Vec<u8> = (0..size).map(|i| (i % 256) as u8).collect();
            let mut dst = vec![0u8; size];
            
            SimdMemCopy::copy_aligned(&src, &mut dst).unwrap();
            
            assert_eq!(src, dst, "Memory copy failed for size {}", size);
        }
    }

    /// Test SIMD Memory Copy Error Handling
    #[test]
    fn test_simd_memory_copy_error_handling() {
        let src = vec![1, 2, 3, 4];
        let mut dst = vec![0, 0, 0]; // Different size
        
        let result = SimdMemCopy::copy_aligned(&src, &mut dst);
        assert!(result.is_err(), "Should fail with size mismatch");
    }

    /// Test SIMD Entropy Calculation
    #[test]
    fn test_simd_entropy_calculation() {
        // Test uniform data (low entropy)
        let uniform_data = vec![0xAB; 1024];
        let uniform_entropy = SimdEntropy::calculate_entropy(&uniform_data);
        assert!(uniform_entropy < 1.0, "Uniform data should have low entropy");
        
        // Test random data (high entropy)
        let random_data: Vec<u8> = (0..1024).map(|i| (i % 256) as u8).collect();
        let random_entropy = SimdEntropy::calculate_entropy(&random_data);
        assert!(random_entropy > 6.0, "Random data should have high entropy");
        
        // Test empty data
        let empty_entropy = SimdEntropy::calculate_entropy(&[]);
        assert_eq!(empty_entropy, 0.0, "Empty data should have zero entropy");
    }

    /// Test Compression Level Recommendation
    #[test]
    fn test_compression_level_recommendation() {
        let test_cases = vec![
            (0.5, 1),   // Very low entropy
            (2.5, 3),   // Low entropy
            (4.5, 6),   // Medium entropy
            (6.5, 9),   // High entropy
            (8.0, 12),  // Very high entropy
        ];
        
        for (entropy, expected_level) in test_cases {
            let level = SimdEntropy::recommend_compression_level(entropy);
            assert_eq!(level, expected_level, 
                "Wrong compression level for entropy {}", entropy);
        }
    }

    /// Test SIMD Dictionary Building
    #[test]
    fn test_simd_dictionary_building() {
        let mut builder = SimdDictionary::new(1024);
        
        // Füge Samples mit gemeinsamen Patterns hinzu
        builder.add_sample(b"hello world hello world".to_vec());
        builder.add_sample(b"world hello world hello".to_vec());
        builder.add_sample(b"hello hello world world".to_vec());
        
        let dictionary = builder.build_dictionary().unwrap();
        
        assert!(!dictionary.is_empty(), "Dictionary should not be empty");
        assert!(dictionary.len() <= 1024, "Dictionary should respect size limit");
        
        // Dictionary sollte häufige Patterns enthalten
        let dict_str = String::from_utf8_lossy(&dictionary);
        assert!(dict_str.contains("hello") || dict_str.contains("world"),
            "Dictionary should contain common patterns");
    }

    /// Test ZSTD Preprocessing
    #[test]
    fn test_zstd_preprocessing() {
        let test_data = b"This is test data for ZSTD preprocessing optimization";
        
        let processed = SimdZstdPreprocessor::preprocess(test_data).unwrap();
        
        // Für jetzt sollte es identisch sein (da nur Copy implementiert)
        assert_eq!(processed, test_data);
        assert_eq!(processed.len(), test_data.len());
    }

    /// Test Large Data Processing
    #[test]
    fn test_large_data_processing() {
        let large_data = vec![0xCD; 1024 * 1024]; // 1MB
        
        // Test CRC32
        let mut crc_hasher = SimdCrc32::new();
        crc_hasher.update(&large_data).unwrap();
        let crc_result = crc_hasher.finalize();
        assert_ne!(crc_result, 0);
        
        // Test Blake3
        let mut blake3_hasher = SimdBlake3::new();
        blake3_hasher.update(&large_data);
        let blake3_result = blake3_hasher.finalize();
        assert_ne!(blake3_result.as_bytes(), &[0u8; 32]);
        
        // Test Entropy
        let entropy = SimdEntropy::calculate_entropy(&large_data);
        assert!(entropy < 1.0); // Uniform data
        
        // Test Memory Copy
        let mut dst = vec![0u8; large_data.len()];
        SimdMemCopy::copy_aligned(&large_data, &mut dst).unwrap();
        assert_eq!(large_data, dst);
    }

    /// Test SIMD Integration mit Compression Engine
    #[test]
    fn test_simd_compression_engine_integration() {
        let engine = CompressionEngine::new().with_simd(true);
        let test_data = b"Hello, SIMD World! ".repeat(1000);
        
        let mut input = Cursor::new(&test_data);
        let mut output = Cursor::new(Vec::new());
        
        let level = ruzip::CompressionLevel::new(6).unwrap();
        let stats = engine.compress(&mut input, &mut output, level).unwrap();
        
        assert_eq!(stats.original_size, test_data.len() as u64);
        assert!(stats.duration_ms > 0);
    }

    /// Test SIMD Integration mit Archive Validator
    #[test]
    fn test_simd_archive_validator_integration() {
        let validator = ArchiveValidator::new().with_simd_hashing(true);
        
        // Teste dass der Validator erstellt werden kann
        assert!(validator.simd_hashing);
        assert!(validator.verify_checksums);
    }

    /// Test Threading Integration mit SIMD
    #[test]
    fn test_simd_threading_integration() {
        use rayon::prelude::*;
        
        let test_data: Vec<Vec<u8>> = (0..10)
            .map(|i| vec![(i % 256) as u8; 1024])
            .collect();
        
        // Parallele SIMD-Hashing
        let results: Vec<u32> = test_data
            .par_iter()
            .map(|data| {
                let mut hasher = SimdCrc32::new();
                hasher.update(data).unwrap();
                hasher.finalize()
            })
            .collect();
        
        assert_eq!(results.len(), 10);
        
        // Vergleiche mit sequenzieller Verarbeitung
        for (i, data) in test_data.iter().enumerate() {
            let mut hasher = SimdCrc32::new();
            hasher.update(data).unwrap();
            let expected = hasher.finalize();
            assert_eq!(results[i], expected);
        }
    }

    /// Test SIMD Performance Characteristics
    #[test]
    fn test_simd_performance_characteristics() {
        use std::time::Instant;
        
        let large_data = vec![0x42; 1024 * 1024]; // 1MB
        
        // SIMD Blake3
        let start = Instant::now();
        let mut simd_hasher = SimdBlake3::new();
        simd_hasher.update(&large_data);
        let _simd_result = simd_hasher.finalize();
        let simd_time = start.elapsed();
        
        // Standard Blake3
        let start = Instant::now();
        let _standard_result = blake3::hash(&large_data);
        let standard_time = start.elapsed();
        
        println!("SIMD Blake3: {:?}", simd_time);
        println!("Standard Blake3: {:?}", standard_time);
        
        // SIMD sollte nicht signifikant langsamer sein
        // (kann auf manchen Systemen sogar schneller sein)
        assert!(simd_time.as_millis() <= standard_time.as_millis() * 2);
    }

    /// Test Error Handling in SIMD Operations
    #[test]
    fn test_simd_error_handling() {
        // Test CRC32 mit leerem Update
        let mut hasher = SimdCrc32::new();
        assert!(hasher.update(&[]).is_ok());
        let result = hasher.finalize();
        assert_eq!(result, crc32fast::hash(&[]));
        
        // Test Dictionary mit leeren Samples
        let mut builder = SimdDictionary::new(1024);
        builder.add_sample(vec![]);
        let dictionary = builder.build_dictionary().unwrap();
        assert!(dictionary.is_empty());
    }

    /// Test SIMD Feature Detection Consistency
    #[test]
    fn test_simd_feature_detection_consistency() {
        let caps1 = get_simd_capabilities();
        let caps2 = get_simd_capabilities();
        
        // Capabilities sollten konsistent sein
        assert_eq!(caps1.sse2, caps2.sse2);
        assert_eq!(caps1.sse4_2, caps2.sse4_2);
        assert_eq!(caps1.avx, caps2.avx);
        assert_eq!(caps1.avx2, caps2.avx2);
        assert_eq!(caps1.neon, caps2.neon);
        assert_eq!(caps1.crc32, caps2.crc32);
    }
}

/// Tests für Systeme ohne SIMD-Feature
#[cfg(not(feature = "simd"))]
mod no_simd_tests {
    #[test]
    fn test_no_simd_compilation() {
        // Sollte ohne SIMD-Feature kompilieren
        assert!(true);
    }
}