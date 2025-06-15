//! RuZip - Modern Compression Tool
//!
//! A high-performance compression tool with modern cryptography,
//! built with Rust for safety, speed, and security.

pub mod cli;
pub mod crypto;
pub mod error;
pub mod utils;
pub mod compression;
pub mod archive;
pub mod threading;
pub mod memory;

#[cfg(feature = "simd")]
pub mod simd;

// Re-export main types for library usage
pub use error::{RuzipError, Result};

// Re-export crypto types
pub use crypto::{
    CryptoConfig, CryptoMethod, DigitalSignature, KeyDerivationParams,
    SecureBytes, CryptoError, CryptoResult,
};

// Re-export compression types
pub use compression::{
    CompressionEngine, CompressionLevel, CompressionMethod, CompressionStats,
    CompressedReader, CompressedWriter,
};

// Re-export archive types
pub use archive::{
    ArchiveOptions, ArchiveInfo, ArchiveStats, ArchiveHeader, FileEntry,
    FileMetadata, EntryType, ArchiveWriter, ArchiveReader,
};

// Re-export threading types
pub use threading::{
    ThreadPool, ThreadConfig, ParallelPipeline, ThreadSafeProgress,
    ThreadResult, ThreadStats,
};

// Re-export memory types
pub use memory::{
    BufferPool, MemoryArena, ScratchBuffer, ThreadLocalPool,
    MemoryPressure, MemoryPressureDetector, AdaptiveBufferSizer,
    streaming::{ZeroCopyReader, ZeroCopyWriter, ChainedBuffer, MemoryMappedArchive},
    profiler::{MemoryProfiler, MemoryStats, AllocationTracker},
    init_memory_management, get_memory_pressure_detector,
};

// Re-export SIMD types (conditional)
#[cfg(feature = "simd")]
pub use simd::{
    SimdCapabilities, SimdOperation, get_simd_capabilities, init_simd,
    hashing::{SimdCrc32, SimdBlake3, SimdSha256, MultiHasher, MultiHashResult},
    compression::{SimdMemCopy, SimdEntropy, SimdDictionary, SimdZstdPreprocessor},
};

/// Library version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Library name
pub const NAME: &str = env!("CARGO_PKG_NAME");