//! Memory Pool System for Zero-Allocation Operations
//!
//! Provides reusable buffer pools and arena allocators to minimize
//! memory allocations during archive operations.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::cell::RefCell;
use std::rc::Rc;
use crate::error::{RuzipError, Result};
use super::{MemoryPressureDetector, AdaptiveBufferSizer};

/// Generic object pool for reusable buffers
pub struct BufferPool<T> {
    small_buffers: Mutex<VecDeque<T>>,    // 4KB - 64KB
    medium_buffers: Mutex<VecDeque<T>>,   // 64KB - 1MB
    large_buffers: Mutex<VecDeque<T>>,    // 1MB - 16MB
    max_pool_size: usize,
    buffer_factory: Box<dyn Fn(usize) -> T + Send + Sync>,
    sizer: AdaptiveBufferSizer,
}

impl BufferPool<Vec<u8>> {
    /// Create new buffer pool for byte vectors
    pub fn new_byte_pool(
        max_pool_size: usize,
        pressure_detector: Arc<MemoryPressureDetector>
    ) -> Self {
        Self {
            small_buffers: Mutex::new(VecDeque::new()),
            medium_buffers: Mutex::new(VecDeque::new()),
            large_buffers: Mutex::new(VecDeque::new()),
            max_pool_size,
            buffer_factory: Box::new(|size| Vec::with_capacity(size)),
            sizer: AdaptiveBufferSizer::new(pressure_detector),
        }
    }

    /// Get a small buffer (4KB - 64KB)
    pub fn get_small_buffer(&self) -> PooledBuffer {
        let size = self.sizer.small_buffer_size();
        let buffer = {
            let mut pool = self.small_buffers.lock().unwrap();
            pool.pop_front().unwrap_or_else(|| (self.buffer_factory)(size))
        };
        PooledBuffer::new(buffer, BufferSize::Small, self)
    }

    /// Get a medium buffer (64KB - 1MB)
    pub fn get_medium_buffer(&self) -> PooledBuffer {
        let size = self.sizer.medium_buffer_size();
        let buffer = {
            let mut pool = self.medium_buffers.lock().unwrap();
            pool.pop_front().unwrap_or_else(|| (self.buffer_factory)(size))
        };
        PooledBuffer::new(buffer, BufferSize::Medium, self)
    }

    /// Get a large buffer (1MB - 16MB)
    pub fn get_large_buffer(&self) -> PooledBuffer {
        let size = self.sizer.large_buffer_size();
        let buffer = {
            let mut pool = self.large_buffers.lock().unwrap();
            pool.pop_front().unwrap_or_else(|| (self.buffer_factory)(size))
        };
        PooledBuffer::new(buffer, BufferSize::Large, self)
    }

    /// Return buffer to appropriate pool
    fn return_buffer(&self, mut buffer: Vec<u8>, size: BufferSize) {
        // Clear buffer but keep capacity
        buffer.clear();
        
        let pool = match size {
            BufferSize::Small => &self.small_buffers,
            BufferSize::Medium => &self.medium_buffers,
            BufferSize::Large => &self.large_buffers,
        };

        let mut pool_guard = pool.lock().unwrap();
        if pool_guard.len() < self.max_pool_size {
            pool_guard.push_back(buffer);
        }
        // If pool is full, buffer will be dropped
    }

    /// Get pool statistics
    pub fn stats(&self) -> PoolStats {
        let small_count = self.small_buffers.lock().unwrap().len();
        let medium_count = self.medium_buffers.lock().unwrap().len();
        let large_count = self.large_buffers.lock().unwrap().len();

        PoolStats {
            small_buffers: small_count,
            medium_buffers: medium_count,
            large_buffers: large_count,
            total_buffers: small_count + medium_count + large_count,
            max_pool_size: self.max_pool_size,
        }
    }

    /// Clear all pools
    pub fn clear(&self) {
        self.small_buffers.lock().unwrap().clear();
        self.medium_buffers.lock().unwrap().clear();
        self.large_buffers.lock().unwrap().clear();
    }
}

/// Buffer size categories
#[derive(Debug, Clone, Copy)]
enum BufferSize {
    Small,
    Medium,
    Large,
}

/// RAII wrapper for pooled buffers
pub struct PooledBuffer {
    buffer: Option<Vec<u8>>,
    size: BufferSize,
    pool: *const BufferPool<Vec<u8>>,
}

impl PooledBuffer {
    fn new(buffer: Vec<u8>, size: BufferSize, pool: &BufferPool<Vec<u8>>) -> Self {
        Self {
            buffer: Some(buffer),
            size,
            pool: pool as *const _,
        }
    }

    /// Get mutable reference to buffer
    pub fn as_mut(&mut self) -> &mut Vec<u8> {
        self.buffer.as_mut().unwrap()
    }

    /// Get immutable reference to buffer
    pub fn as_ref(&self) -> &Vec<u8> {
        self.buffer.as_ref().unwrap()
    }

    /// Take ownership of buffer (prevents return to pool)
    pub fn take(mut self) -> Vec<u8> {
        self.buffer.take().unwrap()
    }

    /// Resize buffer to exact size needed
    pub fn resize(&mut self, size: usize) {
        if let Some(ref mut buffer) = self.buffer {
            buffer.resize(size, 0);
        }
    }

    /// Get buffer capacity
    pub fn capacity(&self) -> usize {
        self.buffer.as_ref().map(|b| b.capacity()).unwrap_or(0)
    }

    /// Get buffer length
    pub fn len(&self) -> usize {
        self.buffer.as_ref().map(|b| b.len()).unwrap_or(0)
    }

    /// Check if buffer is empty
    pub fn is_empty(&self) -> bool {
        self.buffer.as_ref().map(|b| b.is_empty()).unwrap_or(true)
    }
}

impl Drop for PooledBuffer {
    fn drop(&mut self) {
        if let Some(buffer) = self.buffer.take() {
            // Safety: Pool pointer is valid during buffer lifetime
            unsafe {
                if let Some(pool) = self.pool.as_ref() {
                    pool.return_buffer(buffer, self.size);
                }
            }
        }
    }
}

unsafe impl Send for PooledBuffer {}

/// Pool statistics
#[derive(Debug, Clone)]
pub struct PoolStats {
    pub small_buffers: usize,
    pub medium_buffers: usize,
    pub large_buffers: usize,
    pub total_buffers: usize,
    pub max_pool_size: usize,
}

/// Stack allocator for temporary objects
pub struct MemoryArena {
    data: Vec<u8>,
    offset: usize,
    checkpoints: Vec<usize>,
}

impl MemoryArena {
    /// Create new memory arena with specified capacity
    pub fn new(capacity: usize) -> Self {
        Self {
            data: Vec::with_capacity(capacity),
            offset: 0,
            checkpoints: Vec::new(),
        }
    }

    /// Allocate aligned memory from arena
    pub fn alloc_aligned(&mut self, size: usize, align: usize) -> Result<&mut [u8]> {
        // Align offset
        let aligned_offset = (self.offset + align - 1) & !(align - 1);
        let end_offset = aligned_offset + size;

        if end_offset > self.data.capacity() {
            return Err(RuzipError::Memory {
                message: "Arena out of memory".into(),
                source: None,
            });
        }

        // Extend data if needed
        if end_offset > self.data.len() {
            self.data.resize(end_offset, 0);
        }

        self.offset = end_offset;
        Ok(&mut self.data[aligned_offset..end_offset])
    }

    /// Allocate memory from arena
    pub fn alloc(&mut self, size: usize) -> Result<&mut [u8]> {
        self.alloc_aligned(size, 1)
    }

    /// Create checkpoint for later reset
    pub fn checkpoint(&mut self) -> ArenaCheckpoint {
        let checkpoint = self.offset;
        self.checkpoints.push(checkpoint);
        ArenaCheckpoint { offset: checkpoint }
    }

    /// Reset to checkpoint
    pub fn reset_to_checkpoint(&mut self, checkpoint: ArenaCheckpoint) {
        self.offset = checkpoint.offset;
        // Remove checkpoints after this one
        self.checkpoints.retain(|&cp| cp <= checkpoint.offset);
    }

    /// Reset entire arena
    pub fn reset(&mut self) {
        self.offset = 0;
        self.checkpoints.clear();
    }

    /// Get used bytes
    pub fn used(&self) -> usize {
        self.offset
    }

    /// Get remaining capacity
    pub fn remaining(&self) -> usize {
        self.data.capacity() - self.offset
    }

    /// Get total capacity
    pub fn capacity(&self) -> usize {
        self.data.capacity()
    }
}

/// Arena checkpoint for reset operations
#[derive(Debug, Clone, Copy)]
pub struct ArenaCheckpoint {
    offset: usize,
}

/// Reusable compression buffer with metadata
pub struct ScratchBuffer {
    compression_buffer: Vec<u8>,
    decompression_buffer: Vec<u8>,
    temp_buffer: Vec<u8>,
    dictionary: Option<Vec<u8>>,
    last_used: std::time::Instant,
}

impl ScratchBuffer {
    /// Create new scratch buffer
    pub fn new(comp_size: usize, decomp_size: usize, temp_size: usize) -> Self {
        Self {
            compression_buffer: Vec::with_capacity(comp_size),
            decompression_buffer: Vec::with_capacity(decomp_size),
            temp_buffer: Vec::with_capacity(temp_size),
            dictionary: None,
            last_used: std::time::Instant::now(),
        }
    }

    /// Get compression buffer
    pub fn compression_buffer(&mut self) -> &mut Vec<u8> {
        self.last_used = std::time::Instant::now();
        self.compression_buffer.clear();
        &mut self.compression_buffer
    }

    /// Get decompression buffer
    pub fn decompression_buffer(&mut self) -> &mut Vec<u8> {
        self.last_used = std::time::Instant::now();
        self.decompression_buffer.clear();
        &mut self.decompression_buffer
    }

    /// Get temporary buffer
    pub fn temp_buffer(&mut self) -> &mut Vec<u8> {
        self.last_used = std::time::Instant::now();
        self.temp_buffer.clear();
        &mut self.temp_buffer
    }

    /// Set dictionary for compression
    pub fn set_dictionary(&mut self, dict: Vec<u8>) {
        self.dictionary = Some(dict);
    }

    /// Get dictionary reference
    pub fn dictionary(&self) -> Option<&[u8]> {
        self.dictionary.as_deref()
    }

    /// Check if buffer was recently used
    pub fn is_recently_used(&self, threshold: std::time::Duration) -> bool {
        self.last_used.elapsed() < threshold
    }

    /// Reset all buffers
    pub fn reset(&mut self) {
        self.compression_buffer.clear();
        self.decompression_buffer.clear();
        self.temp_buffer.clear();
        self.dictionary = None;
    }
}

thread_local! {
    static THREAD_LOCAL_POOL: RefCell<Option<Rc<ThreadLocalPool>>> = RefCell::new(None);
}

/// Thread-local pool implementation
pub struct ThreadLocalPool {
    byte_buffers: RefCell<VecDeque<Vec<u8>>>,
    scratch_buffers: RefCell<VecDeque<ScratchBuffer>>,
    arena: RefCell<MemoryArena>,
    max_buffers: usize,
}

impl ThreadLocalPool {
    /// Create new thread-local pool
    pub fn new(max_buffers: usize, arena_size: usize) -> Self {
        Self {
            byte_buffers: RefCell::new(VecDeque::new()),
            scratch_buffers: RefCell::new(VecDeque::new()),
            arena: RefCell::new(MemoryArena::new(arena_size)),
            max_buffers,
        }
    }

    /// Get byte buffer from thread-local pool
    pub fn get_byte_buffer(&self, size: usize) -> Vec<u8> {
        let mut buffers = self.byte_buffers.borrow_mut();
        buffers.pop_front()
            .map(|mut buf| {
                buf.clear();
                if buf.capacity() < size {
                    buf.reserve(size - buf.capacity());
                }
                buf
            })
            .unwrap_or_else(|| Vec::with_capacity(size))
    }

    /// Return byte buffer to thread-local pool
    pub fn return_byte_buffer(&self, buffer: Vec<u8>) {
        let mut buffers = self.byte_buffers.borrow_mut();
        if buffers.len() < self.max_buffers {
            buffers.push_back(buffer);
        }
    }

    /// Get scratch buffer from thread-local pool
    pub fn get_scratch_buffer(&self) -> ScratchBuffer {
        let mut buffers = self.scratch_buffers.borrow_mut();
        buffers.pop_front()
            .unwrap_or_else(|| ScratchBuffer::new(64 * 1024, 64 * 1024, 16 * 1024))
    }

    /// Return scratch buffer to thread-local pool
    pub fn return_scratch_buffer(&self, mut buffer: ScratchBuffer) {
        buffer.reset();
        let mut buffers = self.scratch_buffers.borrow_mut();
        if buffers.len() < self.max_buffers {
            buffers.push_back(buffer);
        }
    }

    /// Get arena allocator
    pub fn arena(&self) -> std::cell::Ref<MemoryArena> {
        self.arena.borrow()
    }

    /// Get mutable arena allocator
    pub fn arena_mut(&self) -> std::cell::RefMut<MemoryArena> {
        self.arena.borrow_mut()
    }
}

/// Initialize thread-local pool for current thread
pub fn init_thread_local_pool(max_buffers: usize, arena_size: usize) {
    THREAD_LOCAL_POOL.with(|pool| {
        *pool.borrow_mut() = Some(Rc::new(ThreadLocalPool::new(max_buffers, arena_size)));
    });
}

/// Get thread-local pool for current thread
pub fn get_thread_local_pool() -> Option<Rc<ThreadLocalPool>> {
    THREAD_LOCAL_POOL.with(|pool| pool.borrow().clone())
}

/// RAII wrapper for thread-local buffers
pub struct ThreadLocalBuffer {
    buffer: Option<Vec<u8>>,
    pool: Option<Rc<ThreadLocalPool>>,
}

impl ThreadLocalBuffer {
    /// Create new thread-local buffer
    pub fn new(size: usize) -> Self {
        let pool = get_thread_local_pool();
        let buffer = pool.as_ref()
            .map(|p| p.get_byte_buffer(size))
            .unwrap_or_else(|| Vec::with_capacity(size));

        Self {
            buffer: Some(buffer),
            pool,
        }
    }

    /// Get mutable reference to buffer
    pub fn as_mut(&mut self) -> &mut Vec<u8> {
        self.buffer.as_mut().unwrap()
    }

    /// Get immutable reference to buffer
    pub fn as_ref(&self) -> &Vec<u8> {
        self.buffer.as_ref().unwrap()
    }
}

impl Drop for ThreadLocalBuffer {
    fn drop(&mut self) {
        if let (Some(buffer), Some(pool)) = (self.buffer.take(), &self.pool) {
            pool.return_byte_buffer(buffer);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_buffer_pool() {
        let detector = Arc::new(super::super::MemoryPressureDetector::new(100, 200, 300));
        let pool = BufferPool::new_byte_pool(10, detector);

        let mut buffer1 = pool.get_small_buffer();
        buffer1.resize(1024);
        assert_eq!(buffer1.len(), 1024);

        let mut buffer2 = pool.get_medium_buffer();
        buffer2.resize(32 * 1024);
        assert_eq!(buffer2.len(), 32 * 1024);

        drop(buffer1);
        drop(buffer2);

        let stats = pool.stats();
        assert!(stats.total_buffers <= 2);
    }

    #[test]
    fn test_memory_arena() {
        let mut arena = MemoryArena::new(1024);

        let slice1 = arena.alloc(100).unwrap();
        assert_eq!(slice1.len(), 100);

        let checkpoint = arena.checkpoint();
        let slice2 = arena.alloc(200).unwrap();
        assert_eq!(slice2.len(), 200);

        arena.reset_to_checkpoint(checkpoint);
        assert_eq!(arena.used(), 100);

        arena.reset();
        assert_eq!(arena.used(), 0);
    }

    #[test]
    fn test_scratch_buffer() {
        let mut scratch = ScratchBuffer::new(1024, 1024, 512);

        let comp_buf = scratch.compression_buffer();
        comp_buf.extend_from_slice(b"test data");

        let decomp_buf = scratch.decompression_buffer();
        assert!(decomp_buf.is_empty());

        scratch.set_dictionary(vec![1, 2, 3, 4]);
        assert_eq!(scratch.dictionary(), Some([1, 2, 3, 4].as_slice()));
    }

    #[test]
    fn test_thread_local_pool() {
        init_thread_local_pool(5, 4096);
        
        let pool = get_thread_local_pool().unwrap();
        let buffer = pool.get_byte_buffer(1024);
        assert!(buffer.capacity() >= 1024);
        
        pool.return_byte_buffer(buffer);
        
        let scratch = pool.get_scratch_buffer();
        pool.return_scratch_buffer(scratch);
    }
}