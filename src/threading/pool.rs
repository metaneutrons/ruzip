//! Thread pool implementation for parallel operations

use super::config::ThreadConfig;
use super::ThreadResult;
use crate::error::RuzipError;
use std::sync::Arc;
use std::thread;

/// Thread pool wrapper for parallel operations
pub struct ThreadPool {
    config: ThreadConfig,
    thread_count: usize,
}

impl ThreadPool {
    /// Create a new thread pool with the given configuration
    pub fn new(config: ThreadConfig) -> ThreadResult<Self> {
        config.validate().map_err(|e| RuzipError::threading_error(e, None))?;
        
        let thread_count = config.effective_thread_count();
        
        Ok(Self {
            config,
            thread_count,
        })
    }
    
    /// Create a thread pool with default configuration
    pub fn default() -> ThreadResult<Self> {
        Self::new(ThreadConfig::default())
    }
    
    /// Get the thread pool configuration
    pub fn config(&self) -> &ThreadConfig {
        &self.config
    }
    
    /// Get the number of threads in the pool
    pub fn thread_count(&self) -> usize {
        self.thread_count
    }
    
    /// Execute a parallel operation using simple threading
    pub fn execute<F, R>(&self, op: F) -> R
    where
        F: FnOnce() -> R + Send,
        R: Send,
    {
        // For now, just execute directly
        // In a full implementation, this would use a proper thread pool
        op()
    }
    
    /// Execute a parallel map operation using simple threading
    pub fn parallel_map<I, F, T, R>(&self, items: I, map_fn: F) -> Vec<R>
    where
        I: IntoIterator<Item = T>,
        I::IntoIter: Send,
        T: Send + 'static + Clone,
        F: Fn(T) -> R + Sync + Send + 'static,
        R: Send + 'static,
    {
        let items: Vec<T> = items.into_iter().collect();
        let chunk_size = self.config.optimal_chunk_size(items.len());
        
        if items.len() <= chunk_size || self.thread_count == 1 {
            // Process sequentially for small datasets or single thread
            return items.into_iter().map(map_fn).collect();
        }
        
        // Simple parallel processing with std::thread
        let map_fn = Arc::new(map_fn);
        let mut handles = Vec::new();
        let mut results = Vec::new();
        
        for chunk in items.chunks(chunk_size) {
            let chunk = chunk.to_vec();
            let map_fn = Arc::clone(&map_fn);
            
            let handle = thread::spawn(move || {
                chunk.into_iter().map(|item| map_fn(item)).collect::<Vec<R>>()
            });
            
            handles.push(handle);
        }
        
        for handle in handles {
            if let Ok(mut chunk_results) = handle.join() {
                results.append(&mut chunk_results);
            }
        }
        
        results
    }
    
    /// Execute a parallel reduce operation
    pub fn parallel_reduce<I, T, F, C, R>(&self, items: I, identity: R, reduce_fn: F, combine_fn: C) -> R
    where
        I: IntoIterator<Item = T>,
        I::IntoIter: Send,
        T: Send + 'static + Clone,
        F: Fn(R, T) -> R + Sync + Send + 'static,
        C: Fn(R, R) -> R + Sync + Send + 'static,
        R: Send + Clone + 'static,
    {
        let items: Vec<T> = items.into_iter().collect();
        
        if items.is_empty() {
            return identity;
        }
        
        if items.len() <= 100 || self.thread_count == 1 {
            // Process sequentially for small datasets
            return items.into_iter().fold(identity, reduce_fn);
        }
        
        // Simple parallel reduce
        let chunk_size = items.len() / self.thread_count;
        let reduce_fn = Arc::new(reduce_fn);
        let combine_fn = Arc::new(combine_fn);
        let mut handles = Vec::new();
        
        for chunk in items.chunks(chunk_size.max(1)) {
            let chunk = chunk.to_vec();
            let identity = identity.clone();
            let reduce_fn = Arc::clone(&reduce_fn);
            
            let handle = thread::spawn(move || {
                chunk.into_iter().fold(identity, |acc, item| reduce_fn(acc, item))
            });
            
            handles.push(handle);
        }
        
        let mut final_result = identity;
        for handle in handles {
            if let Ok(chunk_result) = handle.join() {
                final_result = combine_fn(final_result, chunk_result);
            }
        }
        
        final_result
    }
    
    /// Execute work in parallel chunks with custom chunk processing
    pub fn parallel_chunks<I, T, F, R>(&self, items: I, chunk_processor: F) -> ThreadResult<Vec<R>>
    where
        I: IntoIterator<Item = T>,
        I::IntoIter: Send,
        T: Send + 'static + Clone,
        F: Fn(Vec<T>) -> ThreadResult<R> + Sync + Send + 'static,
        R: Send + 'static,
    {
        let items: Vec<T> = items.into_iter().collect();
        let chunk_size = self.config.optimal_chunk_size(items.len());
        
        if items.len() <= chunk_size || self.thread_count == 1 {
            // Process sequentially
            return Ok(vec![chunk_processor(items)?]);
        }
        
        let chunk_processor = Arc::new(chunk_processor);
        let mut handles = Vec::new();
        
        for chunk in items.chunks(chunk_size) {
            let chunk = chunk.to_vec();
            let chunk_processor = Arc::clone(&chunk_processor);
            
            let handle = thread::spawn(move || chunk_processor(chunk));
            handles.push(handle);
        }
        
        let mut results = Vec::new();
        for handle in handles {
            match handle.join() {
                Ok(Ok(result)) => results.push(result),
                Ok(Err(e)) => return Err(e),
                Err(_) => return Err(RuzipError::threading_error("Thread panicked", None)),
            }
        }
        
        Ok(results)
    }
    
    /// Process items in parallel with error handling
    pub fn try_parallel_map<I, F, T, R, E>(&self, items: I, map_fn: F) -> Result<Vec<R>, E>
    where
        I: IntoIterator<Item = T>,
        I::IntoIter: Send,
        T: Send + 'static + Clone,
        F: Fn(T) -> Result<R, E> + Sync + Send + 'static,
        R: Send + 'static,
        E: Send + 'static,
    {
        let items: Vec<T> = items.into_iter().collect();
        let chunk_size = self.config.optimal_chunk_size(items.len());
        
        if items.len() <= chunk_size || self.thread_count == 1 {
            // Process sequentially
            return items.into_iter().map(map_fn).collect();
        }
        
        let map_fn = Arc::new(map_fn);
        let mut handles = Vec::new();
        
        for chunk in items.chunks(chunk_size) {
            let chunk = chunk.to_vec();
            let map_fn = Arc::clone(&map_fn);
            
            let handle = thread::spawn(move || {
                chunk.into_iter().map(|item| map_fn(item)).collect::<Result<Vec<R>, E>>()
            });
            
            handles.push(handle);
        }
        
        let mut results = Vec::new();
        for handle in handles {
            match handle.join() {
                Ok(Ok(mut chunk_results)) => results.append(&mut chunk_results),
                Ok(Err(e)) => return Err(e),
                Err(_) => panic!("Thread panicked"),
            }
        }
        
        Ok(results)
    }
    
    /// Get memory usage statistics (estimated)
    pub fn estimated_memory_usage(&self) -> usize {
        self.thread_count * self.config.memory_limit_per_thread
    }
    
    /// Check if the pool is configured for work stealing
    pub fn uses_work_stealing(&self) -> bool {
        self.config.work_stealing
    }
}

impl Clone for ThreadPool {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            thread_count: self.thread_count,
        }
    }
}

unsafe impl Send for ThreadPool {}
unsafe impl Sync for ThreadPool {}

/// Global thread pool instance
static mut GLOBAL_POOL: Option<ThreadPool> = None;
static POOL_INIT: std::sync::Once = std::sync::Once::new();

/// Get or create the global thread pool
#[allow(static_mut_refs)]
pub fn global_pool() -> ThreadResult<&'static ThreadPool> {
    unsafe {
        POOL_INIT.call_once(|| {
            match ThreadPool::default() {
                Ok(pool) => GLOBAL_POOL = Some(pool),
                Err(_) => {} // Will be handled by the None check below
            }
        });
        
        GLOBAL_POOL.as_ref().ok_or_else(|| {
            RuzipError::threading_error("Failed to initialize global thread pool", None)
        })
    }
}

/// Initialize the global thread pool with custom configuration
pub fn init_global_pool(config: ThreadConfig) -> ThreadResult<()> {
    let pool = ThreadPool::new(config)?;
    unsafe {
        GLOBAL_POOL = Some(pool);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_thread_pool_creation() {
        let config = ThreadConfig::new().with_thread_count(2);
        let pool = ThreadPool::new(config).unwrap();
        assert_eq!(pool.thread_count(), 2);
    }
    
    #[test]
    fn test_parallel_map() {
        let pool = ThreadPool::default().unwrap();
        let items = vec![1, 2, 3, 4, 5];
        let results = pool.parallel_map(items, |x| x * 2);
        assert_eq!(results.len(), 5);
        // Results might be in different order due to parallel processing
        let mut results = results;
        results.sort();
        assert_eq!(results, vec![2, 4, 6, 8, 10]);
    }
    
    #[test]
    fn test_parallel_reduce() {
        let pool = ThreadPool::default().unwrap();
        let items = vec![1, 2, 3, 4, 5];
        let sum = pool.parallel_reduce(items, 0, |acc, x| acc + x, |a, b| a + b);
        assert_eq!(sum, 15);
    }
    
    #[test]
    fn test_try_parallel_map_success() {
        let pool = ThreadPool::default().unwrap();
        let items = vec![1, 2, 3, 4, 5];
        let results: Result<Vec<i32>, &str> = pool.try_parallel_map(items, |x| Ok(x * 2));
        let results = results.unwrap();
        assert_eq!(results.len(), 5);
    }
    
    #[test]
    fn test_global_pool() {
        let pool = global_pool().unwrap();
        assert!(pool.thread_count() > 0);
    }
}