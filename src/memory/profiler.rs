//! Memory Profiling and Monitoring
//!
//! Provides tools for tracking memory usage, detecting leaks,
//! and analyzing allocation patterns for performance optimization.

use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime};
use std::thread;
use crate::error::{RuzipError, Result};

/// Memory statistics for profiling
#[derive(Debug, Clone)]
pub struct MemoryStats {
    /// Current memory usage in bytes
    pub current_usage: usize,
    /// Peak memory usage in bytes
    pub peak_usage: usize,
    /// Total allocations count
    pub total_allocations: u64,
    /// Total deallocations count
    pub total_deallocations: u64,
    /// Current active allocations
    pub active_allocations: u64,
    /// Total bytes allocated
    pub total_allocated: u64,
    /// Total bytes deallocated
    pub total_deallocated: u64,
    /// Average allocation size
    pub avg_allocation_size: f64,
    /// Memory fragmentation percentage
    pub fragmentation_percent: f64,
    /// Time when stats were collected
    pub timestamp: SystemTime,
}

impl MemoryStats {
    /// Create new empty memory stats
    pub fn new() -> Self {
        Self {
            current_usage: 0,
            peak_usage: 0,
            total_allocations: 0,
            total_deallocations: 0,
            active_allocations: 0,
            total_allocated: 0,
            total_deallocated: 0,
            avg_allocation_size: 0.0,
            fragmentation_percent: 0.0,
            timestamp: SystemTime::now(),
        }
    }

    /// Calculate derived statistics
    pub fn calculate_derived(&mut self) {
        if self.total_allocations > 0 {
            self.avg_allocation_size = self.total_allocated as f64 / self.total_allocations as f64;
        }
        
        self.active_allocations = self.total_allocations - self.total_deallocations;
        self.current_usage = (self.total_allocated - self.total_deallocated) as usize;
        
        // Simple fragmentation estimation
        if self.current_usage > 0 && self.peak_usage > 0 {
            self.fragmentation_percent = 
                ((self.peak_usage - self.current_usage) as f64 / self.peak_usage as f64) * 100.0;
        }
        
        self.timestamp = SystemTime::now();
    }

    /// Format memory size for display
    pub fn format_size(bytes: usize) -> String {
        const UNITS: &[&str] = &["B", "KB", "MB", "GB", "TB"];
        let mut size = bytes as f64;
        let mut unit_idx = 0;
        
        while size >= 1024.0 && unit_idx < UNITS.len() - 1 {
            size /= 1024.0;
            unit_idx += 1;
        }
        
        if unit_idx == 0 {
            format!("{} {}", bytes, UNITS[unit_idx])
        } else {
            format!("{:.2} {}", size, UNITS[unit_idx])
        }
    }

    /// Get memory efficiency percentage
    pub fn efficiency_percent(&self) -> f64 {
        if self.peak_usage == 0 {
            return 100.0;
        }
        (self.current_usage as f64 / self.peak_usage as f64) * 100.0
    }
}

impl Default for MemoryStats {
    fn default() -> Self {
        Self::new()
    }
}

/// Allocation tracking entry
#[derive(Debug, Clone)]
pub struct AllocationEntry {
    size: usize,
    timestamp: Instant,
    _thread_id: thread::ThreadId,
    operation: String,
}

/// Memory profiler for tracking allocations and usage patterns
pub struct MemoryProfiler {
    stats: Arc<RwLock<MemoryStats>>,
    allocations: Arc<Mutex<HashMap<usize, AllocationEntry>>>,
    enabled: AtomicUsize, // 0 = disabled, 1 = enabled
    next_id: AtomicUsize,
    warning_threshold: usize,
    critical_threshold: usize,
    sample_rate: f64, // 0.0 to 1.0, for performance
}

impl MemoryProfiler {
    /// Create new memory profiler
    pub fn new(warning_mb: usize, critical_mb: usize, sample_rate: f64) -> Self {
        Self {
            stats: Arc::new(RwLock::new(MemoryStats::new())),
            allocations: Arc::new(Mutex::new(HashMap::new())),
            enabled: AtomicUsize::new(1),
            next_id: AtomicUsize::new(1),
            warning_threshold: warning_mb * 1024 * 1024,
            critical_threshold: critical_mb * 1024 * 1024,
            sample_rate: sample_rate.clamp(0.0, 1.0),
        }
    }

    /// Enable profiling
    pub fn enable(&self) {
        self.enabled.store(1, Ordering::Relaxed);
    }

    /// Disable profiling
    pub fn disable(&self) {
        self.enabled.store(0, Ordering::Relaxed);
    }

    /// Check if profiling is enabled
    pub fn is_enabled(&self) -> bool {
        self.enabled.load(Ordering::Relaxed) != 0
    }

    /// Should sample this allocation (for performance)
    fn should_sample(&self) -> bool {
        if self.sample_rate >= 1.0 {
            return true;
        }
        if self.sample_rate <= 0.0 {
            return false;
        }
        
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        thread::current().id().hash(&mut hasher);
        Instant::now().elapsed().as_nanos().hash(&mut hasher);
        let hash = hasher.finish();
        
        (hash as f64 / u64::MAX as f64) < self.sample_rate
    }

    /// Record allocation
    pub fn record_allocation(&self, size: usize, operation: &str) -> AllocationId {
        if !self.is_enabled() || !self.should_sample() {
            return AllocationId(0);
        }

        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let entry = AllocationEntry {
            size,
            timestamp: Instant::now(),
            _thread_id: thread::current().id(),
            operation: operation.to_string(),
        };

        // Update allocations map
        if let Ok(mut allocations) = self.allocations.lock() {
            allocations.insert(id, entry);
        }

        // Update stats
        if let Ok(mut stats) = self.stats.write() {
            stats.total_allocations += 1;
            stats.total_allocated += size as u64;
            
            let new_usage = stats.current_usage + size;
            stats.current_usage = new_usage;
            
            if new_usage > stats.peak_usage {
                stats.peak_usage = new_usage;
            }
            
            stats.calculate_derived();
            
            // Check thresholds
            if new_usage >= self.critical_threshold {
                eprintln!("CRITICAL: Memory usage {} exceeds critical threshold {}", 
                    MemoryStats::format_size(new_usage),
                    MemoryStats::format_size(self.critical_threshold));
            } else if new_usage >= self.warning_threshold {
                eprintln!("WARNING: Memory usage {} exceeds warning threshold {}", 
                    MemoryStats::format_size(new_usage),
                    MemoryStats::format_size(self.warning_threshold));
            }
        }

        AllocationId(id)
    }

    /// Record deallocation
    pub fn record_deallocation(&self, id: AllocationId) {
        if !self.is_enabled() || id.0 == 0 {
            return;
        }

        let size = if let Ok(mut allocations) = self.allocations.lock() {
            allocations.remove(&id.0).map(|entry| entry.size)
        } else {
            None
        };

        if let Some(size) = size {
            if let Ok(mut stats) = self.stats.write() {
                stats.total_deallocations += 1;
                stats.total_deallocated += size as u64;
                stats.current_usage = stats.current_usage.saturating_sub(size);
                stats.calculate_derived();
            }
        }
    }

    /// Get current memory statistics
    pub fn get_stats(&self) -> MemoryStats {
        self.stats.read().unwrap().clone()
    }

    /// Get allocation details by operation
    pub fn get_allocations_by_operation(&self) -> HashMap<String, Vec<AllocationEntry>> {
        let mut result = HashMap::new();
        
        if let Ok(allocations) = self.allocations.lock() {
            for entry in allocations.values() {
                result.entry(entry.operation.clone())
                    .or_insert_with(Vec::new)
                    .push(entry.clone());
            }
        }
        
        result
    }

    /// Get top memory consumers
    pub fn get_top_consumers(&self, limit: usize) -> Vec<(String, usize, usize)> {
        let mut consumers = HashMap::new();
        
        if let Ok(allocations) = self.allocations.lock() {
            for entry in allocations.values() {
                let (count, total_size) = consumers.entry(entry.operation.clone())
                    .or_insert((0, 0));
                *count += 1;
                *total_size += entry.size;
            }
        }
        
        let mut sorted: Vec<_> = consumers.into_iter()
            .map(|(op, (count, size))| (op, count, size))
            .collect();
        sorted.sort_by(|a, b| b.2.cmp(&a.2)); // Sort by total size descending
        sorted.truncate(limit);
        sorted
    }

    /// Detect potential memory leaks
    pub fn detect_leaks(&self, age_threshold: Duration) -> Vec<AllocationEntry> {
        let mut leaks = Vec::new();
        let now = Instant::now();
        
        if let Ok(allocations) = self.allocations.lock() {
            for entry in allocations.values() {
                if now.duration_since(entry.timestamp) > age_threshold {
                    leaks.push(entry.clone());
                }
            }
        }
        
        // Sort by age (oldest first)
        leaks.sort_by(|a, b| a.timestamp.cmp(&b.timestamp));
        leaks
    }

    /// Generate memory report
    pub fn generate_report(&self) -> String {
        let stats = self.get_stats();
        let top_consumers = self.get_top_consumers(10);
        let leaks = self.detect_leaks(Duration::from_secs(300)); // 5 minutes
        
        let mut report = String::new();
        report.push_str("=== MEMORY PROFILING REPORT ===\n\n");
        
        // Basic stats
        report.push_str("MEMORY STATISTICS:\n");
        report.push_str(&format!("  Current Usage: {}\n", MemoryStats::format_size(stats.current_usage)));
        report.push_str(&format!("  Peak Usage: {}\n", MemoryStats::format_size(stats.peak_usage)));
        report.push_str(&format!("  Total Allocations: {}\n", stats.total_allocations));
        report.push_str(&format!("  Active Allocations: {}\n", stats.active_allocations));
        report.push_str(&format!("  Average Allocation Size: {:.2} bytes\n", stats.avg_allocation_size));
        report.push_str(&format!("  Memory Efficiency: {:.1}%\n", stats.efficiency_percent()));
        report.push_str(&format!("  Fragmentation: {:.1}%\n\n", stats.fragmentation_percent));
        
        // Top consumers
        report.push_str("TOP MEMORY CONSUMERS:\n");
        for (i, (operation, count, size)) in top_consumers.iter().enumerate() {
            report.push_str(&format!("  {}. {} - {} allocations, {} total\n", 
                i + 1, operation, count, MemoryStats::format_size(*size)));
        }
        report.push('\n');
        
        // Potential leaks
        if !leaks.is_empty() {
            report.push_str("POTENTIAL MEMORY LEAKS:\n");
            for (i, leak) in leaks.iter().take(10).enumerate() {
                let age = Instant::now().duration_since(leak.timestamp);
                report.push_str(&format!("  {}. {} - {} (age: {:.1}s)\n", 
                    i + 1, leak.operation, MemoryStats::format_size(leak.size), age.as_secs_f64()));
            }
            if leaks.len() > 10 {
                report.push_str(&format!("  ... and {} more\n", leaks.len() - 10));
            }
        } else {
            report.push_str("NO POTENTIAL MEMORY LEAKS DETECTED\n");
        }
        
        report
    }

    /// Clear all tracking data
    pub fn clear(&self) {
        if let Ok(mut allocations) = self.allocations.lock() {
            allocations.clear();
        }
        if let Ok(mut stats) = self.stats.write() {
            *stats = MemoryStats::new();
        }
    }

    /// Set warning threshold
    pub fn set_warning_threshold(&mut self, mb: usize) {
        self.warning_threshold = mb * 1024 * 1024;
    }

    /// Set critical threshold
    pub fn set_critical_threshold(&mut self, mb: usize) {
        self.critical_threshold = mb * 1024 * 1024;
    }
}

/// Allocation ID for tracking
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllocationId(usize);

/// RAII allocation tracker
pub struct AllocationTracker {
    profiler: Arc<MemoryProfiler>,
    id: AllocationId,
}

impl AllocationTracker {
    /// Create new allocation tracker
    pub fn new(profiler: Arc<MemoryProfiler>, size: usize, operation: &str) -> Self {
        let id = profiler.record_allocation(size, operation);
        Self { profiler, id }
    }
}

impl Drop for AllocationTracker {
    fn drop(&mut self) {
        self.profiler.record_deallocation(self.id);
    }
}

/// Global memory profiler instance
static GLOBAL_PROFILER: std::sync::OnceLock<Arc<MemoryProfiler>> = std::sync::OnceLock::new();

/// Initialize global memory profiler
pub fn init_memory_profiler(warning_mb: usize, critical_mb: usize, sample_rate: f64) -> Arc<MemoryProfiler> {
    GLOBAL_PROFILER.get_or_init(|| {
        Arc::new(MemoryProfiler::new(warning_mb, critical_mb, sample_rate))
    }).clone()
}

/// Get global memory profiler
pub fn get_memory_profiler() -> Option<Arc<MemoryProfiler>> {
    GLOBAL_PROFILER.get().cloned()
}

/// Macro for easy allocation tracking
#[macro_export]
macro_rules! track_allocation {
    ($size:expr, $operation:expr) => {
        if let Some(profiler) = $crate::memory::profiler::get_memory_profiler() {
            Some($crate::memory::profiler::AllocationTracker::new(profiler, $size, $operation))
        } else {
            None
        }
    };
}

/// Memory pressure monitor that runs in background
pub struct MemoryPressureMonitor {
    profiler: Arc<MemoryProfiler>,
    running: Arc<AtomicUsize>,
    check_interval: Duration,
}

impl MemoryPressureMonitor {
    /// Create new memory pressure monitor
    pub fn new(profiler: Arc<MemoryProfiler>, check_interval: Duration) -> Self {
        Self {
            profiler,
            running: Arc::new(AtomicUsize::new(0)),
            check_interval,
        }
    }

    /// Start monitoring in background thread
    pub fn start(&self) -> Result<()> {
        if self.running.compare_exchange(0, 1, Ordering::Relaxed, Ordering::Relaxed).is_err() {
            return Err(RuzipError::memory_error("Monitor already running", None));
        }

        let profiler = self.profiler.clone();
        let running = self.running.clone();
        let interval = self.check_interval;

        thread::spawn(move || {
            while running.load(Ordering::Relaxed) == 1 {
                let stats = profiler.get_stats();
                
                // Check for concerning patterns
                if stats.active_allocations > 10000 {
                    eprintln!("WARNING: High allocation count: {}", stats.active_allocations);
                }
                
                if stats.fragmentation_percent > 50.0 {
                    eprintln!("WARNING: High memory fragmentation: {:.1}%", stats.fragmentation_percent);
                }
                
                // Check for potential leaks
                let leaks = profiler.detect_leaks(Duration::from_secs(600)); // 10 minutes
                if leaks.len() > 100 {
                    eprintln!("WARNING: {} potential memory leaks detected", leaks.len());
                }
                
                thread::sleep(interval);
            }
        });

        Ok(())
    }

    /// Stop monitoring
    pub fn stop(&self) {
        self.running.store(0, Ordering::Relaxed);
    }

    /// Check if monitor is running
    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed) == 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_memory_stats() {
        let mut stats = MemoryStats::new();
        stats.total_allocations = 100;
        stats.total_allocated = 1024 * 1024; // 1MB
        stats.peak_usage = 2 * 1024 * 1024; // 2MB
        stats.calculate_derived();
        
        assert_eq!(stats.avg_allocation_size, 10485.76);
        assert_eq!(stats.active_allocations, 100);
    }

    #[test]
    fn test_memory_profiler() {
        let profiler = MemoryProfiler::new(100, 200, 1.0);
        
        let id1 = profiler.record_allocation(1024, "test_operation");
        let _id2 = profiler.record_allocation(2048, "test_operation");
        
        let stats = profiler.get_stats();
        assert_eq!(stats.total_allocations, 2);
        assert_eq!(stats.current_usage, 3072);
        
        profiler.record_deallocation(id1);
        
        let stats = profiler.get_stats();
        assert_eq!(stats.total_deallocations, 1);
        assert_eq!(stats.current_usage, 2048);
        
        let consumers = profiler.get_top_consumers(5);
        assert_eq!(consumers.len(), 1);
        assert_eq!(consumers[0].0, "test_operation");
    }

    #[test]
    fn test_allocation_tracker() {
        let profiler = Arc::new(MemoryProfiler::new(100, 200, 1.0));
        
        {
            let _tracker = AllocationTracker::new(profiler.clone(), 1024, "tracker_test");
            let stats = profiler.get_stats();
            assert_eq!(stats.total_allocations, 1);
            assert_eq!(stats.current_usage, 1024);
        }
        
        // Should be deallocated when tracker is dropped
        let stats = profiler.get_stats();
        assert_eq!(stats.total_deallocations, 1);
        assert_eq!(stats.current_usage, 0);
    }

    #[test]
    fn test_leak_detection() {
        let profiler = MemoryProfiler::new(100, 200, 1.0);
        
        profiler.record_allocation(1024, "potential_leak");
        thread::sleep(Duration::from_millis(10));
        
        let leaks = profiler.detect_leaks(Duration::from_millis(5));
        assert_eq!(leaks.len(), 1);
        assert_eq!(leaks[0].operation, "potential_leak");
    }

    #[test]
    fn test_memory_size_formatting() {
        assert_eq!(MemoryStats::format_size(512), "512 B");
        assert_eq!(MemoryStats::format_size(1024), "1.00 KB");
        assert_eq!(MemoryStats::format_size(1536), "1.50 KB");
        assert_eq!(MemoryStats::format_size(1024 * 1024), "1.00 MB");
        assert_eq!(MemoryStats::format_size(1024 * 1024 * 1024), "1.00 GB");
    }
}