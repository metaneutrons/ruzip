//! Thread-safe progress tracking for parallel operations

use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

#[cfg(feature = "progress")]
use indicatif::{ProgressBar, ProgressStyle};

/// Thread-safe progress tracker
#[derive(Clone)]
pub struct ThreadSafeProgress {
    inner: Arc<Mutex<ProgressInner>>,
    #[cfg(feature = "progress")]
    progress_bar: Option<Arc<ProgressBar>>,
}

struct ProgressInner {
    total: u64,
    current: u64,
    start_time: Instant,
    last_update: Instant,
    throughput_samples: Vec<(Instant, u64)>,
    thread_contributions: std::collections::HashMap<std::thread::ThreadId, u64>,
}

impl ThreadSafeProgress {
    /// Create a new progress tracker
    pub fn new(total: u64) -> Self {
        let inner = Arc::new(Mutex::new(ProgressInner {
            total,
            current: 0,
            start_time: Instant::now(),
            last_update: Instant::now(),
            throughput_samples: Vec::new(),
            thread_contributions: std::collections::HashMap::new(),
        }));

        #[cfg(feature = "progress")]
        let progress_bar = Self::create_progress_bar(total);

        Self {
            inner,
            #[cfg(feature = "progress")]
            progress_bar,
        }
    }

    /// Create a new progress tracker without visual progress bar
    pub fn new_silent(total: u64) -> Self {
        let inner = Arc::new(Mutex::new(ProgressInner {
            total,
            current: 0,
            start_time: Instant::now(),
            last_update: Instant::now(),
            throughput_samples: Vec::new(),
            thread_contributions: std::collections::HashMap::new(),
        }));

        Self {
            inner,
            #[cfg(feature = "progress")]
            progress_bar: None,
        }
    }

    #[cfg(feature = "progress")]
    fn create_progress_bar(total: u64) -> Option<Arc<ProgressBar>> {
        if !atty::is(atty::Stream::Stderr) {
            return None; // Don't show progress bar if not in terminal
        }

        let pb = ProgressBar::new(total);
        pb.set_style(
            ProgressStyle::default_bar()
                .template("[{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg} ({eta})")
                .unwrap()
                .progress_chars("##-"),
        );
        pb.set_message("Processing");
        Some(Arc::new(pb))
    }

    /// Increment progress by the given amount
    pub fn inc(&self, delta: u64) {
        let thread_id = std::thread::current().id();
        let now = Instant::now();
        
        let (current_pos, throughput) = if let Ok(mut inner) = self.inner.lock() {
            inner.current = (inner.current + delta).min(inner.total);
            inner.last_update = now;
            
            // Track per-thread contributions
            *inner.thread_contributions.entry(thread_id).or_insert(0) += delta;
            
            let current_pos = inner.current;
            
            // Update throughput samples (keep last 10 samples)
            if inner.throughput_samples.len() >= 10 {
                inner.throughput_samples.remove(0);
            }
            inner.throughput_samples.push((now, current_pos));
            
            // Calculate simple throughput from elapsed time
            let throughput = if inner.throughput_samples.len() >= 2 {
                let elapsed = now.duration_since(inner.start_time).as_secs_f64();
                if elapsed > 0.0 {
                    Some(current_pos as f64 / elapsed / 1_048_576.0) // MB/s
                } else {
                    None
                }
            } else {
                None
            };
            
            (current_pos, throughput)
        } else {
            return;
        };
        
        #[cfg(feature = "progress")]
        if let Some(ref pb) = self.progress_bar {
            pb.set_position(current_pos);
            
            // Update message with throughput
            if let Some(throughput_val) = throughput {
                pb.set_message(format!("{:.1} MB/s", throughput_val));
            }
        }
    }

    /// Set the current progress position
    pub fn set_position(&self, pos: u64) {
        let thread_id = std::thread::current().id();
        let now = Instant::now();
        
        if let Ok(mut inner) = self.inner.lock() {
            let old_pos = inner.current;
            inner.current = pos.min(inner.total);
            inner.last_update = now;
            
            // Update thread contribution
            let delta = if pos > old_pos { pos - old_pos } else { 0 };
            *inner.thread_contributions.entry(thread_id).or_insert(0) += delta;
            
            let current_pos = inner.current;
            
            // Update throughput samples (keep last 10 samples)
            if inner.throughput_samples.len() >= 10 {
                inner.throughput_samples.remove(0);
            }
            inner.throughput_samples.push((now, current_pos));
            
            // Calculate simple throughput from elapsed time
            let throughput = if inner.throughput_samples.len() >= 2 {
                let elapsed = now.duration_since(inner.start_time).as_secs_f64();
                if elapsed > 0.0 {
                    Some(current_pos as f64 / elapsed / 1_048_576.0) // MB/s
                } else {
                    None
                }
            } else {
                None
            };
            
            #[cfg(feature = "progress")]
            if let Some(ref pb) = self.progress_bar {
                pb.set_position(current_pos);
                
                if let Some(throughput_val) = throughput {
                    pb.set_message(format!("{:.1} MB/s", throughput_val));
                }
            }
        }
    }

    /// Set a custom message
    pub fn set_message(&self, msg: &str) {
        #[cfg(feature = "progress")]
        if let Some(ref pb) = self.progress_bar {
            pb.set_message(msg.to_string());
        }
    }

    /// Get current progress information
    pub fn get_progress(&self) -> Option<ProgressInfo> {
        if let Ok(inner) = self.inner.lock() {
            let current = inner.current;
            let total = inner.total;
            let elapsed = inner.start_time.elapsed();
            let active_threads = inner.thread_contributions.len();
            
            // Calculate simple throughput
            let throughput_mb_per_sec = if elapsed.as_secs_f64() > 0.0 {
                Some(current as f64 / elapsed.as_secs_f64() / 1_048_576.0)
            } else {
                None
            };
            
            Some(ProgressInfo {
                current,
                total,
                percentage: if total > 0 {
                    (current as f64 / total as f64) * 100.0
                } else {
                    0.0
                },
                elapsed,
                throughput_mb_per_sec,
                active_threads,
            })
        } else {
            None
        }
    }

    /// Calculate current throughput in MB/s
    pub fn calculate_throughput(&self) -> Option<f64> {
        if let Ok(inner) = self.inner.lock() {
            self.calculate_throughput_locked(&inner)
        } else {
            None
        }
    }

    fn calculate_throughput_locked(&self, inner: &ProgressInner) -> Option<f64> {
        if inner.throughput_samples.len() < 2 {
            return None;
        }

        let recent_samples = &inner.throughput_samples[inner.throughput_samples.len().saturating_sub(5)..];
        if recent_samples.len() < 2 {
            return None;
        }

        let first = &recent_samples[0];
        let last = &recent_samples[recent_samples.len() - 1];
        
        let time_diff = last.0.duration_since(first.0).as_secs_f64();
        let bytes_diff = last.1.saturating_sub(first.1) as f64;

        if time_diff > 0.0 {
            Some(bytes_diff / time_diff / 1_048_576.0) // Convert to MB/s
        } else {
            None
        }
    }

    /// Get per-thread statistics
    pub fn get_thread_stats(&self) -> Vec<ThreadStats> {
        if let Ok(inner) = self.inner.lock() {
            inner.thread_contributions
                .iter()
                .map(|(thread_id, contribution)| ThreadStats {
                    thread_id: format!("{:?}", thread_id),
                    contribution: *contribution,
                    percentage: if inner.total > 0 {
                        (*contribution as f64 / inner.total as f64) * 100.0
                    } else {
                        0.0
                    },
                })
                .collect()
        } else {
            Vec::new()
        }
    }

    /// Finish the progress tracking
    pub fn finish(&self) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.current = inner.total;
            
            #[cfg(feature = "progress")]
            if let Some(ref pb) = self.progress_bar {
                pb.finish_with_message("Completed");
            }
        }
    }

    /// Finish with a custom message
    pub fn finish_with_message(&self, msg: &str) {
        if let Ok(mut inner) = self.inner.lock() {
            inner.current = inner.total;
            
            #[cfg(feature = "progress")]
            if let Some(ref pb) = self.progress_bar {
                pb.finish_with_message(msg.to_string());
            }
        }
    }

    /// Check if progress tracking is complete
    pub fn is_finished(&self) -> bool {
        if let Ok(inner) = self.inner.lock() {
            inner.current >= inner.total
        } else {
            false
        }
    }
}

/// Progress information snapshot
#[derive(Debug, Clone)]
pub struct ProgressInfo {
    pub current: u64,
    pub total: u64,
    pub percentage: f64,
    pub elapsed: Duration,
    pub throughput_mb_per_sec: Option<f64>,
    pub active_threads: usize,
}

/// Per-thread statistics
#[derive(Debug, Clone)]
pub struct ThreadStats {
    pub thread_id: String,
    pub contribution: u64,
    pub percentage: f64,
}

/// Create a scoped progress tracker that automatically finishes
pub struct ScopedProgress {
    progress: ThreadSafeProgress,
}

impl ScopedProgress {
    pub fn new(total: u64) -> Self {
        Self {
            progress: ThreadSafeProgress::new(total),
        }
    }

    pub fn new_silent(total: u64) -> Self {
        Self {
            progress: ThreadSafeProgress::new_silent(total),
        }
    }

    pub fn progress(&self) -> &ThreadSafeProgress {
        &self.progress
    }
}

impl Drop for ScopedProgress {
    fn drop(&mut self) {
        self.progress.finish();
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread;
    use std::time::Duration;

    #[test]
    fn test_progress_creation() {
        let progress = ThreadSafeProgress::new(100);
        let info = progress.get_progress().unwrap();
        assert_eq!(info.current, 0);
        assert_eq!(info.total, 100);
        assert_eq!(info.percentage, 0.0);
    }

    #[test]
    fn test_progress_increment() {
        let progress = ThreadSafeProgress::new(100);
        progress.inc(50);
        
        let info = progress.get_progress().unwrap();
        assert_eq!(info.current, 50);
        assert_eq!(info.percentage, 50.0);
    }

    #[test]
    fn test_progress_set_position() {
        let progress = ThreadSafeProgress::new(100);
        progress.set_position(75);
        
        let info = progress.get_progress().unwrap();
        assert_eq!(info.current, 75);
        assert_eq!(info.percentage, 75.0);
    }

    #[test]
    fn test_threaded_progress() {
        let progress = ThreadSafeProgress::new(1000);
        let progress_clone = progress.clone();
        
        let handle = thread::spawn(move || {
            for _ in 0..10 {
                progress_clone.inc(10);
                thread::sleep(Duration::from_millis(1));
            }
        });
        
        for _ in 0..10 {
            progress.inc(10);
            thread::sleep(Duration::from_millis(1));
        }
        
        handle.join().unwrap();
        
        let info = progress.get_progress().unwrap();
        assert_eq!(info.current, 200);
        assert_eq!(info.active_threads, 2); // Main thread + spawned thread
    }

    #[test]
    fn test_scoped_progress() {
        {
            let scoped = ScopedProgress::new(100);
            scoped.progress().inc(50);
            assert!(!scoped.progress().is_finished());
        }
        // ScopedProgress should automatically finish when dropped
    }

    #[test]
    fn test_progress_bounds() {
        let progress = ThreadSafeProgress::new(100);
        progress.inc(150); // Should be clamped to 100
        
        let info = progress.get_progress().unwrap();
        assert_eq!(info.current, 100);
        assert_eq!(info.percentage, 100.0);
    }
}