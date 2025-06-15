//! Fault injection module for chaos engineering tests

use crate::error::{Result, RuzipError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use std::collections::HashMap;

/// Fault injection system for testing resilience
#[derive(Clone)]
pub struct FaultInjector {
    config: super::ChaosTestConfig,
    active_faults: Arc<Mutex<HashMap<FaultType, FaultConfiguration>>>,
    fault_statistics: Arc<Mutex<FaultStatistics>>,
}

/// Types of faults that can be injected
#[derive(Debug, Clone, Hash, PartialEq, Eq)]
pub enum FaultType {
    IoError,
    NetworkTimeout,
    DiskFull,
    PermissionDenied,
    FileCorruption,
    ThreadPanic,
    MemoryExhaustion,
    CpuSpike,
}

/// Configuration for a specific fault type
#[derive(Debug, Clone)]
pub struct FaultConfiguration {
    pub enabled: bool,
    pub probability: f64, // 0.0 to 1.0
    pub duration: Option<Duration>,
    pub parameters: HashMap<String, String>,
}

/// Statistics tracking for fault injection
#[derive(Debug, Clone, Default)]
pub struct FaultStatistics {
    pub total_injections: u64,
    pub successful_injections: u64,
    pub failed_injections: u64,
    pub injections_by_type: HashMap<FaultType, u64>,
    pub start_time: Option<Instant>,
}

impl FaultInjector {
    pub fn new(config: super::ChaosTestConfig) -> Self {
        Self {
            config,
            active_faults: Arc::new(Mutex::new(HashMap::new())),
            fault_statistics: Arc::new(Mutex::new(FaultStatistics::default())),
        }
    }

    /// Enable I/O fault injection
    pub async fn enable_io_faults(&self, probability: f64) -> Result<()> {
        let fault_config = FaultConfiguration {
            enabled: true,
            probability,
            duration: Some(self.config.max_duration),
            parameters: HashMap::new(),
        };

        self.active_faults.lock().unwrap().insert(FaultType::IoError, fault_config);
        
        // Initialize statistics
        let mut stats = self.fault_statistics.lock().unwrap();
        if stats.start_time.is_none() {
            stats.start_time = Some(Instant::now());
        }

        tracing::info!(
            probability = probability,
            "I/O fault injection enabled"
        );

        Ok(())
    }

    /// Enable network fault injection
    pub async fn enable_network_faults(&self, probability: f64) -> Result<()> {
        let fault_config = FaultConfiguration {
            enabled: true,
            probability,
            duration: Some(Duration::from_secs(30)),
            parameters: {
                let mut params = HashMap::new();
                params.insert("timeout_ms".to_string(), "5000".to_string());
                params.insert("drop_rate".to_string(), (probability * 100.0).to_string());
                params
            },
        };

        self.active_faults.lock().unwrap().insert(FaultType::NetworkTimeout, fault_config);

        tracing::info!(
            probability = probability,
            "Network fault injection enabled"
        );

        Ok(())
    }

    /// Enable memory exhaustion simulation
    pub async fn enable_memory_faults(&self, probability: f64) -> Result<()> {
        let fault_config = FaultConfiguration {
            enabled: true,
            probability,
            duration: Some(Duration::from_secs(10)),
            parameters: {
                let mut params = HashMap::new();
                params.insert("allocation_limit_mb".to_string(), "100".to_string());
                params.insert("oom_probability".to_string(), (probability * 0.5).to_string());
                params
            },
        };

        self.active_faults.lock().unwrap().insert(FaultType::MemoryExhaustion, fault_config);

        tracing::info!(
            probability = probability,
            "Memory fault injection enabled"
        );

        Ok(())
    }

    /// Enable disk space exhaustion simulation
    pub async fn enable_disk_faults(&self, probability: f64) -> Result<()> {
        let fault_config = FaultConfiguration {
            enabled: true,
            probability,
            duration: Some(Duration::from_secs(15)),
            parameters: {
                let mut params = HashMap::new();
                params.insert("free_space_limit_mb".to_string(), "10".to_string());
                params
            },
        };

        self.active_faults.lock().unwrap().insert(FaultType::DiskFull, fault_config);

        tracing::info!(
            probability = probability,
            "Disk fault injection enabled"
        );

        Ok(())
    }

    /// Disable all fault injection
    pub async fn disable_faults(&self) -> Result<()> {
        self.active_faults.lock().unwrap().clear();
        
        let stats = self.fault_statistics.lock().unwrap();
        tracing::info!(
            total_injections = stats.total_injections,
            successful_injections = stats.successful_injections,
            "All fault injection disabled"
        );

        Ok(())
    }

    /// Inject failure for specific thread (used in partial failure tests)
    pub async fn inject_failure_for_thread(&self) -> Result<()> {
        let should_inject = self.should_inject_fault(&FaultType::ThreadPanic).await;
        
        if should_inject {
            self.record_injection(&FaultType::ThreadPanic, true).await;
            
            // Simulate thread-specific failure
            tokio::time::sleep(Duration::from_millis(10)).await;
            
            return Err(RuzipError::threading_error(
                "Injected thread failure".to_string(),
                None,
            ));
        }

        Ok(())
    }

    /// Check if a fault should be injected for the given type
    async fn should_inject_fault(&self, fault_type: &FaultType) -> bool {
        let faults = self.active_faults.lock().unwrap();
        
        if let Some(config) = faults.get(fault_type) {
            if config.enabled {
                let random_value: f64 = rand::random();
                return random_value < config.probability;
            }
        }

        false
    }

    /// Record fault injection attempt
    async fn record_injection(&self, fault_type: &FaultType, successful: bool) {
        let mut stats = self.fault_statistics.lock().unwrap();
        stats.total_injections += 1;
        
        if successful {
            stats.successful_injections += 1;
        } else {
            stats.failed_injections += 1;
        }

        *stats.injections_by_type.entry(fault_type.clone()).or_insert(0) += 1;

        tracing::debug!(
            fault_type = ?fault_type,
            successful = successful,
            total_injections = stats.total_injections,
            "Fault injection recorded"
        );
    }

    /// Inject I/O error if conditions are met
    pub async fn maybe_inject_io_error(&self, operation: &str) -> Result<()> {
        if self.should_inject_fault(&FaultType::IoError).await {
            self.record_injection(&FaultType::IoError, true).await;
            
            tracing::warn!(
                operation = operation,
                "Injecting I/O error"
            );

            return Err(RuzipError::io_error(
                format!("Injected I/O error during {}", operation),
                std::io::Error::new(std::io::ErrorKind::Interrupted, "Fault injection"),
            ));
        }

        Ok(())
    }

    /// Inject network timeout if conditions are met
    pub async fn maybe_inject_network_timeout(&self, operation: &str) -> Result<()> {
        if self.should_inject_fault(&FaultType::NetworkTimeout).await {
            self.record_injection(&FaultType::NetworkTimeout, true).await;
            
            // Simulate network delay
            let faults = self.active_faults.lock().unwrap();
            if let Some(config) = faults.get(&FaultType::NetworkTimeout) {
                if let Some(timeout_str) = config.parameters.get("timeout_ms") {
                    if let Ok(timeout_ms) = timeout_str.parse::<u64>() {
                        tokio::time::sleep(Duration::from_millis(timeout_ms)).await;
                    }
                }
            }

            tracing::warn!(
                operation = operation,
                "Injecting network timeout"
            );

            return Err(RuzipError::io_error(
                format!("Injected network timeout during {}", operation),
                std::io::Error::new(std::io::ErrorKind::TimedOut, "Fault injection"),
            ));
        }

        Ok(())
    }

    /// Inject memory exhaustion if conditions are met
    pub async fn maybe_inject_memory_exhaustion(&self, allocation_size: usize) -> Result<()> {
        if self.should_inject_fault(&FaultType::MemoryExhaustion).await {
            self.record_injection(&FaultType::MemoryExhaustion, true).await;
            
            tracing::warn!(
                allocation_size = allocation_size,
                "Injecting memory exhaustion"
            );

            return Err(RuzipError::memory_error(
                format!("Injected memory exhaustion for {} bytes", allocation_size),
                None,
            ));
        }

        Ok(())
    }

    /// Inject disk full error if conditions are met
    pub async fn maybe_inject_disk_full(&self, operation: &str) -> Result<()> {
        if self.should_inject_fault(&FaultType::DiskFull).await {
            self.record_injection(&FaultType::DiskFull, true).await;
            
            tracing::warn!(
                operation = operation,
                "Injecting disk full error"
            );

            return Err(RuzipError::resource_exhausted(
                format!("Injected disk full error during {}", operation),
                "disk".to_string(),
            ));
        }

        Ok(())
    }

    /// Inject permission denied error if conditions are met
    pub async fn maybe_inject_permission_denied(&self, path: &str) -> Result<()> {
        if self.should_inject_fault(&FaultType::PermissionDenied).await {
            self.record_injection(&FaultType::PermissionDenied, true).await;
            
            tracing::warn!(
                path = path,
                "Injecting permission denied error"
            );

            return Err(RuzipError::permission_error(
                format!("Injected permission denied for {}", path),
                Some(std::path::PathBuf::from(path)),
            ));
        }

        Ok(())
    }

    /// Get current fault injection statistics
    pub fn get_statistics(&self) -> FaultStatistics {
        self.fault_statistics.lock().unwrap().clone()
    }

    /// Get active fault configurations
    pub fn get_active_faults(&self) -> HashMap<FaultType, FaultConfiguration> {
        self.active_faults.lock().unwrap().clone()
    }

    /// Reset fault injection statistics
    pub fn reset_statistics(&self) {
        let mut stats = self.fault_statistics.lock().unwrap();
        *stats = FaultStatistics::default();
        stats.start_time = Some(Instant::now());
    }
}

/// Fault injection wrapper for operations
pub struct FaultInjectingOperation<T> {
    operation: T,
    fault_injector: FaultInjector,
}

impl<T> FaultInjectingOperation<T> {
    pub fn new(operation: T, fault_injector: FaultInjector) -> Self {
        Self {
            operation,
            fault_injector,
        }
    }

    /// Execute operation with potential fault injection
    pub async fn execute<F, R>(&self, operation_name: &str, func: F) -> Result<R>
    where
        F: FnOnce(&T) -> Result<R>,
    {
        // Pre-operation fault injection checks
        self.fault_injector.maybe_inject_io_error(operation_name).await?;
        self.fault_injector.maybe_inject_network_timeout(operation_name).await?;
        self.fault_injector.maybe_inject_disk_full(operation_name).await?;

        // Execute the actual operation
        let result = func(&self.operation);

        // Post-operation fault injection (for async scenarios)
        if result.is_ok() {
            // Sometimes inject faults even after successful operations
            if rand::random::<f64>() < 0.05 { // 5% chance
                self.fault_injector.maybe_inject_io_error(&format!("{}_post", operation_name)).await?;
            }
        }

        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_fault_injector_creation() {
        let config = super::super::ChaosTestConfig::default();
        let injector = FaultInjector::new(config);
        
        let stats = injector.get_statistics();
        assert_eq!(stats.total_injections, 0);
    }

    #[tokio::test]
    async fn test_enable_io_faults() {
        let config = super::super::ChaosTestConfig::default();
        let injector = FaultInjector::new(config);
        
        injector.enable_io_faults(0.5).await.unwrap();
        
        let active_faults = injector.get_active_faults();
        assert!(active_faults.contains_key(&FaultType::IoError));
        assert_eq!(active_faults[&FaultType::IoError].probability, 0.5);
    }

    #[tokio::test]
    async fn test_fault_injection_with_high_probability() {
        let config = super::super::ChaosTestConfig::default();
        let injector = FaultInjector::new(config);
        
        // Enable with 100% probability to ensure injection
        injector.enable_io_faults(1.0).await.unwrap();
        
        let result = injector.maybe_inject_io_error("test_operation").await;
        assert!(result.is_err());
        
        let stats = injector.get_statistics();
        assert_eq!(stats.total_injections, 1);
        assert_eq!(stats.successful_injections, 1);
    }

    #[tokio::test]
    async fn test_fault_injection_with_zero_probability() {
        let config = super::super::ChaosTestConfig::default();
        let injector = FaultInjector::new(config);
        
        // Enable with 0% probability to ensure no injection
        injector.enable_io_faults(0.0).await.unwrap();
        
        let result = injector.maybe_inject_io_error("test_operation").await;
        assert!(result.is_ok());
        
        let stats = injector.get_statistics();
        assert_eq!(stats.total_injections, 0);
    }

    #[tokio::test]
    async fn test_disable_faults() {
        let config = super::super::ChaosTestConfig::default();
        let injector = FaultInjector::new(config);
        
        injector.enable_io_faults(0.5).await.unwrap();
        injector.enable_network_faults(0.3).await.unwrap();
        
        assert_eq!(injector.get_active_faults().len(), 2);
        
        injector.disable_faults().await.unwrap();
        
        assert_eq!(injector.get_active_faults().len(), 0);
    }

    #[tokio::test]
    async fn test_fault_injecting_operation() {
        let config = super::super::ChaosTestConfig::default();
        let injector = FaultInjector::new(config);
        let test_data = "test_data";
        
        let operation = FaultInjectingOperation::new(test_data, injector.clone());
        
        // With no faults enabled, operation should succeed
        let result = operation.execute("test", |data| {
            Ok(data.len())
        }).await;
        
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), 9); // "test_data".len()
    }

    #[tokio::test]
    async fn test_statistics_tracking() {
        let config = super::super::ChaosTestConfig::default();
        let injector = FaultInjector::new(config);
        
        injector.enable_io_faults(1.0).await.unwrap();
        injector.enable_network_faults(1.0).await.unwrap();
        
        // Inject some faults
        let _ = injector.maybe_inject_io_error("test1").await;
        let _ = injector.maybe_inject_network_timeout("test2").await;
        let _ = injector.maybe_inject_io_error("test3").await;
        
        let stats = injector.get_statistics();
        assert_eq!(stats.total_injections, 3);
        assert_eq!(stats.successful_injections, 3);
        assert_eq!(stats.injections_by_type[&FaultType::IoError], 2);
        assert_eq!(stats.injections_by_type[&FaultType::NetworkTimeout], 1);
    }

    #[tokio::test]
    async fn test_reset_statistics() {
        let config = super::super::ChaosTestConfig::default();
        let injector = FaultInjector::new(config);
        
        injector.enable_io_faults(1.0).await.unwrap();
        let _ = injector.maybe_inject_io_error("test").await;
        
        assert_eq!(injector.get_statistics().total_injections, 1);
        
        injector.reset_statistics();
        
        assert_eq!(injector.get_statistics().total_injections, 0);
    }
}