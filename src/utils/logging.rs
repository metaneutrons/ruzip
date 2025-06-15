//! Logging infrastructure for RuZip
//!
//! Provides structured logging with tracing, configurable output formats,
//! and performance-aware logging levels.

use crate::error::{Result, RuzipError};
use std::error::Error;
use std::io;
use tracing::Level;
use tracing_subscriber::{
    fmt::format::FmtSpan,
    layer::SubscriberExt,
    util::SubscriberInitExt,
    EnvFilter, Layer,
};

/// Logging configuration
#[derive(Debug, Clone)]
pub struct LoggingConfig {
    /// Log level
    pub level: Level,
    /// Enable JSON output
    pub json_format: bool,
    /// Enable colored output
    pub colored: bool,
    /// Include file and line information
    pub include_location: bool,
    /// Include target module information
    pub include_target: bool,
    /// Span events to log
    pub span_events: FmtSpan,
    /// Log to file
    pub log_file: Option<std::path::PathBuf>,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: Level::INFO,
            json_format: false,
            colored: true,
            include_location: false,
            include_target: false,
            span_events: FmtSpan::NONE,
            log_file: None,
        }
    }
}

/// Initialize logging with the given configuration
pub fn init_logging(config: LoggingConfig) -> Result<()> {
    let filter = EnvFilter::builder()
        .with_default_directive(config.level.into())
        .from_env_lossy()
        .add_directive("ruzip=trace".parse().unwrap()) // Always trace our own crate
        .add_directive("hyper=warn".parse().unwrap()) // Reduce hyper noise
        .add_directive("h2=warn".parse().unwrap()); // Reduce h2 noise

    let subscriber = tracing_subscriber::registry().with(filter);

    if config.json_format {
        // JSON format for structured logging
        let json_layer = tracing_subscriber::fmt::layer()
            .json()
            .with_current_span(true)
            .with_span_list(true)
            .with_target(config.include_target)
            .with_file(config.include_location)
            .with_line_number(config.include_location)
            .with_timer(tracing_subscriber::fmt::time::SystemTime)
            .with_span_events(config.span_events);

        if let Some(log_file) = config.log_file {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_file)
                .map_err(|e| RuzipError::io_error(
                    format!("Failed to open log file: {}", log_file.display()),
                    e,
                ))?;
            
            subscriber
                .with(json_layer.with_writer(file))
                .try_init()
                .map_err(|e| RuzipError::internal_error(
                    format!("Failed to initialize JSON file logging: {}", e),
                    Some(file!()),
                ))?;
        } else {
            subscriber
                .with(json_layer.with_writer(io::stdout))
                .try_init()
                .map_err(|e| RuzipError::internal_error(
                    format!("Failed to initialize JSON logging: {}", e),
                    Some(file!()),
                ))?;
        }
    } else {
        // Human-readable format
        if let Some(log_file) = config.log_file {
            let file = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&log_file)
                .map_err(|e| RuzipError::io_error(
                    format!("Failed to open log file: {}", log_file.display()),
                    e,
                ))?;
            
            let fmt_layer = tracing_subscriber::fmt::layer()
                .with_target(config.include_target)
                .with_file(config.include_location)
                .with_line_number(config.include_location)
                .with_timer(tracing_subscriber::fmt::time::SystemTime)
                .with_span_events(config.span_events)
                .with_writer(file);

            let fmt_layer = if config.colored && atty::is(atty::Stream::Stderr) {
                fmt_layer.with_ansi(true).boxed()
            } else {
                fmt_layer.with_ansi(false).boxed()
            };
            
            subscriber
                .with(fmt_layer)
                .try_init()
                .map_err(|e| RuzipError::internal_error(
                    format!("Failed to initialize file logging: {}", e),
                    Some(file!()),
                ))?;
        } else {
            let fmt_layer = tracing_subscriber::fmt::layer()
                .with_target(config.include_target)
                .with_file(config.include_location)
                .with_line_number(config.include_location)
                .with_timer(tracing_subscriber::fmt::time::SystemTime)
                .with_span_events(config.span_events)
                .with_writer(io::stderr);

            let fmt_layer = if config.colored && atty::is(atty::Stream::Stderr) {
                fmt_layer.with_ansi(true).boxed()
            } else {
                fmt_layer.with_ansi(false).boxed()
            };
            
            subscriber
                .with(fmt_layer)
                .try_init()
                .map_err(|e| RuzipError::internal_error(
                    format!("Failed to initialize logging: {}", e),
                    Some(file!()),
                ))?;
        }
    }

    tracing::debug!("Logging initialized");
    Ok(())
}

/// Initialize simple logging for tests
pub fn init_test_logging() -> Result<()> {
    let config = LoggingConfig {
        level: Level::DEBUG,
        json_format: false,
        colored: false,
        include_location: true,
        include_target: true,
        span_events: FmtSpan::NONE,
        log_file: None,
    };
    
    init_logging(config)
}

/// Parse log level from string
pub fn parse_log_level(level_str: &str) -> Result<Level> {
    match level_str.to_lowercase().as_str() {
        "error" => Ok(Level::ERROR),
        "warn" | "warning" => Ok(Level::WARN),
        "info" => Ok(Level::INFO),
        "debug" => Ok(Level::DEBUG),
        "trace" => Ok(Level::TRACE),
        _ => Err(RuzipError::invalid_input(
            format!("Invalid log level: {}", level_str),
            Some(level_str.to_string()),
        )),
    }
}

/// Create a performance measurement span
pub fn perf_span(name: &'static str) -> tracing::Span {
    tracing::info_span!("perf", name = name, start_time = ?std::time::Instant::now())
}

/// Log performance metrics
pub fn log_performance(
    operation: &str,
    duration: std::time::Duration,
    bytes_processed: Option<u64>,
) {
    let event = tracing::info_span!("performance");
    event.record("operation", operation);
    event.record("duration_ms", duration.as_millis());
    
    if let Some(bytes) = bytes_processed {
        event.record("bytes_processed", bytes);
        event.record("throughput_mbps", 
                    (bytes as f64 / duration.as_secs_f64()) / (1024.0 * 1024.0));
    }
    
    let _enter = event.enter();
    tracing::info!(
        "Performance: {} completed in {}",
        operation,
        crate::utils::format_duration(duration)
    );
}

/// Create a structured error event
pub fn log_error(error: &crate::error::RuzipError, context: Option<&str>) {
    let event = tracing::error_span!("error");
    event.record("error_category", error.category());
    event.record("recoverable", error.is_recoverable());
    
    if let Some(ctx) = context {
        event.record("context", ctx);
    }
    
    let _enter = event.enter();
    tracing::error!("Error occurred: {}", error);
    
    // Log the error chain
    let mut source = error.source();
    let mut level = 1;
    while let Some(err) = source {
        tracing::error!("  Caused by (level {}): {}", level, err);
        source = err.source();
        level += 1;
    }
}

/// Macro for creating timed spans
#[macro_export]
macro_rules! timed_operation {
    ($name:expr, $block:expr) => {{
        let _span = $crate::utils::logging::perf_span($name);
        let start = std::time::Instant::now();
        let result = $block;
        let duration = start.elapsed();
        $crate::utils::logging::log_performance($name, duration, None);
        result
    }};
    ($name:expr, $bytes:expr, $block:expr) => {{
        let _span = $crate::utils::logging::perf_span($name);
        let start = std::time::Instant::now();
        let result = $block;
        let duration = start.elapsed();
        $crate::utils::logging::log_performance($name, duration, Some($bytes));
        result
    }};
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;
    use std::time::Duration;

    #[test]
    fn test_parse_log_level() {
        assert_eq!(parse_log_level("error").unwrap(), Level::ERROR);
        assert_eq!(parse_log_level("WARN").unwrap(), Level::WARN);
        assert_eq!(parse_log_level("Info").unwrap(), Level::INFO);
        assert_eq!(parse_log_level("debug").unwrap(), Level::DEBUG);
        assert_eq!(parse_log_level("trace").unwrap(), Level::TRACE);
        
        assert!(parse_log_level("invalid").is_err());
    }

    #[test]
    fn test_logging_config_default() {
        let config = LoggingConfig::default();
        assert_eq!(config.level, Level::INFO);
        assert!(!config.json_format);
        assert!(config.colored);
        assert!(!config.include_location);
    }

    #[test]
    fn test_init_logging_with_file() {
        let temp_file = NamedTempFile::new().unwrap();
        let config = LoggingConfig {
            level: Level::DEBUG,
            json_format: true,
            colored: false,
            include_location: true,
            include_target: true,
            span_events: FmtSpan::NONE,
            log_file: Some(temp_file.path().to_path_buf()),
        };
        
        // This might fail in test environment if logging is already initialized
        // but we test that the function doesn't panic
        let _ = init_logging(config);
    }

    #[test]
    fn test_log_performance() {
        // Initialize test logging (might fail if already initialized)
        let _ = init_test_logging();
        
        // Test performance logging (should not panic)
        log_performance("test_operation", Duration::from_millis(100), Some(1024));
        log_performance("test_operation_no_bytes", Duration::from_millis(50), None);
    }

    #[test]
    fn test_log_error() {
        // Initialize test logging (might fail if already initialized)
        let _ = init_test_logging();
        
        let error = RuzipError::invalid_input("Test error", Some("test input".to_string()));
        
        // Should not panic
        log_error(&error, Some("test context"));
        log_error(&error, None);
    }

    #[test]
    fn test_timed_operation_macro() {
        // Initialize test logging (might fail if already initialized)  
        let _ = init_test_logging();
        
        let result = timed_operation!("test_op", {
            std::thread::sleep(Duration::from_millis(1));
            42
        });
        
        assert_eq!(result, 42);
        
        let result = timed_operation!("test_op_with_bytes", 1024, {
            std::thread::sleep(Duration::from_millis(1));
            "success"
        });
        
        assert_eq!(result, "success");
    }

    #[test]
    fn test_perf_span() {
        let span = perf_span("test_span");
        if let Some(metadata) = span.metadata() {
            assert_eq!(metadata.name(), "perf");
        }
        // If metadata is None (no active subscriber), the test still passes
        // as the span was created successfully
    }
}

/// Production logger with enhanced monitoring capabilities
pub struct ProductionLogger {
    metrics: std::sync::Arc<std::sync::Mutex<SystemMetrics>>,
    performance_tracker: std::sync::Arc<std::sync::Mutex<PerformanceTracker>>,
    health_monitor: std::sync::Arc<std::sync::Mutex<HealthMonitor>>,
    enable_metrics: bool,
}

/// System metrics for production monitoring
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SystemMetrics {
    pub operations_total: u64,
    pub operations_success: u64,
    pub operations_failed: u64,
    pub bytes_processed: u64,
    pub memory_usage_bytes: u64,
    pub cpu_usage_percent: f64,
    pub io_operations: u64,
    pub network_operations: u64,
    pub error_counts: std::collections::HashMap<String, u64>,
    pub last_updated: u64,
}

/// Performance tracking for production environments
#[derive(Debug, Clone)]
pub struct PerformanceTracker {
    pub throughput_history: Vec<ThroughputMeasurement>,
    pub latency_history: Vec<LatencyMeasurement>,
    pub resource_usage_history: Vec<ResourceUsage>,
    pub operation_timings: std::collections::HashMap<String, Vec<std::time::Duration>>,
}

/// Throughput measurement
#[derive(Debug, Clone, serde::Serialize)]
pub struct ThroughputMeasurement {
    pub timestamp: u64,
    pub bytes_per_second: f64,
    pub operation_type: String,
}

/// Latency measurement
#[derive(Debug, Clone, serde::Serialize)]
pub struct LatencyMeasurement {
    pub timestamp: u64,
    pub latency_ms: u64,
    pub operation_type: String,
}

/// Resource usage snapshot
#[derive(Debug, Clone, serde::Serialize)]
pub struct ResourceUsage {
    pub timestamp: u64,
    pub memory_mb: f64,
    pub cpu_percent: f64,
    pub disk_io_mb_per_sec: f64,
    pub network_io_mb_per_sec: f64,
}

/// Health monitoring for production systems
#[derive(Debug, Clone)]
pub struct HealthMonitor {
    pub status: HealthStatus,
    pub last_check: std::time::Instant,
    pub error_rate: f64,
    pub response_time_ms: u64,
    pub resource_alerts: Vec<ResourceAlert>,
    pub uptime_start: std::time::Instant,
}

/// Health status enumeration
#[derive(Debug, Clone, PartialEq, serde::Serialize)]
pub enum HealthStatus {
    Healthy,
    Degraded,
    Unhealthy,
    Critical,
}

/// Resource alert information
#[derive(Debug, Clone, serde::Serialize)]
pub struct ResourceAlert {
    pub alert_type: AlertType,
    pub message: String,
    pub severity: AlertSeverity,
    pub timestamp: u64,
}

/// Alert types for resource monitoring
#[derive(Debug, Clone, serde::Serialize)]
pub enum AlertType {
    MemoryUsage,
    CpuUsage,
    DiskUsage,
    IoWait,
    ErrorRate,
    ResponseTime,
}

/// Alert severity levels
#[derive(Debug, Clone, serde::Serialize)]
pub enum AlertSeverity {
    Info,
    Warning,
    Error,
    Critical,
}

impl Default for SystemMetrics {
    fn default() -> Self {
        Self {
            operations_total: 0,
            operations_success: 0,
            operations_failed: 0,
            bytes_processed: 0,
            memory_usage_bytes: 0,
            cpu_usage_percent: 0.0,
            io_operations: 0,
            network_operations: 0,
            error_counts: std::collections::HashMap::new(),
            last_updated: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        }
    }
}

impl Default for PerformanceTracker {
    fn default() -> Self {
        Self {
            throughput_history: Vec::new(),
            latency_history: Vec::new(),
            resource_usage_history: Vec::new(),
            operation_timings: std::collections::HashMap::new(),
        }
    }
}

impl Default for HealthMonitor {
    fn default() -> Self {
        let now = std::time::Instant::now();
        Self {
            status: HealthStatus::Healthy,
            last_check: now,
            error_rate: 0.0,
            response_time_ms: 0,
            resource_alerts: Vec::new(),
            uptime_start: now,
        }
    }
}

impl ProductionLogger {
    /// Create a new production logger
    pub fn new(enable_metrics: bool) -> Self {
        Self {
            metrics: std::sync::Arc::new(std::sync::Mutex::new(SystemMetrics::default())),
            performance_tracker: std::sync::Arc::new(std::sync::Mutex::new(PerformanceTracker::default())),
            health_monitor: std::sync::Arc::new(std::sync::Mutex::new(HealthMonitor::default())),
            enable_metrics,
        }
    }

    /// Record an operation completion
    pub fn record_operation(&self, success: bool, bytes_processed: u64, operation_type: &str) {
        if !self.enable_metrics {
            return;
        }

        let mut metrics = self.metrics.lock().unwrap();
        metrics.operations_total += 1;
        if success {
            metrics.operations_success += 1;
        } else {
            metrics.operations_failed += 1;
        }
        metrics.bytes_processed += bytes_processed;
        metrics.last_updated = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        tracing::info!(
            operation_type = operation_type,
            success = success,
            bytes_processed = bytes_processed,
            total_operations = metrics.operations_total,
            "Operation completed"
        );
    }

    /// Record operation timing
    pub fn record_timing(&self, operation_type: &str, duration: std::time::Duration) {
        if !self.enable_metrics {
            return;
        }

        let mut tracker = self.performance_tracker.lock().unwrap();
        tracker.operation_timings
            .entry(operation_type.to_string())
            .or_insert_with(Vec::new)
            .push(duration);

        // Keep only last 1000 measurements per operation type
        if let Some(timings) = tracker.operation_timings.get_mut(operation_type) {
            if timings.len() > 1000 {
                timings.drain(0..timings.len() - 1000);
            }
        }

        let latency = LatencyMeasurement {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            latency_ms: duration.as_millis() as u64,
            operation_type: operation_type.to_string(),
        };

        tracker.latency_history.push(latency);
        let len = tracker.latency_history.len();
        if len > 10000 {
            tracker.latency_history.drain(0..len - 10000);
        }

        tracing::debug!(
            operation_type = operation_type,
            duration_ms = duration.as_millis(),
            "Operation timing recorded"
        );
    }

    /// Record throughput measurement
    pub fn record_throughput(&self, bytes_per_second: f64, operation_type: &str) {
        if !self.enable_metrics {
            return;
        }

        let mut tracker = self.performance_tracker.lock().unwrap();
        let measurement = ThroughputMeasurement {
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            bytes_per_second,
            operation_type: operation_type.to_string(),
        };

        let len = tracker.throughput_history.len();
        tracker.throughput_history.push(measurement);
        if len >= 1000 {
            tracker.throughput_history.drain(0..len - 999);
        }

        tracing::info!(
            operation_type = operation_type,
            throughput_mbps = bytes_per_second / 1_000_000.0,
            "Throughput measurement recorded"
        );
    }

    /// Record error by category
    pub fn record_error(&self, error_category: &str) {
        if !self.enable_metrics {
            return;
        }

        let mut metrics = self.metrics.lock().unwrap();
        *metrics.error_counts.entry(error_category.to_string()).or_insert(0) += 1;
        metrics.last_updated = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        tracing::error!(
            error_category = error_category,
            total_errors = metrics.error_counts.get(error_category).unwrap_or(&0),
            "Error recorded"
        );
    }

    /// Update health status
    pub fn update_health_status(&self, status: HealthStatus, response_time_ms: u64) {
        let mut monitor = self.health_monitor.lock().unwrap();
        monitor.status = status.clone();
        monitor.last_check = std::time::Instant::now();
        monitor.response_time_ms = response_time_ms;

        // Calculate error rate
        let metrics = self.metrics.lock().unwrap();
        if metrics.operations_total > 0 {
            monitor.error_rate = (metrics.operations_failed as f64 / metrics.operations_total as f64) * 100.0;
        }

        tracing::info!(
            health_status = ?status,
            response_time_ms = response_time_ms,
            error_rate_percent = monitor.error_rate,
            uptime_seconds = monitor.uptime_start.elapsed().as_secs(),
            "Health status updated"
        );
    }

    /// Add resource alert
    pub fn add_resource_alert(&self, alert_type: AlertType, message: String, severity: AlertSeverity) {
        let alert = ResourceAlert {
            alert_type: alert_type.clone(),
            message: message.clone(),
            severity: severity.clone(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        };

        {
            let mut monitor = self.health_monitor.lock().unwrap();
            let len = monitor.resource_alerts.len();
            monitor.resource_alerts.push(alert);
            
            // Keep only last 100 alerts
            if len >= 100 {
                monitor.resource_alerts.drain(0..len - 99);
            }
        }

        tracing::warn!(
            alert_type = ?alert_type,
            severity = ?severity,
            message = message,
            "Resource alert added"
        );
    }

    /// Get current metrics snapshot
    pub fn get_metrics(&self) -> SystemMetrics {
        self.metrics.lock().unwrap().clone()
    }

    /// Get health status
    pub fn get_health_status(&self) -> HealthMonitor {
        self.health_monitor.lock().unwrap().clone()
    }

    /// Export metrics in Prometheus format
    pub fn export_prometheus_metrics(&self) -> String {
        let metrics = self.metrics.lock().unwrap();
        let monitor = self.health_monitor.lock().unwrap();
        
        let mut output = String::new();
        
        // Basic metrics
        output.push_str("# HELP ruzip_operations_total Total number of operations\n");
        output.push_str("# TYPE ruzip_operations_total counter\n");
        output.push_str(&format!("ruzip_operations_total {}\n", metrics.operations_total));
        
        output.push_str("# HELP ruzip_operations_success_total Total number of successful operations\n");
        output.push_str("# TYPE ruzip_operations_success_total counter\n");
        output.push_str(&format!("ruzip_operations_success_total {}\n", metrics.operations_success));
        
        output.push_str("# HELP ruzip_operations_failed_total Total number of failed operations\n");
        output.push_str("# TYPE ruzip_operations_failed_total counter\n");
        output.push_str(&format!("ruzip_operations_failed_total {}\n", metrics.operations_failed));
        
        output.push_str("# HELP ruzip_bytes_processed_total Total bytes processed\n");
        output.push_str("# TYPE ruzip_bytes_processed_total counter\n");
        output.push_str(&format!("ruzip_bytes_processed_total {}\n", metrics.bytes_processed));
        
        output.push_str("# HELP ruzip_memory_usage_bytes Current memory usage in bytes\n");
        output.push_str("# TYPE ruzip_memory_usage_bytes gauge\n");
        output.push_str(&format!("ruzip_memory_usage_bytes {}\n", metrics.memory_usage_bytes));
        
        output.push_str("# HELP ruzip_cpu_usage_percent Current CPU usage percentage\n");
        output.push_str("# TYPE ruzip_cpu_usage_percent gauge\n");
        output.push_str(&format!("ruzip_cpu_usage_percent {}\n", metrics.cpu_usage_percent));
        
        output.push_str("# HELP ruzip_error_rate_percent Current error rate percentage\n");
        output.push_str("# TYPE ruzip_error_rate_percent gauge\n");
        output.push_str(&format!("ruzip_error_rate_percent {}\n", monitor.error_rate));
        
        output.push_str("# HELP ruzip_uptime_seconds System uptime in seconds\n");
        output.push_str("# TYPE ruzip_uptime_seconds gauge\n");
        output.push_str(&format!("ruzip_uptime_seconds {}\n", monitor.uptime_start.elapsed().as_secs()));
        
        // Error counts by category
        for (category, count) in &metrics.error_counts {
            output.push_str(&format!(
                "ruzip_errors_total{{category=\"{}\"}} {}\n",
                category, count
            ));
        }
        
        output
    }

    /// Export metrics in JSON format
    pub fn export_json_metrics(&self) -> Result<String> {
        let metrics = self.metrics.lock().unwrap();
        let monitor = self.health_monitor.lock().unwrap();
        let tracker = self.performance_tracker.lock().unwrap();

        let export = serde_json::json!({
            "metrics": *metrics,
            "health": {
                "status": monitor.status,
                "error_rate": monitor.error_rate,
                "response_time_ms": monitor.response_time_ms,
                "uptime_seconds": monitor.uptime_start.elapsed().as_secs(),
                "alerts": monitor.resource_alerts
            },
            "performance": {
                "throughput_history": tracker.throughput_history.iter().take(10).collect::<Vec<_>>(),
                "latency_history": tracker.latency_history.iter().take(10).collect::<Vec<_>>(),
                "resource_usage_history": tracker.resource_usage_history.iter().take(10).collect::<Vec<_>>()
            }
        });

        serde_json::to_string_pretty(&export)
            .map_err(|e| RuzipError::config_error(
                format!("Failed to serialize metrics: {}", e),
                None,
            ))
    }
}

/// Initialize production logging with enhanced monitoring
pub fn init_production_logging(level: Level, enable_metrics: bool) -> Result<ProductionLogger> {
    let config = LoggingConfig {
        level,
        json_format: true,
        colored: false,
        include_location: true,
        include_target: true,
        span_events: FmtSpan::CLOSE,
        log_file: None,
    };

    init_logging(config)?;
    
    let logger = ProductionLogger::new(enable_metrics);
    tracing::info!(
        metrics_enabled = enable_metrics,
        "Production logging initialized with enhanced monitoring"
    );
    
    Ok(logger)
}

/// Health check endpoint functionality
pub fn perform_health_check(logger: &ProductionLogger) -> Result<serde_json::Value> {
    let start_time = std::time::Instant::now();
    
    // Simulate health check operations
    let metrics = logger.get_metrics();
    let health = logger.get_health_status();
    
    let response_time = start_time.elapsed().as_millis() as u64;
    
    // Update health status based on metrics
    let status = if health.error_rate > 10.0 {
        HealthStatus::Critical
    } else if health.error_rate > 5.0 {
        HealthStatus::Unhealthy
    } else if health.error_rate > 1.0 {
        HealthStatus::Degraded
    } else {
        HealthStatus::Healthy
    };
    
    logger.update_health_status(status.clone(), response_time);
    
    Ok(serde_json::json!({
        "status": status,
        "uptime_seconds": health.uptime_start.elapsed().as_secs(),
        "error_rate_percent": health.error_rate,
        "response_time_ms": response_time,
        "operations_total": metrics.operations_total,
        "operations_success": metrics.operations_success,
        "operations_failed": metrics.operations_failed,
        "bytes_processed": metrics.bytes_processed,
        "memory_usage_bytes": metrics.memory_usage_bytes,
        "cpu_usage_percent": metrics.cpu_usage_percent,
        "timestamp": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs()
    }))
}