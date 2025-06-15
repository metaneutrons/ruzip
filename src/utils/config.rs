//! Configuration management for RuZip
//!
//! Provides hierarchical configuration loading from multiple sources:
//! System -> User -> Project -> CLI arguments

use crate::error::{Result, RuzipError};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Main configuration structure
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Config {
    /// Default settings
    pub default: DefaultConfig,
    /// Security settings
    pub security: SecurityConfig,
    /// Keychain settings
    pub keychain: KeychainConfig,
    /// Certificate settings
    pub certificates: CertificateConfig,
    /// Output settings
    pub output: OutputConfig,
}

/// Default configuration settings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DefaultConfig {
    /// Default compression level (1-22)
    pub compression_level: u8,
    /// Number of threads (0 = auto-detect)
    pub threads: u16,
    /// Preserve file permissions
    pub preserve_permissions: bool,
    /// Preserve timestamps
    pub preserve_timestamps: bool,
    /// Show progress bar by default
    pub progress_bar: bool,
}

/// Security configuration settings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct SecurityConfig {
    /// Default encryption algorithm
    pub default_encryption: String,
    /// Asymmetric algorithm preference
    pub asymmetric_algorithm: String,
    /// Signature algorithm preference
    pub signature_algorithm: String,
    /// Key derivation rounds
    pub key_derivation_rounds: u32,
    /// Secure delete temporary files
    pub secure_delete: bool,
    /// Use OS keychain by default
    pub use_keychain: bool,
}

/// Keychain configuration settings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct KeychainConfig {
    /// macOS keychain name
    #[cfg(target_os = "macos")]
    pub keychain_name: String,
    /// Key label prefix
    pub key_label_prefix: String,
    /// Windows certificate store location
    #[cfg(target_os = "windows")]
    pub store_location: String,
    /// Windows certificate store name
    #[cfg(target_os = "windows")]
    pub store_name: String,
    /// Linux secret service collection
    #[cfg(target_os = "linux")]
    pub collection: String,
}

/// Certificate configuration settings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CertificateConfig {
    /// Verify certificate chain
    pub verify_chain: bool,
    /// Require valid certificate
    pub require_valid_cert: bool,
    /// Trusted CA file path
    pub trusted_ca_file: Option<PathBuf>,
}

/// Output configuration settings
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct OutputConfig {
    /// Use JSON format by default
    pub json_format: bool,
    /// Verbose level
    pub verbose_level: String,
    /// Color output
    pub color_output: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            default: DefaultConfig::default(),
            security: SecurityConfig::default(),
            keychain: KeychainConfig::default(),
            certificates: CertificateConfig::default(),
            output: OutputConfig::default(),
        }
    }
}

impl Default for DefaultConfig {
    fn default() -> Self {
        Self {
            compression_level: 6,
            threads: 0,
            preserve_permissions: true,
            preserve_timestamps: true,
            progress_bar: true,
        }
    }
}

impl Default for SecurityConfig {
    fn default() -> Self {
        Self {
            default_encryption: "aes256".to_string(),
            asymmetric_algorithm: "rsa4096".to_string(),
            signature_algorithm: "rsa-pss".to_string(),
            key_derivation_rounds: 100_000,
            secure_delete: true,
            use_keychain: true,
        }
    }
}

impl Default for KeychainConfig {
    fn default() -> Self {
        Self {
            #[cfg(target_os = "macos")]
            keychain_name: "login".to_string(),
            key_label_prefix: "ruzip-".to_string(),
            #[cfg(target_os = "windows")]
            store_location: "CurrentUser".to_string(),
            #[cfg(target_os = "windows")]
            store_name: "My".to_string(),
            #[cfg(target_os = "linux")]
            collection: "default".to_string(),
        }
    }
}

impl Default for CertificateConfig {
    fn default() -> Self {
        Self {
            verify_chain: true,
            require_valid_cert: false,
            trusted_ca_file: None,
        }
    }
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            json_format: false,
            verbose_level: "info".to_string(),
            color_output: true,
        }
    }
}

/// Configuration builder that loads from multiple sources
pub struct ConfigBuilder {
    config: Config,
}

impl ConfigBuilder {
    /// Create a new configuration builder with defaults
    pub fn new() -> Self {
        Self {
            config: Config::default(),
        }
    }

    /// Load system-wide configuration
    pub fn load_system_config(mut self) -> Result<Self> {
        if let Some(system_config_path) = get_system_config_path() {
            if system_config_path.exists() {
                let system_config = load_config_file(&system_config_path)?;
                self.config = merge_configs(self.config, system_config);
                tracing::debug!("Loaded system config from: {}", system_config_path.display());
            }
        }
        Ok(self)
    }

    /// Load user configuration
    pub fn load_user_config(mut self) -> Result<Self> {
        if let Some(user_config_path) = get_user_config_path() {
            if user_config_path.exists() {
                let user_config = load_config_file(&user_config_path)?;
                self.config = merge_configs(self.config, user_config);
                tracing::debug!("Loaded user config from: {}", user_config_path.display());
            }
        }
        Ok(self)
    }

    /// Load project-specific configuration
    pub fn load_project_config(mut self) -> Result<Self> {
        if let Some(project_config_path) = get_project_config_path() {
            if project_config_path.exists() {
                let project_config = load_config_file(&project_config_path)?;
                self.config = merge_configs(self.config, project_config);
                tracing::debug!("Loaded project config from: {}", project_config_path.display());
            }
        }
        Ok(self)
    }

    /// Override with CLI arguments
    pub fn override_with_cli_args(self, _args: &[&str]) -> Result<Self> {
        // TODO: Implement CLI argument parsing and override logic
        // This would parse specific CLI flags and override config values
        Ok(self)
    }

    /// Build the final configuration
    pub fn build(self) -> Result<Config> {
        // Validate the configuration
        self.validate_config()?;
        Ok(self.config)
    }

    /// Validate the configuration
    fn validate_config(&self) -> Result<()> {
        // Validate compression level
        if !(1..=22).contains(&self.config.default.compression_level) {
            return Err(RuzipError::config_error(
                format!("Invalid compression level: {} (must be 1-22)", 
                       self.config.default.compression_level),
                None,
            ));
        }

        // Validate key derivation rounds
        if self.config.security.key_derivation_rounds < 1000 {
            return Err(RuzipError::config_error(
                format!("Key derivation rounds too low: {} (minimum 1000)", 
                       self.config.security.key_derivation_rounds),
                None,
            ));
        }

        // Validate verbose level
        let valid_levels = ["error", "warn", "info", "debug", "trace"];
        if !valid_levels.contains(&self.config.output.verbose_level.as_str()) {
            return Err(RuzipError::config_error(
                format!("Invalid verbose level: {} (must be one of: {})", 
                       self.config.output.verbose_level,
                       valid_levels.join(", ")),
                None,
            ));
        }

        Ok(())
    }
}

impl Default for ConfigBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Load configuration from a TOML file
fn load_config_file<P: AsRef<Path>>(path: P) -> Result<Config> {
    let content = std::fs::read_to_string(&path)
        .map_err(|e| RuzipError::io_error(
            format!("Failed to read config file: {}", path.as_ref().display()),
            e,
        ))?;

    let config: Config = toml::from_str(&content)
        .map_err(|e| RuzipError::config_error(
            format!("Failed to parse config file: {}", e),
            Some(path.as_ref().to_path_buf()),
        ))?;

    Ok(config)
}

/// Merge two configurations, with the second one taking precedence
fn merge_configs(_base: Config, override_config: Config) -> Config {
    // For now, do a simple override. In the future, this could be more sophisticated
    // to merge only non-default values from the override config.
    override_config
}

/// Get system-wide configuration path
fn get_system_config_path() -> Option<PathBuf> {
    #[cfg(unix)]
    {
        Some(PathBuf::from("/etc/ruzip/config.toml"))
    }
    #[cfg(windows)]
    {
        // On Windows, use ProgramData
        std::env::var("PROGRAMDATA")
            .ok()
            .map(|pd| PathBuf::from(pd).join("ruzip").join("config.toml"))
    }
}

/// Get user-specific configuration path
fn get_user_config_path() -> Option<PathBuf> {
    dirs::config_dir().map(|dir| dir.join("ruzip").join("config.toml"))
}

/// Get project-specific configuration path
fn get_project_config_path() -> Option<PathBuf> {
    // Look for .ruzip.toml in current directory
    let current_dir = std::env::current_dir().ok()?;
    Some(current_dir.join(".ruzip.toml"))
}

/// Save configuration to file
pub fn save_config<P: AsRef<Path>>(config: &Config, path: P) -> Result<()> {
    let content = toml::to_string_pretty(config)
        .map_err(|e| RuzipError::config_error(
            format!("Failed to serialize config: {}", e),
            None,
        ))?;

    // Create parent directory if needed
    if let Some(parent) = path.as_ref().parent() {
        std::fs::create_dir_all(parent)
            .map_err(|e| RuzipError::io_error(
                format!("Failed to create config directory: {}", parent.display()),
                e,
            ))?;
    }

    std::fs::write(&path, content)
        .map_err(|e| RuzipError::io_error(
            format!("Failed to write config file: {}", path.as_ref().display()),
            e,
        ))?;

    tracing::info!("Saved configuration to: {}", path.as_ref().display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::NamedTempFile;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.default.compression_level, 6);
        assert_eq!(config.default.threads, 0);
        assert!(config.default.preserve_permissions);
        assert_eq!(config.security.default_encryption, "aes256");
    }

    #[test]
    fn test_config_validation() {
        let mut config = Config::default();
        let builder = ConfigBuilder { config: config.clone() };
        
        // Valid config should pass
        assert!(builder.validate_config().is_ok());
        
        // Invalid compression level
        config.default.compression_level = 25;
        let builder = ConfigBuilder { config: config.clone() };
        assert!(builder.validate_config().is_err());
        
        // Reset and test invalid key derivation rounds
        config.default.compression_level = 6;
        config.security.key_derivation_rounds = 500;
        let builder = ConfigBuilder { config: config.clone() };
        assert!(builder.validate_config().is_err());
        
        // Reset and test invalid verbose level
        config.security.key_derivation_rounds = 100_000;
        config.output.verbose_level = "invalid".to_string();
        let builder = ConfigBuilder { config };
        assert!(builder.validate_config().is_err());
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        let toml_str = toml::to_string(&config).unwrap();
        
        // Should be able to deserialize back
        let deserialized: Config = toml::from_str(&toml_str).unwrap();
        assert_eq!(config, deserialized);
    }

    #[test]
    fn test_save_and_load_config() {
        let temp_file = NamedTempFile::new().unwrap();
        let config = Config::default();
        
        // Save config
        save_config(&config, temp_file.path()).unwrap();
        
        // Load config back
        let loaded_config = load_config_file(temp_file.path()).unwrap();
        assert_eq!(config, loaded_config);
    }

    #[test]
    fn test_config_builder() {
        let builder = ConfigBuilder::new();
        let config = builder.build().unwrap();
        
        // Should have default values
        assert_eq!(config.default.compression_level, 6);
        assert_eq!(config.security.default_encryption, "aes256");
    }

    #[test]
    fn test_merge_configs() {
        let base = Config::default();
        let mut override_config = Config::default();
        override_config.default.compression_level = 9;
        
        let merged = merge_configs(base, override_config.clone());
        assert_eq!(merged.default.compression_level, 9);
    }
}

/// Production-specific configuration for enterprise deployments
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ProductionConfig {
    /// Maximum memory usage in MB
    pub max_memory_mb: usize,
    /// Maximum number of threads
    pub max_threads: usize,
    /// Enable error recovery mechanisms
    pub error_recovery_enabled: bool,
    /// Enable metrics collection
    pub metrics_enabled: bool,
    /// Health check interval in milliseconds
    pub health_check_interval_ms: u64,
    /// Log level for production
    pub log_level: String,
    /// Enable configuration backup
    pub backup_enabled: bool,
    /// Maximum retry attempts for operations
    pub max_retry_attempts: u32,
    /// Enable graceful degradation
    pub graceful_degradation: bool,
    /// Resource monitoring thresholds
    pub resource_thresholds: ResourceThresholds,
    /// Circuit breaker configuration
    pub circuit_breaker: CircuitBreakerConfig,
}

/// Resource monitoring thresholds
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ResourceThresholds {
    /// Memory usage threshold (percentage)
    pub memory_threshold_percent: f64,
    /// CPU usage threshold (percentage)
    pub cpu_threshold_percent: f64,
    /// Disk usage threshold (percentage)
    pub disk_threshold_percent: f64,
    /// I/O wait threshold (milliseconds)
    pub io_wait_threshold_ms: u64,
}

/// Circuit breaker configuration for fault tolerance
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct CircuitBreakerConfig {
    /// Failure threshold to open circuit
    pub failure_threshold: u32,
    /// Success threshold to close circuit
    pub success_threshold: u32,
    /// Timeout in half-open state (milliseconds)
    pub timeout_ms: u64,
    /// Enable circuit breaker
    pub enabled: bool,
}

impl Default for ProductionConfig {
    fn default() -> Self {
        Self {
            max_memory_mb: 2048,
            max_threads: num_cpus::get(),
            error_recovery_enabled: true,
            metrics_enabled: true,
            health_check_interval_ms: 30000,
            log_level: "info".to_string(),
            backup_enabled: true,
            max_retry_attempts: 3,
            graceful_degradation: true,
            resource_thresholds: ResourceThresholds::default(),
            circuit_breaker: CircuitBreakerConfig::default(),
        }
    }
}

impl Default for ResourceThresholds {
    fn default() -> Self {
        Self {
            memory_threshold_percent: 85.0,
            cpu_threshold_percent: 90.0,
            disk_threshold_percent: 95.0,
            io_wait_threshold_ms: 1000,
        }
    }
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 3,
            timeout_ms: 60000,
            enabled: true,
        }
    }
}

/// Extended configuration with production features
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ExtendedConfig {
    /// Base configuration
    pub base: Config,
    /// Production-specific settings
    pub production: ProductionConfig,
}

impl Default for ExtendedConfig {
    fn default() -> Self {
        Self {
            base: Config::default(),
            production: ProductionConfig::default(),
        }
    }
}

/// Environment variable configuration loader
pub struct EnvironmentConfigLoader;

impl EnvironmentConfigLoader {
    /// Load configuration from environment variables
    pub fn load_from_env() -> Result<ProductionConfig> {
        let mut config = ProductionConfig::default();
        
        // Load RUZIP_* environment variables
        if let Ok(max_memory) = std::env::var("RUZIP_MAX_MEMORY_MB") {
            config.max_memory_mb = max_memory.parse()
                .map_err(|e| RuzipError::config_error(
                    format!("Invalid RUZIP_MAX_MEMORY_MB: {}", e),
                    None,
                ))?;
        }
        
        if let Ok(max_threads) = std::env::var("RUZIP_MAX_THREADS") {
            config.max_threads = max_threads.parse()
                .map_err(|e| RuzipError::config_error(
                    format!("Invalid RUZIP_MAX_THREADS: {}", e),
                    None,
                ))?;
        }
        
        if let Ok(log_level) = std::env::var("RUZIP_LOG_LEVEL") {
            config.log_level = log_level;
        }
        
        if let Ok(error_recovery) = std::env::var("RUZIP_ERROR_RECOVERY") {
            config.error_recovery_enabled = error_recovery.parse()
                .map_err(|e| RuzipError::config_error(
                    format!("Invalid RUZIP_ERROR_RECOVERY: {}", e),
                    None,
                ))?;
        }
        
        if let Ok(metrics) = std::env::var("RUZIP_METRICS_ENABLED") {
            config.metrics_enabled = metrics.parse()
                .map_err(|e| RuzipError::config_error(
                    format!("Invalid RUZIP_METRICS_ENABLED: {}", e),
                    None,
                ))?;
        }
        
        if let Ok(health_check) = std::env::var("RUZIP_HEALTH_CHECK_INTERVAL_MS") {
            config.health_check_interval_ms = health_check.parse()
                .map_err(|e| RuzipError::config_error(
                    format!("Invalid RUZIP_HEALTH_CHECK_INTERVAL_MS: {}", e),
                    None,
                ))?;
        }
        
        if let Ok(backup) = std::env::var("RUZIP_BACKUP_ENABLED") {
            config.backup_enabled = backup.parse()
                .map_err(|e| RuzipError::config_error(
                    format!("Invalid RUZIP_BACKUP_ENABLED: {}", e),
                    None,
                ))?;
        }
        
        if let Ok(retry_attempts) = std::env::var("RUZIP_MAX_RETRY_ATTEMPTS") {
            config.max_retry_attempts = retry_attempts.parse()
                .map_err(|e| RuzipError::config_error(
                    format!("Invalid RUZIP_MAX_RETRY_ATTEMPTS: {}", e),
                    None,
                ))?;
        }
        
        if let Ok(graceful_degradation) = std::env::var("RUZIP_GRACEFUL_DEGRADATION") {
            config.graceful_degradation = graceful_degradation.parse()
                .map_err(|e| RuzipError::config_error(
                    format!("Invalid RUZIP_GRACEFUL_DEGRADATION: {}", e),
                    None,
                ))?;
        }
        
        // Load resource thresholds
        if let Ok(memory_threshold) = std::env::var("RUZIP_MEMORY_THRESHOLD_PERCENT") {
            config.resource_thresholds.memory_threshold_percent = memory_threshold.parse()
                .map_err(|e| RuzipError::config_error(
                    format!("Invalid RUZIP_MEMORY_THRESHOLD_PERCENT: {}", e),
                    None,
                ))?;
        }
        
        if let Ok(cpu_threshold) = std::env::var("RUZIP_CPU_THRESHOLD_PERCENT") {
            config.resource_thresholds.cpu_threshold_percent = cpu_threshold.parse()
                .map_err(|e| RuzipError::config_error(
                    format!("Invalid RUZIP_CPU_THRESHOLD_PERCENT: {}", e),
                    None,
                ))?;
        }
        
        if let Ok(disk_threshold) = std::env::var("RUZIP_DISK_THRESHOLD_PERCENT") {
            config.resource_thresholds.disk_threshold_percent = disk_threshold.parse()
                .map_err(|e| RuzipError::config_error(
                    format!("Invalid RUZIP_DISK_THRESHOLD_PERCENT: {}", e),
                    None,
                ))?;
        }
        
        // Load circuit breaker config
        if let Ok(failure_threshold) = std::env::var("RUZIP_CIRCUIT_BREAKER_FAILURE_THRESHOLD") {
            config.circuit_breaker.failure_threshold = failure_threshold.parse()
                .map_err(|e| RuzipError::config_error(
                    format!("Invalid RUZIP_CIRCUIT_BREAKER_FAILURE_THRESHOLD: {}", e),
                    None,
                ))?;
        }
        
        if let Ok(cb_enabled) = std::env::var("RUZIP_CIRCUIT_BREAKER_ENABLED") {
            config.circuit_breaker.enabled = cb_enabled.parse()
                .map_err(|e| RuzipError::config_error(
                    format!("Invalid RUZIP_CIRCUIT_BREAKER_ENABLED: {}", e),
                    None,
                ))?;
        }
        
        Ok(config)
    }
}

/// Configuration validator for production environments
pub struct ProductionConfigValidator;

impl ProductionConfigValidator {
    /// Validate production configuration
    pub fn validate(config: &ProductionConfig) -> Result<()> {
        // Validate memory limits
        if config.max_memory_mb < 64 {
            return Err(RuzipError::config_error(
                format!("max_memory_mb too low: {} (minimum 64MB)", config.max_memory_mb),
                None,
            ));
        }
        
        if config.max_memory_mb > 32768 {
            tracing::warn!(
                "max_memory_mb very high: {}MB - ensure system has sufficient RAM",
                config.max_memory_mb
            );
        }
        
        // Validate thread count
        if config.max_threads == 0 {
            return Err(RuzipError::config_error(
                "max_threads cannot be 0".to_string(),
                None,
            ));
        }
        
        let cpu_count = num_cpus::get();
        if config.max_threads > cpu_count * 4 {
            tracing::warn!(
                "max_threads ({}) is more than 4x CPU count ({})",
                config.max_threads, cpu_count
            );
        }
        
        // Validate health check interval
        if config.health_check_interval_ms < 1000 {
            return Err(RuzipError::config_error(
                format!("health_check_interval_ms too low: {}ms (minimum 1000ms)",
                       config.health_check_interval_ms),
                None,
            ));
        }
        
        // Validate log level
        let valid_levels = ["error", "warn", "info", "debug", "trace"];
        if !valid_levels.contains(&config.log_level.as_str()) {
            return Err(RuzipError::config_error(
                format!("Invalid log_level: {} (must be one of: {})",
                       config.log_level, valid_levels.join(", ")),
                None,
            ));
        }
        
        // Validate retry attempts
        if config.max_retry_attempts > 10 {
            tracing::warn!(
                "max_retry_attempts ({}) is very high - may cause long delays",
                config.max_retry_attempts
            );
        }
        
        // Validate resource thresholds
        Self::validate_resource_thresholds(&config.resource_thresholds)?;
        
        // Validate circuit breaker
        Self::validate_circuit_breaker(&config.circuit_breaker)?;
        
        Ok(())
    }
    
    fn validate_resource_thresholds(thresholds: &ResourceThresholds) -> Result<()> {
        if !(0.0..=100.0).contains(&thresholds.memory_threshold_percent) {
            return Err(RuzipError::config_error(
                format!("memory_threshold_percent out of range: {} (must be 0-100)",
                       thresholds.memory_threshold_percent),
                None,
            ));
        }
        
        if !(0.0..=100.0).contains(&thresholds.cpu_threshold_percent) {
            return Err(RuzipError::config_error(
                format!("cpu_threshold_percent out of range: {} (must be 0-100)",
                       thresholds.cpu_threshold_percent),
                None,
            ));
        }
        
        if !(0.0..=100.0).contains(&thresholds.disk_threshold_percent) {
            return Err(RuzipError::config_error(
                format!("disk_threshold_percent out of range: {} (must be 0-100)",
                       thresholds.disk_threshold_percent),
                None,
            ));
        }
        
        if thresholds.io_wait_threshold_ms == 0 {
            return Err(RuzipError::config_error(
                "io_wait_threshold_ms cannot be 0".to_string(),
                None,
            ));
        }
        
        Ok(())
    }
    
    fn validate_circuit_breaker(config: &CircuitBreakerConfig) -> Result<()> {
        if config.enabled {
            if config.failure_threshold == 0 {
                return Err(RuzipError::config_error(
                    "circuit_breaker failure_threshold cannot be 0".to_string(),
                    None,
                ));
            }
            
            if config.success_threshold == 0 {
                return Err(RuzipError::config_error(
                    "circuit_breaker success_threshold cannot be 0".to_string(),
                    None,
                ));
            }
            
            if config.timeout_ms < 1000 {
                return Err(RuzipError::config_error(
                    format!("circuit_breaker timeout_ms too low: {}ms (minimum 1000ms)",
                           config.timeout_ms),
                    None,
                ));
            }
        }
        
        Ok(())
    }
}

/// Runtime configuration reloader
pub struct ConfigReloader {
    config_path: PathBuf,
    last_modified: std::time::SystemTime,
}

impl ConfigReloader {
    pub fn new<P: Into<PathBuf>>(config_path: P) -> Result<Self> {
        let path = config_path.into();
        let metadata = std::fs::metadata(&path)
            .map_err(|e| RuzipError::io_error(
                format!("Failed to read config file metadata: {}", path.display()),
                e,
            ))?;
        
        Ok(Self {
            config_path: path,
            last_modified: metadata.modified().unwrap_or(std::time::UNIX_EPOCH),
        })
    }
    
    /// Check if configuration has been modified
    pub fn has_changed(&mut self) -> Result<bool> {
        let metadata = std::fs::metadata(&self.config_path)
            .map_err(|e| RuzipError::io_error(
                format!("Failed to read config file metadata: {}", self.config_path.display()),
                e,
            ))?;
        
        let current_modified = metadata.modified().unwrap_or(std::time::UNIX_EPOCH);
        if current_modified > self.last_modified {
            self.last_modified = current_modified;
            Ok(true)
        } else {
            Ok(false)
        }
    }
    
    /// Reload configuration if changed
    pub fn reload_if_changed(&mut self) -> Result<Option<ExtendedConfig>> {
        if self.has_changed()? {
            let content = std::fs::read_to_string(&self.config_path)
                .map_err(|e| RuzipError::io_error(
                    format!("Failed to read config file: {}", self.config_path.display()),
                    e,
                ))?;
            
            let config: ExtendedConfig = toml::from_str(&content)
                .map_err(|e| RuzipError::config_error(
                    format!("Failed to parse config file: {}", e),
                    Some(self.config_path.clone()),
                ))?;
            
            // Validate the reloaded configuration
            ProductionConfigValidator::validate(&config.production)?;
            
            tracing::info!("Configuration reloaded from: {}", self.config_path.display());
            Ok(Some(config))
        } else {
            Ok(None)
        }
    }
}