# Configuration Guide

This guide covers RuZip's flexible configuration system, designed for both end-users and system administrators.

## 📋 Table of Contents

- [Configuration Overview](#configuration-overview)
- [Configuration Hierarchy](#configuration-hierarchy)
- [Configuration File Format](#configuration-file-format)
- [Configuration Sections](#configuration-sections)
- [Environment Variables](#environment-variables)
- [Platform-Specific Settings](#platform-specific-settings)
- [Configuration Templates](#configuration-templates)
- [Advanced Configuration](#advanced-configuration)
- [Validation and Troubleshooting](#validation-and-troubleshooting)

## 🔧 Configuration Overview

RuZip uses a hierarchical configuration system that allows flexible customization at multiple levels:

- **System-wide**: `/etc/ruzip/config.toml`
- **User-specific**: `~/.config/ruzip/config.toml`
- **Project-specific**: `./.ruzip.toml`
- **CLI arguments**: Highest priority, overrides all file-based settings

### Configuration Priority Order
```
CLI Arguments > Project Config > User Config > System Config > Built-in Defaults
```

## 🏗️ Configuration Hierarchy

### System-Wide Configuration
**Location**: `/etc/ruzip/config.toml` (Linux/macOS), `%PROGRAMDATA%\RuZip\config.toml` (Windows)

Used for:
- Organization-wide defaults
- System administrator policies
- Security requirements
- Resource limits

### User Configuration
**Location**: `~/.config/ruzip/config.toml` (Linux/macOS), `%APPDATA%\RuZip\config.toml` (Windows)

Used for:
- Personal preferences
- User-specific optimizations
- Frequently used settings
- Custom profiles

### Project Configuration
**Location**: `./.ruzip.toml` (current directory)

Used for:
- Project-specific requirements
- Team collaboration settings
- Automated build configurations
- CI/CD pipeline settings

### Configuration Discovery
```bash
# Show active configuration
ruzip config show

# Show configuration sources
ruzip config sources

# Validate configuration
ruzip config validate
```

## 📄 Configuration File Format

RuZip uses TOML format for all configuration files. Here's the complete structure:

```toml
# ~/.config/ruzip/config.toml

[default]
# Compression settings
compression_level = 9
compression_method = "zstd"
threads = 0  # 0 = auto-detect
preserve_permissions = true
preserve_timestamps = true
recursive = true

# Output settings
progress_bar = true
verbose_level = "info"
json_output = false
color_output = true

# Performance settings
memory_limit = "2GB"
buffer_size = "64KB"
chunk_size = "1MB"

[security]
# Encryption settings
default_encryption = "aes256-gcm"
key_derivation = "argon2id"
use_keychain = true
require_encryption = false

# Signature settings
default_signature = "ed25519"
verify_signatures = true
require_signatures = false

[keychain]
# Platform-specific keychain settings
service_name = "RuZip"
account_prefix = "ruzip-"

[keychain.macos]
keychain_name = "login"
access_group = "com.ruzip.keys"

[keychain.windows]
credential_target = "RuZip Keys"
credential_type = "generic"

[keychain.linux]
collection = "default"
service = "org.ruzip.KeyStorage"

[certificate]
# Certificate validation settings
verify_chain = true
check_revocation = true
trusted_roots = [
    "/etc/ssl/certs/ca-certificates.crt",  # Linux
    "/System/Library/Keychains/SystemRootCertificates.keychain",  # macOS
]

[performance]
# Memory management
memory_limit = "2GB"
memory_pressure_threshold = 0.8
use_memory_mapping = true
buffer_pool_size = 16

# Threading
max_threads = 0  # 0 = CPU cores
thread_strategy = "adaptive"
work_stealing = true
stack_size = "2MB"

# SIMD optimizations
simd_enabled = true
simd_fallback = true
prefer_hardware_acceleration = true

[logging]
# Logging configuration
level = "info"
format = "compact"
timestamp = true
target = "stdout"
file_path = "~/.local/share/ruzip/logs/ruzip.log"
max_file_size = "10MB"
max_files = 5

[output]
# Output formatting
json_format = false
color_output = true
progress_style = "bar"
timestamp_format = "%Y-%m-%d %H:%M:%S"

# Compression reporting
show_compression_ratio = true
show_speed = true
show_memory_usage = false

[paths]
# Default paths
temp_dir = "/tmp"  # Linux/macOS
config_dir = "~/.config/ruzip"
cache_dir = "~/.cache/ruzip"
log_dir = "~/.local/share/ruzip/logs"

[platform]
# Platform-specific optimizations
[platform.linux]
use_io_uring = true
use_splice = true
prefer_huge_pages = false
filesystem_optimization = true

[platform.macos]
use_apfs_cloning = true
use_unified_buffer = true
prefer_metal_acceleration = false

[platform.windows]
use_overlapped_io = true
use_completion_ports = true
prefer_large_pages = false

[profiles]
# Predefined configuration profiles
[profiles.fast]
compression_level = 3
compression_method = "lz4"
threads = 0
memory_limit = "1GB"

[profiles.balanced]
compression_level = 9
compression_method = "zstd"
threads = 0
memory_limit = "2GB"

[profiles.maximum]
compression_level = 22
compression_method = "zstd"
threads = 0
memory_limit = "4GB"

[profiles.secure]
compression_level = 9
default_encryption = "aes256-gcm"
require_encryption = true
require_signatures = true
use_keychain = true
```

## ⚙️ Configuration Sections

### Default Section
Controls basic operation parameters:

```toml
[default]
compression_level = 9        # 1-22, higher = better compression
compression_method = "zstd"  # zstd, lz4, brotli
threads = 0                  # 0 = auto-detect
preserve_permissions = true
preserve_timestamps = true
recursive = true
follow_symlinks = false
```

### Security Section
Manages encryption and authentication:

```toml
[security]
default_encryption = "aes256-gcm"    # aes256-gcm, chacha20-poly1305
key_derivation = "argon2id"          # argon2id, pbkdf2, scrypt
use_keychain = true                  # OS keychain integration
require_encryption = false           # Force encryption for all archives
default_signature = "ed25519"        # ed25519, rsa, ecdsa
verify_signatures = true             # Auto-verify signatures
require_signatures = false           # Force signatures for all archives
```

### Performance Section
Optimizes resource usage:

```toml
[performance]
memory_limit = "2GB"                 # Maximum memory usage
memory_pressure_threshold = 0.8      # When to apply memory pressure
use_memory_mapping = true            # Use mmap for large files
buffer_pool_size = 16               # Number of reusable buffers
max_threads = 0                      # Maximum thread count
thread_strategy = "adaptive"         # adaptive, fixed, work-stealing
simd_enabled = true                  # Enable SIMD optimizations
```

### Logging Section
Controls logging behavior:

```toml
[logging]
level = "info"                       # error, warn, info, debug, trace
format = "compact"                   # compact, full, json
timestamp = true
target = "stdout"                    # stdout, stderr, file
file_path = "~/.local/share/ruzip/logs/ruzip.log"
max_file_size = "10MB"
max_files = 5                        # Log rotation
```

## 🌍 Environment Variables

RuZip supports environment variables for configuration:

### General Settings
```bash
export RUZIP_CONFIG_FILE="/custom/path/config.toml"
export RUZIP_LOG_LEVEL="debug"
export RUZIP_THREADS="8"
export RUZIP_MEMORY_LIMIT="4GB"
export RUZIP_COMPRESSION_LEVEL="15"
```

### Security Settings
```bash
export RUZIP_ENCRYPTION="aes256-gcm"
export RUZIP_USE_KEYCHAIN="true"
export RUZIP_REQUIRE_ENCRYPTION="true"
export RUZIP_SIGNATURE_ALGORITHM="ed25519"
```

### Performance Settings
```bash
export RUZIP_SIMD_ENABLED="true"
export RUZIP_BUFFER_SIZE="128KB"
export RUZIP_CHUNK_SIZE="2MB"
export RUZIP_WORK_STEALING="true"
```

### Platform-Specific Variables
```bash
# Linux
export RUZIP_USE_IO_URING="true"
export RUZIP_USE_SPLICE="true"

# macOS
export RUZIP_USE_APFS_CLONING="true"
export RUZIP_KEYCHAIN_NAME="login"

# Windows
export RUZIP_USE_OVERLAPPED_IO="true"
export RUZIP_CREDENTIAL_TARGET="RuZip Keys"
```

## 🖥️ Platform-Specific Settings

### Linux Configuration
```toml
[platform.linux]
# I/O optimizations
use_io_uring = true              # Use io_uring for async I/O
use_splice = true                # Use splice() for zero-copy
preferred_filesystem = "ext4"    # Optimize for filesystem

# Memory management
prefer_huge_pages = false        # Use transparent huge pages
numa_awareness = true            # NUMA-aware allocation

# Security
selinux_context = "unconfined_u:object_r:user_home_t:s0"
```

### macOS Configuration
```toml
[platform.macos]
# APFS optimizations
use_apfs_cloning = true          # Use APFS copy-on-write
use_unified_buffer = true        # Use unified buffer cache
compression_aware = true         # Detect APFS compression

# Performance
prefer_metal_acceleration = false # Use Metal Performance Shaders
use_grand_central_dispatch = true # Use GCD for threading
```

### Windows Configuration
```toml
[platform.windows]
# I/O optimizations
use_overlapped_io = true         # Use overlapped I/O
use_completion_ports = true      # Use I/O completion ports
preferred_allocation = "virtual" # VirtualAlloc vs heap

# Security
use_crypto_api = true            # Use Windows Crypto API
credential_manager = true        # Use Windows Credential Manager
```

### BSD Configuration
```toml
[platform.bsd]
# FreeBSD specific
use_kqueue = true                # Use kqueue for events
zfs_aware = true                 # ZFS-aware optimizations
use_capsicum = false             # Capsicum sandboxing

# OpenBSD specific
use_pledge = true                # Use pledge() for security
use_unveil = true                # Use unveil() for filesystem access
```

## 📋 Configuration Templates

### Personal Use Template
```toml
# ~/.config/ruzip/config.toml - Personal configuration
[default]
compression_level = 12
threads = 0
preserve_permissions = true
progress_bar = true
verbose_level = "info"

[security]
use_keychain = true
default_encryption = "aes256-gcm"

[performance]
memory_limit = "2GB"
simd_enabled = true
```

### Server Administration Template
```toml
# /etc/ruzip/config.toml - Server configuration
[default]
compression_level = 15
threads = 0
preserve_permissions = true
preserve_timestamps = true
progress_bar = false
verbose_level = "warn"

[security]
require_encryption = true
require_signatures = true
use_keychain = false  # Use explicit keys in server environment

[performance]
memory_limit = "8GB"
max_threads = 16
thread_strategy = "fixed"
buffer_pool_size = 32

[logging]
level = "info"
target = "file"
file_path = "/var/log/ruzip/ruzip.log"
max_file_size = "100MB"
max_files = 10
```

### CI/CD Template
```toml
# .ruzip.toml - CI/CD configuration
[default]
compression_level = 9
threads = 0
progress_bar = false
verbose_level = "error"
json_output = true

[security]
require_encryption = false
require_signatures = false

[performance]
memory_limit = "1GB"
max_threads = 4

[logging]
level = "warn"
format = "json"
target = "stdout"
```

### Development Template
```toml
# .ruzip.toml - Development configuration
[default]
compression_level = 6
threads = 2
progress_bar = true
verbose_level = "debug"

[security]
use_keychain = false
require_encryption = false

[performance]
memory_limit = "1GB"
simd_enabled = false  # Disable for debugging

[logging]
level = "debug"
format = "full"
target = "file"
file_path = "./ruzip-debug.log"
```

## 🔧 Advanced Configuration

### Custom Compression Profiles
```toml
[profiles.web_assets]
compression_level = 19
compression_method = "brotli"
threads = 4
memory_limit = "1GB"
exclude_patterns = ["*.jpg", "*.png", "*.gif"]

[profiles.database_backup]
compression_level = 22
compression_method = "zstd"
threads = 0
memory_limit = "8GB"
encryption = "aes256-gcm"
signature = "ed25519"

[profiles.log_archival]
compression_level = 15
compression_method = "zstd"
threads = 2
memory_limit = "512MB"
preserve_timestamps = true
exclude_patterns = ["*.tmp", "*.lock"]
```

### Security Policies
```toml
[security.policies]
# Minimum security requirements
min_compression_level = 9
require_strong_passwords = true
min_key_length = 256
allowed_algorithms = ["aes256-gcm", "chacha20-poly1305"]
forbidden_algorithms = ["des", "3des", "rc4"]

# Audit settings
audit_enabled = true
audit_log_path = "/var/log/ruzip/audit.log"
log_all_operations = true
log_key_usage = true
```

### Resource Limits
```toml
[limits]
# Global limits
max_archive_size = "100GB"
max_file_size = "10GB"
max_files_per_archive = 1000000
max_compression_time = "24h"

# Per-user limits (system-wide config)
[limits.user]
max_memory_per_user = "4GB"
max_threads_per_user = 8
max_archives_per_day = 100
```

## ✅ Validation and Troubleshooting

### Configuration Validation
```bash
# Validate current configuration
ruzip config validate

# Check specific configuration file
ruzip config validate --file /etc/ruzip/config.toml

# Show effective configuration
ruzip config show --resolved

# Test configuration with dry-run
ruzip config test --dry-run
```

### Common Configuration Issues

#### Invalid TOML Syntax
```bash
# Check for syntax errors
ruzip config validate 2>&1 | grep -i "syntax error"

# Use TOML validator
toml-validator config.toml
```

#### Path Resolution Problems
```bash
# Check path expansion
ruzip config show | grep -E "(path|dir)"

# Test path accessibility
ruzip config test --check-paths
```

#### Permission Issues
```bash
# Check file permissions
ls -la ~/.config/ruzip/config.toml
ls -la /etc/ruzip/config.toml

# Fix permissions
chmod 644 ~/.config/ruzip/config.toml
sudo chmod 644 /etc/ruzip/config.toml
```

### Configuration Debugging
```bash
# Enable configuration debugging
RUZIP_LOG_LEVEL=debug ruzip config show

# Trace configuration loading
RUZIP_TRACE_CONFIG=1 ruzip --help

# Show configuration precedence
ruzip config sources --verbose
```

### Performance Tuning
```bash
# Profile configuration performance
ruzip config benchmark

# Test different thread settings
for threads in 1 2 4 8 16; do
    echo "Testing $threads threads:"
    time ruzip a test.rzp largefile --threads $threads
done

# Memory usage analysis
ruzip config analyze-memory --target-size 10GB
```

## 🔄 Configuration Management

### Backup and Restore
```bash
# Backup configuration
cp ~/.config/ruzip/config.toml ~/.config/ruzip/config.toml.backup

# Restore configuration
cp ~/.config/ruzip/config.toml.backup ~/.config/ruzip/config.toml

# Export configuration
ruzip config export > ruzip-config-backup.toml

# Import configuration
ruzip config import < ruzip-config-backup.toml
```

### Version Control Integration
```bash
# Add project configuration to git
git add .ruzip.toml

# Template for .gitignore
echo ".ruzip.toml.local" >> .gitignore  # Local overrides
```

### Configuration Distribution
```bash
# System administrator: Deploy configuration
sudo cp organization-config.toml /etc/ruzip/config.toml

# User: Import shared configuration
ruzip config import --user < shared-config.toml

# Project: Set up team configuration
ruzip config init --template team-defaults
```

---

**Next Steps**: 
- [User Guide](USER_GUIDE.md) - Learn how to use RuZip with your configuration
- [Security Guide](SECURITY.md) - Security-specific configuration options
- [Performance Guide](PERFORMANCE.md) - Performance optimization settings