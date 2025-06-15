# Development Setup

This document explains how to set up the development environment for RuZip with conventional commits and semantic versioning.

## 🚀 Quick Setup

Run the setup script to configure everything automatically:

```bash
./scripts/setup-dev.sh
```

This script will:
- Install required Rust tools (`git-cliff`, `cargo-release`)
- Set up Git hooks for commit validation
- Configure commit message templates
- Set up helpful Git aliases

## 📝 Conventional Commits

RuZip uses [Conventional Commits](https://conventionalcommits.org/) for automated versioning and changelog generation.

### Commit Format

```
<type>[optional scope]: <description>

[optional body]

[optional footer(s)]
```

### Valid Types

| Type | Description | Version Bump |
|------|-------------|--------------|
| `feat` | New feature | Minor |
| `fix` | Bug fix | Patch |
| `docs` | Documentation changes | None |
| `style` | Code style changes | None |
| `refactor` | Code refactoring | Patch |
| `perf` | Performance improvements | Patch |
| `test` | Test changes | None |
| `build` | Build system changes | None |
| `ci` | CI/CD changes | None |
| `chore` | Maintenance tasks | None |
| `revert` | Revert previous commit | Patch |

### Valid Scopes

- `cli` - Command-line interface
- `compression` - Compression algorithms
- `crypto` - Cryptography features
- `archive` - Archive format handling
- `simd` - SIMD optimizations
- `threading` - Multi-threading features
- `memory` - Memory management
- `platform` - Platform-specific code
- `utils` - Utilities and helpers

### Breaking Changes

Indicate breaking changes by adding `!` after the type/scope:

```bash
feat!: drop support for Rust < 1.70
fix(crypto)!: change default encryption to AES-256-GCM
```

### Examples

```bash
# Feature additions
feat(compression): add zstd level 22 support
feat(cli): add --parallel flag for multi-threading

# Bug fixes
fix(cli): resolve argument parsing for --exclude flag
fix(crypto): handle edge case in key derivation

# Documentation
docs: update installation guide for macOS
docs(api): add examples for compression API

# Performance improvements
perf(simd): optimize AVX2 memory copy operations
perf(compression): reduce memory allocations

# Breaking changes
feat!: drop support for Rust < 1.70
fix(api)!: rename CompressionLevel::Fast to CompressionLevel::Fastest
```

## 📋 Development Workflow

### 1. Make Changes

```bash
# Create feature branch
git checkout -b feat/new-compression-algo

# Make your changes
# ...

# Stage changes
git add .
```

### 2. Commit with Convention

```bash
# Use conventional format
git commit -m "feat(compression): add brotli compression support"

# Or use aliases
git feat "add brotli compression support"

# For scoped changes
git commit -m "fix(cli): resolve parsing issue with --output flag"
```

### 3. Pre-commit Validation

The pre-commit hook automatically:
- Validates commit message format
- Runs `cargo fmt --check`
- Runs `cargo clippy`
- Runs `cargo test`
- Builds documentation

### 4. Push and Release

```bash
# Push changes
git push origin feat/new-compression-algo

# Create PR - CI will validate all commits

# After merge to main, automatic release will:
# 1. Analyze commits for version bump
# 2. Generate changelog
# 3. Create Git tag
# 4. Build and upload binaries
# 5. Create GitHub release
```

## 📊 Semantic Versioning

RuZip follows [Semantic Versioning](https://semver.org/):

- **MAJOR** version for incompatible API changes (breaking changes)
- **MINOR** version for backwards-compatible functionality additions
- **PATCH** version for backwards-compatible bug fixes

### Automatic Version Bumps

| Commit Type | Version Bump | Example |
|-------------|--------------|---------|
| `feat` | Minor | `1.2.3` → `1.3.0` |
| `fix`, `perf` | Patch | `1.2.3` → `1.2.4` |
| Any type with `!` | Major | `1.2.3` → `2.0.0` |
| `docs`, `style`, `test`, `chore` | None | No release |

## 🛠️ Tools Used

### git-cliff
- **Purpose**: Changelog generation from conventional commits
- **Config**: `cliff.toml`
- **Usage**: `git cliff --output CHANGELOG.md`

### cargo-release
- **Purpose**: Automated Rust project releases
- **Config**: `release.toml`
- **Usage**: `cargo release minor --execute`

### Git Hooks
- **pre-commit**: Code quality checks before commit
- **commit-msg**: Validates conventional commit format
- **Location**: `.githooks/`

## 🔍 Manual Validation

Test your setup:

```bash
# Validate commit message format
echo "feat: test message" | .githooks/commit-msg

# Run pre-commit checks
.githooks/pre-commit

# Generate changelog preview
git cliff --unreleased

# Test release (dry run)
cargo release --dry-run
```

## 📚 References

- [Conventional Commits Specification](https://conventionalcommits.org/)
- [Semantic Versioning](https://semver.org/)
- [git-cliff Documentation](https://git-cliff.org/)
- [cargo-release Documentation](https://github.com/crate-ci/cargo-release)
