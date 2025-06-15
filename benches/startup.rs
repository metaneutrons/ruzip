//! Startup performance benchmarks for RuZip
//!
//! These benchmarks measure the startup time and memory usage
//! to ensure we meet the <10ms startup target.

use criterion::{black_box, criterion_group, criterion_main, Criterion, BenchmarkId};
use std::process::Command;
use std::time::{Duration, Instant};

/// Benchmark CLI parsing performance
fn cli_parsing_benchmark(c: &mut Criterion) {
    use ruzip::cli::Cli;
    use clap::Parser;
    
    let test_cases = vec![
        vec!["ruzip", "--help"],
        vec!["ruzip", "a", "test.rzp", "file.txt"],
        vec!["ruzip", "x", "test.rzp", "-o", "output/"],
        vec!["ruzip", "l", "test.rzp", "--verbose"],
        vec!["ruzip", "a", "-mx9", "-p", "password", "--threads", "8", "archive.rzp", "dir/"],
    ];
    
    let mut group = c.benchmark_group("cli_parsing");
    
    for (i, args) in test_cases.iter().enumerate() {
        group.bench_with_input(BenchmarkId::new("parse_args", i), args, |b, args| {
            b.iter(|| {
                // Convert &str to String for parsing
                let string_args: Vec<String> = args.iter().map(|s| s.to_string()).collect();
                black_box(Cli::try_parse_from(&string_args))
            });
        });
    }
    
    group.finish();
}

/// Benchmark error creation performance
fn error_creation_benchmark(c: &mut Criterion) {
    use ruzip::error::RuzipError;
    use std::io;
    
    let mut group = c.benchmark_group("error_creation");
    
    group.bench_function("io_error", |b| {
        b.iter(|| {
            let io_err = io::Error::new(io::ErrorKind::NotFound, "file not found");
            black_box(RuzipError::io_error("Test error", io_err))
        });
    });
    
    group.bench_function("crypto_error", |b| {
        b.iter(|| {
            black_box(RuzipError::crypto_error("Crypto test error", None))
        });
    });
    
    group.bench_function("archive_format_error", |b| {
        b.iter(|| {
            black_box(RuzipError::archive_format_error(
                "Invalid format", 
                Some("Expected RUZIP header".to_string())
            ))
        });
    });
    
    group.finish();
}

/// Benchmark configuration loading
fn config_loading_benchmark(c: &mut Criterion) {
    use ruzip::utils::config::ConfigBuilder;
    
    let mut group = c.benchmark_group("config_loading");
    
    group.bench_function("default_config", |b| {
        b.iter(|| {
            black_box(ConfigBuilder::new().build())
        });
    });
    
    group.finish();
}

/// Benchmark utility functions
fn utility_functions_benchmark(c: &mut Criterion) {
    use ruzip::utils::{format_size, format_duration, compression_ratio, compression_speed};
    
    let mut group = c.benchmark_group("utility_functions");
    
    group.bench_function("format_size", |b| {
        b.iter(|| {
            black_box(format_size(1_073_741_824)); // 1GB
        });
    });
    
    group.bench_function("format_duration", |b| {
        b.iter(|| {
            black_box(format_duration(Duration::from_millis(1234)));
        });
    });
    
    group.bench_function("compression_ratio", |b| {
        b.iter(|| {
            black_box(compression_ratio(1000, 250));
        });
    });
    
    group.bench_function("compression_speed", |b| {
        b.iter(|| {
            black_box(compression_speed(1_048_576, Duration::from_secs(1)));
        });
    });
    
    group.finish();
}

/// Benchmark cold startup time (actual process startup)
fn cold_startup_benchmark(c: &mut Criterion) {
    let mut group = c.benchmark_group("cold_startup");
    
    // Set a longer measurement time for startup tests
    group.measurement_time(Duration::from_secs(20));
    group.sample_size(50); // Fewer samples for process startup
    
    group.bench_function("version_command", |b| {
        b.iter(|| {
            let start = Instant::now();
            let output = Command::new("cargo")
                .args(&["run", "--release", "--", "version"])
                .output()
                .expect("Failed to execute command");
            let duration = start.elapsed();
            
            black_box((output, duration))
        });
    });
    
    group.bench_function("help_command", |b| {
        b.iter(|| {
            let start = Instant::now();
            let output = Command::new("cargo")
                .args(&["run", "--release", "--", "--help"])
                .output()
                .expect("Failed to execute command");
            let duration = start.elapsed();
            
            black_box((output, duration))
        });
    });
    
    group.finish();
}

/// Benchmark memory allocation patterns
fn memory_benchmark(c: &mut Criterion) {
    use ruzip::utils::config::Config;
    
    let mut group = c.benchmark_group("memory_allocation");
    
    group.bench_function("config_clone", |b| {
        let config = Config::default();
        b.iter(|| {
            black_box(config.clone())
        });
    });
    
    group.bench_function("vector_allocation", |b| {
        b.iter(|| {
            let mut vec = Vec::with_capacity(1000);
            for i in 0..1000 {
                vec.push(i);
            }
            black_box(vec)
        });
    });
    
    group.finish();
}

criterion_group!(
    startup_benches,
    cli_parsing_benchmark,
    error_creation_benchmark,
    config_loading_benchmark,
    utility_functions_benchmark,
    memory_benchmark
);

// Only run cold startup benchmark on release builds to avoid skewing results
#[cfg(not(debug_assertions))]
criterion_group!(
    cold_startup_benches,
    cold_startup_benchmark
);

#[cfg(debug_assertions)]
criterion_group!(
    cold_startup_benches,
);

criterion_main!(startup_benches, cold_startup_benches);