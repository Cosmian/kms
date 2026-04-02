# Cosmian Logger

A flexible logging crate that supports both synchronous and asynchronous environments.

## Features

- `full`: Enables complete functionality including OpenTelemetry integration, syslog support, and advanced tracing features
- Without `full`: Provides basic tracing functionality for synchronous applications

⚠️ **Important**: If you need `TelemetryConfig` or OpenTelemetry functionality, you must enable the `full` feature:

```toml
[dependencies]
cosmian_logger = { version = "0.5.4", features = ["full"] }
```

## Usage

### With Full Features

For applications that need OpenTelemetry and advanced features:

```toml
[dependencies]
cosmian_logger = { version = "0.5.4", features = ["full"] }
```

```rust
use cosmian_logger::{tracing_init, TelemetryConfig, TracingConfig};

#[tokio::main]
async fn main() {
    let config = TracingConfig {
        service_name: "my-service".to_string(),
        otlp: Some(TelemetryConfig {
            version: Some("1.0.0".to_string()),
            environment: Some("production".to_string()),
            otlp_url: "http://localhost:4317".to_string(),
            enable_metering: true,
        }),
        no_log_to_stdout: false,
        with_ansi_colors: true,
        ..Default::default()
    };

    let _guard = tracing_init(&config);

    tracing::info!("Application started");
}
```

### Without Full Features (Basic Mode)

For synchronous applications that only need basic logging:

```toml
[dependencies]
cosmian_logger = "0.5.4"
```

```rust
use cosmian_logger::{tracing_init, TracingConfig};

fn main() {
    let config = TracingConfig {
        service_name: "my-sync-service".to_string(),
        no_log_to_stdout: false,
        with_ansi_colors: true,
        // Note: otlp field is not available without full feature
        ..Default::default()
    };

    let _guard = tracing_init(&config);

    tracing::info!("Synchronous application started");
}
```

## Logging Macros

The crate provides logging macros that work with or without the full feature:

```rust
use cosmian_logger::{info, debug, warn, error, trace};

// Function name is automatically prefixed to log messages
info!("Application initialized");
debug!(user_id = 123, "Processing user request");
warn!("Low memory warning");
error!(error = %err, "Operation failed");
```

## Features Summary

- **Basic logging**: stdout, file, and structured logging support
- **OpenTelemetry** (requires full feature): OTLP tracing and metrics
- **Syslog support** (requires full feature): System log integration
- **Structured logging**: Multiple message patterns supported
- **ANSI colors**: Configurable for interactive vs persistent outputs

A versatile logging and tracing utility for Rust applications that provides:

- Structured logging to stdout
- Syslog integration
- OpenTelemetry support for distributed tracing
- Runtime configuration options

## Installation

Add the dependency to your `Cargo.toml`:

```toml
[dependencies]
cosmian_logger = { path = "../path/to/crate/logger" }
```

## Basic Usage

For simple applications, use the `log_init` function to set up logging:

```rust
use cosmian_logger::log_init;
use tracing::{debug, info};

fn main() {
    // Initialize with custom log level
    log_init(Some("debug"));

    info!("This is an info message");
    debug!("This is a debug message");
}
```

The `log_init` function accepts an optional log level string parameter:

- When `None` is provided, it falls back to the `RUST_LOG` environment variable
- Log levels follow Rust's standard: trace, debug, info, warn, error

## Advanced Configuration with OpenTelemetry

For more advanced use cases with OpenTelemetry integration, enable the `full` feature:

```toml
[dependencies]
cosmian_logger = { version = "0.5.4", features = ["full"] }
```

```rust
use cosmian_logger::{tracing_init, TelemetryConfig, TracingConfig};
use tracing::span;
use tracing_core::Level;

#[tokio::main]
async fn main() {
    let config = TracingConfig {
        service_name: "my_service".to_string(),
        otlp: Some(TelemetryConfig {
            version: Some("1.0.0".to_string()),
            environment: Some("development".to_string()),
            otlp_url: "http://localhost:4317".to_string(),
            enable_metering: true,
        }),
        no_log_to_stdout: false,
        #[cfg(not(target_os = "windows"))]
        log_to_syslog: true,
        rust_log: Some("debug".to_string()),
        ..Default::default()
    };

    let _otel_guard = tracing_init(&config);

    // Create and enter a span for better tracing context
    let span = span!(Level::TRACE, "application");
    let _span_guard = span.enter();

    // Your application code here
    tracing::info!("Application started");
}
```

## OpenTelemetry Setup

To use OpenTelemetry, start a collector like Jaeger:

```bash
docker run -p16686:16686 -p4317:4317 -p4318:4318 \
-e COLLECTOR_OTLP_ENABLED=true -e LOG_LEVEL=debug \
jaegertracing/jaeger:2.5.0
```

Then access the Jaeger UI at `http://localhost:16686`

## Configuration Options

The `TracingConfig` struct supports:

- `service_name`: Name of your service for tracing
- `otlp`: OpenTelemetry configuration (only available with `full` feature)
- `no_log_to_stdout`: Disable logging to stdout
- `log_to_syslog`: Enable logging to system log (only available with `full` feature)
- `rust_log`: Log level configuration
- `with_ansi_colors`: Enable ANSI colors in output
- `log_to_file`: Optional file logging configuration

## In Tests

The `log_init` function is safe to use in tests:

```rust
#[test]
fn test_something() {
    cosmian_logger::log_init(Some("debug"));
    // Your test code
}
```

## Re-exports

The logger crate re-exports common tracing utilities:

```rust
use cosmian_logger::reexport::{tracing, tracing_subscriber};
```
