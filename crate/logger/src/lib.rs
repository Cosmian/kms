//! # Cosmian Logger
//!
//! A flexible logging crate that supports both synchronous and asynchronous
//! environments.
//!
//! ## Features
//!
//! - `full`: Enables complete functionality including tokio/async support,
//!   OpenTelemetry integration, and syslog support
//! - Without `full`: Provides basic tracing functionality for synchronous
//!   applications
//!
//! ## Important Note
//!
//! If you need `TelemetryConfig` or full OpenTelemetry functionality, you must
//! enable the `full` feature:
//!
//! ```toml
//! [dependencies]
//! cosmian_logger = { version = "0.5.4", features = ["full"] }
//! ```
//!
//! If you get an error like "no `TelemetryConfig` in the root", it means you
//! need to enable the full feature in your Cargo.toml dependency declaration.
mod error;
mod log_utils;
mod macros;
#[cfg(feature = "full")]
mod otlp;
mod tracing;

pub use error::LoggerError;
pub use log_utils::log_init;
#[cfg(feature = "full")]
pub use tracing::TelemetryConfig;
pub use tracing::{LoggingGuards, TracingConfig, tracing_init};

/// Re-exported dependencies for use with the logging macros
///
/// The logging macros (info!, debug!, warn!, error!, trace!) use these
/// re-exported tracing modules internally, so external crates don't need to add
/// tracing as a direct dependency.
pub mod reexport {
    pub use tracing;
    pub use tracing_subscriber;
}
