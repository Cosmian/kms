use std::sync::Once;

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt, EnvFilter};

static LOG_INIT: Once = Once::new();

/// # Panics
///
/// Will panic if we cannot set global tracing subscriber
pub fn log_init(default_value: &str) {
    LOG_INIT.call_once(|| {
        if std::env::var("RUST_BACKTRACE").is_err() {
            unsafe {
                std::env::set_var("RUST_BACKTRACE", "1");
            }
        }

        unsafe {
            if let Ok(current_value) = std::env::var("RUST_LOG") {
                std::env::set_var("RUST_LOG", current_value);
            } else {
                std::env::set_var("RUST_LOG", default_value);
            }
        }

        tracing_setup();
    });
}

/// # Panics
///
/// Will panic if:
/// - we cannot set global subscriber
/// - we cannot init the log tracer
fn tracing_setup() {
    let format = tracing_subscriber::fmt::layer()
        .with_level(true)
        .with_target(true)
        .with_thread_ids(true)
        .with_line_number(true)
        .with_file(true)
        .with_ansi(true)
        .compact();

    let (filter, _reload_handle) =
        tracing_subscriber::reload::Layer::new(EnvFilter::from_default_env());

    tracing_subscriber::registry()
        .with(filter)
        .with(format)
        .init();
}
