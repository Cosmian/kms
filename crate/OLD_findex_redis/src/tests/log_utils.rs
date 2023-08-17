use std::sync::Once;

use tracing_subscriber::{layer::SubscriberExt, EnvFilter};
static LOG_INIT: Once = Once::new();

/// # Panics
///
/// Will panic if we cannot set global tracing subscriber
pub fn log_init(paths: &str) {
    LOG_INIT.call_once(|| {
        if let Ok(old) = std::env::var("RUST_LOG") {
            std::env::set_var("RUST_LOG", format!("{old},{paths}"));
        } else {
            std::env::set_var("RUST_LOG", paths);
        }
        tracing_setup();
    });
}

/// # Panics
///
/// Will panic if we cannot set global subscriber
fn tracing_setup() {
    let layer = tracing_tree::HierarchicalLayer::default()
        .with_verbose_exit(true)
        .with_verbose_entry(true)
        .with_targets(true)
        .with_thread_names(true)
        .with_thread_ids(true)
        .with_indent_lines(true);
    let (filter, _reload_handle) =
        tracing_subscriber::reload::Layer::new(EnvFilter::from_default_env());

    let subscriber = tracing_subscriber::Registry::default()
        .with(filter)
        .with(layer);
    tracing::subscriber::set_global_default(subscriber).unwrap();

    tracing_log::LogTracer::init().unwrap();
}
