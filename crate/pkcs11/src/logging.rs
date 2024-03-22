use std::{fs, fs::OpenOptions, path::PathBuf, sync::Once};

use tracing::level_filters::LevelFilter;
use tracing_error::ErrorLayer;
use tracing_subscriber::{
    fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry,
};

static TRACING_INIT: Once = Once::new();

pub fn initialize_logging(
    log_name: &str,
    log_home: Option<String>,
    level_filter: Option<LevelFilter>,
) {
    TRACING_INIT.call_once(|| {
        init(log_name, log_home, level_filter).unwrap_or_else(|e| {
            eprintln!("Failed to initialize logging: {e}");
        });
    });
}

fn init(
    log_name: &str,
    log_home: Option<String>,
    level_filter: Option<LevelFilter>,
) -> Result<(), Box<dyn std::error::Error>> {
    let log_home = match log_home {
        None => {
            let log_home = etcetera::home_dir().map_err(|e| format!("No home directory {e:?}"))?;
            log_home.join(".cosmian")
        }
        Some(log_home) => PathBuf::from(log_home),
    };
    // Use `create_dir_all` to create the directory and all its parent directories
    // if they do not exist.
    fs::create_dir_all(&log_home)?;
    let log_path = log_home.join(log_name);
    // Open the file in append mode, or create it if it doesn't exist.
    let file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(log_path)?;
    let env_filter = EnvFilter::builder()
        .with_default_directive(level_filter.unwrap_or(LevelFilter::TRACE).into())
        .from_env_lossy();
    _ = Registry::default()
        .with(
            tracing_subscriber::fmt::layer()
                .with_writer(std::sync::Mutex::new(file))
                .with_span_events(FmtSpan::ENTER),
        )
        .with(env_filter)
        .with(ErrorLayer::default())
        .try_init();
    Ok(())
}
