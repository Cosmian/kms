use std::{fs, fs::OpenOptions, path::PathBuf, sync::Once};

use tracing::Level;
use tracing_error::ErrorLayer;
use tracing_subscriber::{
    fmt::format::FmtSpan, layer::SubscriberExt, util::SubscriberInitExt, EnvFilter, Registry,
};

static TRACING_INIT: Once = Once::new();

pub(crate) fn initialize_logging(log_name: &str, level: Option<Level>, log_home: Option<String>) {
    TRACING_INIT.call_once(|| {
        init(log_name, level, log_home).unwrap_or_else(|e| {
            eprintln!("Failed to initialize logging: {e}");
        });
    });
}

#[cfg(not(target_os = "linux"))]
fn init(
    log_name: &str,
    level: Option<Level>,
    log_home: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let log_home = match log_home {
        None => {
            let log_home = etcetera::home_dir().map_err(|e| format!("No home directory {e:?}"))?;
            log_home.join(".cosmian")
        }
        Some(log_home) => PathBuf::from(log_home),
    };
    log_to_file(log_name, level.unwrap_or(Level::INFO), &log_home)
}

#[cfg(target_os = "linux")]
/// For Linux, log to /var/log
fn init(
    log_name: &str,
    level: Option<Level>,
    _log_home: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    let level = level.unwrap_or(Level::INFO);
    println!("ckms-pkcs11 module logging at {level} level to file /var/log/{log_name}.log");
    log_to_file(log_name, level, &PathBuf::from("/var/log"))
}

fn log_to_file(
    log_name: &str,
    level: Level,
    log_home: &PathBuf,
) -> Result<(), Box<dyn std::error::Error>> {
    // Use `create_dir_all` to create the directory and all its parent directories
    // if they do not exist.
    if !log_home.exists() {
        fs::create_dir_all(log_home)?;
    }
    let log_path = log_home.join(format!("{log_name}.log"));
    // Open the file in append mode, or create it if it doesn't exist.
    let file = OpenOptions::new()
        .append(true)
        .create(true)
        .open(log_path)?;
    let env_filter =
        EnvFilter::new(format!("info,ckms_pkcs11={level},cosmian_pkcs11_module={level}").as_str());
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
