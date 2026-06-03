//! Windows Service Control Manager (SCM) integration.
//!
//! When `cosmian_kms.exe` is launched by the Windows SCM (via `sc start`), the
//! process must call `StartServiceCtrlDispatcher` within 30 seconds or the SCM
//! marks it as failed.  This module bridges the SCM lifecycle to the regular
//! Actix-web server by:
//!
//! 1. Registering a service entry point with [`service_dispatcher::start`].
//! 2. Subscribing for `Stop` / `Interrogate` control events.
//! 3. Reporting `Running` once the HTTP server is ready.
//! 4. On `Stop`, triggering a graceful Actix shutdown via the `ServerHandle`.

use std::{ffi::OsString, sync::Arc, time::Duration};

use cosmian_logger::{TelemetryConfig, TracingConfig, tracing_init};
use tracing::{error, info};
use windows_service::{
    define_windows_service,
    service::{
        ServiceControl, ServiceControlAccept, ServiceExitCode, ServiceState, ServiceStatus,
        ServiceType,
    },
    service_control_handler::{self, ServiceControlHandlerResult},
    service_dispatcher,
};

use crate::config::{ClapConfig, ServerParams};

/// The Windows service name registered with `sc create`.
const SERVICE_NAME: &str = "CosmianKMS";

// Generate the low-level FFI entry point that the SCM calls.
define_windows_service!(ffi_service_main, service_main);

/// Attempt to register with the Windows SCM.
///
/// Returns `Ok(())` if the SCM dispatcher started (and later returned after
/// service stop). Returns `Err` if the process was NOT launched by the SCM
/// (e.g. run from a console), so the caller should fall through to the normal
/// console startup path.
pub fn try_run_as_service() -> Result<(), windows_service::Error> {
    service_dispatcher::start(SERVICE_NAME, ffi_service_main)
}

/// High-level service entry point (called on a background thread by the SCM).
fn service_main(_arguments: Vec<OsString>) {
    if let Err(e) = run_service() {
        error!("Windows service failed: {e}");
    }
}

fn run_service() -> crate::result::KResult<()> {
    // Build a tokio runtime for the async server.
    // We use `current_thread` because `start_kms_server` produces a !Send
    // future (due to OpenSSL handles held across await points).
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| {
            crate::error::KmsError::ServerError(format!("Failed to build tokio runtime: {e}"))
        })?;

    let local = tokio::task::LocalSet::new();
    local.block_on(&rt, run_service_async())
}

async fn run_service_async() -> crate::result::KResult<()> {
    // Channel for the ServerHandle (std::sync::mpsc matches start_kms_server API).
    let (handle_tx, handle_rx) = std::sync::mpsc::channel::<actix_web::dev::ServerHandle>();

    // Channel for the SCM Stop signal (std::sync::mpsc so the event_handler
    // closure — which is FnMut + Send, not async — can send without a runtime).
    let (stop_tx, stop_rx) = std::sync::mpsc::channel::<()>();

    // Register the SCM event handler.
    let event_handler = move |control_event| -> ServiceControlHandlerResult {
        match control_event {
            ServiceControl::Stop => {
                let _ = stop_tx.send(());
                ServiceControlHandlerResult::NoError
            }
            ServiceControl::Interrogate => ServiceControlHandlerResult::NoError,
            _ => ServiceControlHandlerResult::NotImplemented,
        }
    };

    let status_handle = Arc::new(
        service_control_handler::register(SERVICE_NAME, event_handler).map_err(|e| {
            crate::error::KmsError::ServerError(format!("SCM register failed: {e}"))
        })?,
    );

    // Report StartPending
    status_handle
        .set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::StartPending,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 1,
            wait_hint: Duration::from_secs(30),
            process_id: None,
        })
        .map_err(|e| {
            crate::error::KmsError::ServerError(format!("SCM set StartPending failed: {e}"))
        })?;

    // Load config (same path as normal main)
    dotenvy::dotenv().ok();
    let clap_config = ClapConfig::load_configuration()?;

    // Initialize tracing/logging (same as main.rs::run()) so that the Windows
    // service has proper log output, rolling file logs, and OTLP export.
    let log_to_file = clap_config.logging.rolling_log_dir.clone().and_then(|dir| {
        if let Err(e) = std::fs::create_dir_all(&dir) {
            eprintln!(
                "WARNING: Cannot create rolling log directory '{}': {e}. \
                 File logging disabled.",
                dir.display()
            );
            return None;
        }
        let probe = dir.join(".cosmian_kms_write_probe");
        match std::fs::File::create(&probe) {
            Ok(file) => {
                drop(file);
                std::fs::remove_file(&probe).ok();
            }
            Err(e) => {
                eprintln!(
                    "WARNING: Rolling log directory '{}' is not writable: {e}. \
                     File logging disabled.",
                    dir.display()
                );
                return None;
            }
        }
        let name = clap_config
            .logging
            .rolling_log_name
            .clone()
            .unwrap_or_else(|| "kms".to_owned());
        Some((dir, name))
    });

    let _otel_guard = tracing_init(&TracingConfig {
        service_name: "cosmian_kms".to_owned(),
        otlp: clap_config
            .logging
            .otlp
            .as_ref()
            .map(|url| TelemetryConfig {
                version: option_env!("CARGO_PKG_VERSION").map(String::from),
                environment: clap_config.logging.environment.clone(),
                otlp_url: url.to_owned(),
                enable_metering: clap_config.logging.enable_metering,
            }),
        no_log_to_stdout: clap_config.logging.quiet,
        rust_log: clap_config.logging.rust_log.clone().or_else(|| {
            std::env::var("RUST_LOG").ok().or_else(|| {
                Some("info,cosmian=info,cosmian_kms_server=info,actix_web=info".to_owned())
            })
        }),
        log_to_file,
        with_ansi_colors: clap_config.logging.ansi_colors,
    });

    let server_params = Arc::new(ServerParams::try_from(clap_config)?);

    // Spawn a background OS thread that:
    //  1. Waits for the ServerHandle from start_kms_server.
    //  2. Reports Running to the SCM.
    //  3. Waits for the SCM Stop signal.
    //  4. Calls handle.stop(false) to trigger immediate Actix shutdown.
    //
    // We use a plain thread because the event loop is single-threaded
    // (LocalSet) and we cannot spawn_blocking from it.
    let status_handle_clone = Arc::clone(&status_handle);
    std::thread::spawn(move || {
        // Block until the server has started and sent its handle.
        let Ok(server_handle) = handle_rx.recv() else {
            // Channel dropped — server failed to start.
            return;
        };

        // Report Running to SCM
        info!("Windows service reporting Running to SCM");
        let _status = status_handle_clone.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::Running,
            controls_accepted: ServiceControlAccept::STOP,
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 0,
            wait_hint: Duration::default(),
            process_id: None,
        });

        // Block until the SCM sends a Stop signal.
        let _msg = stop_rx.recv();
        info!("Windows service received Stop signal, shutting down...");

        // Report StopPending
        let _status = status_handle_clone.set_service_status(ServiceStatus {
            service_type: ServiceType::OWN_PROCESS,
            current_state: ServiceState::StopPending,
            controls_accepted: ServiceControlAccept::empty(),
            exit_code: ServiceExitCode::Win32(0),
            checkpoint: 1,
            wait_hint: Duration::from_secs(10),
            process_id: None,
        });

        // Trigger Actix shutdown (immediate, not graceful).
        // `ServerHandle::stop(graceful)` sends a stop command and returns a
        // future that resolves once the server loop exits.  We just need to
        // send the stop signal — the main task (start_kms_server) will observe
        // the server exit and proceed to report Stopped.
        // We do NOT await the future here because it depends on the server's
        // event loop (running on the main LocalSet) processing the stop.
        drop(server_handle.stop(false));
    });

    // Run the KMS server on the current (local) task.
    // This blocks until the server exits (triggered by handle.stop() above).
    let result = crate::start_kms_server::start_kms_server(server_params, Some(handle_tx)).await;

    // Report Stopped
    let _status = status_handle.set_service_status(ServiceStatus {
        service_type: ServiceType::OWN_PROCESS,
        current_state: ServiceState::Stopped,
        controls_accepted: ServiceControlAccept::empty(),
        exit_code: ServiceExitCode::Win32(0),
        checkpoint: 0,
        wait_hint: Duration::default(),
        process_id: None,
    });

    result
}
