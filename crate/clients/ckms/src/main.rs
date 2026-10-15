use std::process::ExitCode;

use ckms::ckms_main;

fn main() -> ExitCode {
    // Run the CLI in a dedicated thread with a large stack to avoid stack overflows
    // on Windows when processing deeply nested KMIP/TTLV structures.
    let handle = match std::thread::Builder::new()
        .name("ckms-main".into())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| -> Result<(), String> {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_stack_size(16 * 1024 * 1024)
                .build()
                .map_err(|e| format!("failed to build tokio runtime: {e}"))?;
            rt.block_on(ckms_main()).map_err(|e| e.to_string())
        }) {
        Ok(handle) => handle,
        Err(e) => {
            eprintln!("ERROR: failed to spawn ckms main thread: {e}");
            return ExitCode::FAILURE;
        }
    };

    match handle.join() {
        Ok(Ok(())) => ExitCode::SUCCESS,
        Ok(Err(err)) => {
            eprintln!("ERROR: {err}");
            ExitCode::FAILURE
        }
        Err(_) => {
            eprintln!("ERROR: panic in ckms main thread");
            ExitCode::FAILURE
        }
    }
}
