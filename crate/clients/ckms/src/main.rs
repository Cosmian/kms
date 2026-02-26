#![allow(clippy::expect_used)]

use std::process;

use ckms::cosmian_main;

fn main() {
    // Run the CLI in a dedicated thread with a large stack to avoid stack overflows
    // on Windows when processing deeply nested KMIP/TTLV structures.
    let handle = std::thread::Builder::new()
        .name("cosmian-main".into())
        .stack_size(32 * 1024 * 1024)
        .spawn(|| {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .thread_stack_size(16 * 1024 * 1024)
                .build()
                .expect("failed to build tokio runtime");
            rt.block_on(cosmian_main())
        })
        .expect("failed to spawn cosmian main thread");

    match handle.join() {
        Ok(Ok(())) => {}
        Ok(Err(err)) => {
            eprintln!("ERROR: {err}");
            process::exit(1);
        }
        Err(_) => {
            eprintln!("ERROR: panic in main thread");
            process::exit(1);
        }
    }
}
