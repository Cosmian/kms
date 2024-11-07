use std::process;

use cosmian_kms_cli::ckms_main;

#[tokio::main]
async fn main() {
    if let Some(err) = ckms_main().await.err() {
        eprintln!("ERROR: {err}");
        process::exit(1);
    }
}
