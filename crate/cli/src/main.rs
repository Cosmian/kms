use std::process;

use cosmian_cli::cosmian_main;

#[tokio::main]
async fn main() {
    if let Some(err) = cosmian_main().await.err() {
        eprintln!("ERROR: {err}");
        process::exit(1);
    }
}
