mod ansi_x931;

use std::sync::OnceLock;

pub(crate) use ansi_x931::AnsiX931Rng;
use tokio::sync::Mutex;

static GLOBAL_RNG: OnceLock<Mutex<AnsiX931Rng>> = OnceLock::new();

/// Get the process-wide ANSI X9.31 RNG instance.
pub(crate) fn global_rng() -> &'static Mutex<AnsiX931Rng> {
    GLOBAL_RNG.get_or_init(|| Mutex::new(AnsiX931Rng::new()))
}
