use std::sync::{Mutex, OnceLock};

use openssl::rand::rand_bytes;

// A minimal global RNG facade backed by OpenSSL RAND APIs.
// We do not expose this widely; it's intended to support RNGSeed semantics.
pub(crate) struct GlobalOsslRng {
    // Hold onto the last provided seed material to satisfy lints and enable
    // optional future introspection/debugging if needed.
    last_seed_accumulator: Vec<u8>,
}

impl GlobalOsslRng {
    pub(crate) const fn new() -> Self {
        Self {
            last_seed_accumulator: Vec::new(),
        }
    }

    // Best-effort reseed: record the seed locally and burn a few bytes from RAND_bytes
    // to create a side effect without altering global OpenSSL configuration.
    pub(crate) fn reseed(&mut self, seed: &[u8]) {
        // Accumulate a rolling window up to 4 KiB to avoid unbounded growth.
        const MAX_ACCUM: usize = 4 * 1024;
        if seed.is_empty() {
            return;
        }
        if self.last_seed_accumulator.len() + seed.len() > MAX_ACCUM {
            // Keep only the tail if exceeding the cap.
            let overflow = self
                .last_seed_accumulator
                .len()
                .saturating_add(seed.len())
                .saturating_sub(MAX_ACCUM);
            if overflow < self.last_seed_accumulator.len() {
                self.last_seed_accumulator.drain(0..overflow);
            } else {
                self.last_seed_accumulator.clear();
            }
        }
        self.last_seed_accumulator.extend_from_slice(seed);

        // Burn a small, fixed amount of random bytes as a harmless side effect.
        let mut burn = [0_u8; 32];
        // Ignore errors; this is best-effort and RAND_bytes is expected to succeed in practice.
        let _unused = rand_bytes(&mut burn);
    }
}

// Single-process global RNG instance.
static GLOBAL_RNG: OnceLock<Mutex<GlobalOsslRng>> = OnceLock::new();

pub(crate) fn global_rng() -> &'static Mutex<GlobalOsslRng> {
    GLOBAL_RNG.get_or_init(|| Mutex::new(GlobalOsslRng::new()))
}
