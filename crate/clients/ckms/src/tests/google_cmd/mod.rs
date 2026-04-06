#![allow(clippy::print_stdout)]
// Those tests are not run in CI, but they are useful for local testing.
// mod identities;
// mod key_pairs_enabling;
#[cfg(feature = "non-fips")]
mod key_pairs;
