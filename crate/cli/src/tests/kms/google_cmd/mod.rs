#![allow(clippy::large_futures)]
// Those tests are not run in CI, but they are useful for local testing.
// mod identities;
// mod key_pairs_enabling;
#[cfg(feature = "non-fips")]
mod key_pairs;
#[cfg(feature = "non-fips")]
mod using_hsm;
