// This is required at the top level to support Findex
#![feature(async_fn_in_trait)]

mod callbacks;
mod error;
mod findex;

#[cfg(test)]
mod tests;

pub use callbacks::RemovedLocationsFinder;
pub use cosmian_findex::Location;
pub use error::FindexError;
pub use findex::FindexRedis;
