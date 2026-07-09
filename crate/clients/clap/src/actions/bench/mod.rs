#![allow(
    clippy::as_conversions,
    clippy::indexing_slicing,
    clippy::expect_used,
    clippy::unwrap_used,
    clippy::implicit_clone,
    clippy::format_push_string,
    clippy::branches_sharing_code,
    clippy::only_used_in_recursion,
    clippy::cast_possible_truncation,
    clippy::cast_possible_wrap,
    // Benchmark size sweeps are intentionally kept as loops for easy re-expansion.
    clippy::single_element_loop
)]

mod clap;
pub(crate) mod helpers;
pub(crate) mod jose;
pub(crate) mod kmip;
pub(crate) mod load;
pub(crate) mod output;
pub(crate) mod transport;
mod types;

pub use types::BenchAction;
