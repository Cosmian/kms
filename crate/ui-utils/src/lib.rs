#![deny(
  nonstandard_style,
  refining_impl_trait,
  future_incompatible,
  keyword_idents,
  let_underscore,
  unreachable_pub,
  unused,
  unsafe_code,
  clippy::all,
  clippy::suspicious,
  clippy::complexity,
  clippy::perf,
  clippy::style,
  clippy::pedantic,
  clippy::cargo,
  clippy::nursery,

  // restriction lints
  clippy::unwrap_used,
  clippy::get_unwrap,
  clippy::expect_used,
  clippy::indexing_slicing,
  clippy::missing_asserts_for_indexing,
  clippy::unwrap_in_result,
  clippy::assertions_on_result_states,
  clippy::panic,
  clippy::panic_in_result_fn,
  clippy::renamed_function_params,
  clippy::verbose_file_reads,
  clippy::str_to_string,
  clippy::string_to_string,
  clippy::unreachable,
  clippy::as_conversions,
  clippy::print_stdout,
  clippy::empty_structs_with_brackets,
  clippy::unseparated_literal_suffix,
  clippy::map_err_ignore,
  clippy::redundant_clone,
  // clippy::use_debug,
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::similar_names,
    clippy::too_many_lines,
    clippy::cargo_common_metadata,
    clippy::multiple_crate_versions,
    clippy::missing_errors_doc,
    clippy::missing_panics_doc,
    clippy::redundant_pub_crate,
    clippy::cognitive_complexity
)]

pub mod cover_crypt_utils;
pub mod create_utils;
pub mod error;
pub mod export_utils;
pub mod import_utils;
pub mod locate_utils;
pub mod rsa_utils;
pub mod symmetric_utils;
pub mod wasm;
