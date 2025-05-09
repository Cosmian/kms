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
    clippy::too_long_first_doc_paragraph,
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
// required to detect generic type in Serializer
#![feature(min_specialization)]

pub use error::{KmipError, result::KmipResultHelper};

mod bytes_ser_de;
pub use bytes_ser_de::{Deserializer, Serializer, test_serialization, to_leb128_len};
mod data_to_encrypt;
pub use data_to_encrypt::DataToEncrypt;
mod error;
pub mod kmip_0;
pub mod kmip_1_4;
pub mod kmip_2_1;
mod safe_bigint;
pub mod ttlv;

pub use safe_bigint::SafeBigInt;

pub fn pad_be_bytes(bytes: &mut Vec<u8>, size: usize) {
    while bytes.len() < size {
        bytes.insert(0, 0);
    }
}
