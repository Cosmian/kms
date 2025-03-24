#![deny(
    nonstandard_style,
    refining_impl_trait,
    future_incompatible,
    keyword_idents,
    let_underscore,
    unreachable_pub,
    unused,
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
    clippy::todo
)]
#![allow(
    clippy::module_name_repetitions,
    clippy::too_many_lines,
    clippy::cargo_common_metadata,
    clippy::multiple_crate_versions,
    clippy::redundant_pub_crate
)]
//required to detect generic type in Serializer
#![feature(min_specialization)]

pub use config::{GmailApiConf, KmsClientConfig};
pub use cosmian_kmip::{self, kmip_2_1, pad_be_bytes};
pub use encodings::{der_to_pem, objects_from_pem};
pub use error::{KmsClientError, result::KmsClientResult};
pub use export_utils::{ExportObjectParams, batch_export_objects, export_object};
pub use file_utils::{
    read_bytes_from_file, read_bytes_from_files_to_bulk, read_from_json_file,
    read_object_from_json_ttlv_bytes, read_object_from_json_ttlv_file, write_bulk_decrypted_data,
    write_bulk_encrypted_data, write_bytes_to_file, write_json_object_to_file,
    write_kmip_object_to_file, write_single_decrypted_data, write_single_encrypted_data,
};
pub use import_utils::import_object;
pub use kms_rest_client::KmsClient;

mod batch_utils;
mod config;
mod encodings;
mod error;
mod export_utils;
mod file_utils;
mod import_utils;
mod kms_rest_client;

pub mod reexport {
    pub use cosmian_config_utils;
    pub use cosmian_http_client;
    pub use cosmian_kmip;
    pub use cosmian_kms_access;
}
