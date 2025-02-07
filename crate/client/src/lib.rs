#![allow(clippy::upper_case_acronyms)]
//required to detect generic type in Serializer
#![feature(min_specialization)]

pub use config::{GmailApiConf, KmsClientConfig, KMS_CLI_CONF_ENV};
pub use cosmian_kmip::{self, kmip_2_1, pad_be_bytes};
pub use error::{result::KmsClientResult, KmsClientError};
pub use export_utils::{batch_export_objects, export_object, ExportObjectParams};
pub use file_utils::{
    read_bytes_from_file, read_bytes_from_files_to_bulk, read_from_json_file,
    read_object_from_json_ttlv_bytes, read_object_from_json_ttlv_file, write_bulk_decrypted_data,
    write_bulk_encrypted_data, write_bytes_to_file, write_json_object_to_file,
    write_kmip_object_to_file, write_single_decrypted_data, write_single_encrypted_data,
};
pub use kms_rest_client::KmsClient;

mod batch_utils;
mod config;
mod error;
mod export_utils;
mod file_utils;
mod kms_rest_client;

pub mod reexport {
    pub use cosmian_config_utils;
    pub use cosmian_http_client;
    pub use cosmian_kmip;
    pub use cosmian_kms_access;
    pub use cosmian_kms_ui_utils;
}
