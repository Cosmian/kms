#![allow(clippy::upper_case_acronyms)]
//required to detect generic type in Serializer
#![feature(min_specialization)]

pub use config::{ClientConf, KMS_CLI_CONF_ENV};
pub use cosmian_kmip::kmip;
pub use encodings::{der_to_pem, objects_from_pem};
pub use error::ClientError;
pub use export_utils::{batch_export_objects, export_object};
pub use import_utils::import_object;
pub use kms_rest_client::KmsRestClient;
pub use result::{RestClientResult, RestClientResultHelper};

pub mod access;
mod batch_utils;
mod certificate_verifier;
mod config;
mod encodings;
mod error;
mod export_utils;
mod import_utils;
mod kms_rest_client;
mod result;

pub use cosmian_kmip;
pub use error::RestClientError;
pub use kms_rest_client::KmsRestClient;
pub use result::{RestClientResult, RestClientResultHelper};
