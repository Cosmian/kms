#![allow(clippy::upper_case_acronyms)]
//required to detect generic type in Serializer
#![feature(min_specialization)]

pub use config::{ClientConf, KMS_CLI_CONF_ENV};
pub use cosmian_kmip::kmip;
pub use error::RestClientError;
pub use export_utils::export_object;
pub use import_utils::import_object;
pub use kms_rest_client::KmsRestClient;
pub use result::{RestClientResult, RestClientResultHelper};

pub mod access;
mod certificate_verifier;
mod config;
mod error;
mod export_utils;
mod import_utils;
mod kms_rest_client;
mod result;

pub use cosmian_kmip;
pub use error::RestClientError;
pub use kms_rest_client::KmsRestClient;
pub use result::{RestClientResult, RestClientResultHelper};
