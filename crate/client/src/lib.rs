#![allow(clippy::upper_case_acronyms)]
//required to detect generic type in Serializer
#![feature(min_specialization)]

mod bootstrap_rest_client;
mod certificate_verifier;
mod error;
mod kms_rest_client;
mod result;

pub use bootstrap_rest_client::BootstrapRestClient;
pub use cosmian_kmip::kmip;
pub use error::RestClientError;
pub use kms_rest_client::{parse_pkcs12, KmsRestClient};
pub use result::{RestClientResult, RestClientResultHelper};
