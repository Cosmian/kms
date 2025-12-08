use std::path::PathBuf;

use cosmian_kmip::kmip_2_1::{
    kmip_operations::SignatureVerify,
    kmip_types::{CryptographicParameters, UniqueIdentifier, ValidityIndicator},
};
use cosmian_kms_client::{KmsClient, read_bytes_from_file};

use crate::{
    actions::kms::{console, labels::KEY_ID, shared::get_key_uid},
    error::result::{KmsCliResult, KmsCliResultHelper},
};

pub(crate) async fn run_signature_verify(
    kms_rest_client: KmsClient,
    data_file: &PathBuf,
    signature_file: &PathBuf,
    key_id: &Option<String>,
    tags: &Option<Vec<String>>,
    cryptographic_parameters: Option<CryptographicParameters>,
    digested: bool,
) -> KmsCliResult<ValidityIndicator> {
    let data = read_bytes_from_file(data_file)
        .with_context(|| "Cannot read bytes from the signed data file")?;

    let signature_data = read_bytes_from_file(signature_file)
        .with_context(|| "Cannot read bytes from the signature file")?;

    let id = get_key_uid(key_id.as_ref(), tags.as_ref(), KEY_ID)?;

    let verify_request = if digested {
        SignatureVerify {
            unique_identifier: Some(UniqueIdentifier::TextString(id)),
            cryptographic_parameters,
            data: None,
            digested_data: Some(data),
            signature_data: Some(signature_data),
            correlation_value: None,
            init_indicator: None,
            final_indicator: None,
        }
    } else {
        SignatureVerify {
            unique_identifier: Some(UniqueIdentifier::TextString(id)),
            cryptographic_parameters,
            data: Some(data),
            digested_data: None,
            signature_data: Some(signature_data),
            correlation_value: None,
            init_indicator: None,
            final_indicator: None,
        }
    };

    let response = kms_rest_client
        .signature_verify(verify_request)
        .await
        .with_context(|| "Cannot execute the query on the KMS server")?;

    let validity_indicator = response
        .validity_indicator
        .context("Signature verification: the validity indicator is not set")?;

    let stdout = format!("Signature verification is {validity_indicator}");
    let mut stdout = console::Stdout::new(&stdout);
    stdout.set_tags(tags.as_ref());
    stdout.write()?;

    Ok(validity_indicator)
}
