use std::path::PathBuf;

use cosmian_kmip::kmip_2_1::{kmip_operations::Sign, kmip_types::UniqueIdentifier};
use cosmian_kms_client::{KmsClient, read_bytes_from_file, write_bytes_to_file};

use crate::{
    actions::kms::{console, labels::KEY_ID, shared::get_key_uid},
    error::result::{KmsCliResult, KmsCliResultHelper},
};

pub(crate) async fn run_sign(
    kms_rest_client: KmsClient,
    input_file: PathBuf,
    key_id: Option<String>,
    tags: Option<Vec<String>>,
    output_file: Option<PathBuf>,
    digested: bool,
) -> KmsCliResult<()> {
    let data = read_bytes_from_file(&input_file)
        .with_context(|| "Cannot read bytes from the input file")?;

    let id = get_key_uid(key_id.as_ref(), tags.as_ref(), KEY_ID)?;

    let sign_request = if digested {
        Sign {
            unique_identifier: Some(UniqueIdentifier::TextString(id)),
            cryptographic_parameters: None,
            data: None,
            digested_data: Some(data),
            correlation_value: None,
            init_indicator: None,
            final_indicator: None,
        }
    } else {
        Sign {
            unique_identifier: Some(UniqueIdentifier::TextString(id)),
            cryptographic_parameters: None,
            data: Some(data.into()),
            digested_data: None,
            correlation_value: None,
            init_indicator: None,
            final_indicator: None,
        }
    };

    let response = kms_rest_client
        .sign(sign_request)
        .await
        .with_context(|| "Cannot execute the query on the KMS server")?;

    let signature = response.signature_data.context("The signature is empty")?;

    let output_path = output_file.unwrap_or_else(|| {
        let mut p = input_file.clone();
        p.set_extension("signed");
        p
    });

    write_bytes_to_file(&signature, &output_path)
        .with_context(|| "Cannot write the signature to the output file")?;

    let stdout = format!("Signature written to {}", output_path.display());
    let mut stdout = console::Stdout::new(&stdout);
    stdout.set_tags(tags.as_ref());
    stdout.write()?;

    Ok(())
}
