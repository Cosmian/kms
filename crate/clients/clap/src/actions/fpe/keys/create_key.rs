use clap::Parser;
use cosmian_kms_client::{
    KmsClient,
    kmip_2_1::{
        kmip_types::{CryptographicAlgorithm, UniqueIdentifier},
        requests::symmetric_key_create_request,
    },
};

use crate::{
    actions::console,
    error::result::{KmsCliResult, KmsCliResultHelper},
};

#[derive(Parser, Debug, Default)]
pub struct CreateKeyAction {
    /// The tag to associate with the key.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG")]
    pub tags: Vec<String>,

    /// The unique id of the key; a random uuid is generated if not specified.
    #[clap(required = false)]
    pub key_id: Option<String>,

    /// Sensitive: if set, the key will not be exportable.
    #[clap(long = "sensitive", default_value = "false")]
    pub sensitive: bool,
}

impl CreateKeyAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<UniqueIdentifier> {
        let vendor_id = kms_rest_client.config.vendor_id.as_str();
        let mut tags = self.tags.clone();
        if !tags.iter().any(|tag| tag == "fpe-ff1") {
            tags.push("fpe-ff1".to_owned());
        }

        let key_id = self
            .key_id
            .as_ref()
            .map(|id| UniqueIdentifier::TextString(id.clone()));
        let create_key_request = symmetric_key_create_request(
            vendor_id,
            key_id,
            256,
            CryptographicAlgorithm::FPE_FF1,
            &tags,
            self.sensitive,
            None,
        )?;
        let unique_identifier = kms_rest_client
            .create(create_key_request)
            .await
            .with_context(|| "failed creating the FPE key")?
            .unique_identifier;

        let mut stdout = console::Stdout::new("The FPE key was successfully generated.");
        stdout.set_tags(Some(&tags));
        stdout.set_unique_identifier(&unique_identifier);
        stdout.write()?;

        Ok(unique_identifier)
    }
}
