use clap::Parser;
use cosmian_kms_client::{
    KmsClient,
    cosmian_kmip::kmip_2_1::kmip_types::CryptographicAlgorithm,
    kmip_2_1::{kmip_types::CryptographicParameters, requests::decrypt_request},
};
use cosmian_logger::debug;
use zeroize::Zeroizing;

use crate::{
    actions::kms::{labels::KEY_ID, shared::get_key_uid},
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Open a Configurable-KEM encapsulation.
#[derive(Parser, Debug)]
pub struct DecapsAction {
    /// The user key unique identifier
    /// If not specified, tags should be specified
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    pub(crate) key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    pub(crate) tags: Option<Vec<String>>,

    /// The encapsulation to open.
    #[clap(required = true, name = "FILE")]
    pub(crate) encapsulation: Vec<u8>,
}

impl DecapsAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<Zeroizing<Vec<u8>>> {
        let decrypt_request = decrypt_request(
            &get_key_uid(self.key_id.as_ref(), self.tags.as_ref(), KEY_ID)?,
            None,
            self.encapsulation.clone(),
            None,
            None,
            Some(CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::ConfigurableKEM),
                ..Default::default()
            }),
        );

        debug!("{decrypt_request}");

        let decrypt_response = kms_rest_client
            .decrypt(decrypt_request)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        decrypt_response.data.context("The plain data are empty")
    }
}
