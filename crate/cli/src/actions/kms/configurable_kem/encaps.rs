use crate::{
    actions::kms::{labels::KEY_ID, shared::get_key_uid},
    error::{
        KmsCliError,
        result::{KmsCliResult, KmsCliResultHelper},
    },
};
use clap::Parser;
use cosmian_crypto_core::bytes_ser_de::Serializable;
use cosmian_kms_client::{
    KmsClient,
    cosmian_kmip::kmip_2_1::kmip_types::CryptographicAlgorithm,
    kmip_2_1::{kmip_types::CryptographicParameters, requests::encrypt_request},
};
use cosmian_logger::debug;
use zeroize::Zeroizing;

/// Encapsulate a new symmetric key.
#[derive(Parser, Debug)]
pub struct EncapsAction {
    /// The public key unique identifier.
    /// If not specified, tags should be specified
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    pub(crate) key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    pub(crate) tags: Option<Vec<String>>,

    /// The encryption policy to use.
    /// Example: "`department::marketing` && `level::confidential`"
    pub(crate) encryption_policy: Option<String>,
}

impl EncapsAction {
    pub async fn run(
        &self,
        kms_rest_client: KmsClient,
    ) -> KmsCliResult<(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>)> {
        let encrypt_request = encrypt_request(
            &get_key_uid(self.key_id.as_ref(), self.tags.as_ref(), KEY_ID)?,
            self.encryption_policy.clone(),
            Vec::new(),
            None,
            None,
            Some(CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::ConfigurableKEM),
                ..Default::default()
            }),
        )?;

        debug!("{encrypt_request}");

        let encrypt_response = kms_rest_client
            .encrypt(encrypt_request)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        <(Zeroizing<Vec<u8>>, Zeroizing<Vec<u8>>)>::deserialize(
            &encrypt_response
                .data
                .context("The encrypted-data field is empty")?,
        )
        .map_err(|e| {
            KmsCliError::Conversion(format!(
                "failed deserializing the key and its encapsulation from data \
                 returned by the configurable KEM: {e}"
            ))
        })
    }
}
