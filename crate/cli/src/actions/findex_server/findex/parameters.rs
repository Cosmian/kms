use clap::Parser;
use cosmian_kms_client::{
    KmsClient, reexport::cosmian_kms_client_utils::create_utils::SymmetricAlgorithm,
};
use uuid::Uuid;

use super::findex_instance::FindexKeys;
use crate::{
    actions::kms::symmetric::keys::create_key::CreateKeyAction,
    error::{CosmianError, result::CosmianResult},
};

pub const HMAC_KEY_SIZE: u32 = 256;
pub const AES_XTS_KEY_SIZE: u32 = 512;
pub const SEED_KEY_SIZE: u32 = 256;

#[derive(Clone, Parser, Debug, Default)]
#[clap(verbatim_doc_comment)]
pub struct FindexParameters {
    /// The user findex seed used (to insert, search and delete).
    /// The seed is a 32 bytes hex string.
    #[clap(required = false, short = 's', long, conflicts_with = "aes_xts_key_id")]
    pub seed_key_id: Option<String>,

    /// Either the seed or the KMS keys (HMAC and AES XTS keys) must be provided.
    /// The HMAC key ID used to encrypt the seed.
    #[clap(
        short = 'p',
        long,
        conflicts_with = "seed_key_id",
        requires = "aes_xts_key_id"
    )]
    pub hmac_key_id: Option<String>,

    /// The AES XTS key ID used to encrypt the index.
    #[clap(
        short = 'x',
        long,
        conflicts_with = "seed_key_id",
        requires = "hmac_key_id"
    )]
    pub aes_xts_key_id: Option<String>,

    /// The index ID
    #[clap(long, short = 'i')]
    pub index_id: Uuid,

    /// The number of threads to use for parallel operations
    #[clap(short = 't', long)]
    pub num_threads: Option<usize>,
}

impl FindexParameters {
    #[allow(clippy::as_conversions)]
    /// Instantiates the Findex parameters.
    ///
    /// # Errors
    /// - if the keys cannot be generate via the KMS client
    #[allow(clippy::print_stdout)]
    pub async fn new(
        index_id: Uuid,
        kms_client: &KmsClient,
        server_side_encryption: bool,
        num_threads: Option<usize>,
    ) -> CosmianResult<Self> {
        async fn generate_key(
            kms_client: &KmsClient,
            bits: u32,
            algorithm: SymmetricAlgorithm,
            key_type: &str,
        ) -> CosmianResult<String> {
            let uid = CreateKeyAction {
                number_of_bits: Some(bits as usize),
                algorithm,
                ..CreateKeyAction::default()
            }
            .run(kms_client)
            .await?;
            println!(
                "Warning: This is the only time that this {key_type} key ID will be printed. ID: \
                 {uid}"
            );
            Ok(uid.to_string())
        }

        if server_side_encryption {
            Ok(Self {
                seed_key_id: None,
                hmac_key_id: Some(
                    generate_key(kms_client, HMAC_KEY_SIZE, SymmetricAlgorithm::Sha3, "HMAC")
                        .await?,
                ),
                aes_xts_key_id: Some(
                    generate_key(
                        kms_client,
                        AES_XTS_KEY_SIZE,
                        SymmetricAlgorithm::Aes,
                        "AES-XTS",
                    )
                    .await?,
                ),
                index_id,
                num_threads,
            })
        } else {
            Ok(Self {
                seed_key_id: Some(
                    generate_key(kms_client, SEED_KEY_SIZE, SymmetricAlgorithm::Aes, "seed")
                        .await?,
                ),
                hmac_key_id: None,
                aes_xts_key_id: None,
                index_id,
                num_threads,
            })
        }
    }

    /// Instantiates the Findex keys.
    /// If a seed key is provided, the client side encryption is used.
    /// Otherwise, the KMS server-side encryption is used.
    ///
    /// # Errors
    /// - if no key id is provided
    pub(crate) fn instantiate_keys(self) -> CosmianResult<FindexKeys> {
        match (self.seed_key_id, self.hmac_key_id, self.aes_xts_key_id) {
            (Some(seed_key_id), None, None) => Ok(FindexKeys::ClientSideEncryption {
                seed_key_id,
                index_id: self.index_id,
            }),
            (None, Some(hmac_key_id), Some(aes_xts_key_id)) => {
                Ok(FindexKeys::ServerSideEncryption {
                    hmac_key_id,
                    aes_xts_key_id,
                    index_id: self.index_id,
                })
            }
            _ => Err(CosmianError::Default(
                "Either the seed or the KMS keys (HMAC and AES XTS keys) must be provided."
                    .to_owned(),
            )),
        }
    }
}
