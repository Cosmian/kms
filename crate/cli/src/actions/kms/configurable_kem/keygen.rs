use std::path::PathBuf;

use clap::Parser;
use cosmian_kms_client::{
    KmsClient, kmip_2_1::kmip_types::UniqueIdentifier,
    reexport::cosmian_kms_client_utils::configurable_kem_utils::build_create_configurable_kem_keypair_request,
};
use cosmian_logger::debug;

use crate::{
    actions::kms::console,
    error::{
        KmsCliError,
        result::{KmsCliResult, KmsCliResultHelper},
    },
};

/// Create a new Configurable-KEM keypair and return the key IDs.
///
/// In case the targeted KEM algorithm is `CoverCrypt`, passing an access
/// structure is mandatory, it is otherwise ignored.
#[derive(Parser, Default)]
#[clap(verbatim_doc_comment)]
pub struct CreateKemKeyPairAction {
    /// The JSON access structure specifications file to use to generate the keys.
    /// See the inline doc of the `create-master-key-pair` command for details.
    #[clap(long, short = 's')]
    pub(crate) access_structure: Option<PathBuf>,

    /// The tag to associate with the master key pair.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG")]
    pub(crate) tags: Vec<String>,

    /// Sensitive: if set, the private key will not be exportable
    #[clap(long = "sensitive", default_value = "false")]
    pub(crate) sensitive: bool,

    /// The tag specifying which KEM algorithm to use:
    ///
    /// +----------------------+------+
    /// | KEM algorithm        | code |
    /// +----------------------+------+
    /// | ML-KEM512            |    0 |
    /// | ML-KEM768            |    1 |
    /// | P256                 |   10 |
    /// | Curve25519           |   11 |
    /// | ML-KEM512/P256       |  100 |
    /// | ML-KEM768/P256       |  101 |
    /// | ML-KEM512/Curve25519 |  110 |
    /// | ML-KEM768/Curve25519 |  111 |
    /// | `CoverCrypt`         | 1000 |
    /// +----------------------+------+
    #[clap(long = "kem", short = 'k')]
    pub(crate) kem_tag: usize,

    /// The key encryption key (KEK) used to wrap the keypair with.
    /// If the wrapping key is:
    /// - a symmetric key, AES-GCM will be used
    /// - a RSA key, RSA-OAEP will be used
    /// - a EC key, ECIES will be used (salsa20poly1305 for X25519)
    #[clap(
        long = "wrapping-key-id",
        short = 'w',
        required = false,
        verbatim_doc_comment
    )]
    pub(crate) wrapping_key_id: Option<String>,
}

impl CreateKemKeyPairAction {
    pub async fn run(
        &self,
        kms_rest_client: KmsClient,
    ) -> KmsCliResult<(UniqueIdentifier, UniqueIdentifier)> {
        let access_structure = self
            .access_structure
            .as_ref()
            .map(|path| {
                let access_structure = std::fs::read_to_string(path)?;
                debug!("access_structure: {access_structure:?}");
                Ok::<_, KmsCliError>(access_structure)
            })
            .transpose()?;

        let res = kms_rest_client
            .create_key_pair(build_create_configurable_kem_keypair_request(
                access_structure.as_deref(),
                &self.tags,
                self.kem_tag,
                self.sensitive,
                self.wrapping_key_id.as_ref(),
            )?)
            .await
            .with_context(|| "failed creating a Covercrypt Master Key Pair")?;

        let mut stdout =
            console::Stdout::new("The Configurable-KEM keypair has properly been generated.");
        stdout.set_tags(Some(&self.tags));
        stdout.set_key_pair_unique_identifier(
            &res.private_key_unique_identifier,
            &res.public_key_unique_identifier,
        );
        stdout.write()?;

        Ok((
            res.private_key_unique_identifier,
            res.public_key_unique_identifier,
        ))
    }
}
