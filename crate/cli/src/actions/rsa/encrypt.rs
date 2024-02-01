use std::{fs::File, io::Write, path::PathBuf};

use clap::Parser;
use cosmian_kmip::kmip::kmip_types::HashingAlgorithm;
use cosmian_kms_client::KmsRestClient;
use cosmian_kms_utils::crypto::generic::kmip_requests::build_encryption_request;

use crate::{
    actions::shared::utils::read_bytes_from_file,
    cli_bail,
    error::{result::CliResultHelper, CliError},
};

#[derive(clap::ValueEnum, Debug, Clone, Copy)]
pub enum HashFn {
    Sha1,
    Sha224,
    Sha256,
    Sha384,
    Sha512,
    Sha3_224,
    Sha3_256,
    Sha3_384,
    Sha3_512,
}

impl From<HashFn> for HashingAlgorithm {
    fn from(value: HashFn) -> Self {
        match value {
            HashFn::Sha1 => HashingAlgorithm::SHA1,
            HashFn::Sha224 => HashingAlgorithm::SHA224,
            HashFn::Sha256 => HashingAlgorithm::SHA256,
            HashFn::Sha384 => HashingAlgorithm::SHA384,
            HashFn::Sha512 => HashingAlgorithm::SHA512,
            HashFn::Sha3_224 => HashingAlgorithm::SHA3224,
            HashFn::Sha3_256 => HashingAlgorithm::SHA3256,
            HashFn::Sha3_384 => HashingAlgorithm::SHA3384,
            HashFn::Sha3_512 => HashingAlgorithm::SHA3512,
        }
    }
}

/// Encrypt a file with the given public key using either
///  - CKM_RSA_PKCS_OAEP a.k.a PKCS #1 RSA OAEP as specified in PKCS#11 v2.40
///  - RSA_OAEP AES_128_GCM
/// By default the hashing function is set to SHA-256
///
/// When using CKM_RSA_PKCS_OAEP:
///  - the authentication data is ignored
///  - the maximum plaintext length is k-2-2*hLen where
///     - k is the length in octets of the RSA modulus
///     - hLen is the length in octets of the hash function output for EME-OAEP
///  - the output length is the same as the RSA modulus length.
///
/// Note: this is not a streaming call: the file is entirely loaded in memory before being sent for encryption.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct EncryptAction {
    /// The file to encrypt
    #[clap(required = true, name = "FILE")]
    input_file: PathBuf,

    /// The public key unique identifier.
    /// If not specified, tags should be specified
    #[clap(long = "key-id", short = 'k', group = "key-tags")]
    key_id: Option<String>,

    /// The hashing algorithm
    #[clap(long = "hashing-algorithm", short = 's', default_value = "sha256")]
    hash_fn: HashFn,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    tags: Option<Vec<String>>,

    /// The encrypted output file path
    #[clap(required = false, long, short = 'o')]
    output_file: Option<PathBuf>,

    /// Optional authentication data.
    /// This data needs to be provided back for decryption.
    #[clap(required = false, long, short = 'a')]
    authentication_data: Option<String>,
}

impl EncryptAction {
    pub async fn run(&self, kms_rest_client: &KmsRestClient) -> Result<(), CliError> {
        // Read the file to encrypt
        let mut data = read_bytes_from_file(&self.input_file)
            .with_context(|| "Cannot read bytes from the file to encrypt")?;

        // Recover the unique identifier or set of tags
        let id = if let Some(key_id) = &self.key_id {
            key_id.clone()
        } else if let Some(tags) = &self.tags {
            serde_json::to_string(&tags)?
        } else {
            cli_bail!("Either `--key-id` or one or more `--tag` must be specified")
        };

        // Create the kmip query
        let encrypt_request = build_encryption_request(
            &id,
            None,
            data,
            None,
            self.authentication_data
                .as_deref()
                .map(|s| s.as_bytes().to_vec()),
            None,
            Some(self.hash_fn.into()),
        )?;

        // Query the KMS with your kmip data and get the key pair ids
        let encrypt_response = kms_rest_client
            .encrypt(encrypt_request)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;

        data = encrypt_response
            .data
            .context("The encrypted data is empty")?;

        // Write the encrypted file
        let output_file = self
            .output_file
            .clone()
            .unwrap_or_else(|| self.input_file.with_extension("enc"));
        let mut buffer =
            File::create(&output_file).with_context(|| "failed to write the encrypted file")?;
        buffer
            .write_all(&data)
            .with_context(|| "failed to write the encrypted file")?;

        println!("The encrypted file is available at {output_file:?}");

        Ok(())
    }
}
