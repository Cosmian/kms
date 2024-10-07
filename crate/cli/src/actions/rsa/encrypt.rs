use std::{fs::File, io::Write, path::PathBuf};

use clap::Parser;
use cosmian_kms_client::{
    cosmian_kmip::crypto::generic::kmip_requests::build_encryption_request, read_bytes_from_file,
    KmsClient,
};

use crate::{
    actions::{
        console,
        rsa::{to_cryptographic_parameters, EncryptionAlgorithm, HashFn},
    },
    cli_bail,
    error::result::{CliResult, CliResultHelper},
};

/// Encrypt a file with the given public key using either
///  - `CKM_RSA_PKCS` a.k.a PKCS #1 RSA V1.5 as specified in PKCS#11 v2.40
///  - `CKM_RSA_PKCS_OAEP` a.k.a PKCS #1 RSA OAEP as specified in PKCS#11 v2.40
///  - `CKM_RSA_AES_KEY_WRAP` as specified in PKCS#11 v2.40
///
/// `CKM_RSA_PKCS` is deprecated in FIPS 140-3 and is therefore not available in FIPS mode.
/// `CKM_RSA_AES_KEY_WRAP` is meant be used to wrap/unwrap keys with RSA keys although,
/// since it is using `AES_KEY_WRAP_PAD` (a.k.a RFC 5649), encrypt/decrypt operations of text
/// with arbitrary length should be possible as specified in PKCS#11 v2.40 2.14.
///
/// When using `CKM_RSA_PKCS`:
///  - the maximum plaintext length is k-11 where k is the length in octets of the RSA modulus
///  - the output length is the same as the RSA modulus length.
///
/// When using `CKM_RSA_PKCS_OAEP`:
///  - the authentication data is ignored
///  - the maximum plaintext length is k-2-2*hLen where
///     - k is the length in octets of the RSA modulus
///     - hLen is the length in octets of the hash function output
///  - the output length is the same as the RSA modulus length.
///
/// When using `CKM_RSA_AES_KEY_WRAP`:
///  - the plaintext length is unlimited
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

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    tags: Option<Vec<String>>,

    /// The encryption algorithm
    #[clap(
        long = "encryption-algorithm",
        short = 'e',
        default_value = "ckm-rsa-pkcs-oaep"
    )]
    encryption_algorithm: EncryptionAlgorithm,

    /// The hashing algorithm
    #[clap(long = "hashing-algorithm", short = 's', default_value = "sha256")]
    hash_fn: HashFn,

    /// The encrypted output file path
    #[clap(required = false, long, short = 'o')]
    output_file: Option<PathBuf>,
}

impl EncryptAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
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
            None,
            None,
            Some(to_cryptographic_parameters(
                self.encryption_algorithm,
                self.hash_fn,
            )),
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

        let stdout = format!("The encrypted file is available at {output_file:?}");
        console::Stdout::new(&stdout).write()?;

        Ok(())
    }
}
