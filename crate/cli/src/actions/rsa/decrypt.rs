use std::{fs::File, io::Write, path::PathBuf};

use clap::Parser;
use cosmian_kms_client::{
    cosmian_kmip::crypto::generic::kmip_requests::build_decryption_request, read_bytes_from_file,
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

/// Decrypt a file with the given public key using either
///  - `CKM_RSA_PKCS` a.k.a PKCS #1 RSA V1.5 as specified in PKCS#11 v2.40
///  - `CKM_RSA_PKCS_OAEP` a.k.a PKCS #1 RSA OAEP as specified in PKCS#11 v2.40
///  - `CKM_RSA_AES_KEY_WRAP` as specified in PKCS#11 v2.40
///
/// `CKM_RSA_PKCS` is deprecated in FIPS 140-3 and is therefore not available in FIPS mode.
/// `CKM_RSA_AES_KEY_WRAP` is meant be used to wrap/unwrap keys with RSA keys although,
/// since it is using `AES_KEY_WRAP_PAD` (a.k.a RFC 5649), encrypt/decrypt operations of text
/// with arbitrary length should be possible as specified in PKCS#11 v2.40 2.14.
///
/// By default, the hashing function used with `CKM_RSA_PKCS_OAEP` and `CKM_RSA_AES_KEY_WRAP`
/// is set to SHA-256 and is ignored with RSA PKCS.
/// When using `CKM_RSA_PKCS`:
///  - the maximum plaintext length is k-11 where k is the length in octets of the RSA modulus
///  - the ciphertext input length is the same as the RSA modulus length.
///
/// When using `CKM_RSA_PKCS_OAEP`:
///  - the maximum plaintext length is k-2-2*hLen where
///     - k is the length in octets of the RSA modulus
///     - hLen is the length in octets of the hash function output
///  - the ciphertext input length is the same as the RSA modulus length.
///
/// When using `CKM_RSA_AES_KEY_WRAP`:
///  - the plaintext length is unlimited
///
/// Note: this is not a streaming call: the file is entirely loaded in memory before being sent for decryption.
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct DecryptAction {
    /// The file to decrypt
    #[clap(required = true, name = "FILE")]
    input_file: PathBuf,

    /// The private key unique identifier
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

impl DecryptAction {
    pub async fn run(&self, kms_rest_client: &KmsClient) -> CliResult<()> {
        // Read the file to decrypt
        let data = read_bytes_from_file(&self.input_file)
            .with_context(|| "Cannot read bytes from the file to decrypt")?;

        // Recover the unique identifier or set of tags
        let id = if let Some(key_id) = &self.key_id {
            key_id.clone()
        } else if let Some(tags) = &self.tags {
            serde_json::to_string(&tags)?
        } else {
            cli_bail!("Either `--key-id` or one or more `--tag` must be specified")
        };

        // Create the kmip query
        let decrypt_request = build_decryption_request(
            &id,
            None,
            data,
            None,
            None,
            Some(to_cryptographic_parameters(
                self.encryption_algorithm,
                self.hash_fn,
            )),
        );

        // Query the KMS with your kmip data and get the key pair ids
        let decrypt_response = kms_rest_client
            .decrypt(decrypt_request)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;
        let plaintext = decrypt_response
            .data
            .context("Decrypt with RSA: the plaintext is empty")?;

        // Write the decrypted file
        let output_file = self
            .output_file
            .clone()
            .unwrap_or_else(|| self.input_file.clone().with_extension(".plain"));
        let mut buffer =
            File::create(&output_file).with_context(|| "Fail to write the plain file")?;
        buffer
            .write_all(&plaintext)
            .with_context(|| "Fail to write the plain file")?;

        let stdout = format!("The decrypted file is available at {output_file:?}");
        let mut stdout = console::Stdout::new(&stdout);
        stdout.set_tags(self.tags.as_ref());
        stdout.write()?;

        Ok(())
    }
}
