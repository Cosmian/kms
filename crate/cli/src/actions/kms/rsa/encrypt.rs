use std::{fs::File, io::Write, path::PathBuf};

use clap::Parser;
use cosmian_kms_client::{
    KmsClient,
    kmip_2_1::requests::encrypt_request,
    read_bytes_from_file,
    reexport::cosmian_kms_client_utils::rsa_utils::{HashFn, RsaEncryptionAlgorithm},
};

use crate::{
    actions::kms::{console, labels::KEY_ID, shared::get_key_uid},
    error::result::{KmsCliResult, KmsCliResultHelper},
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
    pub(crate) input_file: PathBuf,

    /// The public key unique identifier.
    /// If not specified, tags should be specified
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    pub(crate) key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    pub(crate) tags: Option<Vec<String>>,

    /// The encryption algorithm
    #[clap(
        long = "encryption-algorithm",
        short = 'e',
        default_value = "ckm-rsa-pkcs-oaep"
    )]
    pub(crate) encryption_algorithm: RsaEncryptionAlgorithm,

    /// The hashing algorithm
    #[clap(long = "hashing-algorithm", short = 's', default_value = "sha256")]
    pub(crate) hash_fn: HashFn,

    /// The encrypted output file path
    #[clap(required = false, long, short = 'o')]
    pub(crate) output_file: Option<PathBuf>,
}

impl EncryptAction {
    /// Run the encryption action
    ///
    /// # Arguments
    ///
    /// * `kms_rest_client` - A reference to the KMS client used to perform encryption.
    ///
    /// # Results
    ///
    /// This function returns a `KmsCliResult<()>` indicating the success or failure of the encryption action.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * The input file cannot be read.
    /// * The key ID or tags are not specified.
    /// * The encryption request cannot be built.
    /// * The KMS server query fails.
    /// * The encrypted data is empty.
    /// * The encrypted file cannot be written.
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        // Read the file to encrypt
        let mut data = read_bytes_from_file(&self.input_file)
            .with_context(|| "Cannot read bytes from the file to encrypt")?;

        // Recover the unique identifier or set of tags
        let id = get_key_uid(self.key_id.as_ref(), self.tags.as_ref(), KEY_ID)?;

        // Create the kmip query
        let encrypt_request = encrypt_request(
            &id,
            None,
            data,
            None,
            None,
            Some(
                self.encryption_algorithm
                    .to_cryptographic_parameters(self.hash_fn),
            ),
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

        let stdout = format!(
            "The encrypted file is available at {}",
            output_file.display()
        );
        console::Stdout::new(&stdout).write()?;

        Ok(())
    }
}
