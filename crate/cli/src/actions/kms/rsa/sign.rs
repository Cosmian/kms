use std::{fs::File, io::Write, path::PathBuf};

use clap::{Parser, ValueEnum};
use cosmian_kmip::{
    kmip_0::kmip_types::PaddingMethod,
    kmip_2_1::{
        kmip_types::{CryptographicAlgorithm, CryptographicParameters},
        requests::sign_request,
    },
};
use cosmian_kms_client::{
    KmsClient, read_bytes_from_file, reexport::cosmian_kms_client_utils::rsa_utils::HashFn,
};
use serde::Deserialize;
use strum::EnumString;

use crate::{
    actions::kms::{console, labels::KEY_ID, shared::get_key_uid},
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Decrypt a file with the given private key using either
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
pub struct SignAction {
    /// The file to decrypt
    #[clap(required = true, name = "FILE")]
    pub(crate) input_file: PathBuf,

    /// The private key unique identifier
    /// If not specified, tags should be specified
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    pub(crate) key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    /// To specify multiple tags, use the option multiple times.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    pub(crate) tags: Option<Vec<String>>,

    /// The signature algorithm
    #[clap(
        long = "signature-algorithm",
        short = 's',
        default_value = "rsassa-pss"
    )]
    pub(crate) signature_algorithm: CDigitalSignatureAlgorithm,

    /// The encrypted output file path
    #[clap(required = false, long, short = 'o')]
    pub(crate) output_file: Option<PathBuf>,
}

impl SignAction {
    /// Runs the decryption process.
    ///
    /// This function performs the following steps:
    /// 1. Reads the file to decrypt.
    /// 2. Recovers the unique identifier or set of tags for the key.
    /// 3. Creates the KMIP decryption request.
    /// 4. Queries the KMS with the KMIP data and retrieves the plaintext.
    /// 5. Writes the decrypted file to the specified output path.
    ///
    /// # Arguments
    ///
    /// * `kms_rest_client` - A reference to the KMS client.
    ///
    /// # Returns
    ///
    /// * `KmsCliResult<()>` - The result of the decryption process.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// * The file to decrypt cannot be read.
    /// * Neither `--key-id` nor `--tag` is specified.
    /// * The KMIP decryption request cannot be created.
    /// * The KMS query fails.
    /// * The decrypted file cannot be written.
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        // Read the file to decrypt
        let data = read_bytes_from_file(&self.input_file)
            .with_context(|| "Cannot read bytes from the file to decrypt")?;

        // Recover the unique identifier or set of tags
        let id = get_key_uid(self.key_id.as_ref(), self.tags.as_ref(), KEY_ID)?;

        // Create the kmip query
        let sign_request = sign_request(
            &id,
            None,
            Some(data),
            Some(self.signature_algorithm.to_cryptographic_parameters()),
        );

        // Query the KMS with your kmip data and get the key pair ids
        let sign_response = kms_rest_client
            .sign(sign_request)
            .await
            .with_context(|| "Can't execute the query on the kms server")?;
        let plaintext = sign_response
            .signature_data
            .context("Decrypt with RSA: the plaintext is empty")?;

        // Write the decrypted file
        let output_file = self
            .output_file
            .clone()
            .unwrap_or_else(|| self.input_file.clone().with_extension("plain"));
        let mut buffer =
            File::create(&output_file).with_context(|| "Fail to write the plain file")?;
        buffer
            .write_all(&plaintext)
            .with_context(|| "Fail to write the plain file")?;

        let stdout = format!(
            "The decrypted file is available at {}",
            output_file.display()
        );
        let mut stdout = console::Stdout::new(&stdout);
        stdout.set_tags(self.tags.as_ref());
        stdout.write()?;

        Ok(())
    }
}

#[derive(ValueEnum, Debug, Clone, Copy, EnumString, Deserialize)]
pub enum CDigitalSignatureAlgorithm {
    RSASSAPSS,
}

impl CDigitalSignatureAlgorithm {
    #[must_use]
    pub fn to_cryptographic_parameters(self) -> CryptographicParameters {
        match self {
            Self::RSASSAPSS => CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::RSA),
                padding_method: Some(PaddingMethod::None),
                hashing_algorithm: Some(HashFn::Sha1.into()),
                ..Default::default()
            },
        }
    }

    #[must_use]
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::RSASSAPSS => "rsassa-pss",
        }
    }
}
