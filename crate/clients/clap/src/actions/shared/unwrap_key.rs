use std::path::PathBuf;

use base64::{Engine as _, engine::general_purpose};
use clap::Parser;
use cosmian_kms_client::{
    ExportObjectParams, KmsClient,
    cosmian_kmip::kmip_2_1::{kmip_objects::Object, kmip_types::CryptographicAlgorithm},
    export_object,
    kmip_2_1::{
        kmip_attributes::Attributes,
        kmip_operations::Destroy,
        kmip_types::UniqueIdentifier,
        requests::{create_symmetric_key_kmip_object, import_object_request},
    },
    read_object_from_json_ttlv_file, write_kmip_object_to_file,
};
use cosmian_kms_crypto::crypto::wrap::unwrap_key_block;
use cosmian_logger::trace;
use uuid::Uuid;

use crate::{
    actions::console,
    cli_bail,
    error::result::{KmsCliResult, KmsCliResultHelper},
};

/// Locally unwrap a secret data or key in KMIP JSON TTLV format.
///
/// The secret data or key can be unwrapped using either:
///  - a password derived into a symmetric key using Argon2
///  - symmetric key bytes in base64
///  - a key in the KMS (which will be exported first)
///  - a key in a KMIP JSON TTLV file
///
/// For the latter 2 cases, the key may be a symmetric key,
/// and RFC 5649 will be used, or a curve 25519 private key
/// and ECIES will be used.
#[derive(Parser, Default, Debug)]
#[clap(verbatim_doc_comment)]
pub struct UnwrapSecretDataOrKeyAction {
    /// The KMIP JSON TTLV input key file to unwrap
    #[clap(required = true)]
    pub(crate) key_file_in: PathBuf,

    /// The KMIP JSON output file. When not specified the input file is overwritten.
    #[clap(required = false)]
    pub(crate) key_file_out: Option<PathBuf>,

    /// A symmetric key as a base 64 string to unwrap the imported key.
    #[clap(
        long = "unwrap-key-b64",
        short = 'k',
        required = false,
        group = "unwrap"
    )]
    pub(crate) unwrap_key_b64: Option<String>,

    /// The id of an unwrapping key in the KMS that will be exported and used to unwrap the key.
    #[clap(
        long = "unwrap-key-id",
        short = 'i',
        required = false,
        group = "unwrap"
    )]
    pub(crate) unwrap_key_id: Option<String>,

    /// An unwrapping key in a KMIP JSON TTLV file used to unwrap the key.
    #[clap(
        long = "unwrap-key-file",
        short = 'f',
        required = false,
        group = "unwrap"
    )]
    pub(crate) unwrap_key_file: Option<PathBuf>,
}

impl UnwrapSecretDataOrKeyAction {
    /// Export a key from the KMS
    ///
    /// # Errors
    ///
    /// This function can return an error if:
    ///
    /// - The key file cannot be read.
    /// - The unwrap key fails to decode from base64.
    /// - The unwrapping key fails to be created.
    /// - The unwrapping key fails to unwrap the key.
    /// - The output file fails to be written.
    /// - The console output fails to be written.
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        // read the key file
        let mut object = read_object_from_json_ttlv_file(&self.key_file_in)?;

        // cache the object type
        let object_type = object.object_type();

        let vendor_id = kms_rest_client.config.vendor_id.as_str();
        // if the key must be unwrapped, prepare the unwrapping key
        let unwrapping_key = if let Some(b64) = &self.unwrap_key_b64 {
            trace!(
                "unwrap using a base64 encoded key (length: {} chars)",
                b64.len()
            );
            let key_bytes = general_purpose::STANDARD
                .decode(b64)
                .with_context(|| "failed decoding the unwrap key")?;
            create_symmetric_key_kmip_object(
                vendor_id,
                &key_bytes,
                &Attributes {
                    cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                    ..Default::default()
                },
            )?
        } else if let Some(key_id) = &self.unwrap_key_id {
            // When the unwrapping key is stored in an HSM (sensitive, non-exportable),
            // we cannot export it for local unwrapping. Instead, import the wrapped
            // object to the KMS server with key_wrap_type=NotWrapped so the server uses
            // its HSM crypto oracle for server-side unwrapping, then export the result
            // (issue #762).
            if key_id.contains("::") {
                trace!("unwrap using server-side HSM crypto oracle for key: {key_id}");
                return self
                    .unwrap_via_server(kms_rest_client, object, key_id)
                    .await;
            }
            trace!("unwrap using the KMS server with the unique identifier of the unwrapping key");
            export_object(&kms_rest_client, key_id, ExportObjectParams::default())
                .await?
                .1
        } else if let Some(key_file) = &self.unwrap_key_file {
            trace!("unwrap using a key file path");
            read_object_from_json_ttlv_file(key_file)?
        } else {
            cli_bail!("one of the unwrapping options must be specified");
        };

        unwrap_key_block(object.key_block_mut()?, &unwrapping_key)?;

        // set the output file path to the input file path if not specified
        let output_file = self
            .key_file_out
            .as_ref()
            .unwrap_or(&self.key_file_in)
            .clone();

        write_kmip_object_to_file(&object, &output_file)?;

        let stdout = format!(
            "The key of type {:?} in file {} was unwrapped in file: {}",
            object_type,
            self.key_file_in.display(),
            &output_file.display()
        );
        console::Stdout::new(&stdout).write()?;

        Ok(())
    }

    /// Unwrap a key stored in a local KMIP JSON TTLV file by delegating the
    /// cryptographic operation to the KMS server.  This path is used when the
    /// unwrapping key resides in an HSM and cannot be exported (sensitive).
    ///
    /// The wrapped object is temporarily imported into the KMS with
    /// `key_wrap_type = NotWrapped` so the server can decrypt it using its
    /// crypto oracle, then the plaintext key is exported back and written to
    /// the output file.  The temporary KMS object is deleted afterwards.
    async fn unwrap_via_server(
        &self,
        kms_rest_client: KmsClient,
        object: Object,
        _unwrap_key_id: &str,
    ) -> KmsCliResult<()> {
        let vendor_id = kms_rest_client.config.vendor_id.as_str();
        let tmp_id = Uuid::new_v4().to_string();

        // Import the wrapped object asking the server to unwrap it immediately.
        let import_request = import_object_request(
            vendor_id,
            Some(tmp_id.clone()),
            object,
            None,
            true, // unwrap = true → key_wrap_type = NotWrapped
            true, // replace_existing
            std::iter::empty::<String>(),
        )?;
        kms_rest_client.import(import_request).await.with_context(
            || "server-side unwrap: failed to import the wrapped key to the KMS server",
        )?;

        // Export the now-unwrapped object back.
        // Use `unwrap: true` to retrieve the plaintext: the server may have re-wrapped the
        // key for secure storage (when a server-level key_encryption_key is configured), and
        // the unwrapped cache is populated by wrap_and_cache.  Requesting NotWrapped on export
        // causes the server to serve the plaintext from the cache (issue #762).
        let (_, unwrapped_object, _) = export_object(
            &kms_rest_client,
            &tmp_id,
            ExportObjectParams {
                unwrap: true,
                ..ExportObjectParams::default()
            },
        )
        .await
        .with_context(|| "server-side unwrap: failed to export the unwrapped key")?;

        // Clean up the temporary key from the server.
        let destroy_request = Destroy {
            unique_identifier: Some(UniqueIdentifier::TextString(tmp_id.clone())),
            remove: true,
            cascade: true,
            expected_object_type: None,
        };
        kms_rest_client
            .destroy(destroy_request)
            .await
            .with_context(|| "server-side unwrap: failed to destroy temporary KMS key")?;

        let object_type = unwrapped_object.object_type();
        let output_file = self
            .key_file_out
            .as_ref()
            .unwrap_or(&self.key_file_in)
            .clone();
        write_kmip_object_to_file(&unwrapped_object, &output_file)?;

        let stdout = format!(
            "The key of type {:?} in file {} was unwrapped via the KMS server in file: {}",
            object_type,
            self.key_file_in.display(),
            &output_file.display()
        );
        console::Stdout::new(&stdout).write()?;
        Ok(())
    }
}
