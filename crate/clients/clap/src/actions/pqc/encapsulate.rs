use std::{fs::File, io::Write, path::PathBuf};

use clap::Parser;
use cosmian_crypto_core::bytes_ser_de::Serializable;
use cosmian_kms_client::{KmsClient, kmip_2_1::requests::encrypt_request};

use crate::{
    actions::{console, labels::KEY_ID, shared::get_key_uid},
    error::{
        KmsCliError,
        result::{KmsCliResult, KmsCliResultHelper},
    },
};

/// Encapsulate using a PQC public key (ML-KEM-512/768/1024, X25519MLKEM768,
/// X448MLKEM1024).
///
/// Produces a shared secret and a ciphertext (encapsulation).
/// The shared secret is written to `<output>.key` and the ciphertext to `<output>`.
#[derive(Parser, Debug)]
pub struct EncapsulateAction {
    /// The public key unique identifier.
    #[clap(long = KEY_ID, short = 'k', group = "key-tags")]
    pub(crate) key_id: Option<String>,

    /// Tag to use to retrieve the key when no key id is specified.
    #[clap(long = "tag", short = 't', value_name = "TAG", group = "key-tags")]
    pub(crate) tags: Option<Vec<String>>,

    /// The output file path for the encapsulation (ciphertext)
    #[clap(required = false, long, short = 'o')]
    pub(crate) output_file: Option<PathBuf>,
}

impl EncapsulateAction {
    pub async fn run(&self, kms_rest_client: KmsClient) -> KmsCliResult<()> {
        let request = encrypt_request(
            &get_key_uid(self.key_id.as_ref(), self.tags.as_ref(), KEY_ID)?,
            None,
            Vec::new(),
            None,
            None,
            None,
        )?;

        let response = kms_rest_client
            .encrypt(request)
            .await
            .with_context(|| "KEM encapsulation failed")?;

        let (shared_secret, ciphertext) = if let Some(ciphertext) = response.i_v_counter_nonce {
            // Standard PQC KEM: shared_secret in data, ciphertext in iv_counter_nonce
            let shared_secret = response.data.context("shared secret is empty")?;
            (shared_secret, ciphertext)
        } else {
            // ConfigurableKEM: both packed as a serialized tuple in data
            let data = response.data.context("encrypted data is empty")?;
            let (session_key, encapsulation) =
                <(zeroize::Zeroizing<Vec<u8>>, zeroize::Zeroizing<Vec<u8>>)>::deserialize(&data)
                    .map_err(|e| {
                        KmsCliError::Conversion(format!(
                            "failed deserializing KEM encapsulation from response data: {e}"
                        ))
                    })?;
            (session_key.to_vec(), encapsulation.to_vec())
        };

        let output_file = self
            .output_file
            .clone()
            .unwrap_or_else(|| PathBuf::from("output.enc"));

        let mut buffer =
            File::create(&output_file).with_context(|| "failed to write the encapsulation file")?;
        buffer
            .write_all(&ciphertext)
            .with_context(|| "failed to write the encapsulation file")?;

        let session_key_file = output_file.with_extension("key");
        let mut key_buffer = File::create(&session_key_file)
            .with_context(|| "failed to write the shared secret file")?;
        key_buffer
            .write_all(&shared_secret)
            .with_context(|| "failed to write the shared secret file")?;

        let stdout = format!(
            "The encapsulation is available at {}\nThe shared secret is available at {}",
            output_file.display(),
            session_key_file.display()
        );
        let mut stdout = console::Stdout::new(&stdout);
        stdout.set_tags(self.tags.as_ref());
        stdout.write()?;

        Ok(())
    }
}
