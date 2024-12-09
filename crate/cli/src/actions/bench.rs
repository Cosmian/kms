use std::{
    io,
    io::Write,
    sync::{atomic::AtomicUsize, Arc, Mutex},
};

use clap::Parser;
use cosmian_kms_client::{
    kmip::{
        extra::BulkData,
        kmip_operations::{Decrypt, Encrypt},
        kmip_types::{
            BlockCipherMode, CryptographicAlgorithm, CryptographicParameters, UniqueIdentifier,
        },
    },
    KmsClient,
};
use num_format::{CustomFormat, Grouping, ToFormattedString};
use zeroize::Zeroizing;

use crate::{
    actions::{
        rsa::keys::{create_key_pair::CreateKeyPairAction, revoke_key::RevokeKeyAction},
        symmetric::keys::create_key::CreateKeyAction,
    },
    error::{
        result::{CliResult, CliResultHelper},
        CliError,
    },
};

struct EncryptionResult {
    batch_id: usize,
    ciphertext: Zeroizing<Vec<u8>>,
    encryption_time: u128,
}

struct FinalResult {
    batch_id: usize,
    encryption_time: u128,
    decryption_time: u128,
}

/// Run a set of benches to check the server performance.
///
/// This command will create one or more keys, encrypt and decrypt a set of data
/// then revoke the keys.
#[derive(Parser, Debug)]
pub struct BenchAction {
    /// The number of parallel threads to use
    #[clap(long = "number-of-threads", short = 't', default_value = "1")]
    num_threads: usize,

    /// The size of an encryption/decryption batch.
    /// A size of 1 does not use the `BulkData` API
    #[clap(
        long = "batch-size",
        short = 'b',
        default_value = "1",
        verbatim_doc_comment
    )]
    batch_size: usize,

    /// The number of batches to run
    #[clap(long = "num-batches", short = 'n', default_value = "1")]
    num_batches: usize,

    /// Use a wrapped key (by a 4096 RSA key) to encrypt the symmetric key
    #[clap(long = "wrapped-key", short = 'w', default_value = "false")]
    wrapped_key: bool,

    /// Display batch results details
    #[clap(long = "verbose", short = 'v', default_value = "false")]
    verbose: bool,
}

impl BenchAction {
    /// Run the tests
    #[allow(clippy::print_stdout)]
    pub async fn process(&self, kms_rest_client: Arc<KmsClient>) -> CliResult<()> {
        let version = kms_rest_client
            .version()
            .await
            .with_context(|| "Can't execute the version query on the kms server")?;
        println!("Server version: {version}");
        println!(
            "Running bench with {} threads, batch size {}, {} batches.",
            self.num_threads, self.batch_size, self.num_batches
        );
        if self.wrapped_key {
            println!("Algorithm: AES GCM using a 256 bit key wrapped by a 4096 bit RSA key");
        } else {
            println!("Algorithm: AES GCM using a 256 bit key");
        }
        let (key_id, wrapping_key) = self.create_keys(&kms_rest_client).await?;

        // u128 formatter
        let format = CustomFormat::builder()
            .grouping(Grouping::Standard)
            .separator(" ")
            .build()
            .unwrap();

        // the data to encrypt
        let data = if self.batch_size == 1 {
            Zeroizing::new(vec![1u8; 64])
        } else {
            BulkData::new(vec![Zeroizing::new(vec![1u8; 64]); self.batch_size]).serialize()?
        };

        // Encryption
        {
            let mut stdout = io::stdout().lock();
            write!(stdout, "Encrypting")?;
            stdout.flush()?;
        }
        let amortized_encryption_time = std::time::Instant::now();
        let counter = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..self.num_threads {
            let kms_rest_client = kms_rest_client.clone();
            let key_id = key_id.clone();
            let data = data.clone();
            let counter = counter.clone();
            let num_batches = self.num_batches;
            let handle = tokio::spawn(async move {
                encrypt(kms_rest_client, key_id, data, counter, num_batches).await
            });
            handles.push(handle);
        }

        let mut encryption_results = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(Ok(results)) => {
                    encryption_results.extend(results);
                }
                Ok(Err(e)) => return Err(e),
                Err(e) => return Err(CliError::Default(format!("Tokio Error: {e}"))),
            }
        }
        let total_encryption_time_amortized = amortized_encryption_time.elapsed().as_micros();
        {
            let mut stdout = io::stdout().lock();
            writeln!(
                stdout,
                ": {}µs",
                total_encryption_time_amortized.to_formatted_string(&format)
            )?;
        }

        // Decryption
        {
            let mut stdout = io::stdout().lock();
            write!(stdout, "Decrypting")?;
            stdout.flush()?;
        }
        let amortized_decryption_time = std::time::Instant::now();
        let ciphertexts_to_process = Arc::new(Mutex::new(encryption_results));
        let mut handles = Vec::new();
        for _ in 0..self.num_threads {
            let kms_rest_client = kms_rest_client.clone();
            let key_id = key_id.clone();
            let ciphertexts_to_process = ciphertexts_to_process.clone();
            let handle = tokio::spawn(async move {
                decrypt(kms_rest_client, key_id, ciphertexts_to_process).await
            });
            handles.push(handle);
        }

        let mut final_results = Vec::new();
        for handle in handles {
            match handle.await {
                Ok(Ok(results)) => {
                    final_results.extend(results);
                }
                Ok(Err(e)) => return Err(e),
                Err(e) => return Err(CliError::Default(format!("Tokio Error: {e}"))),
            }
        }
        let total_decryption_time_amortized = amortized_decryption_time.elapsed().as_micros();
        {
            let mut stdout = io::stdout().lock();
            writeln!(
                stdout,
                ": {}µs",
                total_decryption_time_amortized.to_formatted_string(&format)
            )?;
            stdout.flush()?;
        }
        // revoke the keys
        self.revoke_keys(&kms_rest_client, key_id, wrapping_key)
            .await?;

        // Parse results
        final_results.sort_by_key(|r| r.batch_id);
        let mut total_encryption_time = 0_u128;
        let mut total_decryption_time = 0_u128;
        if self.verbose {
            for result in final_results {
                total_encryption_time += result.encryption_time;
                total_decryption_time += result.decryption_time;
                if self.verbose {
                    println!(
                        "{}: encryption: {}µs ({}µs/v), decryption: {}µs ({}µs/v)",
                        result.batch_id,
                        result.encryption_time.to_formatted_string(&format),
                        result.encryption_time / (self.batch_size as u128),
                        result.decryption_time.to_formatted_string(&format),
                        result.decryption_time / (self.batch_size as u128)
                    );
                }
            }
        }

        println!(
            "Encryption time {}µs => {}µs/batch => {}µs/value",
            total_encryption_time.to_formatted_string(&format),
            (total_encryption_time / (self.num_batches as u128)).to_formatted_string(&format),
            total_encryption_time / (self.num_batches * self.batch_size) as u128
        );
        println!(
            "Decryption time {}µs => {}µs/batch => {}µs/value",
            total_decryption_time.to_formatted_string(&format),
            (total_decryption_time / self.num_batches as u128).to_formatted_string(&format),
            total_decryption_time / (self.num_batches * self.batch_size) as u128
        );
        println!(
            "Amortized encryption time ({} threads): {}µs => {}µs/batch => {}µs/value",
            self.num_threads,
            total_encryption_time_amortized.to_formatted_string(&format),
            (total_encryption_time_amortized / (self.num_batches as u128))
                .to_formatted_string(&format),
            total_encryption_time_amortized / (self.num_batches * self.batch_size) as u128
        );
        println!(
            "Amortized decryption time ({} threads): {}µs => {}µs/batch => {}µs/value",
            self.num_threads,
            total_decryption_time_amortized.to_formatted_string(&format),
            (total_decryption_time_amortized / (self.num_batches as u128))
                .to_formatted_string(&format),
            total_decryption_time_amortized / (self.num_batches * self.batch_size) as u128
        );

        Ok(())
    }

    async fn create_keys(
        &self,
        kms_rest_client: &KmsClient,
    ) -> CliResult<(
        UniqueIdentifier,
        Option<(UniqueIdentifier, UniqueIdentifier)>,
    )> {
        if self.wrapped_key {
            // create an RSA key pair
            let (sk, pk) = CreateKeyPairAction {
                tags: vec!["bench".to_owned()],
                ..Default::default()
            }
            .run(kms_rest_client)
            .await?;
            let kk = CreateKeyAction {
                number_of_bits: Some(256),
                wrapping_key_id: Some(pk.to_string()),
                tags: vec!["bench".to_owned()],
                ..Default::default()
            }
            .run(kms_rest_client)
            .await?;
            return Ok((kk, Some((sk, pk))));
        }
        let kk = CreateKeyAction {
            number_of_bits: Some(256),
            tags: vec!["bench".to_owned()],
            ..Default::default()
        }
        .run(kms_rest_client)
        .await?;
        Ok((kk, None))
    }

    async fn revoke_keys(
        &self,
        kms_rest_client: &KmsClient,
        symmetric_key: UniqueIdentifier,
        wrapping_key: Option<(UniqueIdentifier, UniqueIdentifier)>,
    ) -> CliResult<()> {
        RevokeKeyAction {
            revocation_reason: "Bench".to_owned(),
            key_id: Some(symmetric_key.to_string()),
            tags: None,
        }
        .run(kms_rest_client)
        .await?;
        if let Some((sk, _pk)) = wrapping_key {
            // revoking the private key will revoke the public key
            RevokeKeyAction {
                revocation_reason: "Bench".to_owned(),
                key_id: Some(sk.to_string()),
                tags: None,
            }
            .run(kms_rest_client)
            .await?;
        }
        Ok(())
    }
}

async fn encrypt(
    kms_rest_client: Arc<KmsClient>,
    key_id: UniqueIdentifier,
    data: Zeroizing<Vec<u8>>,
    counter: Arc<AtomicUsize>,
    num_batches: usize,
) -> CliResult<Vec<EncryptionResult>> {
    let mut results = Vec::new();
    loop {
        let next = counter.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        if next >= num_batches {
            break;
        }
        {
            let mut stdout = io::stdout().lock();
            write!(stdout, ".",)?;
            stdout.flush()?;
        }
        let encrypt = Encrypt {
            unique_identifier: Some(key_id.clone()),
            cryptographic_parameters: Some(CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                block_cipher_mode: Some(BlockCipherMode::GCM),
                ..Default::default()
            }),
            data: Some(data.clone()),
            ..Default::default()
        };
        let start = std::time::Instant::now();
        let response = kms_rest_client
            .encrypt(encrypt)
            .await
            .with_context(|| "failed encrypting")?;
        let elapsed = start.elapsed().as_micros();
        let ciphertext = Zeroizing::new(
            [
                response.iv_counter_nonce.unwrap_or_default(),
                response.data.unwrap_or_default(),
                response.authenticated_encryption_tag.unwrap_or_default(),
            ]
            .concat(),
        );
        results.push(EncryptionResult {
            batch_id: next,
            ciphertext,
            encryption_time: elapsed,
        });
    }
    Ok(results)
}

async fn decrypt(
    kms_rest_client: Arc<KmsClient>,
    key_id: UniqueIdentifier,
    encryptions: Arc<Mutex<Vec<EncryptionResult>>>,
) -> CliResult<Vec<FinalResult>> {
    let mut results = Vec::new();
    loop {
        let next = encryptions
            .lock()
            .expect("could not lock encryption results")
            .pop();
        let Some(next) = next else { break };
        {
            let mut stdout = io::stdout().lock();
            write!(stdout, ".",)?;
            stdout.flush()?;
        }
        let (iv, data, tag) = match BulkData::deserialize(next.ciphertext.as_ref()) {
            Ok(_data) => (None, Some(next.ciphertext.as_slice()), None),
            Err(_e) => {
                // Single AES GCM query => split the data
                let iv_len = 12;
                let tag_len = 16;
                let iv = &next.ciphertext[..iv_len];
                let tag = &next.ciphertext[next.ciphertext.len() - tag_len..];
                let data = &next.ciphertext[iv_len..next.ciphertext.len() - tag_len];
                (Some(iv), Some(data), Some(tag))
            }
        };
        let decrypt = Decrypt {
            unique_identifier: Some(key_id.clone()),
            cryptographic_parameters: Some(CryptographicParameters {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                block_cipher_mode: Some(BlockCipherMode::GCM),
                ..Default::default()
            }),
            iv_counter_nonce: iv.map(Vec::from),
            data: data.map(Vec::from),
            authenticated_encryption_tag: tag.map(Vec::from),
            ..Default::default()
        };
        let start = std::time::Instant::now();
        let _response = kms_rest_client
            .decrypt(decrypt)
            .await
            .with_context(|| "failed encrypting")?;
        let elapsed = start.elapsed().as_micros();
        results.push(FinalResult {
            batch_id: next.batch_id,
            encryption_time: next.encryption_time,
            decryption_time: elapsed,
        });
    }
    Ok(results)
}
