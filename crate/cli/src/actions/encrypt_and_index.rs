use std::{
    collections::{HashMap, HashSet},
    fs::File,
    path::PathBuf,
};

use clap::Parser;
use cosmian_findex_cli::{
    actions::findex::{FindexParameters, instantiate_findex},
    reexports::{
        cloudproof_findex::reexport::cosmian_findex::{
            Data, IndexedValue, IndexedValueToKeywordsMap, Keyword, Keywords,
        },
        cosmian_findex_client::FindexRestClient,
        cosmian_findex_structs::EncryptedEntries,
    },
};
use cosmian_kms_cli::{
    actions::symmetric::{DataEncryptionAlgorithm, EncryptAction, KeyEncryptionAlgorithm},
    reexport::cosmian_kms_client::KmsClient,
};
use tracing::trace;

use crate::{
    cli_bail,
    error::result::{CliResultHelper, CosmianResult},
};

/// Encrypt entries and index the corresponding database UUIDs with the Findex.
///
/// First the CSV file is read and encrypted on client-side with KEM-DEM crypto-system
/// KEM: Key Encapsulation Mechanism
/// DEM: Data Encapsulation Mechanism
#[derive(Parser, Debug)]
#[clap(verbatim_doc_comment)]
pub struct EncryptAndIndexAction {
    #[clap(flatten)]
    pub(crate) findex_parameters: FindexParameters,

    /// The path to the CSV file path containing the data to index
    #[clap(long)]
    pub(crate) csv_path: PathBuf,

    /// The key encryption key (KEK) unique identifier.
    /// If provided, all encryption is done client side. The KEK is first exported locally and is used in the KEM to encapsulates the ephemeral Data Encryption Key (DEK).
    /// This KEK has been created in KMS and provides the Key Encapsulation Mechanism (KEM) parameters such as algorithm and mode.
    /// KEM supported are:
    /// - RFC5649
    /// - AES-GCM
    /// - RSA PKCS#1 v1.5
    /// - RSA-OAEP
    /// - RSA-AES hybrid key wrapping
    /// - Salsa Sealed Box
    /// - ECIES
    ///
    /// If no key encryption key is specified, the data will be sent to the server
    /// and will be encrypted server side.
    #[clap(long = "kek-id", group = "kem", conflicts_with = "dem")]
    pub(crate) key_encryption_key_id: Option<String>,

    /// The data encryption key (DEK) unique identifier.
    /// The key has been created in KMS.
    /// DEM supported are:
    /// - RFC5649
    /// - AES-GCM
    #[clap(
        required = false,
        long = "dek-id",
        group = "dem",
        conflicts_with = "kem"
    )]
    pub(crate) data_encryption_key_id: Option<String>,

    /// The data encryption algorithm.
    /// If not specified, aes-gcm is used.
    #[clap(long, short = 'd', default_value = "AesGcm")]
    pub(crate) data_encryption_algorithm: DataEncryptionAlgorithm,

    /// Optional nonce/IV (or tweak for XTS) as a hex string.
    /// If not provided, a random value is generated.
    #[clap(required = false, long, short = 'n')]
    pub(crate) nonce: Option<String>,

    /// Optional additional authentication data as a hex string.
    /// This data needs to be provided back for decryption.
    /// This data is ignored with XTS.
    #[clap(required = false, long, short = 'a')]
    pub(crate) authentication_data: Option<String>,
}

impl EncryptAndIndexAction {
    pub(crate) async fn _kem_server_side_dem_client_side(
        &self,
        csv: PathBuf,
        kms_rest_client: &KmsClient,
        key_encryption_key_id: &str,
        key_encryption_algorithm: KeyEncryptionAlgorithm,
        nonce: Option<Vec<u8>>,
        authentication_data: Option<Vec<u8>>,
    ) -> CosmianResult<(EncryptedEntries, IndexedValueToKeywordsMap)> {
        let mut encrypted_entries = EncryptedEntries::new();
        let mut indexed_value_to_keywords = Vec::new();

        let encrypt_action = EncryptAction::default();
        // Generate an ephemeral key (DEK) and wrap it with the KEK.
        let (dek, encapsulation) = encrypt_action
            .server_side_kem_encapsulation(
                kms_rest_client,
                key_encryption_key_id,
                key_encryption_algorithm,
                self.data_encryption_algorithm,
            )
            .await?;

        let file = File::open(csv.clone())?;
        let mut rdr = csv::Reader::from_reader(file);
        for result in rdr.byte_records() {
            // The iterator yields Result<StringRecord, Error>, so we check the
            // error here.
            let record = result?;
            trace!("CSV line: {record:?}");
            let record_bytes = record.as_slice();
            let encrypted_record = encrypt_action.client_side_encrypt_with_buffer(
                &dek,
                &encapsulation,
                self.data_encryption_algorithm,
                nonce.clone(),
                record_bytes,
                authentication_data.clone(),
            )?;
            let new_uuid = uuid::Uuid::new_v4();
            encrypted_entries.insert(new_uuid, encrypted_record);

            let indexed_value = IndexedValue::Data(Data::from(new_uuid.as_bytes().to_vec()));
            let keywords = record.iter().map(Keyword::from).collect::<HashSet<_>>();
            trace!("my keywords: {}", Keywords::from(keywords.clone()));
            indexed_value_to_keywords.push((indexed_value, keywords));
        }
        let indexed_value_to_keywords_map = IndexedValueToKeywordsMap::from(
            indexed_value_to_keywords
                .iter()
                .cloned()
                .collect::<HashMap<IndexedValue<Keyword, Data>, HashSet<Keyword>>>(),
        );

        Ok((encrypted_entries, indexed_value_to_keywords_map))
    }

    pub(crate) async fn client_side_encrypt_entries(
        &self,
        csv: PathBuf,
        kms_rest_client: &KmsClient,
        key_encryption_key_id: &str,
        nonce: Option<Vec<u8>>,
        authentication_data: Option<Vec<u8>>,
    ) -> CosmianResult<(EncryptedEntries, IndexedValueToKeywordsMap)> {
        let mut encrypted_entries = EncryptedEntries::new();
        let mut indexed_value_to_keywords = Vec::new();

        let encrypt_action = EncryptAction::default();
        // Generate an ephemeral key (DEK) and wrap it with the KEK.
        let (dek, encapsulation) = encrypt_action
            .client_side_kem_encapsulation(
                kms_rest_client,
                key_encryption_key_id,
                self.data_encryption_algorithm,
            )
            .await?;

        let file = File::open(csv.clone())?;
        for result in csv::Reader::from_reader(file).byte_records() {
            // The iterator yields Result<StringRecord, Error>, so we check the
            // error here.
            let record = result?;
            trace!("CSV line: {record:?}");
            let record_bytes = record.as_slice();
            let encrypted_record = encrypt_action.client_side_encrypt_with_buffer(
                &dek,
                &encapsulation,
                self.data_encryption_algorithm,
                nonce.clone(),
                record_bytes,
                authentication_data.clone(),
            )?;
            let new_uuid = uuid::Uuid::new_v4();
            encrypted_entries.insert(new_uuid, encrypted_record);

            let indexed_value = IndexedValue::Data(Data::from(new_uuid.as_bytes().to_vec()));
            let keywords = record.iter().map(Keyword::from).collect::<HashSet<_>>();
            trace!("my keywords: {}", Keywords::from(keywords.clone()));
            indexed_value_to_keywords.push((indexed_value, keywords));
        }
        let indexed_value_to_keywords_map = IndexedValueToKeywordsMap::from(
            indexed_value_to_keywords
                .iter()
                .cloned()
                .collect::<HashMap<IndexedValue<Keyword, Data>, HashSet<Keyword>>>(),
        );

        Ok((encrypted_entries, indexed_value_to_keywords_map))
    }

    pub(crate) async fn server_side_encrypt_entries(
        &self,
        csv: PathBuf,
        kms_rest_client: &KmsClient,
        data_encryption_key_id: &str,
        nonce: Option<Vec<u8>>,
        authentication_data: Option<Vec<u8>>,
    ) -> CosmianResult<(EncryptedEntries, IndexedValueToKeywordsMap)> {
        let mut encrypted_entries = EncryptedEntries::new();
        let mut indexed_value_to_keywords = Vec::new();

        let encrypt_action = EncryptAction::default();

        let file = File::open(csv.clone())?;
        let mut rdr = csv::Reader::from_reader(file);
        for result in rdr.byte_records() {
            // The iterator yields Result<StringRecord, Error>, so we check the
            // error here.
            let record = result?;
            trace!("CSV line: {record:?}");
            let record_bytes = record.as_slice();
            let (nonce, data, tag) = encrypt_action
                .server_side_encrypt(
                    kms_rest_client,
                    data_encryption_key_id,
                    self.data_encryption_algorithm.into(),
                    nonce.clone(),
                    record_bytes.to_vec(),
                    authentication_data.clone(),
                )
                .await?;

            let mut encrypted_record = Vec::with_capacity(nonce.len() + data.len() + tag.len());
            encrypted_record.extend_from_slice(&nonce);
            encrypted_record.extend_from_slice(&data);
            encrypted_record.extend_from_slice(&tag);

            let new_uuid = uuid::Uuid::new_v4();
            encrypted_entries.insert(new_uuid, encrypted_record);

            let indexed_value = IndexedValue::Data(Data::from(new_uuid.as_bytes().to_vec()));
            let keywords = record.iter().map(Keyword::from).collect::<HashSet<_>>();
            trace!("my keywords: {}", Keywords::from(keywords.clone()));
            indexed_value_to_keywords.push((indexed_value, keywords));
        }
        let indexed_value_to_keywords_map = IndexedValueToKeywordsMap::from(
            indexed_value_to_keywords
                .iter()
                .cloned()
                .collect::<HashMap<IndexedValue<Keyword, Data>, HashSet<Keyword>>>(),
        );

        Ok((encrypted_entries, indexed_value_to_keywords_map))
    }

    /// Adds the data from the CSV file to the Findex index.
    ///
    /// # Errors
    ///
    /// This function will return an error if:
    /// - There is an error instantiating the Findex client.
    /// - There is an error retrieving the user key or label from the Findex
    ///   parameters.
    /// - There is an error converting the CSV file to a hashmap.
    /// - There is an error adding the data to the Findex index.
    /// - There is an error writing the result to the console.
    #[allow(clippy::future_not_send, clippy::print_stdout)]
    pub async fn run(
        &self,
        findex_rest_client: &FindexRestClient,
        kms_rest_client: &KmsClient,
    ) -> CosmianResult<()> {
        let nonce = self
            .nonce
            .as_deref()
            .map(hex::decode)
            .transpose()
            .with_context(|| "failed to decode the nonce")?;

        let authentication_data = self
            .authentication_data
            .as_deref()
            .map(hex::decode)
            .transpose()
            .with_context(|| "failed to decode the authentication data")?;

        let (encrypted_entries, indexed_value_to_keywords_map) = match (
            self.key_encryption_key_id.clone(),
            self.data_encryption_key_id.clone(),
        ) {
            (Some(key_encryption_key_id), None) => {
                self.client_side_encrypt_entries(
                    self.csv_path.clone(),
                    kms_rest_client,
                    &key_encryption_key_id,
                    nonce,
                    authentication_data,
                )
                .await?
            }
            (None, Some(data_encryption_key_id)) => {
                self.server_side_encrypt_entries(
                    self.csv_path.clone(),
                    kms_rest_client,
                    &data_encryption_key_id,
                    nonce,
                    authentication_data,
                )
                .await?
            }
            _ => {
                cli_bail!("Either a key encryption key or a data encryption key must be provided")
            }
        };

        findex_rest_client
            .add_entries(&self.findex_parameters.index_id, &encrypted_entries)
            .await?;

        let keywords = instantiate_findex(findex_rest_client, &self.findex_parameters.index_id)
            .await?
            .add(
                &self.findex_parameters.user_key()?,
                &self.findex_parameters.label(),
                indexed_value_to_keywords_map,
            )
            .await?;
        trace!("indexing done: keywords: {keywords}");

        let uuids = encrypted_entries.get_uuids();
        println!("Data behind those UUIDS were encrypted and indexed: {uuids}");

        Ok(())
    }
}
