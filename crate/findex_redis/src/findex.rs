use std::{
    collections::{HashMap, HashSet},
    fmt::Display,
    sync::Mutex,
};

use cloudproof::reexport::crypto_core::{reexport::rand_core::SeedableRng, CsRng};
use cosmian_findex::{
    impl_findex_trait,
    parameters::{BLOCK_LENGTH, CHAIN_TABLE_WIDTH, KWI_LENGTH, UID_LENGTH},
    EncryptedMultiTable, EncryptedTable, FetchChains, FindexCallbacks, FindexCompact, FindexSearch,
    FindexUpsert, IndexedValue, Keyword, Location, Uid, Uids, UpsertData,
};
use redis::{aio::ConnectionManager, transaction, AsyncCommands, Commands, Connection, Script};

use crate::error::FindexError;
// use rand::Rng;
#[cfg(feature = "live_compact")]
use crate::{
    compact_live::FindexLiveCompact,
    parameters::{BLOCK_LENGTH, CHAIN_TABLE_WIDTH, KMAC_KEY_LENGTH, KWI_LENGTH, MASTER_KEY_LENGTH},
};

#[derive(Copy, Clone)]
enum FindexTable {
    EntryTable,
    ChainTable,
}

/// Generate a key for the entry table or chain table
fn key(table: FindexTable, uid: &[u8]) -> Vec<u8> {
    let mut key = match table {
        FindexTable::EntryTable => b"fe::".to_vec(),
        FindexTable::ChainTable => b"fc::".to_vec(),
    };
    key.extend_from_slice(uid);
    key
}

pub struct FindexRedis<const UID_LENGTH: usize> {
    mgr: ConnectionManager,
    upsert_script: Script, // entry_table: EncryptedTable<UID_LENGTH>,
                           // chain_table: EncryptedTable<UID_LENGTH>,
                           // removed_locations: HashSet<Location>,
                           // pub check_progress_callback_next_keyword: bool,
                           // pub progress_callback_cancel: bool,
}

impl<const UID_LENGTH: usize> FindexRedis<UID_LENGTH> {
    /// The conditional upsert script used to
    /// only update a table if the previous value matches ARGV[2].
    /// When the value does not match, the previous value is returned
    const CONDITIONAL_UPSERT_SCRIPT: &str = r#"
        local value=redis.call('GET',ARGV[1])
        if((value==false) or (not(value == false) and (ARGV[2] == value))) then 
            redis.call('SET', ARGV[1], ARGV[3])
            return {} 
        else 
            return {value} 
        end;
    "#;

    /// Connect to a Redis server
    ///
    /// # Arguments
    ///  * `redis_url` - The Redis URL e.g. "redis://user:password@localhost:6379"
    pub async fn connect(redis_url: &str) -> Result<Self, FindexError> {
        //todo add username/password support
        let client = redis::Client::open(redis_url)?;
        let mgr = ConnectionManager::new(client).await?;

        Ok(FindexRedis {
            mgr,
            upsert_script: Script::new(Self::CONDITIONAL_UPSERT_SCRIPT),
        })
    }

    async fn get_all_keys(&self, table: FindexTable) -> Result<Uids<UID_LENGTH>, FindexError> {
        let keys: Vec<Vec<u8>> = self.mgr.clone().keys(key(table, b"*")).await?;
        Ok(Uids(
            keys.iter()
                .map(|v| {
                    let mut uid = [0u8; UID_LENGTH];
                    uid.copy_from_slice(&v[4..]);
                    Uid::from(uid)
                })
                .collect(),
        ))
    }

    async fn get_values(
        &self,
        table: FindexTable,
        uids: Uids<UID_LENGTH>,
    ) -> Result<EncryptedMultiTable<UID_LENGTH>, FindexError> {
        let keys: Vec<Vec<u8>> = uids.0.iter().map(|uid| key(table, uid)).collect();
        let values: Vec<Vec<u8>> = self.mgr.clone().mget(keys).await?;
        Ok(EncryptedMultiTable(
            uids.0.into_iter().zip(values).collect::<Vec<_>>(),
        ))
    }
}

impl<const UID_LENGTH: usize> FindexCallbacks<FindexError, UID_LENGTH> for FindexRedis<UID_LENGTH> {
    async fn progress(
        &self,
        _results: &HashMap<Keyword, HashSet<IndexedValue>>,
    ) -> Result<bool, FindexError> {
        //TODO: allow passing callback fn on connect
        Ok(true)
    }

    async fn fetch_all_entry_table_uids(&self) -> Result<Uids<UID_LENGTH>, FindexError> {
        self.get_all_keys(FindexTable::EntryTable).await
    }

    async fn fetch_entry_table(
        &self,
        entry_table_uids: Uids<UID_LENGTH>,
    ) -> Result<EncryptedMultiTable<UID_LENGTH>, FindexError> {
        let keys: Vec<Vec<u8>> = entry_table_uids
            .0
            .iter()
            .map(|uid| key(FindexTable::EntryTable, uid))
            .collect();
        let values: Vec<Vec<u8>> = self.mgr.clone().mget(keys).await?;
        Ok(EncryptedMultiTable(
            entry_table_uids
                .0
                .into_iter()
                .zip(values)
                .collect::<Vec<_>>(),
        ))
    }

    async fn fetch_chain_table(
        &self,
        chain_table_uids: Uids<UID_LENGTH>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexError> {
        let keys: Vec<Vec<u8>> = chain_table_uids
            .0
            .iter()
            .map(|uid| key(FindexTable::ChainTable, uid))
            .collect();
        let values: Vec<Vec<u8>> = self.mgr.clone().mget(keys).await?;

        Ok(EncryptedTable::from(
            chain_table_uids
                .0
                .into_iter()
                .zip(values)
                .collect::<HashMap<Uid<UID_LENGTH>, Vec<u8>>>(),
        ))
    }

    async fn upsert_entry_table(
        &mut self,
        modifications: UpsertData<UID_LENGTH>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexError> {
        let mut rejected = EncryptedTable::default();
        for (uid, (old_value, new_value)) in modifications {
            let value: Vec<u8> = self
                .upsert_script
                .arg(key(FindexTable::EntryTable, &uid))
                .arg(old_value.unwrap_or_default())
                .arg(new_value)
                .invoke_async(&mut self.mgr.clone())
                .await?;
            if !value.is_empty() {
                rejected.insert(uid, value);
            }
        }
        Ok(rejected)
    }

    async fn insert_chain_table(
        &mut self,
        items: EncryptedTable<UID_LENGTH>,
    ) -> Result<(), FindexError> {
        let keys: Vec<Vec<u8>> = items
            .keys()
            .map(|uid| key(FindexTable::ChainTable, uid))
            .collect();

        transaction(&mut self.mgr.clone(), &keys, func)?;

        for (uid, value) in items {
            if self.chain_table.contains_key(&uid) {
                return Err(FindexError(format!(
                    "Conflict in Chain Table for UID: {uid:?}"
                )))
            }
            self.chain_table.insert(uid, value);
        }
        Ok(())
    }

    fn update_lines(
        &mut self,
        chain_table_uids_to_remove: Uids<UID_LENGTH>,
        new_encrypted_entry_table_items: EncryptedTable<UID_LENGTH>,
        new_encrypted_chain_table_items: EncryptedTable<UID_LENGTH>,
    ) -> Result<(), FindexError> {
        self.entry_table = new_encrypted_entry_table_items;

        for new_encrypted_chain_table_item in new_encrypted_chain_table_items {
            self.chain_table.insert(
                new_encrypted_chain_table_item.0,
                new_encrypted_chain_table_item.1,
            );
        }

        for removed_chain_table_uid in chain_table_uids_to_remove {
            self.chain_table.remove(&removed_chain_table_uid);
        }

        Ok(())
    }

    fn list_removed_locations(
        &self,
        _: HashSet<Location>,
    ) -> Result<HashSet<Location>, FindexError> {
        Ok(self.removed_locations.iter().cloned().collect())
    }

    #[cfg(feature = "live_compact")]
    fn filter_removed_locations(
        &self,
        locations: HashSet<Location>,
    ) -> Result<HashSet<Location>, FindexError> {
        Ok(locations
            .into_iter()
            .filter(|location| !self.removed_locations.contains(location))
            .collect())
    }

    #[cfg(feature = "live_compact")]
    async fn delete_chain(&mut self, uids: Uids<UID_LENGTH>) -> Result<(), FindexError> {
        self.chain_table.retain(|uid, _| !uids.contains(uid));
        Ok(())
    }
}

impl FetchChains<UID_LENGTH, BLOCK_LENGTH, CHAIN_TABLE_WIDTH, KWI_LENGTH, FindexError>
    for FindexRedis<UID_LENGTH>
{
}

impl_findex_trait!(FindexSearch, FindexRedis<UID_LENGTH>, FindexError);

impl_findex_trait!(FindexUpsert, FindexRedis<UID_LENGTH>, FindexError);

impl_findex_trait!(FindexCompact, FindexRedis<UID_LENGTH>, FindexError);

#[cfg(feature = "live_compact")]
impl
    FindexLiveCompact<
        UID_LENGTH,
        BLOCK_LENGTH,
        CHAIN_TABLE_WIDTH,
        MASTER_KEY_LENGTH,
        KWI_LENGTH,
        KMAC_KEY_LENGTH,
        FindexError,
    > for FindexRedis<UID_LENGTH>
{
    const BATCH_SIZE: usize = 10;
    const NOISE_RATIO: f64 = 0.5;
}
