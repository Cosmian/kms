use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use cosmian_findex::{
    parameters::{
        BLOCK_LENGTH, CHAIN_TABLE_WIDTH, KMAC_KEY_LENGTH, KWI_LENGTH, MASTER_KEY_LENGTH, UID_LENGTH,
    },
    EncryptedMultiTable, EncryptedTable, FetchChains, FindexCallbacks, FindexCompact, FindexSearch,
    FindexUpsert, IndexedValue, KeyingMaterial, Keyword, Label, Location, Uid, Uids, UpsertData,
};
use redis::{aio::ConnectionManager, pipe, AsyncCommands, Script};
use tokio::sync::RwLock;
use tracing::trace;

use crate::{error::FindexError, RemovedLocationsFinder};

#[derive(Copy, Clone)]
enum FindexTable {
    Entry,
    Chain,
}

/// Generate a key for the entry table or chain table
fn key(table: FindexTable, uid: &[u8]) -> Vec<u8> {
    let mut key = match table {
        FindexTable::Entry => b"fe::".to_vec(),
        FindexTable::Chain => b"fc::".to_vec(),
    };
    key.extend_from_slice(uid);
    key
}

pub struct FindexRedis {
    // we keep redis_url for the updateLines method
    mgr: ConnectionManager,
    upsert_script: Script,
    removed_locations_finder: Arc<dyn RemovedLocationsFinder + Sync + Send>,
    compact_lock: RwLock<()>,
}

impl FindexRedis {
    /// The conditional upsert script used to
    /// only update a table if the previous value matches ARGV[2].
    /// When the value does not match, the previous value is returned
    const CONDITIONAL_UPSERT_SCRIPT: &str = r#"
        local value=redis.call('GET',ARGV[1])
        if((value==false) or (not(value == false) and (ARGV[2] == value))) then 
            redis.call('SET', ARGV[1], ARGV[3])
            return  
        else 
            return value 
        end;
    "#;

    /// Connect to a Redis server
    ///
    /// # Arguments
    ///  * `redis_url` - The Redis URL e.g. "redis://user:password@localhost:6379"
    pub async fn connect(
        redis_url: &str,
        removed_locations_finder: Arc<dyn RemovedLocationsFinder + Sync + Send>,
    ) -> Result<Self, FindexError> {
        let client = redis::Client::open(redis_url)?;
        let mgr = ConnectionManager::new(client).await?;

        Ok(FindexRedis {
            mgr,
            upsert_script: Script::new(Self::CONDITIONAL_UPSERT_SCRIPT),
            removed_locations_finder,
            compact_lock: RwLock::new(()),
        })
    }

    /// Connect to a Redis server with a ConnectionManager
    ///
    /// # Arguments
    ///  * `redis_url` - The Redis URL e.g. "redis://user:password@localhost:6379"
    pub async fn connect_with_manager(
        mgr: ConnectionManager,
        removed_locations_finder: Arc<dyn RemovedLocationsFinder + Sync + Send>,
    ) -> Result<Self, FindexError> {
        Ok(FindexRedis {
            mgr,
            upsert_script: Script::new(Self::CONDITIONAL_UPSERT_SCRIPT),
            removed_locations_finder,
            compact_lock: RwLock::new(()),
        })
    }

    /// Clear all indexes
    ///
    /// # Warning
    /// This is definitive
    pub async fn clear_indexes(&self) -> Result<(), FindexError> {
        redis::cmd("FLUSHDB")
            .query_async(&mut self.mgr.clone())
            .await?;
        Ok(())
    }

    /// Upsert the given chain elements in Findex tables.
    ///
    /// # Parameters
    ///
    /// - `master_key`  : Findex master key
    /// - `label`       : additional public information used in key hashing
    /// - `additions`   : values to indexed for a set of keywords
    /// - `deletions`   : values to remove from the indexes for a set of
    ///   keywords
    pub async fn upsert(
        &mut self,
        master_key: &[u8; 16],
        label: &[u8],
        additions: HashMap<IndexedValue, HashSet<Keyword>>,
        deletions: HashMap<IndexedValue, HashSet<Keyword>>,
    ) -> Result<(), FindexError> {
        FindexUpsert::upsert(
            self,
            &KeyingMaterial::<MASTER_KEY_LENGTH>::from(*master_key),
            &Label::from(label),
            additions,
            deletions,
        )
        .await?;
        Ok(())
    }

    /// Searches for the `Location`s indexed by the given `Keyword`s. This is
    /// the entry point of the Findex search.
    ///
    /// # Parameters
    ///
    /// - `master_key`          : Findex master key
    /// - `label`               : public label
    /// - `keywords`            : keywords to search
    /// - `max_depth`           : maximum recursion depth allowed
    pub async fn search(
        &mut self,
        master_key: &[u8; 16],
        label: &[u8],
        keywords: HashSet<Keyword>,
    ) -> Result<HashMap<Keyword, HashSet<Location>>, FindexError> {
        let res = FindexSearch::search(
            self,
            &KeyingMaterial::<MASTER_KEY_LENGTH>::from(*master_key),
            &Label::from(label),
            keywords,
        )
        .await?;
        Ok(res)
    }

    /// Replaces all the Index Entry Table UIDs and values. New UIDs are derived
    /// using the given label and the KMAC key derived from the new master key.
    /// The values are decrypted using the DEM key derived from the master key
    /// and re-encrypted using the DEM key derived from the new master key.
    ///
    /// Randomly selects index entries and recompact their associated chains.
    /// Chains indexing no existing location are removed. Others are recomputed
    /// from a new keying material. This removes unneeded paddings. New UIDs are
    /// derived for the chain and values are re-encrypted using a DEM key
    /// derived from the new keying material.
    ///
    /// - `master_key`                      : master key used to generate the
    ///   current index
    /// - `new_master_key`                  : master key used to generate the
    ///   new index
    /// - `label`                           : label used to generate the new
    ///   index
    /// - `num_reindexing_before_full_set`  : average number of calls to compact
    ///   needed to recompute all of the Chain Table.
    ///
    /// **WARNING**: the compact operation *cannot* be done concurrently with
    /// upsert operations. This could result in corrupted indexes.
    pub async fn compact(
        &mut self,
        master_key: &[u8; 16],
        new_master_key: &[u8; 16],
        label: &[u8],
        num_reindexing_before_full_set: u32,
    ) -> Result<(), FindexError> {
        FindexCompact::compact(
            self,
            &KeyingMaterial::<MASTER_KEY_LENGTH>::from(*master_key),
            &KeyingMaterial::<MASTER_KEY_LENGTH>::from(*new_master_key),
            &Label::from(label),
            num_reindexing_before_full_set,
        )
        .await?;
        Ok(())
    }
}

impl FindexCallbacks<FindexError, UID_LENGTH> for FindexRedis {
    async fn progress(
        &self,
        _results: &HashMap<Keyword, HashSet<IndexedValue>>,
    ) -> Result<bool, FindexError> {
        //TODO: allow passing callback fn on connect
        Ok(true)
    }

    async fn fetch_all_entry_table_uids(&self) -> Result<Uids<UID_LENGTH>, FindexError> {
        let keys: Vec<Vec<u8>> = self.mgr.clone().keys(key(FindexTable::Entry, b"*")).await?;
        trace!("fetch_all_entry_table_uids num keywords: {}", keys.len());
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

    async fn fetch_entry_table(
        &self,
        entry_table_uids: Uids<UID_LENGTH>,
    ) -> Result<EncryptedMultiTable<UID_LENGTH>, FindexError> {
        trace!(
            "fetch_entry_table num keywords: {}:",
            entry_table_uids.0.len(),
        );
        // guard against empty uids
        if entry_table_uids.0.is_empty() {
            return Ok(EncryptedMultiTable::default())
        }

        // build Redis keys
        let keys: Vec<Vec<u8>> = entry_table_uids
            .0
            .iter()
            .map(|uid| key(FindexTable::Entry, uid))
            .collect();

        // mget the values from the Redis keys
        let values: Vec<Vec<u8>> = self.mgr.clone().mget(keys).await?;

        // discard empty values
        let tuples = entry_table_uids
            .0
            .into_iter()
            .zip(values)
            .filter(|(_uid, v)| !v.is_empty())
            .collect::<Vec<_>>();
        trace!("fetch_entry_table non empty tuples len: {}", tuples.len(),);

        Ok(EncryptedMultiTable(tuples))
    }

    async fn fetch_chain_table(
        &self,
        chain_table_uids: Uids<UID_LENGTH>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexError> {
        trace!(
            "fetch_chain_table num entries: {}:",
            chain_table_uids.0.len(),
        );

        //guard against empty uids
        if chain_table_uids.0.is_empty() {
            return Ok(EncryptedTable::default())
        }

        let keys: Vec<Vec<u8>> = chain_table_uids
            .0
            .iter()
            .map(|uid| key(FindexTable::Chain, uid))
            .collect();
        let values: Vec<Vec<u8>> = self.mgr.clone().mget(keys).await?;

        Ok(EncryptedTable::from(
            chain_table_uids
                .0
                .into_iter()
                .zip(values)
                .filter(|(_uid, v)| !v.is_empty())
                .collect::<HashMap<Uid<UID_LENGTH>, Vec<u8>>>(),
        ))
    }

    async fn upsert_entry_table(
        &mut self,
        modifications: UpsertData<UID_LENGTH>,
    ) -> Result<EncryptedTable<UID_LENGTH>, FindexError> {
        // Prevent upserting while compacting
        if self.compact_lock.try_read().is_err() {
            return Err(FindexError::Compacting)
        }

        trace!("upsert_entry_table num keywords {:?}", modifications.len());

        let mut rejected = EncryptedTable::default();
        for (uid, (old_value, new_value)) in modifications {
            let value: Vec<u8> = self
                .upsert_script
                .arg(key(FindexTable::Entry, &uid))
                .arg(old_value.unwrap_or_default())
                .arg(new_value)
                .invoke_async(&mut self.mgr.clone())
                .await?;
            if !value.is_empty() {
                rejected.insert(uid, value);
            }
        }
        trace!("upsert_entry_table rejected: {}", rejected.len());
        Ok(rejected)
    }

    async fn insert_chain_table(
        &mut self,
        items: EncryptedTable<UID_LENGTH>,
    ) -> Result<(), FindexError> {
        let mut pipe = pipe();
        for item in items {
            pipe.set(key(FindexTable::Chain, &item.0), item.1);
        }
        pipe.atomic().query_async(&mut self.mgr.clone()).await?;
        Ok(())
    }

    async fn update_lines(
        &mut self,
        chain_table_uids_to_remove: Uids<UID_LENGTH>,
        new_encrypted_entry_table_items: EncryptedTable<UID_LENGTH>,
        new_encrypted_chain_table_items: EncryptedTable<UID_LENGTH>,
    ) -> Result<(), FindexError> {
        // Prevent compacting while already compacting
        // We could add support to make sure we are not upserting
        if self.compact_lock.try_read().is_err() {
            return Err(FindexError::Compacting)
        }
        let _compact_lock = self.compact_lock.write().await;

        trace!(
            "update_lines chain_table_uids_to_remove: {}, new_encrypted_entry_table_items: {}, \
             new_encrypted_chain_table_items: {}",
            chain_table_uids_to_remove.len(),
            new_encrypted_entry_table_items.len(),
            new_encrypted_chain_table_items.len()
        );
        // delete the entry table
        let entry_keys: Vec<Vec<u8>> = self.mgr.clone().keys(key(FindexTable::Entry, b"*")).await?;
        let mut pipeline = pipe();
        for entry_key in entry_keys {
            pipeline.del(entry_key);
        }
        pipeline.atomic().query_async(&mut self.mgr.clone()).await?;

        // add new entry table entries
        let mut pipeline = pipe();
        for item in new_encrypted_entry_table_items {
            pipeline.set(key(FindexTable::Entry, &item.0), item.1);
        }
        pipeline.atomic().query_async(&mut self.mgr.clone()).await?;

        // delete the chain table
        let mut pipeline = pipe();
        for item in chain_table_uids_to_remove {
            pipeline.del(key(FindexTable::Chain, &item));
        }
        pipeline.atomic().query_async(&mut self.mgr.clone()).await?;

        // add new chain table entries
        let mut pipeline = pipe();
        for item in new_encrypted_chain_table_items {
            pipeline.set(key(FindexTable::Chain, &item.0), item.1);
        }
        pipeline.atomic().query_async(&mut self.mgr.clone()).await?;

        Ok(())
    }

    async fn list_removed_locations(
        &self,
        locations: HashSet<Location>,
    ) -> Result<HashSet<Location>, FindexError> {
        self.removed_locations_finder
            .find_removed_locations(locations)
            .await
    }

    #[cfg(feature = "live_compact")]
    fn filter_removed_locations(
        &self,
        locations: HashSet<Location>,
    ) -> Result<HashSet<Location>, FindexError> {
        unimplemented!("this method will be removed in a future release")
    }

    #[cfg(feature = "live_compact")]
    async fn delete_chain(&mut self, uids: Uids<UID_LENGTH>) -> Result<(), FindexError> {
        unimplemented!("this method will be removed in a future release")
    }
}

impl FetchChains<UID_LENGTH, BLOCK_LENGTH, CHAIN_TABLE_WIDTH, KWI_LENGTH, FindexError>
    for FindexRedis
{
}

impl
    FindexUpsert<
        UID_LENGTH,
        BLOCK_LENGTH,
        CHAIN_TABLE_WIDTH,
        MASTER_KEY_LENGTH,
        KWI_LENGTH,
        KMAC_KEY_LENGTH,
        FindexError,
    > for FindexRedis
{
}

impl
    FindexSearch<
        UID_LENGTH,
        BLOCK_LENGTH,
        CHAIN_TABLE_WIDTH,
        MASTER_KEY_LENGTH,
        KWI_LENGTH,
        KMAC_KEY_LENGTH,
        FindexError,
    > for FindexRedis
{
}

impl
    FindexCompact<
        UID_LENGTH,
        BLOCK_LENGTH,
        CHAIN_TABLE_WIDTH,
        MASTER_KEY_LENGTH,
        KWI_LENGTH,
        KMAC_KEY_LENGTH,
        FindexError,
    > for FindexRedis
{
}
