use std::{
    collections::HashMap,
    fmt,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, RwLock,
    },
    time::SystemTime,
};

use cosmian_kmip::crypto::{secret::Secret, symmetric::symmetric_ciphers::AES_256_GCM_KEY_LENGTH};
use sqlx::{Pool, Sqlite};
use tracing::{debug, info, trace};

use crate::{db_bail, db_error, error::DbError, DbResult};

macro_rules! mac {
    ($res: expr, $key:expr, $($bytes: expr),+) => {
        {
            let mut hasher = tiny_keccak::Sha3::v256();
            <tiny_keccak::Sha3 as tiny_keccak::Hasher>::update(&mut hasher, $key);
            $(
                <tiny_keccak::Sha3 as tiny_keccak::Hasher>::update(&mut hasher, $bytes);
            )*
            <tiny_keccak::Sha3 as tiny_keccak::Hasher>::finalize(hasher, $res);
        }
    };
}

/// The item of the KMS sqlite cache
pub(crate) struct KMSSqliteCacheItem {
    /// The handler to the sqlite
    sqlite: Arc<Pool<Sqlite>>,
    /// The MAC of the inserted item computed using the DB secret key
    mac: Vec<u8>,
    /// The date of the first insertion
    #[allow(dead_code)]
    inserted_at: u64,
    /// The number of instances of the sqlite currently running
    in_used: u32,
    /// The date of last used
    last_used_at: u64,
    /// Whether the sqlite is closed
    closed: bool,
    /// The date of the last sqlite close
    closed_at: u64,
    /// The index of the item inside the freeable cache
    freeable_cache_index: usize,
}

impl fmt::Debug for KMSSqliteCacheItem {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KMSSqliteCacheItem")
            .field("MAC", &self.mac)
            .field("inserted_at", &self.inserted_at)
            .field("in_used", &self.in_used)
            .field("last_used_at", &self.last_used_at)
            .field("closed", &self.closed)
            .field("closed_at", &self.closed_at)
            .field("freeable_cache_index", &self.freeable_cache_index)
            .finish_non_exhaustive()
    }
}

/// Give the time since EPOCH in secs
pub(crate) fn _now() -> DbResult<u64> {
    Ok(SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map_err(|e| {
            DbError::DatabaseError(format!("Unable to get duration since epoch. Error: {e:?}"))
        })?
        .as_secs())
}

impl KMSSqliteCacheItem {
    pub(crate) fn new(
        sqlite: Pool<Sqlite>,
        mac: Vec<u8>,
        freeable_cache_index: usize,
    ) -> DbResult<Self> {
        Ok(Self {
            sqlite: Arc::new(sqlite),
            mac,
            inserted_at: _now()?,
            in_used: 0,
            last_used_at: 0,
            closed: false,
            closed_at: 0,
            freeable_cache_index,
        })
    }
}

/// The KMS Sqlite cache contains all handlers to the opened and closed Sqlite
///
/// The structure is designed to keep opened in memory a given max number of Sqlite handlers
/// However:
/// - An item is never removed from the cache. The handler is just closed
/// - The cache will never refuse a new Sqlite handler insertion. It will flush the unused handler if adding a new one
///   makes the cache exceed its max size but if all handlers are currently in used, it will accept the insertion. The
///   clean up will occur during the next insertion.
/// - The cache always removes the oldest unused items first. To do so, the cache contains a `FreeableSqliteCache` structure which is a linked list. The first item is the oldest, the last one the freshest. A new item is always pushed back and an old item is always popped front. An item already in the list and now reused will be removed and pushed back to the end of the linked list.
/// - An handler is considered as used after each `get` and won't be closed until it is not explicitly `release`-ed by the caller. Several `get` are allowed. The `release` will take effect when the last one got is explicitly `release`-ed.
///
/// The cache saves already decrypted sqlite handler. To verify that a user can `get` the handler, the key is checked at each access.
pub(crate) struct KMSSqliteCache {
    /// The item of the cache
    sqlites: RwLock<HashMap<u128, KMSSqliteCacheItem>>,
    /// The list of unused sqlite that could be closed if needed
    freeable_sqlites: RwLock<FreeableSqliteCache>,
    /// The number of opened sqlite allowed
    max_size: usize,
    /// The number of currently opened sqlite
    current_size: AtomicUsize,
}

impl KMSSqliteCache {
    #[must_use]
    pub(crate) fn new(size: usize) -> Self {
        Self {
            sqlites: RwLock::new(HashMap::with_capacity(size)),
            freeable_sqlites: RwLock::new(FreeableSqliteCache::new(size)),
            max_size: size,
            current_size: AtomicUsize::new(0),
        }
    }

    /// Test if a sqlite connection is opened for a given id
    pub(crate) fn opened(&self, id: u128) -> DbResult<bool> {
        let sqlites = self.sqlites.read().map_err(|e| {
            DbError::DatabaseError(format!("Unable to lock for read. Error: {e:?}"))
        })?;
        if !sqlites.contains_key(&id) {
            return Ok(false);
        }

        Ok(!sqlites[&id].closed)
    }

    /// Test if a sqlite connection exist in the cache
    pub(crate) fn exists(&self, id: u128) -> DbResult<bool> {
        Ok(self
            .sqlites
            .read()
            .map_err(|e| DbError::DatabaseError(format!("Unable to lock for read. Error: {e:?}")))?
            .contains_key(&id))
    }

    /// Get the sqlite handler and tag it as "used"
    ///
    /// The function will return an error if the database is closed or the key is not the right one
    pub(crate) fn get(
        &self,
        id: u128,
        key: &Secret<AES_256_GCM_KEY_LENGTH>,
    ) -> DbResult<Arc<Pool<Sqlite>>> {
        let mut sqlites = self.sqlites.write().map_err(|e| {
            DbError::DatabaseError(format!("Unable to lock for write. Error: {e:?}"))
        })?;

        let item = sqlites
            .get_mut(&id)
            .ok_or_else(|| db_error!("Key is not in the cache"))?;

        if item.closed {
            db_bail!("Database is closed");
        }

        // We need to check if the key provided by the user is the same that was used to open the database
        // If we do not, we can just send any password: the database is already opened anyway.
        // Do this by checking the macs
        let mut mac = vec![0_u8; 32];
        mac!(mac.as_mut_slice(), key, id.to_be_bytes().as_slice());
        if mac != item.mac {
            db_bail!("Database secret is wrong");
        }

        // Now, we can't close this connection until it is used.
        if item.in_used == 0 {
            self.freeable_sqlites
                .write()
                .map_err(|e| {
                    DbError::DatabaseError(format!("Unable to lock for write. Error: {e:?}"))
                })?
                .uncache(item.freeable_cache_index)?;
        }

        item.in_used += 1;
        item.last_used_at = _now()?;

        Ok(Arc::clone(&item.sqlite))
    }

    /// Say the cache that the sqlite handler is not used at the current moment
    /// The cache will let it opened until it needs that slot
    ///
    /// The function will return an error if the database is not in the cache or already released
    pub(crate) fn release(&self, id: u128) -> DbResult<()> {
        let mut sqlites = self.sqlites.write().map_err(|e| {
            DbError::DatabaseError(format!("Unable to lock for write. Error: {e:?}"))
        })?;

        let item = sqlites
            .get_mut(&id)
            .ok_or_else(|| db_error!("Key is not in the cache"))?;

        if item.in_used == 0 {
            db_bail!("Can't release twice a cache item");
        }

        item.in_used -= 1;

        // Now, we can close this connection if we need it.
        if item.in_used == 0 {
            self.freeable_sqlites
                .write()
                .map_err(|e| {
                    DbError::DatabaseError(format!("Unable to lock for write. Error: {e:?}"))
                })?
                .recache(item.freeable_cache_index)?;
        }

        Ok(())
    }

    /// Remove oldest sqlite handlers until reaching down the max cache size allowed
    async fn flush(&self) -> DbResult<()> {
        trace!(
            "CachedSQLCipher: cache size = {}",
            self.current_size.load(Ordering::Relaxed)
        );

        while self.max_size <= self.current_size.load(Ordering::Relaxed) {
            let id = self
                .freeable_sqlites
                .write()
                .map_err(|e| {
                    DbError::DatabaseError(format!("Unable to lock for write. Error: {e:?}"))
                })?
                .pop();

            let Ok(id) = id else { break }; // nothing in the cache, just leave

            let sq = {
                let mut sqlites = self.sqlites.write().map_err(|e| {
                    DbError::DatabaseError(format!("Unable to lock for write. Error: {e:?}"))
                })?;

                let item = sqlites
                    .get_mut(&id)
                    .ok_or_else(|| db_error!("Key is not in the cache"))?;

                item.closed = true;
                item.closed_at = _now()?;

                info!("CachedSQLCipher: freeing = {item:?}");

                Arc::clone(&item.sqlite)
            };
            // We are forced to design the code like that. We can't make an async call on a lock value
            sq.close().await;

            self.current_size.fetch_sub(1, Ordering::Relaxed);
        }

        debug!(
            "CachedSQLCipher: cache size after flush = {}",
            self.current_size.load(Ordering::Relaxed)
        );

        Ok(())
    }

    /// Save a sqlite handler inside the cache for further use
    /// The handler is considered as used until it is explicitly release.
    ///
    /// This function will call a `flush` if needed to close the oldest unused databases.
    pub(crate) async fn save(
        &self,
        id: u128,
        key: &Secret<AES_256_GCM_KEY_LENGTH>,
        pool: Pool<Sqlite>,
    ) -> DbResult<()> {
        // Flush the cache if necessary
        self.flush().await?;
        // If nothing has been flush, allow to exceed max cache size

        let mut sqlites = self.sqlites.write().map_err(|e| {
            DbError::DatabaseError(format!("Unable to lock for write. Error: {e:?}"))
        })?;

        let mut freeable_sqlites = self.freeable_sqlites.write().map_err(|e| {
            DbError::DatabaseError(format!("Unable to lock for write. Error: {e:?}"))
        })?;

        let item = sqlites.get_mut(&id);
        if let Some(item) = item {
            if !item.closed {
                // Sqlite is already saved and opened
                return Ok(())
            }

            trace!("CachedSQLCipher: reopen group_id={id}");

            item.sqlite = Arc::new(pool);
            item.closed = false;
            item.in_used = 1;
            item.last_used_at = _now()?;
        } else {
            trace!("CachedSQLCipher: new group_id={id}");

            // Book a slot for it
            let freeable_cache_id = freeable_sqlites.push(id);

            // Add it to the SqliteCache
            // compute the mac
            let mut mac = vec![0_u8; 32];
            mac!(mac.as_mut_slice(), key, id.to_be_bytes().as_slice());
            let mut item = KMSSqliteCacheItem::new(pool, mac, freeable_cache_id)?;

            freeable_sqlites.uncache(freeable_cache_id)?;

            // Make it usable (to avoid direct free after alloc in case of cache overflow)
            item.in_used = 1;
            item.last_used_at = _now()?;

            sqlites.insert(id, item);
        };

        self.current_size.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }
}

#[derive(Eq, PartialEq, Debug, Clone)]
pub(crate) enum FSCNeighborEntry {
    /// Start/End of chain
    Nil,
    //// The index of the previous/next item
    Chained(usize),
}

pub(crate) struct FSCEntry {
    /// The value to store
    val: u128,
    /// The previous item
    prev: FSCNeighborEntry,
    /// The next item
    next: FSCNeighborEntry,
    /// The item is a member of the chain
    chained: bool,
}

impl FSCEntry {
    /// Create an entry as a last item of a chain
    pub(crate) const fn last(value: u128, last_index: usize) -> Self {
        Self {
            val: value,
            prev: FSCNeighborEntry::Chained(last_index),
            next: FSCNeighborEntry::Nil,
            chained: true,
        }
    }

    /// Create an entry as the first item of a new chain
    pub(crate) const fn singleton(value: u128) -> Self {
        Self {
            val: value,
            prev: FSCNeighborEntry::Nil,
            next: FSCNeighborEntry::Nil,
            chained: true,
        }
    }
}

/// The cache contained chained items. The first item of the chain is the next one to free.
pub(crate) struct FreeableSqliteCache {
    /// The entries of the cache (order by insertion)
    entries: Vec<FSCEntry>,
    /// The first item of the chain (next one to free)
    head: usize,
    /// The last item of the chain (last one to free)
    tail: usize,
    /// Number of items contained in the chain
    length: usize,
    /// Number of entries (part of the chain)
    size: usize,
}

impl FreeableSqliteCache {
    pub(crate) fn new(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
            head: 0,
            tail: 0,
            length: 0,
            size: 0,
        }
    }

    // Add an element at the end of the cache
    pub(crate) fn push(&mut self, value: u128) -> usize {
        if self.length == 0 {
            self.head = self.size;
            self.entries.push(FSCEntry::singleton(value));
        } else {
            self.entries.push(FSCEntry::last(value, self.tail));
            self.entries[self.tail].next = FSCNeighborEntry::Chained(self.size);
        }
        self.tail = self.size;
        self.size += 1;
        self.length += 1;

        self.tail
    }

    // Remove the first element from the cache and return its value
    pub(crate) fn pop(&mut self) -> DbResult<u128> {
        if self.length == 0 {
            db_bail!("Cache is empty")
        }

        let prev_head = self.head;
        self.length -= 1;

        match self.entries[self.head].next {
            FSCNeighborEntry::Nil => {
                self.head = 0; // Whatever
            }
            FSCNeighborEntry::Chained(next) => {
                self.entries[next].prev = FSCNeighborEntry::Nil;
                self.head = next;
            }
        }

        self.entries[prev_head].chained = false;

        Ok(self.entries[prev_head].val)
    }

    // Remove the given index from the cache
    pub(crate) fn uncache(&mut self, index: usize) -> DbResult<()> {
        if index >= self.size {
            db_bail!("Index is too large")
        }

        if !self.entries[index].chained {
            db_bail!("Index has already been uncached")
        }

        match (
            self.entries[index].prev.clone(),
            self.entries[index].next.clone(),
        ) {
            (FSCNeighborEntry::Nil, FSCNeighborEntry::Nil) => {}
            (FSCNeighborEntry::Nil, FSCNeighborEntry::Chained(next)) => {
                self.entries[next].prev = FSCNeighborEntry::Nil;
                self.head = next;
            }
            (FSCNeighborEntry::Chained(prev), FSCNeighborEntry::Nil) => {
                self.entries[prev].next = FSCNeighborEntry::Nil;
                self.tail = prev;
            }
            (FSCNeighborEntry::Chained(prev), FSCNeighborEntry::Chained(next)) => {
                self.entries[prev].next = FSCNeighborEntry::Chained(next);
                self.entries[next].prev = FSCNeighborEntry::Chained(prev);
            }
        };

        self.entries[index].chained = false;
        self.length -= 1;

        Ok(())
    }

    // Recache the index at the last position of the cache
    pub(crate) fn recache(&mut self, index: usize) -> DbResult<()> {
        if index >= self.size {
            db_bail!("Index is too large")
        }

        if self.entries[index].chained {
            db_bail!("Index is already cached")
        }

        self.entries[index].chained = true;
        self.entries[index].next = FSCNeighborEntry::Nil;

        if self.length == 0 {
            self.entries[index].prev = FSCNeighborEntry::Nil;
            self.head = index;
        } else {
            self.entries[self.tail].next = FSCNeighborEntry::Chained(index);
            self.entries[index].prev = FSCNeighborEntry::Chained(self.tail);
        }

        self.length += 1;
        self.tail = index;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::expect_used)]
    use std::{str::FromStr, sync::atomic::Ordering, time::Duration};

    use cosmian_kmip::crypto::{
        secret::Secret, symmetric::symmetric_ciphers::AES_256_GCM_KEY_LENGTH,
    };
    use sqlx::{
        sqlite::{SqliteConnectOptions, SqlitePoolOptions},
        ConnectOptions,
    };

    use super::{FSCNeighborEntry, FreeableSqliteCache, KMSSqliteCache};

    #[test]
    pub(crate) fn test_fsc_new() {
        let fsc = FreeableSqliteCache::new(10);
        assert_eq!(fsc.head, 0);
        assert_eq!(fsc.tail, 0);
        assert_eq!(fsc.length, 0);
        assert_eq!(fsc.size, 0);
    }

    #[test]
    pub(crate) fn test_fsc_push() {
        let mut fsc = FreeableSqliteCache::new(10);
        assert_eq!(fsc.push(1), 0);
        assert_eq!(fsc.push(2), 1);
        assert_eq!(fsc.push(3), 2);

        assert_eq!(fsc.head, 0);
        assert_eq!(fsc.tail, 2);
        assert_eq!(fsc.length, 3);
        assert_eq!(fsc.size, 3);
        assert!(fsc.entries[0].chained);
        assert!(fsc.entries[1].chained);
        assert!(fsc.entries[2].chained);
        assert_eq!(fsc.entries[0].val, 1);
        assert_eq!(fsc.entries[1].val, 2);
        assert_eq!(fsc.entries[2].val, 3);
        assert_eq!(fsc.entries[0].next, FSCNeighborEntry::Chained(1));
        assert_eq!(fsc.entries[0].prev, FSCNeighborEntry::Nil);
        assert_eq!(fsc.entries[1].next, FSCNeighborEntry::Chained(2));
        assert_eq!(fsc.entries[1].prev, FSCNeighborEntry::Chained(0));
        assert_eq!(fsc.entries[2].next, FSCNeighborEntry::Nil);
        assert_eq!(fsc.entries[2].prev, FSCNeighborEntry::Chained(1));
    }

    #[test]
    pub(crate) fn test_fsc_pop() {
        let mut fsc = FreeableSqliteCache::new(10);
        assert_eq!(fsc.push(1), 0);
        assert_eq!(fsc.push(2), 1);
        assert_eq!(fsc.push(3), 2);

        assert_eq!(fsc.pop().unwrap(), 1);

        assert_eq!(fsc.head, 1);
        assert_eq!(fsc.tail, 2);
        assert_eq!(fsc.length, 2);
        assert_eq!(fsc.size, 3);

        assert!(!fsc.entries[0].chained);

        assert_eq!(fsc.entries[1].next, FSCNeighborEntry::Chained(2));
        assert_eq!(fsc.entries[1].prev, FSCNeighborEntry::Nil);

        assert_eq!(fsc.push(4), 3);

        assert_eq!(fsc.head, 1);
        assert_eq!(fsc.tail, 3);
        assert_eq!(fsc.length, 3);
        assert_eq!(fsc.size, 4);

        assert_eq!(fsc.entries[2].next, FSCNeighborEntry::Chained(3));
        assert_eq!(fsc.entries[2].prev, FSCNeighborEntry::Chained(1));
        assert_eq!(fsc.entries[3].next, FSCNeighborEntry::Nil);
        assert_eq!(fsc.entries[3].prev, FSCNeighborEntry::Chained(2));

        assert_eq!(fsc.pop().unwrap(), 2);
        assert_eq!(fsc.pop().unwrap(), 3);
        assert_eq!(fsc.pop().unwrap(), 4);

        assert_eq!(fsc.length, 0);
        assert_eq!(fsc.size, 4);

        fsc.pop().unwrap_err();

        assert_eq!(fsc.push(5), 4);

        assert_eq!(fsc.head, 4);
        assert_eq!(fsc.tail, 4);
        assert_eq!(fsc.length, 1);
        assert_eq!(fsc.size, 5);

        assert_eq!(fsc.entries[4].next, FSCNeighborEntry::Nil);
        assert_eq!(fsc.entries[4].prev, FSCNeighborEntry::Nil);

        assert_eq!(fsc.pop().unwrap(), 5);
    }

    #[test]
    pub(crate) fn test_fsc_uncache() {
        let mut fsc = FreeableSqliteCache::new(10);
        assert_eq!(fsc.push(1), 0);
        assert_eq!(fsc.push(2), 1);
        assert_eq!(fsc.push(3), 2);
        assert_eq!(fsc.push(4), 3);

        assert!(fsc.uncache(4).is_err());

        fsc.uncache(2).unwrap();

        assert_eq!(fsc.head, 0);
        assert_eq!(fsc.tail, 3);
        assert_eq!(fsc.length, 3);
        assert_eq!(fsc.size, 4);

        assert!(!fsc.entries[2].chained);
        assert_eq!(fsc.entries[1].next, FSCNeighborEntry::Chained(3));
        assert_eq!(fsc.entries[1].prev, FSCNeighborEntry::Chained(0));
        assert_eq!(fsc.entries[3].next, FSCNeighborEntry::Nil);
        assert_eq!(fsc.entries[3].prev, FSCNeighborEntry::Chained(1));

        fsc.uncache(0).unwrap();

        assert_eq!(fsc.head, 1);
        assert_eq!(fsc.tail, 3);
        assert_eq!(fsc.length, 2);
        assert_eq!(fsc.size, 4);

        assert!(!fsc.entries[0].chained);
        assert_eq!(fsc.entries[1].next, FSCNeighborEntry::Chained(3));
        assert_eq!(fsc.entries[1].prev, FSCNeighborEntry::Nil);

        fsc.uncache(3).unwrap();

        assert_eq!(fsc.head, 1);
        assert_eq!(fsc.tail, 1);
        assert_eq!(fsc.length, 1);
        assert_eq!(fsc.size, 4);

        assert!(!fsc.entries[3].chained);
        assert_eq!(fsc.entries[1].next, FSCNeighborEntry::Nil);
        assert_eq!(fsc.entries[1].prev, FSCNeighborEntry::Nil);

        fsc.uncache(1).unwrap();

        assert_eq!(fsc.length, 0);
        assert_eq!(fsc.size, 4);

        assert!(!fsc.entries[1].chained);

        assert!(fsc.uncache(1).is_err());
        fsc.pop().unwrap_err();

        assert_eq!(fsc.push(5), 4);
        assert_eq!(fsc.head, 4);
        assert_eq!(fsc.tail, 4);
        assert_eq!(fsc.length, 1);
        assert_eq!(fsc.size, 5);

        assert!(fsc.entries[4].chained);
        assert_eq!(fsc.entries[4].next, FSCNeighborEntry::Nil);
        assert_eq!(fsc.entries[4].prev, FSCNeighborEntry::Nil);
    }

    #[test]
    pub(crate) fn test_fsc_recache() {
        let mut fsc = FreeableSqliteCache::new(10);
        assert_eq!(fsc.push(1), 0);
        assert_eq!(fsc.push(2), 1);
        assert_eq!(fsc.push(3), 2);
        assert_eq!(fsc.push(4), 3);

        assert!(fsc.recache(4).is_err());
        assert!(fsc.recache(3).is_err());

        fsc.uncache(2).unwrap();

        assert_eq!(fsc.head, 0);
        assert_eq!(fsc.tail, 3);
        assert_eq!(fsc.length, 3);
        assert_eq!(fsc.size, 4);

        assert!(!fsc.entries[2].chained);
        assert_eq!(fsc.entries[1].next, FSCNeighborEntry::Chained(3));
        assert_eq!(fsc.entries[1].prev, FSCNeighborEntry::Chained(0));
        assert_eq!(fsc.entries[3].next, FSCNeighborEntry::Nil);
        assert_eq!(fsc.entries[3].prev, FSCNeighborEntry::Chained(1));

        fsc.recache(2).unwrap();
        assert!(fsc.recache(2).is_err());

        assert_eq!(fsc.head, 0);
        assert_eq!(fsc.tail, 2);
        assert_eq!(fsc.length, 4);
        assert_eq!(fsc.size, 4);

        assert!(fsc.entries[2].chained);
        assert_eq!(fsc.entries[2].next, FSCNeighborEntry::Nil);
        assert_eq!(fsc.entries[2].prev, FSCNeighborEntry::Chained(3));
        assert_eq!(fsc.entries[3].next, FSCNeighborEntry::Chained(2));
        assert_eq!(fsc.entries[3].prev, FSCNeighborEntry::Chained(1));

        fsc.uncache(0).unwrap();
        fsc.uncache(1).unwrap();
        fsc.uncache(2).unwrap();
        fsc.uncache(3).unwrap();
        fsc.recache(3).unwrap();

        assert_eq!(fsc.head, 3);
        assert_eq!(fsc.tail, 3);
        assert_eq!(fsc.length, 1);
        assert_eq!(fsc.size, 4);

        assert!(fsc.entries[3].chained);
        assert_eq!(fsc.entries[3].next, FSCNeighborEntry::Nil);
        assert_eq!(fsc.entries[3].prev, FSCNeighborEntry::Nil);
    }

    #[tokio::test]
    pub async fn test_sqlite_cache() {
        let cache = KMSSqliteCache::new(2);

        assert_eq!(cache.max_size, 2);
        assert_eq!(cache.current_size.load(Ordering::Relaxed), 0);

        let password = Secret::<AES_256_GCM_KEY_LENGTH>::new_random().unwrap();

        let sqlite = connect().await.expect("Can't create database");
        let sqlite2 = connect().await.expect("Can't create database");
        let sqlite3 = connect().await.expect("Can't create database");

        cache.save(1, &password, sqlite).await.unwrap();
        assert_eq!(cache.current_size.load(Ordering::Relaxed), 1);
        cache.save(2, &password, sqlite2).await.unwrap();
        assert_eq!(cache.current_size.load(Ordering::Relaxed), 2); // flush should do nothing here
        assert!(cache.opened(1).unwrap());
        assert!(cache.opened(2).unwrap());

        assert!(cache.exists(1).unwrap());

        let sqlite2 = connect().await.expect("Can't create database");
        cache.save(2, &password, sqlite2).await.unwrap(); // double saved = ok

        cache.release(2).unwrap();
        assert!(cache.release(2).is_err()); // not twice

        assert!(cache.exists(2).unwrap());
        assert!(cache.opened(2).unwrap()); // still opened

        assert!(!cache.exists(3).unwrap());
        cache.save(3, &password, sqlite3).await.unwrap();
        assert_eq!(cache.current_size.load(Ordering::Relaxed), 2); // flush should do nothing here
        assert!(cache.opened(3).unwrap()); // still opened
        assert!(!cache.opened(2).unwrap()); // not opened anymore
        assert!(cache.exists(2).unwrap());

        let sqlite2 = connect().await.expect("Can't create database");
        cache.save(2, &password, sqlite2).await.unwrap();
        assert_eq!(cache.current_size.load(Ordering::Relaxed), 3); // flush should do nothing here
        assert!(cache.opened(2).unwrap());

        cache.get(4, &password).unwrap_err();
        cache
            .get(1, &Secret::<AES_256_GCM_KEY_LENGTH>::new_random().unwrap())
            .unwrap_err(); // bad &password
        cache.get(1, &password).unwrap(); // 2 uses of sqlite1

        let sqlite4 = connect().await.expect("Can't create database");
        cache.save(4, &password, sqlite4).await.unwrap();
        assert_eq!(cache.current_size.load(Ordering::Relaxed), 4); // flush should do nothing here
        assert!(cache.opened(1).unwrap());

        cache.release(1).unwrap(); // 1 uses of sqlite1

        let sqlite5 = connect().await.expect("Can't create database");
        cache.save(5, &password, sqlite5).await.unwrap();
        assert_eq!(cache.current_size.load(Ordering::Relaxed), 5); // flush should do nothing here
        assert!(cache.opened(1).unwrap());

        cache.release(1).unwrap(); // 0 uses of sqlite1
        assert!(cache.opened(1).unwrap());

        let sqlite6 = connect().await.expect("Can't create database");
        cache.save(6, &password, sqlite6).await.unwrap();
        assert_eq!(cache.current_size.load(Ordering::Relaxed), 5); // flush should do something here
        assert!(!cache.opened(1).unwrap());
        assert!(cache.exists(1).unwrap());

        cache.get(1, &password).unwrap_err(); // get after close
    }

    async fn connect() -> std::result::Result<sqlx::Pool<sqlx::Sqlite>, sqlx::Error> {
        let options = SqliteConnectOptions::from_str("sqlite::memory:")?
            .pragma("journal_mode", "OFF")
            .busy_timeout(Duration::from_secs(120))
            .create_if_missing(true)
            // disable logging of each query
            .disable_statement_logging();

        SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
    }
}
