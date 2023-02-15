use std::{
    collections::HashMap,
    fmt,
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc, RwLock,
    },
    time::SystemTime,
};

use sqlx::{Pool, Sqlite};
use tracing::info;

use crate::{kms_bail, kms_error, result::KResult};

/// The item of the KMS sqlite cache
pub struct KMSSqliteCacheItem {
    /// The handler to the sqlite
    sqlite: Arc<Pool<Sqlite>>,
    /// They key of the sqlite
    key: String,
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
            .field("group_ id", &self.key)
            .field("inserted_at", &self.inserted_at)
            .field("in_used", &self.in_used)
            .field("last_used_at", &self.last_used_at)
            .field("closed", &self.closed)
            .field("closed_at", &self.closed_at)
            .field("freeable_cache_index", &self.freeable_cache_index)
            .finish()
    }
}

/// Give the time sonce EPOCH in secs
pub fn _now() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .expect("Unable to get duration since epoch")
        .as_secs()
}

impl KMSSqliteCacheItem {
    #[must_use]
    pub fn new(sqlite: Pool<Sqlite>, key: String, freeable_cache_index: usize) -> Self {
        Self {
            sqlite: Arc::new(sqlite),
            key,
            inserted_at: _now(),
            in_used: 0,
            last_used_at: 0,
            closed: false,
            closed_at: 0,
            freeable_cache_index,
        }
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
pub struct KMSSqliteCache {
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
    pub fn new(size: usize) -> Self {
        Self {
            sqlites: RwLock::new(HashMap::with_capacity(size)),
            freeable_sqlites: RwLock::new(FreeableSqliteCache::new(size)),
            max_size: size,
            current_size: AtomicUsize::new(0),
        }
    }

    /// Test if a sqlite connection is opened for a given id
    pub fn opened(&self, id: u128) -> bool {
        let sqlites = self.sqlites.read().expect("Unable to lock for read");
        if !sqlites.contains_key(&id) {
            return false
        }

        !sqlites[&id].closed
    }

    /// Test if a sqlite connection exist in the cache
    pub fn exists(&self, id: u128) -> bool {
        self.sqlites
            .read()
            .expect("Unable to lock for read")
            .contains_key(&id)
    }

    /// Get the sqlite handler and tag it as "used"
    ///
    /// The function will return an error if the database is closed or the key is not the right one
    pub fn get(&self, id: u128, key: &str) -> KResult<Arc<Pool<Sqlite>>> {
        let mut sqlites = self.sqlites.write().expect("Unable to lock for write");

        let item = sqlites
            .get_mut(&id)
            .ok_or_else(|| kms_error!("Key is not in the cache"))?;

        if item.closed {
            kms_bail!("Database is closed");
        }

        // We need to check if the key provided by the user is the same that was used to open the database
        // If we do not, we can just send any password: the database is already opened anyway.
        if key != item.key {
            kms_bail!("Database secret is wrong");
        }

        // Now, we can't close this connection until it is used.
        if item.in_used == 0 {
            self.freeable_sqlites
                .write()
                .expect("Unable to lock for write")
                .uncache(item.freeable_cache_index)?;
        }

        item.in_used += 1;
        item.last_used_at = _now();

        Ok(Arc::clone(&item.sqlite))
    }

    /// Say the cache that the sqlite handler is not used at the current moment
    /// The cache will let it opened until it needs that slot
    ///
    /// The function will return an error if the database is not in the cache or already released
    pub fn release(&self, id: u128) -> KResult<()> {
        let mut sqlites = self.sqlites.write().expect("Unable to lock for write");

        let item = sqlites
            .get_mut(&id)
            .ok_or_else(|| kms_error!("Key is not in the cache"))?;

        if item.in_used == 0 {
            kms_bail!("Can't release twice a cache item");
        }

        item.in_used -= 1;

        // Now, we can close this connection if we need it.
        if item.in_used == 0 {
            self.freeable_sqlites
                .write()
                .expect("Unable to lock for write")
                .recache(item.freeable_cache_index)?;
        }

        Ok(())
    }

    /// Remove oldest sqlite handlers until reaching down the max cache size allowed
    async fn flush(&self) -> KResult<()> {
        info!(
            "CachedSQLCipher: cache size = {}",
            self.current_size.load(Ordering::Relaxed)
        );

        while self.max_size <= self.current_size.load(Ordering::Relaxed) {
            let id = self
                .freeable_sqlites
                .write()
                .expect("Unable to lock for write")
                .pop();

            let id = match id {
                Ok(id) => id,
                Err(_) => break, // nothing in the cache, just leave
            };

            let sq = {
                let mut sqlites = self.sqlites.write().expect("Unable to lock for write");

                let item = sqlites
                    .get_mut(&id)
                    .ok_or_else(|| kms_error!("Key is not in the cache"))?;

                item.closed = true;
                item.closed_at = _now();

                info!("CachedSQLCipher: freeing = {item:?}");

                Arc::clone(&item.sqlite)
            };
            // We are forced to design the code like that. We can't make an async call on a lock value
            sq.close().await;

            self.current_size.fetch_sub(1, Ordering::Relaxed);
        }

        info!(
            "CachedSQLCipher: cache size after flush = {}",
            self.current_size.load(Ordering::Relaxed)
        );

        Ok(())
    }

    /// Save a sqlite handler inside the cache for further use
    /// The handler is considered as used until it is explicitly release.
    ///
    /// This function will call a `flush` if needed to close the oldest unused databases.
    pub async fn save(&self, id: u128, key: &str, pool: Pool<Sqlite>) -> KResult<()> {
        // Flush the cache if necessary
        self.flush().await?;
        // If nothing has been flush, allow to exceed max cache size

        let mut sqlites = self.sqlites.write().expect("Unable to lock for write");

        let mut freeable_sqlites = self
            .freeable_sqlites
            .write()
            .expect("Unable to lock for write");

        let item = sqlites.get_mut(&id);
        match item {
            // Deal with the case: the id is already known but the sqlite was closed
            Some(item) => {
                if !item.closed {
                    // Sqlite is already saved and opened
                    return Ok(())
                }

                info!("CachedSQLCipher: reopen group_id={id}");

                item.sqlite = Arc::new(pool);
                item.closed = false;
                item.in_used = 1;
                item.last_used_at = _now();
            }
            None => {
                info!("CachedSQLCipher: new group_id={id}");

                // Book a slot for it
                let freeable_cache_id = freeable_sqlites.push(id)?;

                // Add it to the SqliteCache
                let mut item = KMSSqliteCacheItem::new(pool, key.to_string(), freeable_cache_id);

                freeable_sqlites.uncache(freeable_cache_id)?;

                // Make it usable (to avoid direct free after alloc in case of cache overflow)
                item.in_used = 1;
                item.last_used_at = _now();

                sqlites.insert(id, item);
            }
        };

        self.current_size.fetch_add(1, Ordering::Relaxed);

        Ok(())
    }
}

#[derive(Eq, PartialEq, Debug, Clone)]
pub enum FSCNeighborEntry {
    /// Start/End of chain
    Nil,
    //// The index of the previous/next item
    Chained(usize),
}

pub struct FSCEntry {
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
    pub fn last(value: u128, last_index: usize) -> Self {
        Self {
            val: value,
            prev: FSCNeighborEntry::Chained(last_index),
            next: FSCNeighborEntry::Nil,
            chained: true,
        }
    }

    /// Create an entry as the first item of a new chain
    pub fn singleton(value: u128) -> Self {
        Self {
            val: value,
            prev: FSCNeighborEntry::Nil,
            next: FSCNeighborEntry::Nil,
            chained: true,
        }
    }
}

/// The cache contained chained items. The first item of the chain is the next one to free.
pub struct FreeableSqliteCache {
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
    pub fn new(capacity: usize) -> Self {
        Self {
            entries: Vec::with_capacity(capacity),
            head: 0,
            tail: 0,
            length: 0,
            size: 0,
        }
    }

    // Add an element at the end of the cache
    pub fn push(&mut self, value: u128) -> KResult<usize> {
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

        Ok(self.tail)
    }

    // Remove the first element from the cache and return its value
    pub fn pop(&mut self) -> KResult<u128> {
        if self.length == 0 {
            kms_bail!("Cache is empty")
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
    pub fn uncache(&mut self, index: usize) -> KResult<()> {
        if index >= self.size {
            kms_bail!("Index is too large")
        }

        if !self.entries[index].chained {
            kms_bail!("Index has already been uncached")
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
    pub fn recache(&mut self, index: usize) -> KResult<()> {
        if index >= self.size {
            kms_bail!("Index is too large")
        }

        if self.entries[index].chained {
            kms_bail!("Index is already cached")
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
    use std::{str::FromStr, sync::atomic::Ordering, time::Duration};

    use sqlx::{
        sqlite::{SqliteConnectOptions, SqlitePoolOptions},
        ConnectOptions,
    };

    use super::{FSCNeighborEntry, FreeableSqliteCache, KMSSqliteCache};

    #[test]
    pub fn test_fsc_new() {
        let fsc = FreeableSqliteCache::new(10);
        assert_eq!(fsc.head, 0);
        assert_eq!(fsc.tail, 0);
        assert_eq!(fsc.length, 0);
        assert_eq!(fsc.size, 0);
    }

    #[test]
    pub fn test_fsc_push() {
        let mut fsc = FreeableSqliteCache::new(10);
        assert_eq!(fsc.push(1), Ok(0));
        assert_eq!(fsc.push(2), Ok(1));
        assert_eq!(fsc.push(3), Ok(2));

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
    pub fn test_fsc_pop() {
        let mut fsc = FreeableSqliteCache::new(10);
        assert_eq!(fsc.push(1), Ok(0));
        assert_eq!(fsc.push(2), Ok(1));
        assert_eq!(fsc.push(3), Ok(2));

        assert_eq!(fsc.pop(), Ok(1));

        assert_eq!(fsc.head, 1);
        assert_eq!(fsc.tail, 2);
        assert_eq!(fsc.length, 2);
        assert_eq!(fsc.size, 3);

        assert!(!fsc.entries[0].chained);

        assert_eq!(fsc.entries[1].next, FSCNeighborEntry::Chained(2));
        assert_eq!(fsc.entries[1].prev, FSCNeighborEntry::Nil);

        assert_eq!(fsc.push(4), Ok(3));

        assert_eq!(fsc.head, 1);
        assert_eq!(fsc.tail, 3);
        assert_eq!(fsc.length, 3);
        assert_eq!(fsc.size, 4);

        assert_eq!(fsc.entries[2].next, FSCNeighborEntry::Chained(3));
        assert_eq!(fsc.entries[2].prev, FSCNeighborEntry::Chained(1));
        assert_eq!(fsc.entries[3].next, FSCNeighborEntry::Nil);
        assert_eq!(fsc.entries[3].prev, FSCNeighborEntry::Chained(2));

        assert_eq!(fsc.pop(), Ok(2));
        assert_eq!(fsc.pop(), Ok(3));
        assert_eq!(fsc.pop(), Ok(4));

        assert_eq!(fsc.length, 0);
        assert_eq!(fsc.size, 4);

        assert!(fsc.pop().is_err());

        assert_eq!(fsc.push(5), Ok(4));

        assert_eq!(fsc.head, 4);
        assert_eq!(fsc.tail, 4);
        assert_eq!(fsc.length, 1);
        assert_eq!(fsc.size, 5);

        assert_eq!(fsc.entries[4].next, FSCNeighborEntry::Nil);
        assert_eq!(fsc.entries[4].prev, FSCNeighborEntry::Nil);

        assert_eq!(fsc.pop(), Ok(5));
    }

    #[test]
    pub fn test_fsc_uncache() {
        let mut fsc = FreeableSqliteCache::new(10);
        assert_eq!(fsc.push(1), Ok(0));
        assert_eq!(fsc.push(2), Ok(1));
        assert_eq!(fsc.push(3), Ok(2));
        assert_eq!(fsc.push(4), Ok(3));

        assert!(fsc.uncache(4).is_err());

        assert!(fsc.uncache(2).is_ok());

        assert_eq!(fsc.head, 0);
        assert_eq!(fsc.tail, 3);
        assert_eq!(fsc.length, 3);
        assert_eq!(fsc.size, 4);

        assert!(!fsc.entries[2].chained);
        assert_eq!(fsc.entries[1].next, FSCNeighborEntry::Chained(3));
        assert_eq!(fsc.entries[1].prev, FSCNeighborEntry::Chained(0));
        assert_eq!(fsc.entries[3].next, FSCNeighborEntry::Nil);
        assert_eq!(fsc.entries[3].prev, FSCNeighborEntry::Chained(1));

        assert!(fsc.uncache(0).is_ok());

        assert_eq!(fsc.head, 1);
        assert_eq!(fsc.tail, 3);
        assert_eq!(fsc.length, 2);
        assert_eq!(fsc.size, 4);

        assert!(!fsc.entries[0].chained);
        assert_eq!(fsc.entries[1].next, FSCNeighborEntry::Chained(3));
        assert_eq!(fsc.entries[1].prev, FSCNeighborEntry::Nil);

        assert!(fsc.uncache(3).is_ok());

        assert_eq!(fsc.head, 1);
        assert_eq!(fsc.tail, 1);
        assert_eq!(fsc.length, 1);
        assert_eq!(fsc.size, 4);

        assert!(!fsc.entries[3].chained);
        assert_eq!(fsc.entries[1].next, FSCNeighborEntry::Nil);
        assert_eq!(fsc.entries[1].prev, FSCNeighborEntry::Nil);

        assert!(fsc.uncache(1).is_ok());

        assert_eq!(fsc.length, 0);
        assert_eq!(fsc.size, 4);

        assert!(!fsc.entries[1].chained);

        assert!(fsc.uncache(1).is_err());
        assert!(fsc.pop().is_err());

        assert_eq!(fsc.push(5), Ok(4));
        assert_eq!(fsc.head, 4);
        assert_eq!(fsc.tail, 4);
        assert_eq!(fsc.length, 1);
        assert_eq!(fsc.size, 5);

        assert!(fsc.entries[4].chained);
        assert_eq!(fsc.entries[4].next, FSCNeighborEntry::Nil);
        assert_eq!(fsc.entries[4].prev, FSCNeighborEntry::Nil);
    }

    #[test]
    pub fn test_fsc_recache() {
        let mut fsc = FreeableSqliteCache::new(10);
        assert_eq!(fsc.push(1), Ok(0));
        assert_eq!(fsc.push(2), Ok(1));
        assert_eq!(fsc.push(3), Ok(2));
        assert_eq!(fsc.push(4), Ok(3));

        assert!(fsc.recache(4).is_err());
        assert!(fsc.recache(3).is_err());

        assert!(fsc.uncache(2).is_ok());

        assert_eq!(fsc.head, 0);
        assert_eq!(fsc.tail, 3);
        assert_eq!(fsc.length, 3);
        assert_eq!(fsc.size, 4);

        assert!(!fsc.entries[2].chained);
        assert_eq!(fsc.entries[1].next, FSCNeighborEntry::Chained(3));
        assert_eq!(fsc.entries[1].prev, FSCNeighborEntry::Chained(0));
        assert_eq!(fsc.entries[3].next, FSCNeighborEntry::Nil);
        assert_eq!(fsc.entries[3].prev, FSCNeighborEntry::Chained(1));

        assert!(fsc.recache(2).is_ok());
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

        assert!(fsc.uncache(0).is_ok());
        assert!(fsc.uncache(1).is_ok());
        assert!(fsc.uncache(2).is_ok());
        assert!(fsc.uncache(3).is_ok());
        assert!(fsc.recache(3).is_ok());

        assert_eq!(fsc.head, 3);
        assert_eq!(fsc.tail, 3);
        assert_eq!(fsc.length, 1);
        assert_eq!(fsc.size, 4);

        assert!(fsc.entries[3].chained);
        assert_eq!(fsc.entries[3].next, FSCNeighborEntry::Nil);
        assert_eq!(fsc.entries[3].prev, FSCNeighborEntry::Nil);
    }

    #[actix_rt::test]
    pub async fn test_sqlite_cache() {
        let cache = KMSSqliteCache::new(2);

        assert_eq!(cache.max_size, 2);
        assert_eq!(cache.current_size.load(Ordering::Relaxed), 0);

        let password = "test";

        let sqlite = connect().await.expect("Can't create database");
        let sqlite2 = connect().await.expect("Can't create database");
        let sqlite3 = connect().await.expect("Can't create database");

        assert!(cache.save(1, password, sqlite).await.is_ok());
        assert_eq!(cache.current_size.load(Ordering::Relaxed), 1);
        assert!(cache.save(2, password, sqlite2).await.is_ok());
        assert_eq!(cache.current_size.load(Ordering::Relaxed), 2); // flush should do nothing here
        assert!(cache.opened(1));
        assert!(cache.opened(2));

        assert!(cache.exists(1));

        let sqlite2 = connect().await.expect("Can't create database");
        assert!(cache.save(2, password, sqlite2).await.is_ok()); // double saved = ok

        assert!(cache.release(2).is_ok());
        assert!(cache.release(2).is_err()); // not twice

        assert!(cache.exists(2));
        assert!(cache.opened(2)); // still opened

        assert!(!cache.exists(3));
        assert!(cache.save(3, password, sqlite3).await.is_ok());
        assert_eq!(cache.current_size.load(Ordering::Relaxed), 2); // flush should do nothing here
        assert!(cache.opened(3)); // still opened
        assert!(!cache.opened(2)); // not opened anymore
        assert!(cache.exists(2));

        let sqlite2 = connect().await.expect("Can't create database");
        assert!(cache.save(2, password, sqlite2).await.is_ok());
        assert_eq!(cache.current_size.load(Ordering::Relaxed), 3); // flush should do nothing here
        assert!(cache.opened(2));

        assert!(cache.get(4, password).is_err());
        assert!(cache.get(1, "bad_password").is_err()); // bad password
        assert!(cache.get(1, password).is_ok()); // 2 uses of sqlite1

        let sqlite4 = connect().await.expect("Can't create database");
        assert!(cache.save(4, password, sqlite4).await.is_ok());
        assert_eq!(cache.current_size.load(Ordering::Relaxed), 4); // flush should do nothing here
        assert!(cache.opened(1));

        assert!(cache.release(1).is_ok()); // 1 uses of sqlite1

        let sqlite5 = connect().await.expect("Can't create database");
        assert!(cache.save(5, password, sqlite5).await.is_ok());
        assert_eq!(cache.current_size.load(Ordering::Relaxed), 5); // flush should do nothing here
        assert!(cache.opened(1));

        assert!(cache.release(1).is_ok()); // 0 uses of sqlite1
        assert!(cache.opened(1));

        let sqlite6 = connect().await.expect("Can't create database");
        assert!(cache.save(6, password, sqlite6).await.is_ok());
        assert_eq!(cache.current_size.load(Ordering::Relaxed), 5); // flush should do something here
        assert!(!cache.opened(1));
        assert!(cache.exists(1));

        assert!(cache.get(1, password).is_err()); // get after close
    }

    async fn connect() -> std::result::Result<sqlx::Pool<sqlx::Sqlite>, sqlx::Error> {
        let mut options = SqliteConnectOptions::from_str("sqlite::memory:")?
            .pragma("journal_mode", "OFF")
            .busy_timeout(Duration::from_secs(120))
            .create_if_missing(true);
        // disable logging of each query
        options.disable_statement_logging();

        SqlitePoolOptions::new()
            .max_connections(1)
            .connect_with(options)
            .await
    }
}
