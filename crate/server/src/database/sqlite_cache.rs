use std::{collections::HashMap, time::SystemTime};

use sqlx::{Pool, Sqlite};

/// The item of the KMS sqlite cache
pub struct KMSSqliteCacheItem {
    /// The handler to the sqlite
    sqlite: Pool<Sqlite>,
    /// The date of the first insertion
    inserted_at: u64,
    /// The number of instances of the sqlite currently running
    in_used: u32,
    /// The date of last used
    last_used_at: u64,
    /// Wether the sqlite is closed
    closed: bool,
    /// The date of the last sqlite close
    closed_at: u64,
    /// The index of the item inside the freeable cache
    freeable_cache_index: usize,
}

impl KMSSqliteCacheItem {
    #[must_use]
    pub fn new(sqlite: Pool<Sqlite>, freeable_cache_index: usize) -> KMSSqliteCacheItem {
        KMSSqliteCacheItem {
            sqlite,
            inserted_at: SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Unable to get duration since epoch")
                .as_secs(),
            in_used: 0,
            last_used_at: 0,
            closed: false,
            closed_at: 0,
            freeable_cache_index,
        }
    }
}

/// The KMS sqlite cache contaings all handlers to the opened and closed sqlite
pub struct KMSSqliteCache {
    /// The item of the cache
    sqlites: HashMap<u32, KMSSqliteCacheItem>,
    /// The list of unused sqlite that could be closed if needed
    freeable_sqlites: FreeableSqliteCache,
    /// The number of opened sqlite allowed
    max_size: usize,
    /// The number of currently opened sqlite
    current_size: usize,
}

impl KMSSqliteCache {
    #[must_use]
    pub fn new(size: usize) -> KMSSqliteCache {
        KMSSqliteCache {
            sqlites: HashMap::with_capacity(size),
            freeable_sqlites: FreeableSqliteCache::new(size),
            max_size: size,
            current_size: 0,
        }
    }

    /// Test if a sqlite connection is opened for a given id
    pub fn opened(&self, id: u32) -> bool {
        if !self.sqlites.contains_key(&id) {
            return false
        }

        !self.sqlites[&id].closed
    }

    /// Get the sqlite handler and tag it as "used"
    pub fn get(&mut self, id: u32) -> Result<Option<&Pool<Sqlite>>, &'static str> {
        if !self.sqlites.contains_key(&id) {
            return Ok(None)
        }

        let item = self.sqlites.get_mut(&id).ok_or("Key is not in the cache")?;

        if item.closed {
            return Ok(None)
        }

        // Now, we can't close this connection until it is used.
        if item.in_used == 0 {
            self.freeable_sqlites.uncache(item.freeable_cache_index)?;
        }

        item.in_used += 1;
        item.last_used_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Unable to get duration since epoch")
            .as_secs();

        Ok(Some(&self.sqlites[&id].sqlite))
    }

    /// Say the cache that the sqlite handler is not used at the current moment
    /// The cache will let it opened until it needs that slot
    pub fn release(&mut self, id: u32) -> Result<(), &'static str> {
        let item = self.sqlites.get_mut(&id).ok_or("Key is not in the cache")?;

        if item.in_used == 0 {
            return Err("Can't release twice a cache item")
        }

        item.in_used -= 1;

        // Now, we can close this connection if we need it.
        if item.in_used == 0 {
            self.freeable_sqlites.recache(item.freeable_cache_index)?;
        }

        Ok(())
    }

    /// Remove oldest sqlite handlers until reaching the max cache size allowed
    async fn flush(&mut self) -> Result<(), &'static str> {
        while self.max_size <= self.current_size {
            let id = match self.freeable_sqlites.pop() {
                Ok(id) => id,
                Err(_) => break, // nothing in the cache, just leave
            };

            let item = self.sqlites.get_mut(&id).ok_or("Key is not in the cache")?;

            item.sqlite.close().await;
            item.closed = true;
            item.closed_at = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Unable to get duration since epoch")
                .as_secs();

            self.current_size -= 1;
        }
        Ok(())
    }

    /// Save a sqlite handler inside the cache for further use
    /// The handler is considered as used until it is release.
    pub async fn save(&mut self, id: u32, value: Pool<Sqlite>) -> Result<(), &'static str> {
        // Flush the cache if necessary
        self.flush().await?;
        // If nothing has been flush, allow to exceed max cache size

        // Deal if the case: the id is already known but the sqlite was closed
        if self.sqlites.contains_key(&id) {
            let item = self.sqlites.get_mut(&id).ok_or("Key is not in the cache")?;

            if !item.closed {
                return Err("Sqlite is already saved and opened")
            }

            item.sqlite = value;
            item.closed = false;
            item.in_used = 1;
            item.last_used_at = SystemTime::now()
                .duration_since(SystemTime::UNIX_EPOCH)
                .expect("Unable to get duration since epoch")
                .as_secs();

            self.current_size += 1;

            return Ok(())
        }

        // Book a slot for it
        let freeable_cache_id = self.freeable_sqlites.push(id)?;

        // Add it to the SqliteCache
        let mut item = KMSSqliteCacheItem::new(value, freeable_cache_id);

        // Make it usable (to avoid direct free after alloc in case of cache overflow)
        item.in_used = 1;
        item.last_used_at = SystemTime::now()
            .duration_since(SystemTime::UNIX_EPOCH)
            .expect("Unable to get duration since epoch")
            .as_secs();
        self.freeable_sqlites.uncache(freeable_cache_id)?;

        self.sqlites.insert(id, item);

        self.current_size += 1;

        Ok(())
    }
}

#[derive(PartialEq, Debug, Clone)]
pub enum FSCNeighborEntry {
    /// Start/End of chain
    Nil,
    //// The index of the previous/next item
    Chained(usize),
}

pub struct FSCEntry {
    /// The value to store
    val: u32,
    /// The previous item
    prev: FSCNeighborEntry,
    /// The next item
    next: FSCNeighborEntry,
    /// The item is a member of the chain
    chained: bool,
}

impl FSCEntry {
    /// Create an entry as a last item of a chain
    pub fn last(value: u32, last_index: usize) -> FSCEntry {
        FSCEntry {
            val: value,
            prev: FSCNeighborEntry::Chained(last_index),
            next: FSCNeighborEntry::Nil,
            chained: true,
        }
    }

    /// Create an entry as the first item of a new chain
    pub fn singleton(value: u32) -> FSCEntry {
        FSCEntry {
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
    pub fn new(capacity: usize) -> FreeableSqliteCache {
        FreeableSqliteCache {
            entries: Vec::with_capacity(capacity),
            head: 0,
            tail: 0,
            length: 0,
            size: 0,
        }
    }

    // Add an element at the end of the cache
    pub fn push(&mut self, value: u32) -> Result<usize, &'static str> {
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
    pub fn pop(&mut self) -> Result<u32, &'static str> {
        if self.length == 0 {
            return Err("Cache is empty")
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
    pub fn uncache(&mut self, index: usize) -> Result<(), &'static str> {
        if index >= self.size {
            return Err("Index is too large")
        }

        if !self.entries[index].chained {
            return Err("Index has already been uncached")
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
    pub fn recache(&mut self, index: usize) -> Result<(), &'static str> {
        if index >= self.size {
            return Err("Index is too large")
        }

        if self.entries[index].chained {
            return Err("Index is already cached")
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
    use std::{str::FromStr, time::Duration};

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
        let mut cache = KMSSqliteCache::new(2);

        assert_eq!(cache.max_size, 2);
        assert_eq!(cache.current_size, 0);

        let sqlite = connect().await.expect("Can't create database");
        let sqlite2 = connect().await.expect("Can't create database");
        let sqlite3 = connect().await.expect("Can't create database");

        assert!(cache.save(1, sqlite).await.is_ok());
        assert_eq!(cache.current_size, 1);
        assert!(cache.save(2, sqlite2).await.is_ok());
        assert_eq!(cache.current_size, 2); // flush should do nothing here
        assert!(cache.opened(1));
        assert!(cache.opened(2));

        let sqlite2 = connect().await.expect("Can't create database");
        assert!(cache.save(2, sqlite2).await.is_err()); // double saved = failed

        assert!(cache.release(2).is_ok());
        assert!(cache.release(2).is_err()); // not twice

        assert!(cache.opened(2)); // still opened

        assert!(cache.save(3, sqlite3).await.is_ok());
        assert_eq!(cache.current_size, 2); // flush should do nothing here
        assert!(cache.opened(3)); // still opened
        assert!(!cache.opened(2)); // not opened anymore

        let sqlite2 = connect().await.expect("Can't create database");
        assert!(cache.save(2, sqlite2).await.is_ok());
        assert_eq!(cache.current_size, 3); // flush should do nothing here
        assert!(cache.opened(2));

        assert!(cache.get(4).unwrap().is_none());
        assert!(cache.get(1).unwrap().is_some()); // 2 uses of sqlite1

        let sqlite4 = connect().await.expect("Can't create database");
        assert!(cache.save(4, sqlite4).await.is_ok());
        assert_eq!(cache.current_size, 4); // flush should do nothing here
        assert!(cache.opened(1));

        assert!(cache.release(1).is_ok()); // 1 uses of sqlite1

        let sqlite5 = connect().await.expect("Can't create database");
        assert!(cache.save(5, sqlite5).await.is_ok());
        assert_eq!(cache.current_size, 5); // flush should do nothing here
        assert!(cache.opened(1));

        assert!(cache.release(1).is_ok()); // 0 uses of sqlite1
        assert!(cache.opened(1));

        let sqlite6 = connect().await.expect("Can't create database");
        assert!(cache.save(6, sqlite6).await.is_ok());
        assert_eq!(cache.current_size, 5); // flush should do something here
        assert!(!cache.opened(1));

        assert!(cache.get(1).unwrap().is_none()); // get after close

        // TODO: release when 2 gets
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

fn main() -> Result<(), Box<dyn std::error::Error>> {
    Ok(())
}
