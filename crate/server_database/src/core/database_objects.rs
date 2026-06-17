use std::{
    collections::{HashMap, HashSet},
    future::Future,
    sync::Arc,
    time::Instant,
};

use cosmian_kmip::{
    kmip_0::kmip_types::State,
    kmip_2_1::{kmip_attributes::Attributes, kmip_objects::Object},
};
use cosmian_kms_interfaces::{AtomicOperation, ObjectWithMetadata, ObjectsStore};
use time::Date;

use crate::{
    Database,
    error::{DbError, DbResult},
};

/// Struct representing the database and providing methods to manipulate objects within it.
///
/// The `Database` struct provides various methods to register, unregister, retrieve, create, update,
/// and delete objects in the database. It also supports operations like migration, atomic transactions,
/// and cache management for unwrapped objects.
///
/// # Methods
///
/// - `register_objects_store`: Registers an `ObjectsStore` for objects with a specific prefix.
/// - `unregister_object_store`: Unregister the default objects store or a store for a given prefix.
/// - `get_object_store`: Retrieves the appropriate object store based on the prefix of the `uid`.
/// - `filename`: Returns the filename of the database or `None` if not supported.
/// - `migrate`: Migrates all the databases to the latest version.
/// - `create`: Creates a new object in the database.
/// - `retrieve_objects`: Retrieves objects from the database based on `uid` or tags.
/// - `retrieve_object`: Retrieves a single object from the database.
/// - `retrieve_tags`: Retrieves the tags of an object with the given `uid`.
/// - `update_object`: Updates the specified object in the database.
/// - `update_state`: Updates the state of an object in the database.
/// - `atomic`: Performs an atomic set of operations on the database.
/// - `get_unwrapped`: Unwraps the object (if needed) and returns the unwrapped object.
impl Database {
    #[allow(dead_code)]
    /// Register an Objects store for Objects `uid` starting with `<prefix>::`.
    ///
    /// This function registers an `ObjectsStore` for objects whose unique identifiers
    /// start with the specified prefix. The prefix is used to route operations to the
    /// appropriate store.
    ///
    /// # Arguments
    ///
    /// * `prefix` - A string slice representing the prefix for the objects' unique identifiers.
    /// * `objects_store` - An `Arc` containing the `ObjectsStore` to be registered.
    ///
    /// # Example
    ///
    /// ```
    /// let store = Arc::new(MyObjectsStore::new());
    /// database.register_objects_store("my_prefix", store).await;
    /// ```
    pub async fn register_objects_store(
        &self,
        prefix: &str,
        objects_store: Arc<dyn ObjectsStore + Sync + Send>,
    ) {
        let mut map = self.objects.write().await;
        map.insert(prefix.to_owned(), objects_store);
    }

    #[allow(dead_code)]
    /// Unregister the default objects store or a store for the given prefix
    pub async fn unregister_object_store(&self, prefix: Option<&str>) {
        let mut map = self.objects.write().await;
        map.remove(prefix.unwrap_or(""));
    }

    /// Return the object store for the given `uid`
    ///
    /// This function retrieves the appropriate object store based on the prefix of the `uid`.
    ///
    /// Prefix matching uses **longest-prefix wins**: all registered non-empty prefixes of the form
    /// `"{prefix}::"` are tested against the start of `uid`, and the longest match is chosen.
    /// This correctly handles multi-segment prefixes such as `"hsm::softhsm2"` which would
    /// otherwise be shadowed by the shorter `"hsm"` prefix when using a plain `split_once`:
    ///
    /// - `"hsm::0::mykey"` → prefix `"hsm"` (legacy single-HSM format)
    /// - `"hsm::softhsm2::0::mykey"` → prefix `"hsm::softhsm2"` (new multi-HSM format)
    ///
    /// If no registered prefix matches, the default object store (registered under `""`) is returned.
    ///
    /// # Arguments
    ///
    /// * `uid` - A string slice representing the unique identifier of the object.
    ///
    /// # Returns
    ///
    /// * `DbResult<Arc<dyn ObjectsStore + Sync + Send>>` - A result containing the object store.
    ///
    /// # Errors
    ///
    /// This function will return an error if no object store is found for the given prefix or if no default object store is available.
    async fn get_object_store(&self, uid: &str) -> DbResult<Arc<dyn ObjectsStore + Sync + Send>> {
        let map = self.objects.read().await;
        // Longest-prefix matching: find the registered prefix (non-empty) whose
        // "<prefix>::" string is a prefix of `uid`, preferring the longest one.
        let best = map
            .keys()
            .filter(|k| !k.is_empty())
            .filter(|k| uid.starts_with(&format!("{k}::")))
            .max_by_key(|k| k.len());
        if let Some(prefix) = best {
            if let Some(store) = map.get(prefix) {
                return Ok(store.clone());
            }
        }
        // If the UID carries an HSM prefix (starts with "hsm::") but no HSM store
        // is registered, refuse to route it to the default SQL store.  Silently
        // storing an HSM-prefixed object in the SQL backend would corrupt the key
        // namespace and make the object unreachable once a real HSM is attached.
        if uid.starts_with("hsm::") {
            return Err(DbError::InvalidRequest(format!(
                "No HSM is configured for UID '{uid}'. \
                 Start the server with an HSM plugin to create HSM keys."
            )));
        }
        // No registered prefix matched – fall back to the default store.
        map.get("")
            .ok_or_else(|| DbError::InvalidRequest("No default object store available".to_owned()))
            .map(Arc::clone)
    }

    /// Centralises metrics instrumentation boilerplate so that public methods
    /// stay focused on their core logic.
    ///
    /// Accepts a future representing the database operation (not yet polled),
    /// awaits it, then records the operation name, backend, outcome, and elapsed
    /// duration to the injected [`DbMetricsRecorder`] (if any).
    ///
    /// # Important
    ///
    /// Every new operation added to the `Database` facade must be wrapped with
    /// this method to be accounted for by the metrics recorder.
    pub(crate) async fn record<T>(
        &self,
        operation: &str,
        fut: impl Future<Output = DbResult<T>>,
    ) -> DbResult<T> {
        let start = Instant::now();
        let result = fut.await;
        if let Some(ref rec) = self.recorder {
            rec.record_operation(
                operation,
                self.kind,
                if result.is_ok() { "success" } else { "error" },
                start.elapsed().as_secs_f64(),
            );
        }
        result
    }

    /// Create the given Object in the database.
    /// A new UUID will be created if none is supplier.
    /// This method will fail if an ` uid ` is supplied
    /// and an object with the same id already exists
    ///
    /// A new UUID will be created if none is supplier.
    /// This method will fail if an ` uid ` is supplied
    /// and an object with the same id already exists
    /// # Arguments
    ///
    /// * `uid` - An optional string representing the unique identifier of the object.
    /// * `owner` - A string slice representing the owner of the object.
    /// * `object` - A reference to the `Object` to be created.
    /// * `attributes` - A reference to the `Attributes` of the object.
    /// * `tags` - A reference to a `HashSet` of tags associated with the object.
    /// * `params` - An optional reference to `ExtraStoreParams` for additional parameters.
    ///
    /// # Returns
    ///
    /// * `DbResult<String>` - A result containing the unique identifier of the created object.
    pub async fn create(
        &self,
        uid: Option<String>,
        owner: &str,
        object: &Object,
        attributes: &Attributes,
        tags: &HashSet<String>,
    ) -> DbResult<String> {
        self.record("create", async move {
            let db = self
                .get_object_store(uid.as_deref().unwrap_or_default())
                .await?;
            // New objects never have a cache entry; nothing to invalidate.
            Ok(db.create(uid, owner, object, attributes, tags).await?)
        })
        .await
    }

    /// Retrieve objects from the database.
    ///
    /// The `uid_or_tags` parameter can be either a `uid` or a JSON array of tags.
    ///
    /// The `user_filter` parameter allows filtering based on user permissions.
    ///
    /// The `state_filter` parameter allows filtering based on the state of the objects.
    ///
    /// The `params` parameter allows passing additional parameters for the database query.
    ///
    /// Returns a `DbResult` containing a `HashMap` where the keys are the `uid`s and the values are the `ObjectWithMetadata`.
    ///
    /// # Arguments
    ///
    /// * `uid_or_tags` - A string representing either a `uid` or a JSON array of tags.
    /// * `user` - A string representing the user requesting the objects.
    /// * `user_filter` - A `UserFilter` enum to filter objects based on user permissions.
    /// * `state_filter` - A `StateFilter` enum to filter objects based on their state.
    /// * `params` - An optional reference to `ExtraStoreParams` for additional query parameters.
    ///
    /// # Returns
    ///
    /// * `DbResult<HashMap<String, ObjectWithMetadata>>` - A result containing a map of `uid`s to `ObjectWithMetadata`.
    pub async fn retrieve_objects(
        &self,
        uid_or_tags: &str,
    ) -> DbResult<HashMap<String, ObjectWithMetadata>> {
        self.record("retrieve_objects", async move {
            let uids = if uid_or_tags.starts_with('[') {
                // tags
                let tags: HashSet<String> = serde_json::from_str(uid_or_tags)?;
                self.list_uids_for_tags(&tags).await?
            } else {
                HashSet::from([uid_or_tags.to_owned()])
            };
            let mut results: HashMap<String, ObjectWithMetadata> = HashMap::new();
            for uid in &uids {
                let owm = self.retrieve_object(uid).await?;
                if let Some(owm) = owm {
                    results.insert(uid.to_owned(), owm);
                }
            }
            Ok(results)
        })
        .await
    }

    /// Retrieve a single object from the database.
    ///
    /// This method retrieves an object identified by its `uid` and applies
    /// user and state filters to determine if the object should be returned.
    ///
    /// # Arguments
    ///
    /// * `uid` - A string slice that holds the unique identifier of the object.
    /// * `user` - A string slice representing the user requesting the object.
    /// * `user_filter` - A `UserFilter` enum to filter objects based on user permissions.
    /// * `state_filter` - A `StateFilter` enum to filter objects based on their state.
    /// * `params` - An optional reference to `ExtraStoreParams` for additional query parameters.
    ///
    /// # Returns
    ///
    /// * `DbResult<Option<ObjectWithMetadata>>` - A result containing an optional `ObjectWithMetadata`.
    ///   If the object is found and passes the filters, it is returned wrapped in `Some`.
    ///   If the object is not found or does not pass the filters, `None` is returned.
    pub async fn retrieve_object(&self, uid: &str) -> DbResult<Option<ObjectWithMetadata>> {
        self.record("retrieve", async move {
            let db = self.get_object_store(uid).await?;
            Ok(db.retrieve(uid).await?)
        })
        .await
    }

    /// Retrieve the tags of the object with the given `uid`
    pub async fn retrieve_tags(&self, uid: &str) -> DbResult<HashSet<String>> {
        self.record("retrieve_tags", async move {
            let db = self.get_object_store(uid).await?;
            Ok(db.retrieve_tags(uid).await?)
        })
        .await
    }

    /// This method updates the specified object identified by its `uid` in the database.
    /// If the `tags` parameter is `None`, the tags will not be updated.
    ///
    /// # Arguments
    ///
    /// * `uid` - A string slice that holds the unique identifier of the object.
    /// * `object` - A reference to the `Object` to be updated.
    /// * `attributes` - A reference to the `Attributes` of the object.
    /// * `tags` - An optional reference to a `HashSet` of tags associated with the object.
    /// * `params` - An optional reference to `ExtraStoreParams` for additional parameters.
    ///
    /// # Returns
    ///
    /// * `DbResult<()>` - A result indicating success or failure of the update operation.
    ///
    /// # Errors
    ///
    /// This function will return an error if the object store for the given `uid` cannot be found
    /// or if the update operation fails.
    pub async fn update_object(
        &self,
        uid: &str,
        object: &Object,
        attributes: &Attributes,
        tags: Option<&HashSet<String>>,
    ) -> DbResult<()> {
        self.record("update_object", async move {
            let db = self.get_object_store(uid).await?;
            db.update_object(uid, object, attributes, tags).await?;
            // Key material is immutable; only attributes change via update_object.
            // The GC clears stale unwrap-cache entries; no eager invalidation needed here.
            Ok(())
        })
        .await
    }

    /// Update the state of an object in the database.
    pub async fn update_state(&self, uid: &str, state: State) -> DbResult<()> {
        self.record("update_state", async move {
            let db = self.get_object_store(uid).await?;
            Ok(db.update_state(uid, state).await?)
        })
        .await
    }

    /// Delete an object from the database.
    pub async fn delete(&self, uid: &str) -> DbResult<()> {
        self.record("delete", async move {
            let db = self.get_object_store(uid).await?;
            db.delete(uid).await?;
            self.unwrapped_cache.clear_cache(uid).await;
            Ok(())
        })
        .await
    }

    /// Test if an object identified by its `uid` is currently owned by `owner`
    pub async fn is_object_owned_by(&self, uid: &str, owner: &str) -> DbResult<bool> {
        self.record("is_object_owned_by", async move {
            let db = self.get_object_store(uid).await?;
            Ok(db.is_object_owned_by(uid, owner).await?)
        })
        .await
    }

    pub async fn list_uids_for_tags(&self, tags: &HashSet<String>) -> DbResult<HashSet<String>> {
        self.record("list_uids_for_tags", async move {
            let db_map = self.objects.read().await;
            let mut results = HashSet::new();
            for db in db_map.values() {
                results.extend(db.list_uids_for_tags(tags).await?);
            }
            Ok(results)
        })
        .await
    }

    /// Return uid, state and attributes of the object identified by its owner,
    /// and possibly by its attributes and/or its `state`
    pub async fn find(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<State>,
        user: &str,
        user_must_be_owner: bool,
        vendor_id: &str,
    ) -> DbResult<Vec<(String, State, Attributes)>> {
        self.record("find", async move {
            let map = self.objects.read().await;
            let mut results: Vec<(String, State, Attributes)> = Vec::new();
            for db in map.values() {
                results.extend(
                    db.find(
                        researched_attributes,
                        state,
                        user,
                        user_must_be_owner,
                        vendor_id,
                    )
                    .await
                    .unwrap_or(vec![]),
                );
            }
            Ok(results)
        })
        .await
    }

    /// Return (uid, state, attributes) for every object wrapped by the given wrapping key.
    pub async fn find_wrapped_by(
        &self,
        wrapping_key_uid: &str,
        user: &str,
    ) -> DbResult<Vec<(String, State, Attributes)>> {
        let map = self.objects.read().await;
        let mut results: Vec<(String, State, Attributes)> = Vec::new();
        for db in map.values() {
            results.extend(
                db.find_wrapped_by(wrapping_key_uid, user)
                    .await
                    .unwrap_or_default(),
            );
        }
        Ok(results)
    }

    /// Find all Active objects that have a `rotate_interval > 0` and whose next
    /// rotation instant is ≤ `now`. Returns a list of UIDs.
    pub async fn find_due_for_rotation(&self, now: time::OffsetDateTime) -> DbResult<Vec<String>> {
        let map = self.objects.read().await;
        let mut results: Vec<String> = Vec::new();
        for db in map.values() {
            results.extend(db.find_due_for_rotation(now).await.unwrap_or_default());
        }
        Ok(results)
    }

    /// Find objects by their `x-rotate-name` vendor attribute.
    ///
    /// Queries all registered object stores and returns matching `(uid, attributes)` pairs.
    pub async fn find_by_rotate_name(
        &self,
        name: &str,
        generation: Option<i32>,
        latest: Option<bool>,
        owner: &str,
    ) -> DbResult<Vec<(String, Attributes)>> {
        let map = self.objects.read().await;
        let mut results: Vec<(String, Attributes)> = Vec::new();
        for db in map.values() {
            results.extend(
                db.find_by_rotate_name(name, generation, latest, owner)
                    .await
                    .unwrap_or_default(),
            );
        }
        Ok(results)
    }

    /// Set the `CKA_LABEL` (or equivalent) on a key identified by `uid`.
    ///
    /// Routes to the object store responsible for `uid`. SQL stores silently ignore this.
    pub async fn set_key_label(&self, uid: &str, label: &str) -> DbResult<()> {
        let store = self.get_object_store(uid).await?;
        store.set_key_label(uid, label).await.map_err(Into::into)
    }

    /// Rewrite the PKCS#11 rotation dates on an HSM key identified by `uid`.
    ///
    /// Routes to the object store responsible for `uid`. SQL stores silently ignore this.
    pub async fn set_key_rotation_dates(
        &self,
        uid: &str,
        start_date: Option<Date>,
        end_date: Option<Date>,
    ) -> DbResult<()> {
        let store = self.get_object_store(uid).await?;
        store
            .set_key_rotation_dates(uid, start_date, end_date)
            .await
            .map_err(Into::into)
    }

    /// Perform an atomic set of operations on the database.
    ///
    /// This function executes a series of operations (typically in a transaction) atomically.
    /// It assumes that all objects involved in the operations belong to the same database.
    ///
    /// # Arguments
    ///
    /// * `user` - A string slice representing the user performing the operations.
    /// * `operations` - A slice of `AtomicOperation` representing the operations to be performed.
    /// * `params` - An optional reference to `ExtraStoreParams` for additional parameters.
    ///
    /// # Returns
    ///
    /// * `DbResult<()>` - A result indicating success or failure of the atomic operation.
    ///
    /// # Errors
    ///
    /// This function will return an error if any of the operations fail or if the database
    /// cannot be accessed.
    pub async fn atomic(
        &self,
        user: &str,
        operations: &[AtomicOperation],
    ) -> DbResult<Vec<String>> {
        if operations.is_empty() {
            return Ok(vec![]);
        }

        self.record("atomic", async move {
            #[expect(clippy::indexing_slicing)]
            let first_op = &operations[0];
            let first_uid = first_op.get_object_uid();
            let db = self.get_object_store(first_uid).await?;
            let ids = db.atomic(user, operations).await?;
            // invalidate or clear cache for all operations
            for op in operations {
                match op {
                    AtomicOperation::Create((uid, object, ..))
                    | AtomicOperation::UpdateObject((uid, object, ..))
                    | AtomicOperation::Upsert((uid, object, ..)) => {
                        self.unwrapped_cache.validate_cache(uid, object).await?;
                    }
                    AtomicOperation::Delete(uid) => {
                        self.unwrapped_cache.clear_cache(uid).await;
                    }
                    AtomicOperation::UpdateState(_) => {}
                }
            }
            Ok(ids)
        })
        .await
    }

    /// Count all live (non-destroyed) objects across every registered object store.
    ///
    /// This is a **metrics-only** operation that bypasses user/permission filters.
    /// It is called:
    ///   1. Once at server startup to seed the `kms.objects.total` gauge.
    ///   2. Every 30 s by the metrics cron task.
    ///
    /// Because several stores may be registered simultaneously (e.g. one SQL store
    /// plus one or more HSM stores), the results are summed. Backends that have not
    /// yet implemented `count_all_non_destroyed` return `0` via the trait default,
    /// which is acceptable — the sum will still be a valid lower bound.
    pub async fn count_all_non_destroyed_objects(&self) -> DbResult<u64> {
        let stores: Vec<Arc<dyn ObjectsStore + Sync + Send>> = {
            let map = self.objects.read().await;
            map.values().cloned().collect()
        }; // read guard dropped before any async I/O
        let mut total: u64 = 0;
        for store in &stores {
            let n = store.count_all_non_destroyed().await.unwrap_or_else(|e| {
                cosmian_logger::warn!("[database] count_all_non_destroyed failed: {e}");
                0
            });
            total = total.saturating_add(n);
        }
        Ok(total)
    }

    /// Return the total count of non-destroyed key objects (`SymmetricKey`, `PrivateKey`,
    /// `PublicKey`, `SplitKey`) across all registered stores.
    ///
    /// Aggregates results from every registered backend (SQL stores, HSM stores, etc.).
    /// Backends that have not yet implemented `count_non_destroyed_keys` return `0` via
    /// the trait default — the sum remains a valid lower bound.
    pub async fn count_non_destroyed_key_objects(&self) -> DbResult<u64> {
        let stores: Vec<Arc<dyn ObjectsStore + Sync + Send>> = {
            let map = self.objects.read().await;
            map.values().cloned().collect()
        }; // read guard dropped before any async I/O
        let mut total: u64 = 0;
        for store in &stores {
            let n = store.count_non_destroyed_keys().await.unwrap_or_else(|e| {
                cosmian_logger::warn!("[database] count_non_destroyed_keys failed: {e}");
                0
            });
            total = total.saturating_add(n);
        }
        Ok(total)
    }

    /// Perform an authoritative reconciliation of cached object-count counters
    /// across all registered stores.
    ///
    /// SQL backends are no-ops (every COUNT query is authoritative).
    /// Redis backends recompute counts from a full SCAN and overwrite cached keys.
    /// Called by the slow-path cron loop (every 5 minutes) to prevent counter drift.
    pub async fn reconcile_all_object_counts(&self) -> DbResult<()> {
        let stores: Vec<Arc<dyn ObjectsStore + Sync + Send>> = {
            let map = self.objects.read().await;
            map.values().cloned().collect()
        }; // read guard dropped before any async I/O
        for store in &stores {
            if let Err(e) = store.reconcile_counts().await {
                // Non-fatal: log and continue so one failing backend does not block others.
                cosmian_logger::warn!("[database] reconcile_counts failed for a store: {e}");
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[expect(clippy::expect_used, clippy::panic)]
mod tests {
    use std::{
        collections::HashMap,
        num::NonZeroUsize,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use tempfile::TempDir;

    use super::Database;
    use crate::core::{DbMetricsRecorder, MainDbKind, MainDbParams};

    /// Verify that a UID with an HSM prefix is rejected when no HSM store is registered.
    #[tokio::test]
    async fn test_hsm_uid_rejected_without_hsm_store() {
        let tmp = TempDir::new().expect("Failed to create temp dir");
        let db = Database::instantiate(
            &MainDbParams::Sqlite(tmp.path().to_path_buf(), None),
            false,
            HashMap::new(), // no HSM stores registered
            Duration::from_secs(1),
            NonZeroUsize::new(100).expect("100 is non-zero"),
            None,
        )
        .await
        .expect("Failed to instantiate in-memory database");

        let result = db.get_object_store("hsm::softhsm2::0::mykey").await;
        match result {
            Ok(_) => panic!("Expected an error for an HSM-prefixed UID with no HSM store"),
            Err(e) => {
                let msg = e.to_string();
                assert!(
                    msg.contains("No HSM is configured"),
                    "Expected 'No HSM is configured' in error, got: {msg}"
                );
            }
        }
    }

    /// Verify that the `DbMetricsRecorder` injected into `Database` is called when
    /// DB facade methods are invoked.
    ///
    /// Uses a thread-safe mock recorder that collects every `(operation, backend, outcome)`
    /// triple so the test can assert that the instrumentation fires as expected.
    #[tokio::test]
    async fn test_db_recorder_called_on_operations() {
        /// Minimal mock that records every call in a shared Vec.
        #[derive(Clone, Default)]
        struct MockRecorder {
            calls: Arc<Mutex<Vec<(String, String, String)>>>,
        }
        impl DbMetricsRecorder for MockRecorder {
            fn record_operation(
                &self,
                operation: &str,
                backend: MainDbKind,
                outcome: &str,
                _duration_seconds: f64,
            ) {
                self.calls.lock().expect("mutex poisoned").push((
                    operation.to_owned(),
                    backend.as_str().to_owned(),
                    outcome.to_owned(),
                ));
            }
        }

        let tmp = TempDir::new().expect("Failed to create temp dir");
        let recorder = MockRecorder::default();
        let calls = Arc::clone(&recorder.calls);
        let recorder_arc: Arc<dyn DbMetricsRecorder> = Arc::new(recorder);

        let db = Database::instantiate(
            &MainDbParams::Sqlite(tmp.path().to_path_buf(), None),
            false,
            HashMap::new(),
            Duration::from_secs(1),
            NonZeroUsize::new(100).expect("100 is non-zero"),
            Some(recorder_arc),
        )
        .await
        .expect("Failed to instantiate database with mock recorder");

        // list_user_operations_granted: exercises the permissions facade path.
        drop(db.list_user_operations_granted("test_user").await);

        // retrieve_object on a non-existent uid → Ok(None) → outcome "success"
        drop(db.retrieve_object("non-existent-uid-xyz").await);

        // find with no filters → Ok([]) → outcome "success"
        drop(db.find(None, None, "test_user", false, "").await);

        let recorded = calls.lock().expect("mutex poisoned").clone();

        // At least 3 calls recorded (one per method above)
        assert!(
            recorded.len() >= 3,
            "Expected ≥ 3 recorded calls, got {}",
            recorded.len()
        );

        // All outcomes must be "success" — these operations cannot fail on an empty DB.
        for (op, backend, outcome) in &recorded {
            assert_eq!(
                backend, "sqlite",
                "Expected backend 'sqlite' for op '{op}', got '{backend}'"
            );
            assert_eq!(
                outcome, "success",
                "Expected outcome 'success' for op '{op}', got '{outcome}'"
            );
        }

        // Operation names present in the recorded set.
        let op_names: Vec<&str> = recorded.iter().map(|(op, _, _)| op.as_str()).collect();
        assert!(
            op_names.contains(&"retrieve"),
            "recorder missing 'retrieve' op; got: {op_names:?}"
        );
        assert!(
            op_names.contains(&"find"),
            "recorder missing 'find' op; got: {op_names:?}"
        );
    }
}
