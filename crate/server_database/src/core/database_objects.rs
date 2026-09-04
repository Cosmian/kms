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
use cosmian_kms_interfaces::{
    AtomicOperation, ObjectHandle, ObjectWithMetadata, ObjectsStore, UserId,
};
use time::Date;
use x509_parser::prelude::{FromDer as _, X509Certificate};

use crate::{
    Database,
    error::{DbError, DbResult},
};

/// Object unique identifiers that can never be assigned to a user-created object.
///
/// `"*"` is the internal sentinel under which the global `Create` right is stored
/// (see `KMS::grant_access`).
const RESERVED_UIDS: &[&str] = &["*"];

/// Reject `uid` if it is a reserved identifier (see [`RESERVED_UIDS`]).
fn reject_reserved_uid(uid: &str) -> DbResult<()> {
    if RESERVED_UIDS.contains(&uid) {
        return Err(DbError::InvalidRequest(format!(
            "'{uid}' is a reserved identifier and cannot be used as an object unique identifier"
        )));
    }
    Ok(())
}

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
    /// Execute an async operation and, when a recorder is configured, measure its
    /// wall-clock duration and outcome (`"success"` / `"error"`).
    ///
    /// When no recorder is present the future is awaited directly with no overhead.
    pub(super) async fn record<T, Fut>(&self, operation: &str, fut: Fut) -> DbResult<T>
    where
        Fut: Future<Output = DbResult<T>>,
    {
        if self.recorder.is_none() {
            return fut.await;
        }
        let start = Instant::now();
        let result = fut.await;
        if let Some(ref rec) = self.recorder {
            let outcome = if result.is_ok() { "success" } else { "error" };
            rec.record_operation(operation, self.kind, outcome, start.elapsed().as_secs_f64());
        }
        result
    }

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
        // Fast path: UIDs without "::" cannot match any registered prefix,
        // so skip the prefix search and return the default store directly.
        if !uid.contains("::") {
            let map = self.objects.read().await;
            return map
                .get("")
                .ok_or_else(|| {
                    DbError::InvalidRequest("No default object store available".to_owned())
                })
                .map(Arc::clone);
        }

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
    /// * `owner` - A `UserId` representing the owner of the object.
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
        owner: &UserId,
        object: &Object,
        attributes: &Attributes,
        tags: &HashSet<String>,
        domain: &str,
    ) -> DbResult<String> {
        if let Some(ref uid) = uid {
            reject_reserved_uid(uid)?;
        }
        self.record("create", async move {
            let db = self
                .get_object_store(uid.as_deref().unwrap_or_default())
                .await?;
            let uid = db
                .create(uid, owner, object, attributes, tags, domain)
                .await?;
            // New objects never have a cache entry; nothing to invalidate.
            Ok(uid)
        })
        .await
    }

    /// Retrieve objects from the database.
    ///
    /// The `object_handle` classifies the request identifier: an [`ObjectHandle::Tags`]
    /// expands to every object carrying all of the requested tags, while any other variant
    /// resolves to the single UID it wraps.
    ///
    /// Returns a `DbResult` containing a `HashMap` where the keys are the `uid`s and the values are the `ObjectWithMetadata`.
    ///
    /// # Arguments
    ///
    /// * `object_handle` - the classified request identifier (a UID or a tag-array).
    ///
    /// # Returns
    ///
    /// * `DbResult<HashMap<String, ObjectWithMetadata>>` - A result containing a map of `uid`s to `ObjectWithMetadata`.
    pub async fn retrieve_objects(
        &self,
        object_handle: ObjectHandle<'_>,
    ) -> DbResult<HashMap<String, ObjectWithMetadata>> {
        Box::pin(self.record("retrieve_objects", async move {
            let uids = match object_handle {
                ObjectHandle::Tags(json) => {
                    let tags: HashSet<String> = serde_json::from_str(json)?;
                    self.list_uids_for_tags(&tags).await?
                }
                handle => HashSet::from([handle.as_str().to_owned()]),
            };
            let mut results: HashMap<String, ObjectWithMetadata> = HashMap::new();
            for uid in &uids {
                let owm = self.retrieve_object(uid).await?;
                if let Some(owm) = owm {
                    results.insert(uid.to_owned(), owm);
                }
            }
            Ok(results)
        }))
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
        // Fast path: check the in-memory cache first (no DB round-trip, no recording).
        // The cache returns Arc<ObjectWithMetadata> — unwrap_or_clone avoids a deep
        // copy when the caller is the sole holder (common on the encrypt hot-path
        // where the cache entry is read-only).
        if let Some(owm) = self.object_cache.get(uid).await {
            return Ok(Some(std::sync::Arc::unwrap_or_clone(owm)));
        }
        // Cache miss: fetch from the backing store and record the operation.
        let result: Option<ObjectWithMetadata> = self
            .record("retrieve", async move {
                let db = self.get_object_store(uid).await?;
                db.retrieve(uid).await.map_err(DbError::from)
            })
            .await?;
        // Populate cache on successful retrieval.
        if let Some(ref owm) = result {
            self.object_cache
                .insert(uid.to_owned(), owm.clone())
                .await?;
        }
        Ok(result)
    }

    /// Retrieve a cached object as `Arc<ObjectWithMetadata>` without deep-cloning.
    ///
    /// On cache hit this returns a cheap `Arc` pointer bump instead of the
    /// `~800-byte` deep clone that [`retrieve_object`] performs.  Use this on
    /// read-only hot paths (e.g. encrypt with a non-wrapped key that has no
    /// usage limits) where the caller never mutates the object.
    ///
    /// On cache miss the object is fetched from the backing store, inserted
    /// into the cache, and returned as a fresh `Arc`.
    pub async fn retrieve_object_arc(
        &self,
        uid: &str,
    ) -> DbResult<Option<Arc<ObjectWithMetadata>>> {
        // Fast path: cache hit — zero-copy Arc clone.
        if let Some(owm) = self.object_cache.get(uid).await {
            return Ok(Some(owm));
        }
        // Cache miss: fetch from the backing store and record the operation.
        let result: Option<ObjectWithMetadata> = self
            .record("retrieve", async move {
                let db = self.get_object_store(uid).await?;
                db.retrieve(uid).await.map_err(DbError::from)
            })
            .await?;
        // Populate cache on successful retrieval and return the Arc.
        match result {
            Some(owm) => {
                let arc = std::sync::Arc::new(owm);
                self.object_cache
                    .insert_arc(uid.to_owned(), Arc::clone(&arc))
                    .await?;
                Ok(Some(arc))
            }
            None => Ok(None),
        }
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
            Ok(db.update_object(uid, object, attributes, tags).await?)
        })
        .await?;
        // Invalidate the object cache since attributes or key material may have changed.
        self.object_cache.invalidate(uid).await;
        // Validate the unwrapped cache: if the object fingerprint changed (e.g. a
        // re-wrap), evict the stale unwrapped entry so the next get_unwrapped call
        // performs a fresh unwrap instead of returning stale key material.
        self.unwrapped_cache.validate_cache(uid, object).await?;
        Ok(())
    }

    /// Update the state of an object in the database.
    pub async fn update_state(&self, uid: &str, state: State) -> DbResult<()> {
        self.record("update_state", async move {
            let db = self.get_object_store(uid).await?;
            Ok(db.update_state(uid, state).await?)
        })
        .await?;
        self.object_cache.invalidate(uid).await;
        Ok(())
    }

    /// Delete an object from the database.
    pub async fn delete(&self, uid: &str) -> DbResult<()> {
        self.record("delete", async move {
            let db = self.get_object_store(uid).await?;
            Ok(db.delete(uid).await?)
        })
        .await?;
        self.object_cache.invalidate(uid).await;
        self.unwrapped_cache.clear_cache(uid).await;
        Ok(())
    }

    /// Test if an object identified by its `uid` is currently owned by `owner`
    pub async fn is_object_owned_by(&self, uid: &str, owner: &UserId) -> DbResult<bool> {
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
        user: &UserId,
        user_must_be_owner: bool,
        vendor_id: &str,
    ) -> DbResult<Vec<(String, State, Attributes)>> {
        let start = Instant::now();
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
        if let Some(ref rec) = self.recorder {
            rec.record_operation("find", self.kind, "success", start.elapsed().as_secs_f64());
        }
        Ok(results)
    }

    /// Return uid, state and attributes of ALL objects (bypasses all user filtering).
    ///
    /// Only called from the Administrator/CryptoOfficer Locate path.
    /// Callers must have already verified the requesting user has the required role.
    pub async fn find_all(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<State>,
        vendor_id: &str,
    ) -> DbResult<Vec<(String, State, Attributes)>> {
        let map = self.objects.read().await;
        let mut results: Vec<(String, State, Attributes)> = Vec::new();
        for db in map.values() {
            results.extend(
                db.find_all(researched_attributes, state, vendor_id)
                    .await
                    .unwrap_or_default(),
            );
        }
        Ok(results)
    }

    /// Find a certificate object by its X.509 serial number.
    ///
    /// Searches across all states so OCSP responses correctly distinguish
    /// `good` (Active/PreActive), `revoked` (Compromised/Deactivated/Destroyed/DestroyedCompromised),
    /// and `unknown` (not found).
    ///
    /// Returns `(uid, state)` for the first match or `None` if not found.
    pub async fn find_certificate_by_serial(
        &self,
        issuer_certificate_uid: &str,
        serial_hex: &str,
        vendor_id: &str,
    ) -> DbResult<Option<(String, cosmian_kmip::kmip_0::kmip_types::State)>> {
        use cosmian_kmip::kmip_2_1::{
            kmip_attributes::Attributes,
            kmip_objects::ObjectType,
            kmip_types::{LinkType, LinkedObjectIdentifier},
        };

        // Build search filter: certificate objects linked to the given issuer.
        let mut search_attrs = Attributes {
            object_type: Some(ObjectType::Certificate),
            ..Attributes::default()
        };
        search_attrs.link = Some(vec![cosmian_kmip::kmip_2_1::kmip_types::Link {
            link_type: LinkType::CertificateLink,
            linked_object_identifier: LinkedObjectIdentifier::TextString(
                issuer_certificate_uid.to_owned(),
            ),
        }]);

        // Search every lifecycle state so OCSP can report accurate status.
        for state in [
            cosmian_kmip::kmip_0::kmip_types::State::Active,
            cosmian_kmip::kmip_0::kmip_types::State::PreActive,
            cosmian_kmip::kmip_0::kmip_types::State::Compromised,
            cosmian_kmip::kmip_0::kmip_types::State::Deactivated,
            cosmian_kmip::kmip_0::kmip_types::State::Destroyed,
            cosmian_kmip::kmip_0::kmip_types::State::Destroyed_Compromised,
        ] {
            let candidates = self
                .find_all(Some(&search_attrs), Some(state), vendor_id)
                .await?;

            for (uid, obj_state, _attrs) in candidates {
                if let Some(owm) = self.retrieve_object(&uid).await? {
                    let found_serial = extract_serial_hex_from_object(owm.object());
                    if let Some(s) = found_serial {
                        if s.eq_ignore_ascii_case(serial_hex) {
                            return Ok(Some((uid, obj_state)));
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    /// Find a certificate object by an exact match on its DER-encoded bytes.
    ///
    /// Unlike [`Self::find_certificate_by_serial`], this does **not** require a known
    /// issuer UID: it scans every certificate object across all lifecycle states and
    /// compares `certificate_value` byte-for-byte against `der_bytes`. This lets
    /// callers determine whether an *externally supplied* certificate (e.g. raw DER
    /// bytes in a KMIP `Validate` request, with no `UniqueIdentifier` reference)
    /// happens to be one the KMS already tracks, and if so, its current state.
    ///
    /// Returns `(uid, state)` for the first match or `None` if no certificate object
    /// in the KMS has identical DER bytes.
    pub async fn find_certificate_state_by_der(
        &self,
        der_bytes: &[u8],
        vendor_id: &str,
    ) -> DbResult<Option<(String, cosmian_kmip::kmip_0::kmip_types::State)>> {
        use cosmian_kmip::kmip_2_1::{kmip_attributes::Attributes, kmip_objects::ObjectType};

        let search_attrs = Attributes {
            object_type: Some(ObjectType::Certificate),
            ..Attributes::default()
        };

        // Search every lifecycle state so the caller can distinguish an
        // Active/PreActive certificate from a Compromised/Deactivated/Destroyed one.
        for state in [
            cosmian_kmip::kmip_0::kmip_types::State::Active,
            cosmian_kmip::kmip_0::kmip_types::State::PreActive,
            cosmian_kmip::kmip_0::kmip_types::State::Compromised,
            cosmian_kmip::kmip_0::kmip_types::State::Deactivated,
            cosmian_kmip::kmip_0::kmip_types::State::Destroyed,
            cosmian_kmip::kmip_0::kmip_types::State::Destroyed_Compromised,
        ] {
            let candidates = self
                .find_all(Some(&search_attrs), Some(state), vendor_id)
                .await?;

            for (uid, obj_state, _attrs) in candidates {
                if let Some(owm) = self.retrieve_object(&uid).await? {
                    if let cosmian_kmip::kmip_2_1::kmip_objects::Object::Certificate(cert) =
                        owm.object()
                    {
                        if cert.certificate_value.as_slice() == der_bytes {
                            return Ok(Some((uid, obj_state)));
                        }
                    }
                }
            }
        }

        Ok(None)
    }

    /// Return (uid, state, attributes) for every object wrapped by the given wrapping key.
    pub async fn find_wrapped_by(
        &self,
        wrapping_key_uid: &str,
        user: &UserId,
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
    /// rotation instant is ≤ `now`. Returns `(uid, owner)` pairs.
    pub async fn find_due_for_rotation(
        &self,
        now: time::OffsetDateTime,
    ) -> DbResult<Vec<(String, String)>> {
        let map = self.objects.read().await;
        let mut results: Vec<(String, String)> = Vec::new();
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
        owner: &UserId,
    ) -> DbResult<Vec<(String, Attributes)>> {
        let map = self.objects.read().await;
        let mut results: Vec<(String, Attributes)> = Vec::new();
        for db in map.values() {
            results.extend(
                db.find_by_rotate_name(name, generation, owner)
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
    /// * `user` - A `UserId` representing the user performing the operations.
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
        user: &UserId,
        operations: &[AtomicOperation],
    ) -> DbResult<Vec<String>> {
        if operations.is_empty() {
            return Ok(vec![]);
        }
        for op in operations {
            if let AtomicOperation::Create((uid, ..)) = op {
                reject_reserved_uid(uid)?;
            }
        }
        #[expect(clippy::indexing_slicing)]
        let first_op = &operations[0];
        let first_uid = first_op.get_object_uid();
        let db = self.get_object_store(first_uid).await?;
        let ids = self
            .record("atomic", async move {
                db.atomic(user, operations).await.map_err(DbError::from)
            })
            .await?;
        // invalidate of clear cache for all operations
        for op in operations {
            match op {
                AtomicOperation::Create((uid, _owner, object, ..)) => {
                    self.object_cache.invalidate(uid).await;
                    self.unwrapped_cache.validate_cache(uid, object).await?;
                }
                AtomicOperation::UpdateObject((uid, object, ..))
                | AtomicOperation::Upsert((uid, object, ..)) => {
                    self.object_cache.invalidate(uid).await;
                    self.unwrapped_cache.validate_cache(uid, object).await?;
                }
                AtomicOperation::Delete(uid) => {
                    self.object_cache.invalidate(uid).await;
                    self.unwrapped_cache.clear_cache(uid).await;
                }
                AtomicOperation::UpdateState((uid, _)) => {
                    // Evict the stale object so the new lifecycle state is
                    // visible immediately on the next retrieve_object call.
                    self.object_cache.invalidate(uid).await;
                }
            }
        }
        Ok(ids)
    }
}

/// Extract the X.509 serial number as an uppercase hex string from a KMS `Object`.
///
/// Returns `None` if the object is not a certificate or DER parsing fails.
///
/// The output **must** exactly match the hex string the OCSP crypto layer computes
/// for the same certificate (`extract_serial_hex` in `cosmian_kms_crypto::openssl::ocsp`,
/// which converts the request's `ASN1_INTEGER` via `BN_bn2hex`), or `find_certificate_by_serial`
/// silently fails to match and OCSP incorrectly reports `unknown` for a real, issued
/// certificate. `BN_bn2hex` strips whole leading zero *bytes* (already true of
/// `to_bytes_be()`'s minimal big-endian output) but always prints both hex digits of
/// the remaining most-significant byte — so a serial such as `0x0A…` renders as `"0A…"`,
/// not `"A…"`. Do **not** strip leading zero *characters* here: about 1-in-16 randomly
/// generated serial numbers have a leading nibble of `0`, and naively trimming all
/// leading `'0'` characters (rather than only whole zero bytes) desynchronises this
/// hex string from the OCSP layer's for exactly those certificates.
fn extract_serial_hex_from_object(object: &Object) -> Option<String> {
    const UPPER_HEX_DIGITS: &[u8; 16] = b"0123456789ABCDEF";

    let cert_bytes = match object {
        Object::Certificate(c) => &c.certificate_value,
        _ => return None,
    };
    // Use x509-parser to extract the serial number without depending on openssl here.
    let (_, parsed) = X509Certificate::from_der(cert_bytes).ok()?;
    // `to_bytes_be()` already yields the minimal big-endian representation (no leading
    // zero bytes), matching the canonical form OpenSSL's BIGNUM uses internally.
    let serial_bytes = parsed.serial.to_bytes_be();
    serial_bytes.iter().try_fold(
        String::with_capacity(serial_bytes.len().saturating_mul(2)),
        |mut output, byte| {
            let upper = UPPER_HEX_DIGITS.get(usize::from(*byte >> 4)).copied()?;
            let lower = UPPER_HEX_DIGITS.get(usize::from(*byte & 0x0F)).copied()?;
            output.push(char::from(upper));
            output.push(char::from(lower));
            Some(output)
        },
    )
}

#[cfg(test)]
#[expect(clippy::expect_used, clippy::panic)]
mod tests {
    use std::{
        collections::{HashMap, HashSet},
        num::NonZeroUsize,
        sync::{Arc, Mutex},
        time::Duration,
    };

    use cosmian_kmip::{
        kmip_0::kmip_types::CertificateType,
        kmip_2_1::{
            extra::VENDOR_ID_COSMIAN, kmip_attributes::Attributes,
            kmip_types::CryptographicAlgorithm, requests::create_symmetric_key_kmip_object,
        },
    };
    use cosmian_kms_interfaces::{AtomicOperation, UserId};
    use tempfile::TempDir;

    use super::{Database, Object, extract_serial_hex_from_object};
    use crate::core::{
        DbMetricsRecorder, MainDbKind, MainDbParams, database_objects::reject_reserved_uid,
    };

    async fn test_db() -> Database {
        let tmp = TempDir::new().expect("Failed to create temp dir");
        Database::instantiate(
            &MainDbParams::Sqlite(tmp.path().to_path_buf(), None),
            false,
            HashMap::new(),
            Duration::from_secs(1),
            NonZeroUsize::new(100).expect("100 is non-zero"),
            None,
            false,
            None,
            None,
        )
        .await
        .expect("Failed to instantiate in-memory database")
    }

    /// Direct unit coverage of the reserved-uid check (issue #909).
    #[test]
    fn test_reject_reserved_uid_direct() {
        assert!(reject_reserved_uid("*").is_err());
        reject_reserved_uid("some-real-uid").expect("real uid must be accepted");
    }

    /// `Database::create` must refuse to create an object with the reserved uid `"*"`.
    ///
    /// See `repro_issue_909_get_on_star_bypasses_import_gate` for the end-to-end
    /// escalation this prevents: a real object at uid `"*"` collides with the
    /// internal sentinel used to store the global `Create` right.
    #[tokio::test]
    async fn test_create_rejects_reserved_uid() {
        let db = test_db().await;
        let owner = UserId::from("owner@example.com");
        let key = create_symmetric_key_kmip_object(
            VENDOR_ID_COSMIAN,
            &[0_u8; 32],
            &Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                ..Default::default()
            },
        )
        .expect("failed to build test key object");
        let attributes = key.attributes().expect("key has attributes").clone();

        let result = db
            .create(
                Some("*".to_owned()),
                &owner,
                &key,
                &attributes,
                &HashSet::new(),
                "",
            )
            .await;
        let err = result.expect_err("creating an object with uid '*' must fail");
        assert!(
            err.to_string().contains("reserved"),
            "expected a reserved-identifier error, got: {err}"
        );
    }

    /// `Database::atomic` must refuse a `Create` operation targeting the reserved uid `"*"`.
    #[tokio::test]
    async fn test_atomic_rejects_reserved_uid() {
        let db = test_db().await;
        let owner = UserId::from("owner@example.com");
        let key = create_symmetric_key_kmip_object(
            VENDOR_ID_COSMIAN,
            &[0_u8; 32],
            &Attributes {
                cryptographic_algorithm: Some(CryptographicAlgorithm::AES),
                ..Default::default()
            },
        )
        .expect("failed to build test key object");
        let attributes = key.attributes().expect("key has attributes").clone();

        let operations = vec![AtomicOperation::Create((
            "*".to_owned(),
            owner.clone(),
            key,
            attributes,
            HashSet::new(),
        ))];
        let result = db.atomic(&owner, &operations).await;
        let err = result.expect_err("atomic Create with uid '*' must fail");
        assert!(
            err.to_string().contains("reserved"),
            "expected a reserved-identifier error, got: {err}"
        );
    }

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
            None,  // cache_max_ttl
            false, // disable_unwrapped_cache
            None,  // recorder
            None,  // ceremony_keys
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
            None,
            false,
            Some(recorder_arc),
            None,
        )
        .await
        .expect("Failed to instantiate database with mock recorder");

        // list_user_operations_granted: exercises the permissions facade path.
        drop(
            db.list_user_operations_granted(&UserId::from("test_user"))
                .await,
        );

        // retrieve_object on a non-existent uid → Ok(None) → outcome "success"
        drop(db.retrieve_object("non-existent-uid-xyz").await);

        // find with no filters → Ok([]) → outcome "success"
        drop(
            db.find(None, None, &UserId::from("test_user"), false, "")
                .await,
        );

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

    /// Build a minimal self-signed X.509 certificate DER with an explicit serial number.
    fn cert_der_with_serial(serial_bytes: &[u8]) -> Vec<u8> {
        use openssl::{
            asn1::Asn1Integer,
            bn::BigNum,
            hash::MessageDigest,
            pkey::PKey,
            x509::{X509Builder, X509NameBuilder},
        };

        let rsa = openssl::rsa::Rsa::generate(2048).expect("RSA keygen");
        let pkey = PKey::from_rsa(rsa).expect("PKey");
        let mut nb = X509NameBuilder::new().expect("X509NameBuilder");
        nb.append_entry_by_text("CN", "serial-hex-test")
            .expect("CN");
        let name = nb.build();

        let mut b = X509Builder::new().expect("X509Builder");
        b.set_subject_name(&name).expect("subject");
        b.set_issuer_name(&name).expect("issuer");
        b.set_pubkey(&pkey).expect("pubkey");
        let not_before = openssl::asn1::Asn1Time::days_from_now(0).expect("not_before");
        let not_after = openssl::asn1::Asn1Time::days_from_now(365).expect("not_after");
        b.set_not_before(&not_before).expect("set_not_before");
        b.set_not_after(&not_after).expect("set_not_after");
        let serial = Asn1Integer::from_bn(BigNum::from_slice(serial_bytes).expect("bn").as_ref())
            .expect("serial");
        b.set_serial_number(&serial).expect("set_serial");
        b.sign(&pkey, MessageDigest::sha256()).expect("sign");
        b.build().to_der().expect("to_der")
    }

    /// Regression test: `extract_serial_hex_from_object` must produce the exact same
    /// hex string as the OCSP crypto layer's `extract_serial_hex` (which goes through
    /// OpenSSL's `ASN1_INTEGER_to_BN` + `BN_bn2hex`). `BN_bn2hex` strips whole leading
    /// zero *bytes* but always prints both hex digits of the remaining most-significant
    /// byte, so a serial number whose leading byte is e.g. `0x0A` must render as `"0A…"`,
    /// not `"A…"`. Naively trimming all leading `'0'` characters previously desynced
    /// this from the OCSP layer for ~1-in-16 randomly generated serial numbers, making
    /// `find_certificate_by_serial` (and therefore OCSP) intermittently report a
    /// perfectly valid, just-issued certificate as `unknown`.
    #[test]
    fn test_extract_serial_hex_preserves_leading_zero_nibble() {
        let der = cert_der_with_serial(&[0x0A, 0xBB, 0xCC, 0xDD, 0xEE]);
        let object = Object::Certificate(cosmian_kmip::kmip_2_1::kmip_objects::Certificate {
            certificate_type: CertificateType::X509,
            certificate_value: der,
        });
        let hex = extract_serial_hex_from_object(&object).expect("extract serial hex");
        assert_eq!(
            hex, "0ABBCCDDEE",
            "leading zero nibble of the most-significant byte must be preserved"
        );
    }

    /// Sanity check: a serial with no leading zero nibble round-trips unchanged.
    #[test]
    fn test_extract_serial_hex_no_leading_zero() {
        let der = cert_der_with_serial(&[0x7A, 0xBB, 0xCC, 0xDD, 0xEE]);
        let object = Object::Certificate(cosmian_kmip::kmip_2_1::kmip_objects::Certificate {
            certificate_type: CertificateType::X509,
            certificate_value: der,
        });
        let hex = extract_serial_hex_from_object(&object).expect("extract serial hex");
        assert_eq!(hex, "7ABBCCDDEE");
    }

    /// `find_certificate_state_by_der` must locate a certificate object by exact DER
    /// bytes alone — no issuer UID needed — and report its current lifecycle state.
    /// This is the lookup used by the KMIP `Validate` operation for certificates
    /// supplied as raw bytes (no `UniqueIdentifier` reference in the request).
    #[tokio::test]
    async fn test_find_certificate_state_by_der_finds_known_certificate() {
        use cosmian_kmip::kmip_2_1::kmip_objects::{Certificate, ObjectType};

        let db = test_db().await;
        let owner = UserId::from("owner@example.com");
        let der = cert_der_with_serial(&[0x11, 0x22, 0x33, 0x44]);
        let cert_object = Object::Certificate(Certificate {
            certificate_type: CertificateType::X509,
            certificate_value: der.clone(),
        });
        let attributes = Attributes {
            object_type: Some(ObjectType::Certificate),
            ..Default::default()
        };
        let uid = db
            .create(None, &owner, &cert_object, &attributes, &HashSet::new(), "")
            .await
            .expect("failed to create certificate object");

        let found = Box::pin(db.find_certificate_state_by_der(&der, VENDOR_ID_COSMIAN))
            .await
            .expect("find_certificate_state_by_der must not error");
        let (found_uid, found_state) = found.expect("certificate must be found by exact DER match");
        assert_eq!(found_uid, uid);
        assert_eq!(
            found_state,
            cosmian_kmip::kmip_0::kmip_types::State::PreActive,
            "freshly created certificate defaults to PreActive"
        );
    }

    /// A certificate never stored in the KMS must not match any existing record,
    /// even when other certificates are present.
    #[tokio::test]
    async fn test_find_certificate_state_by_der_returns_none_for_unknown_certificate() {
        use cosmian_kmip::kmip_2_1::kmip_objects::{Certificate, ObjectType};

        let db = test_db().await;
        let owner = UserId::from("owner@example.com");
        let known_der = cert_der_with_serial(&[0x55, 0x66, 0x77, 0x88]);
        let cert_object = Object::Certificate(Certificate {
            certificate_type: CertificateType::X509,
            certificate_value: known_der,
        });
        let attributes = Attributes {
            object_type: Some(ObjectType::Certificate),
            ..Default::default()
        };
        db.create(None, &owner, &cert_object, &attributes, &HashSet::new(), "")
            .await
            .expect("failed to create certificate object");

        let unknown_der = cert_der_with_serial(&[0x99, 0xAA, 0xBB, 0xCC]);
        let found = Box::pin(db.find_certificate_state_by_der(&unknown_der, VENDOR_ID_COSMIAN))
            .await
            .expect("find_certificate_state_by_der must not error");
        assert!(
            found.is_none(),
            "a never-stored certificate must not match any KMS record"
        );
    }
}
