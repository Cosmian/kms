use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use cosmian_kmip::{
    kmip_0::kmip_types::State,
    kmip_2_1::{kmip_attributes::Attributes, kmip_objects::Object},
};
use cosmian_kms_interfaces::{AtomicOperation, ObjectWithMetadata, ObjectsStore};

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
    /// If the `uid` contains a prefix separated by "::", it will look for a store registered with that prefix.
    /// If no prefix is found, it will return the default object store.
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
        // split the uid on the first ::
        let splits = uid.split_once("::");
        Ok(match splits {
            Some((prefix, _rest)) => self
                .objects
                .read()
                .await
                .get(prefix)
                .ok_or_else(|| {
                    DbError::InvalidRequest(format!(
                        "No object store available for UIDs prefixed with: {prefix}"
                    ))
                })?
                .clone(),
            None => self
                .objects
                .read()
                .await
                .get("")
                .ok_or_else(|| {
                    DbError::InvalidRequest("No default object store available".to_owned())
                })?
                .clone(),
        })
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
        let db = self
            .get_object_store(uid.as_deref().unwrap_or_default())
            .await?;
        let uid = db.create(uid, owner, object, attributes, tags).await?;
        // Clear the cache for the unwrapped key (if any)
        self.unwrapped_cache.validate_cache(&uid, object).await;
        Ok(uid)
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
        // retrieve the object
        let db = self.get_object_store(uid).await?;
        Ok(db.retrieve(uid).await?)
    }

    /// Retrieve the tags of the object with the given `uid`
    pub async fn retrieve_tags(&self, uid: &str) -> DbResult<HashSet<String>> {
        let db = self.get_object_store(uid).await?;
        Ok(db.retrieve_tags(uid).await?)
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
        let db = self.get_object_store(uid).await?;
        db.update_object(uid, object, attributes, tags).await?;
        self.unwrapped_cache.validate_cache(uid, object).await;
        Ok(())
    }

    /// Update the state of an object in the database.
    pub async fn update_state(&self, uid: &str, state: State) -> DbResult<()> {
        let db = self.get_object_store(uid).await?;
        Ok(db.update_state(uid, state).await?)
    }

    /// Delete an object from the database.
    pub async fn delete(&self, uid: &str) -> DbResult<()> {
        let db = self.get_object_store(uid).await?;
        db.delete(uid).await?;
        self.unwrapped_cache.clear_cache(uid).await;
        Ok(())
    }

    /// Test if an object identified by its `uid` is currently owned by `owner`
    pub async fn is_object_owned_by(&self, uid: &str, owner: &str) -> DbResult<bool> {
        let db = self.get_object_store(uid).await?;
        Ok(db.is_object_owned_by(uid, owner).await?)
    }

    pub async fn list_uids_for_tags(&self, tags: &HashSet<String>) -> DbResult<HashSet<String>> {
        let db_map = self.objects.read().await;
        let mut results = HashSet::new();
        for (_prefix, db) in db_map.iter() {
            results.extend(db.list_uids_for_tags(tags).await?);
        }
        Ok(results)
    }

    /// Return uid, state and attributes of the object identified by its owner,
    /// and possibly by its attributes and/or its `state`
    pub async fn find(
        &self,
        researched_attributes: Option<&Attributes>,
        state: Option<State>,
        user: &str,
        user_must_be_owner: bool,
    ) -> DbResult<Vec<(String, State, Attributes)>> {
        let map = self.objects.read().await;
        let mut results: Vec<(String, State, Attributes)> = Vec::new();
        for (_prefix, db) in map.iter() {
            results.extend(
                db.find(researched_attributes, state, user, user_must_be_owner)
                    .await
                    .unwrap_or(vec![]),
            );
        }
        Ok(results)
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
        #[expect(clippy::indexing_slicing)]
        let first_op = &operations[0];
        let first_uid = first_op.get_object_uid();
        let db = self.get_object_store(first_uid).await?;
        let ids = db.atomic(user, operations).await?;
        // invalidate of clear cache for all operations
        for op in operations {
            match op {
                AtomicOperation::Create((uid, object, ..))
                | AtomicOperation::UpdateObject((uid, object, ..))
                | AtomicOperation::Upsert((uid, object, ..)) => {
                    self.unwrapped_cache.validate_cache(uid, object).await;
                }
                AtomicOperation::Delete(uid) => {
                    self.unwrapped_cache.clear_cache(uid).await;
                }
                AtomicOperation::UpdateState(_) => {}
            }
        }
        Ok(ids)
    }
}
