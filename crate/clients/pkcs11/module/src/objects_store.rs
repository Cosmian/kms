#![allow(clippy::as_conversions)]

use std::{
    collections::HashMap,
    fmt::Display,
    sync::{self, Arc, Weak},
};

use cosmian_logger::debug;
use pkcs11_sys::CK_OBJECT_HANDLE;

use crate::{
    ModuleError, ModuleResult,
    core::object::{Object, ObjectType},
};

/// The objects store is a global store for all the objects that are fetched by the PKCS#11 module.
/// These objects are visible across all the sessions and are not session-specific.
pub(crate) static OBJECTS_STORE: std::sync::LazyLock<sync::RwLock<ObjectsStore>> =
    std::sync::LazyLock::new(Default::default);

#[derive(Debug)]
pub struct ObjectsStore {
    /// The PKCS#11 objects manipulated by this store; the key is the remote id.
    pub objects: HashMap<String, (Arc<Object>, CK_OBJECT_HANDLE)>,
    pub ids: HashMap<CK_OBJECT_HANDLE, Weak<Object>>,
    /// Monotonically increasing counter for the next handle to assign to a *new* object.
    ///
    /// Must never be derived from `self.ids.len()`: under concurrent
    /// insert/destroy (e.g. two sessions each generating and destroying an ephemeral
    /// key), the map size can shrink between a `C_GenerateKey` and its matching
    /// `C_DestroyObject` on another thread, causing two *simultaneously live* objects
    /// to be assigned the same handle. Assigning that reused handle overwrites the
    /// still-live object's `ids` entry, and a later `C_DestroyObject` for that
    /// original handle then fails with `CKR_OBJECT_HANDLE_INVALID` because its
    /// entry was silently replaced. A strictly increasing counter, incremented only
    /// when a brand-new handle is minted, guarantees no two live objects ever share
    /// a handle regardless of destroy ordering (`OBJECTS_STORE`'s single `RwLock`
    /// already serializes each individual `upsert`/`remove_by_handle` call).
    next_handle: CK_OBJECT_HANDLE,
}

impl Default for ObjectsStore {
    fn default() -> Self {
        Self {
            objects: HashMap::new(),
            ids: HashMap::new(),
            next_handle: 1, // start from 1, 0 is reserved for invalid handle
        }
    }
}

impl ObjectsStore {
    /// Insert the object
    pub(crate) fn upsert(&mut self, object: Arc<Object>) -> CK_OBJECT_HANDLE {
        // check if the object already exists in the store by searching it by ID
        let id = object.remote_id();
        if let Some((stored, handle)) = self.objects.get_mut(&id) {
            debug!("STORE: updating object with remote id: {id} and handle: {handle}");
            *stored = object;
            self.ids.insert(*handle, Arc::downgrade(stored));
            return *handle;
        }
        let handle = self.next_handle;
        self.next_handle += 1;
        debug!("STORE: inserting new object with remote id: {id} and handle: {handle}");
        self.ids.insert(handle, Arc::downgrade(&object));
        self.objects.insert(id, (object, handle));
        handle
    }

    pub(crate) fn get_using_handle(&self, handle: CK_OBJECT_HANDLE) -> Option<Arc<Object>> {
        let weak = self.ids.get(&handle)?;
        weak.upgrade()
    }

    pub(crate) fn get_using_id(&self, id: &str) -> Option<(Arc<Object>, CK_OBJECT_HANDLE)> {
        self.objects.get(id).cloned()
    }

    /// Get Using he Object Type
    pub(crate) fn get_using_type(
        &self,
        object_type: &ObjectType,
    ) -> Vec<(Arc<Object>, CK_OBJECT_HANDLE)> {
        self.objects
            .iter()
            .filter(|(_, (object, _))| &object.object_type() == object_type)
            .map(|(_, (object, handle))| (object.clone(), *handle))
            .collect()
    }

    pub(crate) fn remove_by_handle(&mut self, handle: CK_OBJECT_HANDLE) -> ModuleResult<()> {
        self.ids.remove(&handle).ok_or_else(|| {
            ModuleError::Default(
                "Unexpected failure while removing handle from object store".to_owned(),
            )
        })?;
        // Remove the object from the store
        self.objects.retain(|_, (_, h)| *h != handle);
        Ok(())
    }
}

impl Display for ObjectsStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ObjectsStore {{ objects: {:#?} }}", self.objects)
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::ObjectsStore;
    use crate::core::object::{Object, ObjectType};

    fn profile(id: u32) -> Arc<Object> {
        Arc::new(Object::Profile(id.into()))
    }

    #[test]
    fn upsert_assigns_distinct_handles_starting_at_one() {
        let mut store = ObjectsStore::default();
        let first = store.upsert(profile(1));
        let second = store.upsert(profile(2));
        assert_eq!(first, 1, "handle 0 is reserved as invalid");
        assert_ne!(first, second);
        assert_eq!(store.objects.len(), 2);
        assert_eq!(store.ids.len(), 2);
    }

    #[test]
    fn upsert_of_known_remote_id_keeps_handle_and_replaces_object() {
        let mut store = ObjectsStore::default();
        let handle = store.upsert(profile(7));
        let replacement = profile(7);
        assert_eq!(store.upsert(replacement.clone()), handle);
        assert_eq!(store.objects.len(), 1);
        let stored = store.get_using_handle(handle);
        assert!(stored.is_some_and(|stored| Arc::ptr_eq(&stored, &replacement)));
    }

    #[test]
    fn lookup_by_handle_id_and_type() {
        let mut store = ObjectsStore::default();
        let object = profile(3);
        let handle = store.upsert(object.clone());

        assert!(
            store
                .get_using_handle(handle)
                .is_some_and(|found| Arc::ptr_eq(&found, &object))
        );
        assert!(
            store.get_using_id(&object.remote_id()).is_some_and(
                |(found, found_handle)| Arc::ptr_eq(&found, &object) && found_handle == handle
            )
        );
        assert!(store.get_using_handle(handle + 100).is_none());
        assert!(store.get_using_id("unknown").is_none());
        assert_eq!(store.get_using_type(&ObjectType::Profile).len(), 1);
        assert!(store.get_using_type(&ObjectType::PrivateKey).is_empty());
    }

    #[test]
    fn removed_handles_are_never_reused_for_new_objects() {
        let mut store = ObjectsStore::default();
        let first = store.upsert(profile(1));
        let second = store.upsert(profile(2));

        assert!(store.remove_by_handle(first).err().is_none());
        assert_eq!(store.objects.len(), 1);
        assert!(store.get_using_handle(first).is_none());

        // A brand-new object must not be given the freed handle nor the live one.
        let third = store.upsert(profile(3));
        assert_ne!(third, first);
        assert_ne!(third, second);
        assert!(store.get_using_handle(second).is_some());
    }

    #[test]
    fn removing_an_unknown_handle_fails() {
        let mut store = ObjectsStore::default();
        assert!(store.remove_by_handle(42).err().is_some());
    }
}
