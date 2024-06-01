use std::{
    collections::HashMap,
    sync,
    sync::{Arc, Weak},
};

use once_cell::sync::Lazy;
use pkcs11_sys::CK_OBJECT_HANDLE;
use tracing::debug;

use crate::{
    core::object::{Object, ObjectType},
    MResult,
};

/// The objects store is a global store for all the objects that are fetched by the PKCS#11 module.
/// These objects are visible across all the sessions and are not session-specific.
pub static OBJECTS_STORE: Lazy<sync::RwLock<ObjectsStore>> = Lazy::new(Default::default);

#[derive(Default)]
pub struct ObjectsStore {
    /// The PKCS#11 objects manipulated by this store; the key is the remote id.
    pub objects: HashMap<String, (Arc<Object>, CK_OBJECT_HANDLE)>,
    pub ids: HashMap<CK_OBJECT_HANDLE, Weak<Object>>,
}

impl ObjectsStore {
    /// Insert the object
    pub fn upsert(&mut self, object: Arc<Object>) -> MResult<CK_OBJECT_HANDLE> {
        // check if the object already exists in the store by searching it by ID
        let id = object.remote_id();
        if let Some((object, handle)) = self.objects.get_mut(&id) {
            debug!("STORE: updating object with remote id: {id} and handle: {handle}");
            *object = object.clone();
            self.ids.insert(*handle, Arc::downgrade(object));
            return Ok(*handle);
        }
        let handle = self.ids.len() as CK_OBJECT_HANDLE;
        debug!("STORE: inserting new object with remote id: {id} and handle: {handle}");
        self.ids.insert(handle, Arc::downgrade(&object));
        self.objects.insert(id, (object, handle));
        Ok(handle)
    }

    pub fn get_using_handle(&self, handle: CK_OBJECT_HANDLE) -> Option<Arc<Object>> {
        self.ids.get(&handle).and_then(|weak| weak.upgrade())
    }

    pub fn get_using_id(&self, id: &str) -> Option<(Arc<Object>, CK_OBJECT_HANDLE)> {
        self.objects.get(id).cloned()
    }

    /// Get Using he Object Type
    pub fn get_using_type(&self, object_type: ObjectType) -> Vec<(Arc<Object>, CK_OBJECT_HANDLE)> {
        self.objects
            .iter()
            .filter(|(_, (object, _))| object.object_type() == object_type)
            .map(|(_, (object, handle))| (object.clone(), *handle))
            .collect()
    }

    /// The number of objects in the store
    pub fn len(&self) -> usize {
        self.objects.len()
    }
}
