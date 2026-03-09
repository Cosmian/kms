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

#[derive(Default, Debug)]
pub struct ObjectsStore {
    /// The PKCS#11 objects manipulated by this store; the key is the remote id.
    pub objects: HashMap<String, (Arc<Object>, CK_OBJECT_HANDLE)>,
    pub ids: HashMap<CK_OBJECT_HANDLE, Weak<Object>>,
}

impl ObjectsStore {
    /// Insert the object
    pub(crate) fn upsert(&mut self, object: Arc<Object>) -> CK_OBJECT_HANDLE {
        // check if the object already exists in the store by searching it by ID
        let id = object.remote_id();
        if let Some((object, handle)) = self.objects.get_mut(&id) {
            debug!("STORE: updating object with remote id: {id} and handle: {handle}");
            *object = object.clone();
            self.ids.insert(*handle, Arc::downgrade(object));
            return *handle;
        }
        let handle = if self.ids.is_empty() {
            1 // start from 1, 0 is reserved for invalid handle
        } else {
            1 + self.ids.len() as CK_OBJECT_HANDLE
        };
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

    /// The number of objects in the store
    #[expect(dead_code)]
    pub(crate) fn len(&self) -> usize {
        self.objects.len()
    }
}

impl Display for ObjectsStore {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "ObjectsStore {{ objects: {:#?} }}", self.objects)
    }
}
