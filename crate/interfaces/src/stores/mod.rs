pub(crate) mod object_with_metadata;
mod objects_store;
mod permissions_store;

pub use object_with_metadata::ObjectWithMetadata;
pub use objects_store::{AtomicOperation, ObjectsStore};
pub use permissions_store::PermissionsStore;

pub trait SessionParams: Sync + Send {}

impl dyn SessionParams + 'static {
    /// Downcast the `SessionParams` to a concrete type.
    #[inline]
    #[allow(unsafe_code)]
    pub fn downcast_ref<T: SessionParams + 'static>(&self) -> &T {
        unsafe { &*std::ptr::from_ref::<dyn SessionParams>(self).cast::<T>() }
    }
}
