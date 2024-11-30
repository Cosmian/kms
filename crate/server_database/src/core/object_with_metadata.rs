use std::fmt::{self, Display, Formatter};

use cosmian_kmip::kmip::{
    kmip_objects::Object,
    kmip_types::{Attributes, StateEnumeration},
};

/// An object with its metadata such as owner, permissions and state
///
/// This is the main representation of objects through the KMS server.
/// Mpe APIs should use this representation.
#[derive(Clone)]
pub struct ObjectWithMetadata {
    id: String,
    // this is the object as registered in the DN. For a key, it may be wrapped or unwrapped
    object: Object,
    owner: String,
    state: StateEnumeration,
    attributes: Attributes,
}

impl ObjectWithMetadata {
    #[must_use]
    pub const fn new(
        id: String,
        object: Object,
        owner: String,
        state: StateEnumeration,
        attributes: Attributes,
    ) -> Self {
        Self {
            id,
            object,
            owner,
            state,
            attributes,
        }
    }

    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    #[must_use]
    pub const fn object(&self) -> &Object {
        &self.object
    }

    /// Set a new object, clearing the cached unwrapped version
    /// if any
    pub fn set_object(&mut self, object: Object) {
        self.object = object;
    }

    /// Return a mutable borrow to the Object
    /// Do not use this to set a new object or make sure you clear
    /// the cached unwrapped object
    pub fn object_mut(&mut self) -> &mut Object {
        &mut self.object
    }

    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    #[must_use]
    pub const fn state(&self) -> StateEnumeration {
        self.state
    }

    #[must_use]
    pub const fn attributes(&self) -> &Attributes {
        &self.attributes
    }

    pub fn attributes_mut(&mut self) -> &mut Attributes {
        &mut self.attributes
    }
}

impl Display for ObjectWithMetadata {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ObjectWithMetadata {{ id: {}, object: {}, owner: {}, state: {}, attributes: {:?} }}",
            self.id, self.object, self.owner, self.state, self.attributes
        )
    }
}
