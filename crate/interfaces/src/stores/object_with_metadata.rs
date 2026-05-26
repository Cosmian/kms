use std::fmt::{self, Display, Formatter};

use cosmian_kmip::{
    kmip_0::kmip_types::State,
    kmip_2_1::{
        kmip_attributes::Attributes, kmip_objects::Object, kmip_types::CryptographicAlgorithm,
    },
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
    state: State,
    attributes: Attributes,
}

impl ObjectWithMetadata {
    #[must_use]
    pub const fn new(
        id: String,
        object: Object,
        owner: String,
        state: State,
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
    pub const fn object_mut(&mut self) -> &mut Object {
        &mut self.object
    }

    #[must_use]
    pub fn owner(&self) -> &str {
        &self.owner
    }

    #[must_use]
    pub const fn state(&self) -> State {
        self.state
    }

    #[must_use]
    pub const fn attributes(&self) -> &Attributes {
        &self.attributes
    }

    pub const fn attributes_mut(&mut self) -> &mut Attributes {
        &mut self.attributes
    }

    /// Resolve the effective cryptographic algorithm for this managed object.
    ///
    /// Checks the key block's algorithm first, then falls back to the object's
    /// external attributes. Returns `None` when neither source provides a value.
    #[must_use]
    pub fn resolve_key_algorithm(&self) -> Option<CryptographicAlgorithm> {
        self.object
            .key_block()
            .ok()
            .and_then(|kb| kb.cryptographic_algorithm().copied())
            .or(self.attributes.cryptographic_algorithm)
    }
}

impl Display for ObjectWithMetadata {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "ObjectWithMetadata {{ id: {}, object: {}, owner: {}, state: {}, attributes: {} }}",
            self.id, self.object, self.owner, self.state, self.attributes
        )
    }
}
