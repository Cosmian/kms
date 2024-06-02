// Copyright 2024 Cosmian Tech SAS
// Changes made to the original code are
// licensed under the Business Source License version 1.1.

use std::hash::Hash;

use crate::core::compoundid::Id;

#[derive(Debug, Clone)]
pub enum RemoteObjectType {
    PublicKey,
    Certificate,
    PrivateKey,
    SymmetricKey,
}

/// A remote object is an object that is stored on a remote server
/// and for which we have a reference to.
pub trait RemoteObjectId: Send + Sync {
    fn remote_id(&self) -> String;

    fn remote_type(&self) -> RemoteObjectType;

    /// ID used as CKA_ID when searching objects by ID
    fn id(&self) -> Id {
        Id {
            label: "RemoteObject".to_string(),
            hash: self.remote_id().as_bytes().to_vec(),
        }
    }
}

impl std::fmt::Debug for dyn RemoteObjectId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RemoteObjectId")
            .field("id", &self.remote_id())
            .field("type", &self.remote_type())
            .finish_non_exhaustive()
    }
}
impl PartialEq for dyn RemoteObjectId {
    fn eq(&self, other: &Self) -> bool {
        self.remote_id() == other.remote_id()
    }
}

impl Eq for dyn RemoteObjectId {}

impl Hash for dyn RemoteObjectId {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.remote_id().hash(state);
    }
}
