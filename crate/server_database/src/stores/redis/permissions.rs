use std::{
    collections::{HashMap, HashSet},
    sync::Arc,
};

use cosmian_findex::IndexADT;
use cosmian_kmip::kmip_2_1::KmipOperation;
use cosmian_kms_crypto::reexport::cosmian_crypto_core::bytes_ser_de::{
    Deserializer, Serializable, Serializer,
};

use crate::{
    DbError,
    error::DbResult,
    stores::redis::findex::{FindexRedis, IndexedValue, Keyword},
};

/// An identifier for objects in the permission system.
///
/// Uses `String` for simplicity - to be optimized in case of performance issues
/// (though this is unlikely).
#[derive(Clone, Eq, PartialEq, Debug, Hash)]
pub(crate) struct ObjectUid(pub(crate) String);

impl From<&ObjectUid> for Keyword {
    fn from(uid: &ObjectUid) -> Self {
        // Prefix with "o:" to avoid collisions with users ids
        Self::from([b"o".as_slice(), uid.0.as_bytes()].concat())
    }
}

impl From<ObjectUid> for String {
    fn from(s: ObjectUid) -> Self {
        s.0
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Hash)]
pub(crate) struct UserId(pub(crate) String);

impl From<&UserId> for Keyword {
    fn from(uid: &UserId) -> Self {
        // Prefix with "u:" to avoid collisions with objects ids
        Self::from([b"u".as_slice(), uid.0.as_bytes()].concat())
    }
}

impl From<UserId> for String {
    fn from(s: UserId) -> Self {
        s.0
    }
}

#[derive(Clone, Eq, PartialEq, Debug, Hash)]
pub(crate) struct PermTriple {
    obj_uid: ObjectUid,
    user_id: UserId,
    permission: KmipOperation,
}

impl PermTriple {
    pub(crate) const fn new(
        obj_uid: ObjectUid,
        user_id: UserId,
        permission: KmipOperation,
    ) -> Self {
        Self {
            obj_uid,
            user_id,
            permission,
        }
    }

    pub(crate) fn permissions_per_user(
        permissions_per_user: HashSet<Self>,
    ) -> HashMap<UserId, HashSet<KmipOperation>> {
        let mut map = HashMap::with_capacity(permissions_per_user.len());
        for triple in permissions_per_user {
            let entry = map.entry(triple.user_id).or_insert_with(HashSet::new);
            entry.insert(triple.permission);
        }
        map
    }

    pub(crate) fn permissions_per_object(
        permissions_per_user: HashSet<Self>,
    ) -> HashMap<ObjectUid, HashSet<KmipOperation>> {
        let mut map = HashMap::with_capacity(permissions_per_user.len());
        for triple in permissions_per_user {
            let entry = map.entry(triple.obj_uid).or_insert_with(HashSet::new);
            entry.insert(triple.permission);
        }
        map
    }
}

impl Serializable for PermTriple {
    type Error = DbError;

    fn length(&self) -> usize {
        self.obj_uid.0.length() + self.user_id.0.length() + 1
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut written = 0;
        written += ser.write(&self.obj_uid.0)?;
        written += ser.write(&self.user_id.0)?;
        written += ser.write_array(&[u8::from(self.permission)])?;
        Ok(written)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let obj_uid = ObjectUid(de.read()?);
        let user_id = UserId(de.read()?);
        let perm_byte = de.read_array::<1>()?;
        let permission = KmipOperation::from_repr(perm_byte[0]).ok_or_else(|| {
            DbError::ConversionError(
                format!("Invalid KmipOperation value: {}", perm_byte[0]).into(),
            )
        })?;
        Ok(Self {
            obj_uid,
            user_id,
            permission,
        })
    }
}

impl TryFrom<&IndexedValue> for PermTriple {
    type Error = DbError;

    fn try_from(value: &IndexedValue) -> Result<Self, Self::Error> {
        cosmian_kms_crypto::reexport::cosmian_crypto_core::bytes_ser_de::Serializable::deserialize(
            value,
        )
    }
}

impl TryFrom<&PermTriple> for IndexedValue {
    type Error = DbError;

    fn try_from(value: &PermTriple) -> Result<Self, Self::Error> {
        Ok(Self::from(
            cosmian_kms_crypto::reexport::cosmian_crypto_core::bytes_ser_de::Serializable::serialize(value)?.to_vec(),
        ))
    }
}

/// [`PermissionsDB`] is a database entirely built on top of Findex that stores the permissions
/// using a dual index pattern for efficient lookups as there is no wildcard support.
///
/// For each permission triple (`user_id`, `obj_uid`, `permission`), we store it twice under:
/// - The user id: `u:{user_id}` → (`user_id`, `obj_uid`, `permission`)
/// - The object uid: `o:{obj_uid}` → (`user_id`, `obj_uid`, `permission`)
///
/// A triple size (before serialization) is 56 bytes. Duplicating the index induces doubling the storage,
/// which makes it take at worst 112 bytes per permission triple to store.
///
/// By explicitly maintaining both indexes, we avoid the need for wildcard searches
/// which are not supported by Findex yet needed if we want to list all permissions
/// for a given user OR object in a same [`PermissionsDB`].
#[derive(Clone)]
pub(crate) struct PermissionDB {
    findex: Arc<FindexRedis>,
}

impl PermissionDB {
    pub(crate) const fn new(findex: Arc<FindexRedis>) -> Self {
        Self { findex }
    }

    /// Search for a keyword
    async fn search_one_keyword(&self, keyword: Keyword) -> DbResult<HashSet<PermTriple>> {
        self.findex
            .search(&keyword)
            .await?
            .iter()
            .map(PermTriple::try_from)
            .collect()
    }

    /// List all the permissions granted to a user
    /// per object uid
    pub(crate) async fn list_user_permissions(
        &self,
        user_id: &UserId,
    ) -> DbResult<HashMap<ObjectUid, HashSet<KmipOperation>>> {
        let all_user_permissions = self.search_one_keyword(Keyword::from(user_id)).await?;
        Ok(PermTriple::permissions_per_object(all_user_permissions))
    }

    /// List all the permissions granted on an object
    /// per user id
    pub(crate) async fn list_object_permissions(
        &self,
        obj_uid: &ObjectUid,
    ) -> DbResult<HashMap<UserId, HashSet<KmipOperation>>> {
        let all_object_permissions = self.search_one_keyword(Keyword::from(obj_uid)).await?;
        Ok(PermTriple::permissions_per_user(all_object_permissions))
    }

    /// List all the permissions granted to the user on an object
    pub(crate) async fn get(
        &self,
        obj_uid: &ObjectUid,
        user_id: &UserId,
        no_inherited_access: bool,
    ) -> DbResult<HashSet<KmipOperation>> {
        let user_perms = self
            .search_one_keyword(Keyword::from(obj_uid))
            .await?
            .into_iter()
            .filter(|triple| {
                // Optionally include wildcard permissions (user="*") if inherited access is allowed
                &triple.user_id == user_id
                    || (!no_inherited_access && triple.user_id == UserId("*".to_owned()))
            })
            .map(|triple| triple.permission)
            .collect::<HashSet<KmipOperation>>();
        Ok(user_perms)
    }

    /// Add a permission to the user on an object
    pub(crate) async fn add(
        &self,
        obj_uid: &ObjectUid,
        user_id: &UserId,
        permission: KmipOperation,
    ) -> DbResult<()> {
        let triple = PermTriple::new(obj_uid.clone(), user_id.clone(), permission);
        let indexed_triple = IndexedValue::try_from(&triple)?;
        // Create both keywords for dual indexing:
        let user_keyword = Keyword::from(user_id);
        let obj_keyword = Keyword::from(obj_uid);

        // Finally, insert the indexed value under both keywords
        self.findex
            .insert(user_keyword, [indexed_triple.clone()])
            .await?;
        self.findex.insert(obj_keyword, [indexed_triple]).await?;

        Ok(())
    }

    /// Remove a permission to the user on an object
    pub(crate) async fn remove(
        &self,
        obj_uid: &ObjectUid,
        user_id: &UserId,
        permission: KmipOperation,
    ) -> DbResult<()> {
        let triple = PermTriple::new(obj_uid.clone(), user_id.clone(), permission);
        let indexed_triple = IndexedValue::try_from(&triple)?;

        // Create both keywords for dual indexing:
        let user_keyword = Keyword::from(user_id);
        let obj_keyword = Keyword::from(obj_uid);

        // Finally, insert the indexed value under both keywords
        self.findex
            .delete(user_keyword, [indexed_triple.clone()])
            .await?;
        self.findex.delete(obj_keyword, [indexed_triple]).await?;

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use cosmian_kmip::kmip_2_1::KmipOperation;
    use cosmian_kms_crypto::reexport::cosmian_crypto_core::{
        bytes_ser_de::test_serialization, reexport::rand_core::SeedableRng,
    };
    use strum::EnumCount;

    use super::*;

    #[test]
    #[allow(clippy::unwrap_used, clippy::indexing_slicing, clippy::as_conversions)] // this a test, it's okay
    fn test_perm_triple_serialization_randomized() {
        use cosmian_kms_crypto::reexport::cosmian_crypto_core::{
            CsRng, reexport::rand_core::RngCore,
        };
        use uuid::Uuid;

        let mut rng = CsRng::from_entropy();

        // All KmipOperation variants (17 at the time of writing)
        let all_operations: Vec<KmipOperation> = (0..=KmipOperation::COUNT)
            .filter_map(|arg0: usize| KmipOperation::from_repr(arg0.try_into().unwrap()))
            .collect();

        for _ in 0..10 {
            let obj_uid = ObjectUid(Uuid::new_v4().to_string());
            let user_id = UserId(Uuid::new_v4().to_string());
            let permission = all_operations[rng.next_u32() as usize % all_operations.len()];

            let perm = PermTriple {
                obj_uid,
                user_id,
                permission,
            };

            test_serialization(&perm).unwrap();
        }
    }
}
