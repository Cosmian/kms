use cloudproof::reexport::cover_crypt::{
    abe_policy::Policy, Covercrypt, MasterPublicKey, MasterSecretKey,
};

use super::attributes::RekeyEditAction;
use crate::{
    crypto::cover_crypt::update_keys_policy::RekeyEditAction::{
        AddAttribute, DisableAttribute, PruneAccessPolicy, RekeyAccessPolicy, RemoveAttribute,
        RenameAttribute,
    },
    error::KmipError,
    kmip::kmip_operations::ErrorReason,
};

pub struct MasterKeysUpdater<'a> {
    action: &'a RekeyEditAction,
    pub policy: &'a mut Policy,
    cover_crypt: &'a Covercrypt,
}

impl<'a> MasterKeysUpdater<'a> {
    /// Create an updater object
    ///
    /// # Parameters
    ///
    /// - `action`: an `EditPolicyAction` enum.
    /// - `policy`: the current Policy.
    /// - `cover_crypt`: a `CoverCrypt` instance.
    pub fn new(
        action: &'a RekeyEditAction,
        policy: &'a mut Policy,
        cover_crypt: &'a Covercrypt,
    ) -> Self {
        Self {
            action,
            policy,
            cover_crypt,
        }
    }

    /// Update the master key based on the specified action:
    /// - update keys after a Policy change
    /// - generate new keys for a given access policy
    /// - remove old keys for a given access policy
    pub fn update_master_keys(
        &self,
        msk: &mut MasterSecretKey,
        mpk: &mut MasterPublicKey,
    ) -> Result<(), KmipError> {
        // Update the keys
        match &self.action {
            RemoveAttribute(_) | DisableAttribute(_) | AddAttribute(_) | RenameAttribute(_) => {
                self.cover_crypt.update_master_keys(self.policy, msk, mpk)
            }
            RekeyAccessPolicy(ap) => self.cover_crypt.rekey_master_keys(
                &RekeyEditAction::deserialize_access_policy(ap)?,
                self.policy,
                msk,
                mpk,
            ),
            PruneAccessPolicy(ap) => self.cover_crypt.prune_master_secret_key(
                &RekeyEditAction::deserialize_access_policy(ap)?,
                self.policy,
                msk,
            ),
        }
        .map_err(|e| {
            KmipError::KmipError(
                ErrorReason::Cryptographic_Failure,
                format!("Failed updating the CoverCrypt Master Keys: {e}"),
            )
        })
    }

    /// Update a Covercrypt policy based on the specified action.
    pub fn update_policy(&mut self) -> Result<(), KmipError> {
        match &self.action {
            RekeyAccessPolicy(_) | PruneAccessPolicy(_) => Ok(()),
            RemoveAttribute(attrs) => attrs
                .iter()
                .try_for_each(|attr| self.policy.remove_attribute(attr)), // TODO: tests revoking of existing keys with deleted attribute?
            DisableAttribute(attrs) => attrs
                .iter()
                .try_for_each(|attr| self.policy.disable_attribute(attr)),
            RenameAttribute(pairs_attr_name) => {
                pairs_attr_name.iter().try_for_each(|(attr, new_name)| {
                    self.policy.rename_attribute(attr, new_name.clone())
                })
            }
            AddAttribute(attrs_properties) => {
                attrs_properties
                    .iter()
                    .try_for_each(|(attr, encryption_hint)| {
                        self.policy.add_attribute(attr.clone(), *encryption_hint)
                    })
            }
        }
        .map_err(|e| {
            KmipError::KmipError(
                ErrorReason::Unsupported_Cryptographic_Parameters,
                e.to_string(),
            )
        })?;

        Ok(())
    }
}
