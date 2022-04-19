use std::convert::TryFrom;

use abe_gpsw::core::policy::Policy;
use cosmian_kmip::kmip::{
    kmip_key_utils::WrappedSymmetricKey,
    kmip_objects::{Object, ObjectType},
    kmip_operations::{Create, CreateKeyPair, Get, Import, Locate, ReKeyKeyPairResponse},
    kmip_types::{
        Attributes, CryptographicAlgorithm, KeyFormatType, Link, LinkType, LinkedObjectIdentifier,
    },
};
use cosmian_kms_utils::{
    crypto::abe::{
        attributes::{
            access_policy_from_attributes, attributes_as_vendor_attribute,
            attributes_from_attributes, policy_from_attributes, upsert_policy_in_attributes,
        },
        user_key::create_user_decryption_key_object,
    },
    kmip_utils::{
        key_bytes_and_attributes_from_key_block, public_key_unique_identifier_from_private_key,
    },
    KeyPair,
};
use tracing::trace;

use crate::{core::crud::KmipServer, error::KmsError, kms_bail, result::KResult};

/// `Re_key` an ABE master Key for the given attributes, which in ABE terms
/// is to "revoke" the list of given attributes by increasing their value
pub(crate) async fn rekey_keypair_abe<K>(
    kmip_server: &K,
    master_private_key_uid: &str,
    attributes: &Attributes,
    owner: &str,
) -> KResult<ReKeyKeyPairResponse>
where
    K: KmipServer,
{
    trace!("Internal rekey key pair ABE");

    // Verify the operation is performed for an ABE Master Key
    let key_format_type = attributes.key_format_type.as_ref().ok_or_else(|| {
        KmsError::InvalidRequest(
            "Unable to rekey an ABE key, the format type is not specified".to_owned(),
        )
    })?;
    if key_format_type != &KeyFormatType::AbeMasterSecretKey {
        kms_bail!(KmsError::NotSupported(
            "ReKey: the format of the key must be an ABE master key".to_string()
        ))
    }

    // Determine the list of policy attributes which will be revoked (i.e. their value increased)
    let abe_policy_attributes_to_revoke = attributes_from_attributes(attributes)?;
    trace!(
        "Revoking attributes: {:?}",
        &abe_policy_attributes_to_revoke
    );

    // Recover the master private key
    let private_key = kmip_server
        .get(Get::from(master_private_key_uid), owner)
        .await?
        .object;

    // Recover the Master Public Key
    let master_public_key_uid = public_key_unique_identifier_from_private_key(&private_key)?;
    let public_key = kmip_server
        .get(Get::from(master_public_key_uid.clone()), owner)
        .await?
        .object;

    // Recover the policy from the private key
    let (master_private_key_bytes, private_key_attributes) =
        key_bytes_and_attributes_from_key_block(private_key.key_block()?, master_private_key_uid)?;
    let mut private_key_attributes = private_key_attributes.ok_or_else(|| {
        KmsError::InvalidRequest("The ABE Master key should have attributes".to_owned())
    })?;
    let mut policy = policy_from_attributes(&private_key_attributes)?;

    // Increment the Attributes values in the Policy
    for attr in &abe_policy_attributes_to_revoke {
        policy.rotate(attr)?
    }
    trace!("The new policy is : {:#?}", &policy);

    // Update Master Private Key Policy and re-import the key
    upsert_policy_in_attributes(&mut private_key_attributes, &policy)?;
    // re_import it
    let import_request = Import {
        unique_identifier: master_private_key_uid.to_string(),
        object_type: ObjectType::PrivateKey,
        replace_existing: Some(true),
        key_wrap_type: None,
        attributes: private_key_attributes,
        object: private_key,
    };
    let _import_response = kmip_server.import(import_request, owner).await?;

    // Update Master Public Key Policy and re-import the key
    let mut public_key_attributes = public_key.key_block()?.key_value.attributes()?.clone();
    public_key_attributes.set_object_type(ObjectType::PublicKey);
    upsert_policy_in_attributes(&mut public_key_attributes, &policy)?;
    // re_import it
    let import_request = Import {
        unique_identifier: master_public_key_uid.clone(),
        object_type: ObjectType::PublicKey,
        replace_existing: Some(true),
        key_wrap_type: None,
        attributes: public_key_attributes,
        object: public_key,
    };
    let _import_response = kmip_server.import(import_request, owner).await?;

    // Search the user decryption keys that need to be refreshed
    let search_attributes = Attributes {
        cryptographic_algorithm: Some(CryptographicAlgorithm::ABE),
        key_format_type: Some(KeyFormatType::AbeUserDecryptionKey),
        vendor_attributes: Some(vec![
            // abe_master_private_key_id_as_vendor_attribute(master_private_key_uid),
            attributes_as_vendor_attribute(abe_policy_attributes_to_revoke)?,
        ]),
        link: vec![Link {
            link_type: LinkType::ParentLink,
            linked_object_identifier: LinkedObjectIdentifier::TextString(
                master_private_key_uid.to_owned(),
            ),
        }],
        ..Attributes::new(ObjectType::PrivateKey)
    };
    let locate_request = Locate {
        attributes: search_attributes,
        ..Locate::new(ObjectType::PrivateKey)
    };
    let locate_response = kmip_server.locate(locate_request, owner).await?;

    // Refresh the User Decryption Key that were found
    if let Some(unique_identifiers) = &locate_response.unique_identifiers {
        trace!(
            "Rekeying the following user decryption keys: {:?}",
            &unique_identifiers
        );
        renew_all_user_decryption_keys(
            kmip_server,
            &master_private_key_bytes,
            &policy,
            unique_identifiers,
            owner,
        )
        .await?
    }

    Ok(ReKeyKeyPairResponse {
        private_key_unique_identifier: master_private_key_uid.to_string(),
        public_key_unique_identifier: master_public_key_uid,
    })
}

async fn renew_all_user_decryption_keys<K>(
    kmip_server: &K,
    master_private_key_bytes: &[u8],
    policy: &Policy,
    user_decryption_key_unique_identifiers: &[String],
    owner: &str,
) -> KResult<()>
where
    K: KmipServer,
{
    // Renew user decryption key previously found
    for user_decryption_key_unique_identifier in user_decryption_key_unique_identifiers {
        let get_response = kmip_server
            .get(Get::from(user_decryption_key_unique_identifier), owner)
            .await?;
        let key_block = get_response.object.key_block()?;
        // Handle both plaintext and wrapped key
        let current_key_attributes = match &key_block.key_wrapping_data {
            Some(_) => {
                let wrapped_symmetric_key =
                    WrappedSymmetricKey::try_from(&key_block.key_value.raw_bytes()?)?;
                wrapped_symmetric_key.attributes()
            }
            None => key_block.key_value.attributes()?.clone(),
        };
        let current_access_policy = access_policy_from_attributes(&current_key_attributes)?;
        // Generate a fresh User Decryption Key
        let new_user_decryption_key = create_user_decryption_key_object(
            master_private_key_bytes,
            policy,
            &current_access_policy,
            Some(&current_key_attributes),
        )?;
        let import_request = Import {
            unique_identifier: get_response.unique_identifier,
            object_type: get_response.object_type,
            replace_existing: Some(true),
            key_wrap_type: None,
            attributes: current_key_attributes,
            object: new_user_decryption_key,
        };
        let _import_response = kmip_server.import(import_request, owner).await?;
    }

    Ok(())
}

/// Create a User Decryption Key in the KMS
///
/// The attributes of the `Create` request must contain the
/// `Access Policy`
pub(crate) async fn create_user_decryption_key<K>(
    kmip_server: &K,
    create_request: &Create,
    owner: &str,
) -> KResult<Object>
where
    K: KmipServer,
{
    create_user_decryption_key_(kmip_server, &create_request.attributes, owner).await
}

async fn create_user_decryption_key_<K>(
    kmip_server: &K,
    create_attributes: &Attributes,
    owner: &str,
) -> KResult<Object>
where
    K: KmipServer,
{
    // Recover the access policy
    let access_policy = access_policy_from_attributes(create_attributes)?;

    // Recover private key
    let master_private_key_uid = create_attributes.get_parent_id().ok_or_else(|| {
        KmsError::InvalidRequest(
            "there should be a reference to the master private key in the creation attributes"
                .to_string(),
        )
    })?;
    let gr_private_key = kmip_server
        .get(Get::from(master_private_key_uid.clone()), owner)
        .await?;
    let master_private_key = &gr_private_key.object;

    let (master_private_key_bytes, master_private_key_attributes) =
        key_bytes_and_attributes_from_key_block(
            master_private_key.key_block()?,
            &master_private_key_uid,
        )?;

    // recover the current policy from the key attributes
    let policy = policy_from_attributes(&master_private_key_attributes.ok_or_else(|| {
        KmsError::InvalidRequest(
            "the master private key does not have attributes with the Policy".to_string(),
        )
    })?)?;
    trace!("Policy: {:?}", &policy);

    create_user_decryption_key_object(
        &master_private_key_bytes,
        &policy,
        &access_policy,
        Some(create_attributes),
    )
    .map_err(Into::into)
}

/// Create a KMIP tuple (`Object::PrivateKey`, `Object::PublicKey`)
pub(crate) async fn create_user_decryption_key_pair<K>(
    kmip_server: &K,
    create_key_pair_request: &CreateKeyPair,
    owner: &str,
) -> KResult<KeyPair>
where
    K: KmipServer,
{
    // create user decryption key
    let private_key_attributes = create_key_pair_request
        .private_key_attributes
        .as_ref()
        .or(create_key_pair_request.common_attributes.as_ref())
        .ok_or_else(|| {
            KmsError::InvalidRequest(
                "Missing private attributes in ABE Create Keypair request".to_string(),
            )
        })?;
    let private_key =
        create_user_decryption_key_(kmip_server, private_key_attributes, owner).await?;

    //Recover Public Key
    let public_key_attributes = create_key_pair_request
        .public_key_attributes
        .as_ref()
        .or(create_key_pair_request.common_attributes.as_ref())
        .ok_or_else(|| {
            KmsError::InvalidRequest(
                "Missing public attributes in ABE Create Keypair request".to_string(),
            )
        })?;
    let master_public_key_uid = public_key_attributes.get_parent_id().ok_or_else(|| {
        KmsError::InvalidRequest(
            "the master public key id should be available in the public creation attributes"
                .to_string(),
        )
    })?;
    let gr_public_key = kmip_server
        .get(Get::from(master_public_key_uid), owner)
        .await?;

    Ok(KeyPair((private_key, gr_public_key.object)))
}
