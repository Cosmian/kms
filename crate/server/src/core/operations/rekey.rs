use cosmian_kms_logger::{debug, trace, warn};
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        kmip_0::kmip_types::State,
        kmip_2_1::{
            kmip_data_structures::KeyWrappingSpecification,
            kmip_objects::ObjectType,
            kmip_operations::{Create, ReKey, ReKeyResponse},
            kmip_types::{
                EncodingOption, EncryptionKeyInformation, LinkType, LinkedObjectIdentifier,
                UniqueIdentifier,
            },
        },
        time_normalize,
    },
    cosmian_kms_interfaces::AtomicOperation,
};
use uuid::Uuid;

use crate::{
    core::{KMS, wrapping::unwrap_object},
    error::KmsError,
    kms_bail,
    result::{KResult, KResultHelper},
};

pub(crate) async fn rekey(kms: &KMS, request: ReKey, owner: &str) -> KResult<ReKeyResponse> {
    trace!("{}", serde_json::to_string(&request)?);

    if request.protection_storage_masks.is_some() {
        kms_bail!(KmsError::UnsupportedPlaceholder)
    }

    // there must be an identifier
    let uid_or_tags = request
        .unique_identifier
        .as_ref()
        .ok_or(KmsError::UnsupportedPlaceholder)?
        .as_str()
        .context("Rekey: the symmetric key unique identifier must be a string")?;

    // retrieve the symmetric key associated with the uid (the array MUST contain only one element)
    for owm in kms
        .database
        .retrieve_objects(uid_or_tags)
        .await?
        .into_values()
    {
        // only active objects
        if owm.state() != State::Active {
            continue;
        }
        // only symmetric keys
        if owm.object().object_type() != ObjectType::SymmetricKey {
            continue;
        }

        let old_uid = owm.id().to_owned();

        // §3 — Detect if this key is itself wrapped; recover wrapping context before rekeying
        let mut key_for_material = owm.object().clone();
        // Capture the wrapping key UID now so we can set WrappingKeyLink on the new key later.
        let wrapping_key_uid: Option<String> = key_for_material
            .key_block()
            .ok()
            .and_then(|kb| kb.key_wrapping_data.as_ref())
            .and_then(|kwd| kwd.encryption_key_information.as_ref())
            .and_then(|eki| eki.unique_identifier.as_str())
            .map(str::to_owned);
        let rewrap_spec: Option<KeyWrappingSpecification> = if key_for_material.is_wrapped() {
            // Extract the wrapping specification from the current wrapping data so we can
            // re-wrap the new material with the same wrapping key.
            let wrap_spec = key_for_material
                .key_block()
                .ok()
                .and_then(|kb| kb.key_wrapping_data.as_ref())
                .map(|kwd| KeyWrappingSpecification {
                    wrapping_method: kwd.wrapping_method,
                    encryption_key_information: kwd.encryption_key_information.clone(),
                    mac_or_signature_key_information: kwd.mac_signature_key_information.clone(),
                    attribute_name: None,
                    encoding_option: kwd.encoding_option,
                });
            // Unwrap the object so we can generate fresh key material from the plaintext
            unwrap_object(&mut key_for_material, kms, owner).await?;
            wrap_spec
        } else {
            None
        };

        // Generate fresh symmetric key material with the same attributes
        let mut new_key_attrs = owm.attributes().to_owned();
        // Clear fields that must not be inherited by the new key:
        // - unique_identifier: let create_symmetric_key_and_tags assign a fresh one
        // - key_format_type: `Raw` is a presentation format; the generator only accepts
        //   None or TransparentSymmetricKey.  Clearing it lets the generator pick its default.
        // - link: stale links from the source key would be embedded in new_object's key_block
        //   and would shadow the correct links stored in the metadata column at get_attributes time.
        new_key_attrs.unique_identifier = None;
        new_key_attrs.key_format_type = None;
        new_key_attrs.link = None;
        // Clear rotate_interval on the new-key template so the generator does not
        // embed a stale interval in the key block; we set the final value explicitly
        // on new_key_attrs after Create (see phase-1 attrs block below).
        new_key_attrs.rotate_interval = None;
        new_key_attrs.rotate_name = None;
        new_key_attrs.rotate_offset = None;
        let create_request = Create {
            object_type: ObjectType::SymmetricKey,
            attributes: new_key_attrs,
            protection_storage_masks: None,
        };
        let (_, mut new_object, new_tags) =
            KMS::create_symmetric_key_and_tags(kms.vendor_id(), &create_request)?;

        // Assign a fresh UID to the new key.
        // Convention:
        //   - Pure UUID  →  fresh UUID  (e.g. "abc-…"  →  "def-…")
        //   - User name  →  "<name>_<new-uuid>"  (e.g. "toto"  →  "toto_def-…")
        //   - Already-prefixed name  →  strip the old UUID suffix, re-use the prefix
        //     (e.g. "toto_abc-…"  →  "toto_def-…") so successive rotations don't
        //     keep appending UUID segments.
        let new_uid = if Uuid::parse_str(&old_uid).is_ok() {
            Uuid::new_v4().to_string()
        } else {
            let prefix = old_uid
                .rsplit_once('_')
                .filter(|(_, suffix)| Uuid::parse_str(suffix).is_ok())
                .map_or(old_uid.as_str(), |(prefix, _)| prefix);
            format!("{prefix}_{}", Uuid::new_v4())
        };

        // Capture the new object's attributes BEFORE possible wrapping.
        // After wrap_object() the key_value becomes an opaque ByteString and
        // new_object.attributes() returns an error, losing cryptographic_algorithm,
        // vendor attributes such as wrapping_key_id, etc.
        let attrs_before_wrap = new_object.attributes().cloned().ok();

        // Override the wrapping encoding for the new key: symmetric keys always have
        // recoverable key bytes, so NoEncoding avoids TTLV serialization of the
        // key value (which would embed Cosmian-proprietary attributes such as
        // RotateDate that the TTLV codec cannot serialize).
        // This mirrors the encoding decision in `wrap_and_cache`.
        let rewrap_spec = rewrap_spec.map(|mut spec| {
            if new_object
                .key_block()
                .is_ok_and(|kb| kb.key_bytes().is_ok())
            {
                spec.encoding_option = Some(EncodingOption::NoEncoding);
            }
            spec
        });

        // §3 — Re-wrap the new key with the same wrapping key if the old key was wrapped
        if let Some(spec) = rewrap_spec {
            crate::core::wrapping::wrap_object(&mut new_object, &spec, kms, owner).await?;
        }

        // Build attributes for the new key: add ReplacedObjectLink → old_uid, update rotation metadata.
        // For wrapped keys new_object.attributes() fails (key_value is an opaque ByteString);
        // fall back to the pre-wrap snapshot which retains cryptographic_algorithm, vendor
        // attributes such as wrapping_key_id, etc.
        let mut new_key_attrs = new_object
            .attributes()
            .cloned()
            .unwrap_or_else(|_| attrs_before_wrap.unwrap_or_default());
        new_key_attrs.set_link(
            LinkType::ReplacedObjectLink,
            LinkedObjectIdentifier::TextString(old_uid.clone()),
        );
        // §3 — Per spec, the new wrapped key retains a WrappingKeyLink pointing to the same
        // wrapping key as the original key.
        if let Some(ref wk_uid) = wrapping_key_uid {
            new_key_attrs.set_link(
                LinkType::WrappingKeyLink,
                LinkedObjectIdentifier::TextString(wk_uid.clone()),
            );
        }
        new_key_attrs.rotate_generation = Some(owm.attributes().rotate_generation.unwrap_or(0) + 1);
        new_key_attrs.rotate_date = Some(time_normalize()?);
        // Do not inherit the rotation policy (rotate_interval/name/offset) from
        // the old key — the new key starts with auto-rotate disabled (interval=0).
        // The user must explicitly re-arm auto-rotation on the new key if desired.
        new_key_attrs.rotate_interval = Some(0);
        new_key_attrs.rotate_name = None;
        new_key_attrs.rotate_offset = None;
        // Mark the new key as the latest in the rotation lineage (KMIP §4.51).
        // The old key's rotate_latest will be cleared in phase 2 below.
        new_key_attrs.rotate_latest = Some(true);
        // Set unique identifier on the new key
        new_key_attrs.unique_identifier = Some(UniqueIdentifier::TextString(new_uid.clone()));
        new_key_attrs.object_type = Some(ObjectType::SymmetricKey);
        // Propagate the state: the new key is Active
        new_key_attrs.state = Some(State::Active);

        // Commit phase 1: persist the new key so it is accessible for re-wrapping dependants.
        // We can't fold this into the final atomic batch because `wrap_object` looks up the new
        // wrapping key by UID *from the live database* — if it isn't committed yet, the re-wrap
        // would fail with "key not found".
        kms.database
            .atomic(
                owner,
                &[AtomicOperation::Create((
                    new_uid.clone(),
                    new_object.clone(),
                    new_key_attrs.clone(),
                    new_tags,
                ))],
            )
            .await?;

        // Build attributes for the old key: add ReplacementObjectLink → new_uid,
        // clear rotate_latest so only the newest key carries the flag,
        // and set rotate_interval = 0 so the old key is not picked up by auto-rotation again.
        let mut old_key_attrs = owm.attributes().to_owned();
        old_key_attrs.set_link(
            LinkType::ReplacementObjectLink,
            LinkedObjectIdentifier::TextString(new_uid.clone()),
        );
        old_key_attrs.rotate_latest = Some(false);
        old_key_attrs.rotate_interval = Some(0);

        // Phase 2: update the old key and re-wrap any dependants.
        let mut operations: Vec<AtomicOperation> = vec![AtomicOperation::UpdateObject((
            old_uid.clone(),
            owm.object().clone(),
            old_key_attrs,
            None, // tags: None means don't change tags
        ))];

        // §2 — Rewrap all keys that were wrapped by the old key
        let wrapped_dependants = kms
            .database
            .find_wrapped_by(&old_uid, owner)
            .await
            .unwrap_or_default();

        for (dep_uid, _dep_state, dep_attrs) in wrapped_dependants {
            // Retrieve the full wrapped object
            let Some(dep_owm) = kms.database.retrieve_object(&dep_uid).await? else {
                warn!("wrapped dependant {dep_uid} not found, skipping");
                continue;
            };
            let mut dep_object = dep_owm.object().clone();

            // Extract the current wrapping specification before unwrapping
            let dep_wrap_spec = dep_object
                .key_block()
                .ok()
                .and_then(|kb| kb.key_wrapping_data.as_ref())
                .map(|kwd| KeyWrappingSpecification {
                    wrapping_method: kwd.wrapping_method,
                    encryption_key_information: Some(EncryptionKeyInformation {
                        // Point to the NEW wrapping key
                        unique_identifier: UniqueIdentifier::TextString(new_uid.clone()),
                        cryptographic_parameters: kwd
                            .encryption_key_information
                            .as_ref()
                            .and_then(|e| e.cryptographic_parameters.clone()),
                    }),
                    mac_or_signature_key_information: kwd
                        .mac_signature_key_information
                        .clone()
                        .map(|m| {
                            cosmian_kms_server_database::reexport::cosmian_kmip::kmip_2_1::kmip_types::MacSignatureKeyInformation {
                                unique_identifier: UniqueIdentifier::TextString(new_uid.clone()),
                                cryptographic_parameters: m.cryptographic_parameters,
                            }
                        }),
                    attribute_name: None,
                    encoding_option: kwd.encoding_option,
                });

            if let Some(spec) = dep_wrap_spec {
                // Unwrap using the OLD key (still accessible at old_uid at this point)
                if let Err(e) = unwrap_object(&mut dep_object, kms, owner).await {
                    warn!("failed to unwrap dependant {dep_uid}: {e}, skipping");
                    continue;
                }
                // Re-wrap with the NEW key
                if let Err(e) =
                    crate::core::wrapping::wrap_object(&mut dep_object, &spec, kms, owner).await
                {
                    warn!("failed to re-wrap dependant {dep_uid} with new key: {e}, skipping");
                    continue;
                }
                // Update WrappingKeyLink and wrapping_key_id vendor attribute on the
                // dependant so both the KMIP link and the Cosmian extension attribute
                // reflect the new wrapping key UID.
                let mut updated_dep_attrs = dep_attrs;
                updated_dep_attrs.set_link(
                    LinkType::WrappingKeyLink,
                    LinkedObjectIdentifier::TextString(new_uid.clone()),
                );
                updated_dep_attrs.set_wrapping_key_id(kms.vendor_id(), &new_uid);
                operations.push(AtomicOperation::UpdateObject((
                    dep_uid.clone(),
                    dep_object,
                    updated_dep_attrs,
                    None,
                )));
            }
        }

        // Execute all operations atomically
        kms.database.atomic(owner, &operations).await?;

        debug!("Re-keyed symmetric key: old uid={old_uid} → new uid={new_uid}");

        return Ok(ReKeyResponse {
            unique_identifier: UniqueIdentifier::TextString(new_uid),
        });
    }

    Err(KmsError::InvalidRequest(format!(
        "rekey: no active symmetric key found for uid/tags: {uid_or_tags}",
    )))
}
