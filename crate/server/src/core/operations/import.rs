use std::collections::HashSet;

use cosmian_kmip::kmip::{
    kmip_data_structures::KeyValue,
    kmip_objects::{Object, ObjectType},
    kmip_operations::{Import, ImportResponse},
    kmip_types::{KeyWrapType, StateEnumeration},
};
use cosmian_kms_utils::{
    access::ExtraDatabaseParams,
    tagging::{check_user_tags, get_tags},
};
use tracing::{debug, warn};
use x509_parser::{parse_x509_certificate, prelude::parse_x509_pem};

use super::wrapping::unwrap_key;
use crate::{
    core::{
        certificate::parsing::{get_certificate_subject_key_identifier, get_common_name},
        operations::wrapping::wrap_key,
        KMS,
    },
    error::KmsError,
    kms_bail,
    result::KResult,
};

fn parse_certificate_and_create_tags(
    tags: &mut HashSet<String>,
    certificate_value: &[u8],
) -> KResult<()> {
    debug!("Import with _cert system tag");
    tags.insert("_cert".to_string());

    let (_, pem) = parse_x509_pem(certificate_value)?;
    let (_, x509) = parse_x509_certificate(&pem.contents)?;

    if !x509.validity().is_valid() {
        return Err(KmsError::Certificate(format!(
            "Cannot import expired certificate. Certificate details: {x509:?}"
        )))
    }
    debug!("Certificate is not expired: {:?}", x509.validity());

    let cert_spki = get_certificate_subject_key_identifier(&x509)?;
    if let Some(spki) = cert_spki {
        let spki_tag = format!("_cert_spki={spki}");
        debug!("Add spki system tag: {spki_tag}");
        tags.insert(spki_tag);
    }
    if x509.is_ca() {
        let subject_common_name = get_common_name(&x509.subject)?;
        let ca_tag = format!("_ca={subject_common_name}");
        debug!("Add CA system tag: {}", &ca_tag);
        tags.insert(ca_tag);
    }
    Ok(())
}

/// Import a new object
pub async fn import(
    kms: &KMS,
    request: Import,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<ImportResponse> {
    debug!("Entering import KMIP operation");
    // Unique identifiers starting with `[` are reserved for queries on tags
    // see tagging
    // For instance, a request for uniquer identifier `[tag1]` will
    // attempt to find a valid single object tagged with `tag1`
    if request.unique_identifier.starts_with('[') {
        kms_bail!("Importing objects with uniquer identifiers starting with `[` is not supported");
    }

    // recover user tags
    let mut tags = get_tags(&request.attributes);
    check_user_tags(&tags)?;

    let mut object = request.object;
    let object_type = object.object_type();
    match object_type {
        ObjectType::SymmetricKey | ObjectType::PublicKey | ObjectType::PrivateKey => {
            let object_key_block = object.key_block_mut()?;
            // unwrap before storing if requested
            if request.key_wrap_type == Some(KeyWrapType::NotWrapped) {
                unwrap_key(object_type, object_key_block, kms, owner, params).await?;
            }
            // replace attributes
            object_key_block.key_value = KeyValue {
                key_material: object_key_block.key_value.key_material.clone(),
                attributes: Some(request.attributes),
            };
            // insert the tag corresponding to the object type
            match object_type {
                ObjectType::SymmetricKey => {
                    tags.insert("_kk".to_string());
                }
                ObjectType::PublicKey => {
                    tags.insert("_pk".to_string());
                }
                ObjectType::PrivateKey => {
                    tags.insert("_sk".to_string());
                }
                _ => unreachable!(),
            }
        }
        ObjectType::Certificate => {
            debug!("Import with _cert system tag");
            tags.insert("_cert".to_string());
            let certificate_pem_bytes = match &object {
                Object::Certificate {
                    certificate_value, ..
                } => Ok(certificate_value),
                _ => Err(KmsError::Certificate(format!(
                    "Invalid object type {object_type:?} when importing a certificate"
                ))),
            }?;
            parse_certificate_and_create_tags(&mut tags, certificate_pem_bytes)?;
        }
        x => {
            warn!("Import is not yet supported for objects of type : {x}");
        }
    }

    // check if the object will be replaced if it already exists
    let replace_existing = if let Some(v) = request.replace_existing {
        v
    } else {
        false
    };

    if let Some(kwd) = &request.key_wrapping_data {
        // wrap
        let key_block = object.key_block_mut()?;
        wrap_key(
            &request.unique_identifier,
            key_block,
            kwd,
            kms,
            owner,
            params,
        )
        .await?;
    }

    // insert or update the object
    let uid = if replace_existing {
        debug!(
            "Upserting object of type: {}, with uid: {}",
            request.object_type, request.unique_identifier
        );

        kms.db
            .upsert(
                &request.unique_identifier,
                owner,
                &object,
                &tags,
                StateEnumeration::Active,
                params,
            )
            .await?;
        request.unique_identifier
    } else {
        debug!("Inserting object of type: {}", request.object_type);
        let id = if request.unique_identifier.is_empty() {
            None
        } else {
            Some(request.unique_identifier)
        };

        kms.db.create(id, owner, &object, &tags, params).await?
    };
    Ok(ImportResponse {
        unique_identifier: uid,
    })
}
