use std::collections::HashSet;

use cosmian_kmip::{
    id,
    kmip::{
        kmip_data_structures::{KeyMaterial, KeyValue},
        kmip_objects::{Object, Object::Certificate, ObjectType},
        kmip_operations::{Import, ImportResponse},
        kmip_types::{
            Attributes, CryptographicAlgorithm, KeyFormatType, KeyWrapType, LinkType,
            LinkedObjectIdentifier, StateEnumeration,
        },
    },
    openssl::{
        kmip_private_key_to_openssl, kmip_public_key_to_openssl, openssl_certificate_to_kmip,
        openssl_private_key_to_kmip,
    },
};
use cosmian_kms_utils::{
    access::ExtraDatabaseParams,
    tagging::{check_user_tags, remove_tags},
};
use openssl::{
    pkey::{PKey, Private},
    x509::X509,
};
use tracing::{debug, trace};

use super::wrapping::unwrap_key;
use crate::core::certificate::add_certificate_tags;
/// Import a new object
use crate::{core::KMS, database::AtomicOperation, error::KmsError, kms_bail, result::KResult};

pub async fn import(
    kms: &KMS,
    request: Import,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> KResult<ImportResponse> {
    trace!("Entering import KMIP operation: {:?}", request);
    // Unique identifiers starting with `[` are reserved for queries on tags
    // see tagging
    // For instance, a request for unique identifier `[tag1]` will
    // attempt to find a valid single object tagged with `tag1`
    if request.unique_identifier.starts_with('[') {
        kms_bail!("Importing objects with unique identifiers starting with `[` is not supported");
    }
    // process the request based on the object type
    let (uid, operations) = match request.object.object_type() {
        ObjectType::SymmetricKey => process_symmetric_key(kms, request, owner, params).await?,
        ObjectType::Certificate => process_certificate(request)?,
        ObjectType::PublicKey => process_public_key(kms, request, owner, params).await?,
        ObjectType::PrivateKey => process_private_key(kms, request, owner, params).await?,
        x => {
            return Err(KmsError::InvalidRequest(format!(
                "Import is not yet supported for objects of type : {x}"
            )))
        }
    };
    // execute the operations
    kms.db.atomic(owner, &operations, params).await?;
    // return the uid
    debug!("Imported object with uid: {}", uid);
    Ok(ImportResponse {
        unique_identifier: uid,
    })
}

async fn process_symmetric_key(
    kms: &KMS,
    request: Import,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> Result<(String, Vec<AtomicOperation>), KmsError> {
    // recover user tags
    let mut request_attributes = request.attributes;
    let mut tags = remove_tags(&mut request_attributes);
    if let Some(tags) = tags.as_ref() {
        check_user_tags(tags)?;
    }

    let mut object = request.object;
    // unwrap key block if required
    let object_key_block = object.key_block_mut()?;
    // unwrap before storing if requested
    if request.key_wrap_type == Some(KeyWrapType::NotWrapped) {
        unwrap_key(object_key_block, kms, owner, params).await?;
    }
    // replace attributes
    //TODO: this needs to be revisited when fixing: https://github.com/Cosmian/kms/issues/88
    object_key_block.key_value.attributes = Some(request_attributes);

    let uid = if request.unique_identifier.is_empty() {
        id(&object_key_block.key_bytes()?)?
    } else {
        request.unique_identifier.to_string()
    };

    // insert the tag corresponding to the object type if tags should be updated
    if let Some(tags) = tags.as_mut() {
        tags.insert("_sk".to_string());
    }

    // check if the object will be replaced if it already exists
    let replace_existing = request.replace_existing.unwrap_or(false);
    Ok((
        uid.clone(),
        vec![single_operation(tags, replace_existing, object, uid)],
    ))
}

fn process_certificate(request: Import) -> Result<(String, Vec<AtomicOperation>), KmsError> {
    // recover user tags
    let mut request_attributes = request.attributes;
    let mut user_tags = remove_tags(&mut request_attributes);
    if let Some(tags) = user_tags.as_ref() {
        check_user_tags(tags)?;
    }

    // The specification says that this should be DER bytes
    let certificate_der_bytes = match request.object {
        Certificate {
            certificate_value, ..
        } => Ok(certificate_value),
        o => Err(KmsError::Certificate(format!(
            "invalid object type {:?} on import",
            o.object_type()
        ))),
    }?;

    // parse the certificate as an openssl object to convert it to the pivot
    let certificate = X509::from_der(&certificate_der_bytes)?;

    // insert the tag corresponding to the object type if tags should be updated
    if let Some(tags) = user_tags.as_mut() {
        add_certificate_tags(tags, &certificate)?;
    }

    // convert the certificate to a KMIP object
    let (unique_id, object) = openssl_certificate_to_kmip(certificate)?;
    let uid = if request.unique_identifier.is_empty() {
        unique_id
    } else {
        request.unique_identifier.to_string()
    };

    // check if the object will be replaced if it already exists
    let replace_existing = request.replace_existing.unwrap_or(false);
    Ok((
        uid.clone(),
        vec![single_operation(user_tags, replace_existing, object, uid)],
    ))
}

async fn process_public_key(
    kms: &KMS,
    request: Import,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> Result<(String, Vec<AtomicOperation>), KmsError> {
    // recover user tags
    let mut request_attributes = request.attributes;
    let mut tags = remove_tags(&mut request_attributes);
    if let Some(tags) = tags.as_ref() {
        check_user_tags(tags)?;
    }

    // unwrap key block if required
    let object = {
        let mut object = request.object;
        if request.key_wrap_type == Some(KeyWrapType::NotWrapped) {
            let object_key_block = object.key_block_mut()?;
            unwrap_key(object_key_block, kms, owner, params).await?;
        }
        object
    };

    // convert to PKCS8 if not wrapped and not Covercrypt
    let mut object = {
        let object_key_block = object.key_block()?;
        // if the key is not wrapped, try to parse it as an openssl object and import it
        // else import it as such
        // TODO: add Covercrypt keys when support for SPKI is added
        // TODO: https://github.com/Cosmian/cover_crypt/issues/118
        if object_key_block.key_wrapping_data.is_none()
            && object_key_block.cryptographic_algorithm != Some(CryptographicAlgorithm::CoverCrypt)
        {
            // first, see if the public key can be parsed as an openssl object
            let openssl_pk = kmip_public_key_to_openssl(&(object.clone()))?;

            let mut object = object;
            let object_key_block = object.key_block_mut()?;
            // The Key Format Type should really be SPKI, but it does not exist
            object_key_block.key_format_type = KeyFormatType::PKCS8;
            object_key_block.key_value = KeyValue {
                key_material: KeyMaterial::ByteString(openssl_pk.public_key_to_der()?),
                attributes: None,
            };
            object
        } else {
            object
        }
    };

    // replace attributes
    //TODO: this needs to be revisited when fixing: https://github.com/Cosmian/kms/issues/88
    let object_key_block = object.key_block_mut()?;
    object_key_block.key_value.attributes = Some(request_attributes);

    if let Some(tags) = tags.as_mut() {
        tags.insert("_pk".to_string());
    }

    let uid = if request.unique_identifier.is_empty() {
        id(&object_key_block.key_bytes()?)?
    } else {
        request.unique_identifier.to_string()
    };

    // check if the object will be replaced if it already exists
    let replace_existing = request.replace_existing.unwrap_or(false);
    Ok((
        uid.clone(),
        vec![single_operation(tags, replace_existing, object, uid)],
    ))
}

async fn process_private_key(
    kms: &KMS,
    request: Import,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> Result<(String, Vec<AtomicOperation>), KmsError> {
    // recover user tags
    let mut request_attributes = request.attributes;
    let tags = remove_tags(&mut request_attributes);
    // insert the tag corresponding to the object type if tags should be updated
    if let Some(tags) = tags.as_ref() {
        check_user_tags(tags)?;
    }
    // whether the object will be replaced if it already exists
    let replace_existing = request.replace_existing.unwrap_or(false);

    // unwrap key block if required
    let mut object = {
        let mut object = request.object;
        if request.key_wrap_type == Some(KeyWrapType::NotWrapped) {
            let object_key_block = object.key_block_mut()?;
            unwrap_key(object_key_block, kms, owner, params).await?;
        }
        object
    };

    // Process based on the key block type
    let key_block = object.key_block()?;

    // wrapped keys and Covercrypt keys
    // cannot be further processed and must be imported as such
    // TODO: remove Covercrypt keys from this exception when support for PKCS#8 is added
    // TODO: https://github.com/Cosmian/cover_crypt/issues/118
    if key_block.key_wrapping_data.is_some()
        || key_block.cryptographic_algorithm == Some(CryptographicAlgorithm::CoverCrypt)
    {
        // replace attributes
        //TODO: this needs to be revisited when fixing: https://github.com/Cosmian/kms/issues/88
        let object_key_block = object.key_block_mut()?;
        object_key_block.key_value.attributes = Some(request_attributes);
        // build ui if needed
        let uid = if request.unique_identifier.is_empty() {
            id(&object_key_block.key_bytes()?)?
        } else {
            request.unique_identifier.to_string()
        };
        return Ok((
            uid.clone(),
            vec![single_operation(tags, replace_existing, object, uid)],
        ))
    }

    // PKCS12  have their own processing
    if key_block.key_format_type == KeyFormatType::PKCS12 {
        //PKCS#12 contain more than just a private key, perform specific processing
        return process_pkcs12(
            &request.unique_identifier,
            object,
            request_attributes,
            tags,
            request.replace_existing.unwrap_or(false),
        )
        .await
    }

    // Process a "standard" private key
    // first, see if the private key can be parsed as an openssl object
    let openssl_sk = kmip_private_key_to_openssl(&object)?;
    // generate a KMIP private key
    let (sk_uid, sk, sk_tags) = private_key_from_openssl(
        openssl_sk,
        tags,
        request_attributes,
        &request.unique_identifier,
    )?;
    Ok((
        sk_uid.clone(),
        vec![single_operation(sk_tags, replace_existing, sk, sk_uid)],
    ))
}

fn private_key_from_openssl(
    sk: PKey<Private>,
    user_tags: Option<HashSet<String>>,
    request_attributes: Attributes,
    request_uid: &str,
) -> KResult<(String, Object, Option<HashSet<String>>)> {
    // convert the private key to PKCS#8
    let mut sk = openssl_private_key_to_kmip(&sk, KeyFormatType::PKCS8)?;
    // generate the unique identifiers
    let der_bytes = sk.key_block()?.key_bytes()?;

    let sk_uid = if request_uid.is_empty() {
        id(&der_bytes)?
    } else {
        request_uid.to_string()
    };

    //TODO: this needs to be revisited when fixing: https://github.com/Cosmian/kms/issues/88
    let sk_key_block = sk.key_block_mut()?;
    sk_key_block.key_value.attributes = Some(request_attributes);

    let sk_tags = user_tags.map(|mut tags| {
        tags.insert("_sk".to_string());
        tags
    });
    Ok((sk_uid, sk, sk_tags))
}

fn single_operation(
    tags: Option<HashSet<String>>,
    replace_existing: bool,
    object: Object,
    uid: String,
) -> AtomicOperation {
    if replace_existing {
        AtomicOperation::Upsert((uid, object, tags.to_owned(), StateEnumeration::Active))
    } else {
        AtomicOperation::Create((uid.clone(), object, tags.to_owned().unwrap_or_default()))
    }
}

async fn process_pkcs12(
    private_key_id: &str,
    object: Object,
    request_attributes: Attributes,
    user_tags: Option<HashSet<String>>,
    replace_existing: bool,
) -> Result<(String, Vec<AtomicOperation>), KmsError> {
    // recover the PKCS#12 bytes from the object
    let pkcs12_bytes = match object {
        Object::PrivateKey { key_block } => key_block.key_bytes()?,
        _ => kms_bail!("The PKCS12 object is not correctly formatted"),
    };
    // recover the password from the attributes
    let password = request_attributes
        .get_link(LinkType::PKCS12PasswordLink)
        .unwrap_or_default();
    let pkcs12_parser = openssl::pkcs12::Pkcs12::from_der(&pkcs12_bytes)?;
    let pkcs12 = pkcs12_parser.parse2(&password)?;

    // First build the tuples (id,Object) for the private key, the leaf certificate
    // and the chain certificates

    // build the private key
    let (private_key_id, mut private_key, private_key_tags) = {
        let openssl_sk = pkcs12.pkey.ok_or_else(|| {
            KmsError::InvalidRequest("Private key not found in PKCS12".to_string())
        })?;
        private_key_from_openssl(
            openssl_sk,
            user_tags.clone(),
            request_attributes,
            private_key_id,
        )?
    };

    //build the leaf certificate
    let (leaf_certificate_uid, leaf_certificate, mut leaf_certificate_tags) = {
        // Recover the PKCS12 X509 certificate
        let openssl_cert = pkcs12.cert.ok_or_else(|| {
            KmsError::InvalidRequest("X509 certificate not found in PKCS12".to_string())
        })?;

        // insert the tag corresponding to the object type if tags should be updated
        let mut leaf_certificate_tags = user_tags.clone();
        if let Some(tags) = leaf_certificate_tags.as_mut() {
            add_certificate_tags(tags, &openssl_cert)?;
        }

        // convert to KMIP
        let (leaf_certificate_uid, leaf_certificate) = openssl_certificate_to_kmip(openssl_cert)?;

        (
            leaf_certificate_uid,
            leaf_certificate,
            leaf_certificate_tags,
        )
    };

    // build the chain if any  (the chain is optional)
    let mut chain: Vec<(String, Object, Option<HashSet<String>>)> = Vec::new();
    if let Some(cas) = pkcs12.ca {
        // import the cas
        for openssl_cert in cas.into_iter() {
            // insert the tag corresponding to the object type if tags should be updated
            let mut chain_certificate_tags = user_tags.clone();
            if let Some(tags) = chain_certificate_tags.as_mut() {
                add_certificate_tags(tags, &openssl_cert)?;
            }

            // convert to KMIP
            let (chain_certificate_uid, chain_certificate) =
                openssl_certificate_to_kmip(openssl_cert)?;

            chain.push((
                chain_certificate_uid,
                chain_certificate,
                chain_certificate_tags,
            ));
        }
    }

    //
    // Stage 2 update the attributes and tags
    // and create the corresponding operations
    //
    let mut operations = Vec::with_capacity(2 + chain.len());

    //add link to certificate in the private key attributes
    if let Some(a) = private_key.key_block_mut()?.key_value.attributes.as_mut() {
        a.add_link(
            //Note: it is unclear what link type should be used here according to KMIP
            // CertificateLink seems to be for public key only and there is not description
            // for PKCS12CertificateLink
            LinkType::PKCS12CertificateLink,
            LinkedObjectIdentifier::TextString(leaf_certificate_uid.clone()),
        )
    }
    operations.push(single_operation(
        private_key_tags,
        replace_existing,
        private_key,
        private_key_id.clone(),
    ));

    // Add links to the leaf certificate
    //TODO: attributes not supported until https://github.com/Cosmian/kms/issues/88 is fixed; using tags instead
    if let Some(tags) = leaf_certificate_tags.as_mut() {
        // add private key link to certificate
        // (the KMIP spec is unclear whether there should be a LinkType::PrivateKeyLink)
        let sk_tag = format!("_cert_sk={private_key_id}");
        tags.insert(sk_tag);
        // add parent link to certificate
        // (according to the KMIP spec, this would be LinkType::CertificateLink)
        if let Some((parent_id, _, _)) = chain.first() {
            let parent_tag = format!("_cert_issuer={parent_id}");
            tags.insert(parent_tag);
        }
    }
    operations.push(single_operation(
        leaf_certificate_tags,
        replace_existing,
        leaf_certificate,
        leaf_certificate_uid.clone(),
    ));

    // Add links to the chain certificate
    //TODO: attributes not supported until https://github.com/Cosmian/kms/issues/88 is fixed; using tags instead
    let mut parent_certificate_id = None;
    for (chain_certificate_uid, chain_certificate, mut chain_certificate_tags) in
        chain.into_iter().rev()
    // reverse the chain to have the root first
    {
        if let Some(tags) = chain_certificate_tags.as_mut() {
            if let Some(parent_certificate_id) = parent_certificate_id {
                // add parent link to certificate
                // (according to the KMIP spec, this would be LinkType::CertificateLink)
                let parent_tag = format!("_cert_issuer={parent_certificate_id}");
                tags.insert(parent_tag);
            }
        }
        operations.push(single_operation(
            chain_certificate_tags,
            true,
            chain_certificate,
            chain_certificate_uid.clone(),
        ));
        parent_certificate_id = Some(chain_certificate_uid);
    }

    //return the private key
    Ok((private_key_id, operations))
}
