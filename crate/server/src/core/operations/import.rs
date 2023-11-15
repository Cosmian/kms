use std::{clone, collections::HashSet};

use base58::{FromBase58, ToBase58};
use cosmian_kmip::{
    kmip::{
        kmip_data_structures::{KeyMaterial, KeyValue},
        kmip_objects::{Object, Object::Certificate, ObjectType},
        kmip_operations::{Import, ImportResponse},
        kmip_types::{
            Attributes, CertificateType, CryptographicAlgorithm, KeyFormatType, KeyWrapType,
            LinkType, LinkedObjectIdentifier, StateEnumeration,
        },
    },
    openssl::{
        kmip_private_key_to_openssl, kmip_public_key_to_openssl, openssl_private_key_to_kmip,
        openssl_public_key_to_kmip,
    },
};
use cosmian_kms_utils::{
    access::ExtraDatabaseParams,
    tagging::{check_user_tags, remove_tags},
};
use openssl::{
    pkey::{PKey, Private},
    sha::Sha1,
    x509::X509,
};
use tracing::{debug, trace};

use super::wrapping::unwrap_key;
/// Import a new object
use crate::{
    core::KMS, database::AtomicOperation, error::KmsError, kms_bail, kms_error, result::KResult,
};

async fn import(
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

    let object_type = request.object.object_type();
    let (uid, operations) = match object_type {
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

    kms.db.atomic(owner, &operations, params).await?;

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

    // insert the tag corresponding to the object type if tags should be updated
    if let Some(tags) = tags.as_mut() {
        check_user_tags(tags)?;
        tags.insert("_sk".to_string());
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
        object_key_block.key_bytes()?.to_base58()
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

fn process_certificate(request: Import) -> Result<(String, Vec<AtomicOperation>), KmsError> {
    // recover user tags
    let mut request_attributes = request.attributes;
    let mut tags = remove_tags(&mut request_attributes);
    if let Some(tags) = tags.as_mut() {
        check_user_tags(&tags)?;
        tags.insert("_cert".to_string());
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
    if let Some(tags) = tags.as_mut() {
        add_certificate_tags(&request_attributes, &certificate, tags)?;
    }
    let der_bytes = certificate.to_der()?;
    let object = Certificate {
        certificate_type: CertificateType::X509,
        certificate_value: der_bytes,
    };

    let uid = if request.unique_identifier.is_empty() {
        der_bytes.to_base58()
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

async fn process_public_key(
    kms: &KMS,
    request: Import,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> Result<(String, Vec<AtomicOperation>), KmsError> {
    // recover user tags
    let mut request_attributes = request.attributes;
    let mut tags = remove_tags(&mut request_attributes);
    // insert the tag corresponding to the object type if tags should be updated
    if let Some(tags) = tags.as_mut() {
        check_user_tags(&tags)?;
        tags.insert("_pk".to_string());
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

    let uid = if request.unique_identifier.is_empty() {
        object_key_block.key_bytes()?.to_base58()
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
        check_user_tags(&tags)?;
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
            object_key_block.key_bytes()?.to_base58()
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
            kms,
            owner,
            params,
            &request.unique_identifier,
            object,
            &request_attributes,
            tags,
            request.replace_existing.unwrap_or(false),
        )
        .await
    }

    // Process a "standard" private key
    // first, see if the private key can be parsed as an openssl object
    let openssl_sk = kmip_private_key_to_openssl(&object)?;
    // generate a key pair
    let ((sk_uid, sk, sk_tags), (pk_uid, pk, pk_tags)) =
        generate_key_pair(openssl_sk, tags, request_attributes)?;
    return Ok((
        sk_uid.clone(),
        vec![
            single_operation(sk_tags, replace_existing, sk, sk_uid),
            single_operation(pk_tags, replace_existing, pk, pk_uid),
        ],
    ))
}

fn private_key_from_openssl(
    sk: PKey<Private>,
    user_tags: Option<HashSet<String>>,
    request_attributes: Attributes,
) -> KResult<(String, Object, Option<HashSet<String>>)> {
    // convert the private key to PKCS#8
    let mut sk = openssl_private_key_to_kmip(&sk, KeyFormatType::PKCS8)?;
    // generate the unique identifiers
    let sk_uid = sk.key_block()?.key_bytes()?.to_base58();

    // Update the private key attributes and link it to the public key
    let mut sk_attributes = request_attributes.clone();
    sk_attributes.add_link(
        LinkType::PublicKeyLink,
        LinkedObjectIdentifier::TextString(pk_uid.clone()),
    );
    //TODO: this needs to be revisited when fixing: https://github.com/Cosmian/kms/issues/88
    let mut sk_key_block = sk.key_block_mut()?;
    sk_key_block.key_value.attributes = Some(sk_attributes);

    //update the private key and public key tags
    let sk_tags = if let Some(user_tags) = user_tags {
        let mut sk_tags = user_tags.clone();
        sk_tags.insert("_sk".to_string());
        Some(sk_tags)
    } else {
        None
    };
    Ok((sk_uid, sk, sk_tags))
}

fn generate_key_pair(
    sk: PKey<Private>,
    user_tags: Option<HashSet<String>>,
    request_attributes: Attributes,
) -> KResult<(
    (String, Object, Option<HashSet<String>>),
    (String, Object, Option<HashSet<String>>),
)> {
    // generate the public key (note: having to fo through DER is strange)
    let pk_der = sk.public_key_to_der()?;
    let pk = PKey::public_key_from_der(&pk_der)?;
    // convert the private key to PKCS#8
    let mut sk = openssl_private_key_to_kmip(&sk, KeyFormatType::PKCS8)?;
    // convert the public key to PKCS#8 (SPKI really)
    let mut pk = openssl_public_key_to_kmip(&pk, KeyFormatType::PKCS8)?;
    // generate the unique identifiers
    let sk_uid = sk.key_block()?.key_bytes()?.to_base58();
    let pk_uid = pk.key_block()?.key_bytes()?.to_base58();

    // Update the private key attributes and link it to the public key
    let mut sk_attributes = request_attributes.clone();
    sk_attributes.add_link(
        LinkType::PublicKeyLink,
        LinkedObjectIdentifier::TextString(pk_uid.clone()),
    );
    //TODO: this needs to be revisited when fixing: https://github.com/Cosmian/kms/issues/88
    let mut sk_key_block = sk.key_block_mut()?;
    sk_key_block.key_value.attributes = Some(sk_attributes);

    // Update the public key attributes and link it to the private key
    let mut pk_attributes = request_attributes;
    pk_attributes.add_link(
        LinkType::PrivateKeyLink,
        LinkedObjectIdentifier::TextString(sk_uid.clone()),
    );
    //TODO: this needs to be revisited when fixing: https://github.com/Cosmian/kms/issues/88
    let mut pk_key_block = pk.key_block_mut()?;
    pk_key_block.key_value.attributes = Some(pk_attributes);

    //update the private key and public key tags
    let (sk_tags, pk_tags) = if let Some(user_tags) = user_tags {
        let mut sk_tags = user_tags.clone();
        sk_tags.insert("_sk".to_string());
        let mut pk_tags = user_tags.clone();
        pk_tags.insert("_pk".to_string());
        (Some(sk_tags), Some(pk_tags))
    } else {
        (None, None)
    };

    // return the key pair
    Ok(((sk_uid, sk, sk_tags), (pk_uid, pk, pk_tags)))
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
    kms: &KMS,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
    private_key_id: &str,
    object: Object,
    request_attributes: &Attributes,
    tags: Option<HashSet<String>>,
    replace_existing: bool,
) -> Result<(String, Vec<AtomicOperation>), KmsError> {
    let mut operations: Vec<AtomicOperation> = Vec::new();
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

    let (private_key_id, mut private_key) = {
        let mut tags = tags.clone();
        if let Some(tags) = tags.as_mut() {
            tags.insert("_sk".to_string());
        }

        // Recover the private key
        let mut private_key = openssl_private_key_to_kmip(
            &pkcs12.pkey.ok_or_else(|| {
                KmsError::InvalidRequest("Private key not found in PKCS12".to_string())
            })?,
            KeyFormatType::PKCS8,
        )?;
        let object_key_block = private_key.key_block_mut()?;

        let private_key_id = if private_key_id.is_empty() {
            object_key_block.key_bytes()?.to_base58()
        } else {
            private_key_id.to_string()
        };

        // // replace attributes
        // //TODO: this needs to be revisited when fixing: https://github.com/Cosmian/kms/issues/88
        // object_key_block.key_value.attributes = Some(request_attributes.clone());

        (private_key_id, private_key)

        // // first set the Link to the private key on the attributes
        // let mut request_attributes = request_attributes.clone();
        // request_attributes.add_link(
        //     LinkType::CertificateLink,
        //     LinkedObjectIdentifier::TextString(format!("{}-cert", uid)),
        // );
    };

    //import the leaf certificate
    let (leaf_certificate_uid, mut leaf_certificate) = {
        // Recover the PKCS12 X509 certificate
        let openssl_cert = pkcs12.cert.ok_or_else(|| {
            KmsError::InvalidRequest("X509 certificate not found in PKCS12".to_string())
        })?;
        let der_bytes = openssl_cert.to_der()?;
        let leaf_certificate_uid = der_bytes.to_base58();
        let leaf_certificate = Certificate {
            certificate_type: CertificateType::X509,
            certificate_value: der_bytes,
        };
        (leaf_certificate_uid, leaf_certificate)
    };

    // import the chain if any  (the chain is optional)
    let mut chain: Vec<(String, Object)> = Vec::new();
    if let Some(cas) = pkcs12.ca {
        // import the cas
        for openssl_cert in cas.into_iter() {
            let der_bytes = openssl_cert.to_der()?;
            let chain_certificate_uid = der_bytes.to_base58();
            let chain_certificate = Certificate {
                certificate_type: CertificateType::X509,
                certificate_value: der_bytes,
            };
            chain.push((chain_certificate_uid, chain_certificate));
            // // first set the Link to the private key on the attributes
            // let mut request_attributes = request_attributes.clone();
            // request_attributes.add_link(
            //     LinkType::ChildLink,
            //     LinkedObjectIdentifier::TextString(private_key_id.to_string()),
            // );
            // // set tags
            // let mut tags = tags.to_owned().unwrap_or_default();
            // add_certificate_tags(&request_attributes, &cert, &mut tags)?;
            // //upsert
            // let cert_uid = format!("{}-cert", uid);
            // single_operation(Some(tags), replace_existing, leaf_certificate, cert_uid)?
        }
    }

    //
    // Stage 2 update the attributes and tags
    // and create the correspomding operations
    //

    //private key attributes and tags
    let mut private_key_attributes = request_attributes.clone();
    private_key_attributes.add_link(
        LinkType::CertificateLink,
        LinkedObjectIdentifier::TextString(private_key_id.to_string()),
    );

    // first set the Link to the private key on the attributes
    let mut request_attributes = request_attributes.clone();
    request_attributes.add_link(
        LinkType::PrivateKeyLink,
        LinkedObjectIdentifier::TextString(uid.to_string()),
    );
    // set tags
    let mut tags = tags.clone().unwrap_or_default();
    add_certificate_tags(&request_attributes, &openssl_cert, &mut tags)?;

    //return the private key
    Ok((uid, operations))
}

fn add_certificate_tags(
    request_attributes: &Attributes,
    certificate: &X509,
    tags: &mut HashSet<String>,
) -> Result<(), KmsError> {
    tags.insert("_cert".to_string());

    // Create tags from links passed in attributes
    //TODO: there is no way of keeping the CA signer in the tags
    //TODO: tagging and associated problems will go when fixing: https://github.com/Cosmian/kms/issues/88

    // this tag will help finding the certificate when a Private key is known
    if let Some(private_key_id) = request_attributes.get_link(LinkType::PrivateKeyLink) {
        let sk_tag = format!("_cert_sk={private_key_id}");
        tags.insert(sk_tag);
    }

    // add the SPKI tag corresponding to the `SubjectKeyIdentifier` X509 extension
    let hash_value = hex::encode(get_or_create_subject_key_identifier_value(&certificate)?);
    let spki_tag = format!("_cert_spki={hash_value}");
    tags.insert(spki_tag);

    // add a tag with Subject Common Name
    let subject_name = certificate.subject_name();
    if let Some(subject_common_name) = subject_name
        .entries_by_nid(openssl::nid::Nid::COMMONNAME)
        .next()
        .and_then(|cn| cn.data().as_utf8().ok())
    {
        let cn_tag = format!("_cert_cn={subject_common_name}");
        tags.insert(cn_tag);
    }
    Ok(())
}

/// Get the `SubjectKeyIdentifier` X509 extension value
/// If it not available, it is
/// calculated according to RFC 5280 section 4.2.1.2
fn get_or_create_subject_key_identifier_value(certificate: &X509) -> Result<Vec<u8>, KmsError> {
    Ok(if let Some(ski) = certificate.subject_key_id() {
        ski.as_slice().to_vec()
    } else {
        let pk = certificate.public_key()?;
        let spki_der = pk.public_key_to_der()?;
        let mut sha1 = Sha1::default();
        sha1.update(&spki_der);
        sha1.finish().to_vec()
    })
}
