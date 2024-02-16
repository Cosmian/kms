use std::collections::HashSet;

use cosmian_kmip::{
    kmip::{
        kmip_objects::{
            Object::{self, Certificate},
            ObjectType,
        },
        kmip_operations::{Import, ImportResponse},
        kmip_types::{
            Attributes, CertificateAttributes, CertificateType, CryptographicAlgorithm,
            KeyFormatType, KeyWrapType, LinkType, LinkedObjectIdentifier, StateEnumeration,
            UniqueIdentifier,
        },
    },
    openssl::{
        kmip_private_key_to_openssl, kmip_public_key_to_openssl, openssl_certificate_to_kmip,
        openssl_private_key_to_kmip, openssl_public_key_to_kmip,
    },
};
use openssl::{
    pkey::{PKey, Private},
    x509::X509,
};
use tracing::{debug, trace};
use uuid::Uuid;

use super::wrapping::unwrap_key;
use crate::{
    core::{extra_database_params::ExtraDatabaseParams, KMS},
    database::AtomicOperation,
    error::KmsError,
    kms_bail,
    result::KResult,
};

/// Import a new object
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
    if request
        .unique_identifier
        .as_str()
        .unwrap_or_default()
        .starts_with('[')
    {
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
        unique_identifier: UniqueIdentifier::TextString(uid),
    })
}

async fn process_symmetric_key(
    kms: &KMS,
    request: Import,
    owner: &str,
    params: Option<&ExtraDatabaseParams>,
) -> Result<(String, Vec<AtomicOperation>), KmsError> {
    // recover user tags
    let mut attributes = request.attributes;
    let mut tags = attributes.remove_tags();
    if let Some(tags) = tags.as_ref() {
        Attributes::check_user_tags(tags)?;
    }

    let mut object = request.object;
    // unwrap key block if required
    let object_key_block = object.key_block_mut()?;
    // unwrap before storing if requested
    if request.key_wrap_type == Some(KeyWrapType::NotWrapped) {
        unwrap_key(object_key_block, kms, owner, params).await?;
    }
    // replace attributes
    attributes.object_type = Some(ObjectType::SymmetricKey);
    object_key_block.key_value.attributes = Some(attributes.clone());

    let uid = match request.unique_identifier.to_string().unwrap_or_default() {
        uid if uid.is_empty() => Uuid::new_v4().to_string(),
        uid => uid,
    };

    // insert the tag corresponding to the object type if tags should be updated
    if let Some(tags) = tags.as_mut() {
        tags.insert("_sk".to_string());
    }

    let sk_attributes = object.attributes()?.clone();
    // check if the object will be replaced if it already exists
    let replace_existing = request.replace_existing.unwrap_or(false);
    Ok((
        uid.clone(),
        vec![single_operation(
            tags,
            replace_existing,
            object,
            sk_attributes,
            uid,
        )],
    ))
}

fn process_certificate(request: Import) -> Result<(String, Vec<AtomicOperation>), KmsError> {
    // recover user tags
    let mut request_attributes = request.attributes;
    let mut user_tags = request_attributes.remove_tags();
    if let Some(tags) = user_tags.as_ref() {
        Attributes::check_user_tags(tags)?;
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
    let certificate_attributes = CertificateAttributes::from(&certificate);

    // insert the tag corresponding to the object type if tags should be updated
    if let Some(tags) = user_tags.as_mut() {
        tags.insert("_cert".to_string());
    };

    // convert the certificate to a KMIP object
    let (unique_id, object) = openssl_certificate_to_kmip(&certificate)?;
    let uid = match request.unique_identifier.to_string().unwrap_or_default() {
        uid if uid.is_empty() => unique_id,
        uid => uid,
    };

    let certificate_attributes = Attributes {
        certificate_type: Some(CertificateType::X509),
        key_format_type: Some(KeyFormatType::X509),
        link: request_attributes.link,
        object_type: Some(ObjectType::Certificate),
        unique_identifier: Some(UniqueIdentifier::TextString(uid.clone())),
        certificate_attributes: Some(certificate_attributes),
        ..Attributes::default()
    };

    // check if the object will be replaced if it already exists
    let replace_existing = request.replace_existing.unwrap_or(false);
    Ok((
        uid.clone(),
        vec![single_operation(
            user_tags,
            replace_existing,
            object,
            certificate_attributes,
            uid,
        )],
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
    let mut tags = request_attributes.remove_tags();
    if let Some(tags) = tags.as_ref() {
        Attributes::check_user_tags(tags)?;
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
            // convert back to KMIP Object
            openssl_public_key_to_kmip(&openssl_pk, KeyFormatType::PKCS8)?
        } else {
            object
        }
    };

    // add imported links to attributes
    add_imported_links_to_attributes(
        object
            .key_block_mut()?
            .key_value
            .attributes
            .get_or_insert(Attributes::default()),
        &request_attributes,
    );

    if let Some(tags) = tags.as_mut() {
        tags.insert("_pk".to_string());
    }

    let uid = match request.unique_identifier.to_string().unwrap_or_default() {
        uid if uid.is_empty() => Uuid::new_v4().to_string(),
        uid => uid,
    };

    let public_key_attributes = object.attributes()?.clone();
    // check if the object will be replaced if it already exists
    let replace_existing = request.replace_existing.unwrap_or(false);
    Ok((
        uid.clone(),
        vec![single_operation(
            tags,
            replace_existing,
            object,
            public_key_attributes,
            uid,
        )],
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
    let tags = request_attributes.remove_tags();
    // insert the tag corresponding to the object type if tags should be updated
    if let Some(tags) = tags.as_ref() {
        Attributes::check_user_tags(tags)?;
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
        let object_key_block = object.key_block_mut()?;
        // add imported links to attributes
        add_imported_links_to_attributes(
            &mut request_attributes,
            object_key_block
                .key_value
                .attributes
                .get_or_insert(Attributes::default()),
        );

        // build ui if needed
        let uid = match request.unique_identifier.to_string().unwrap_or_default() {
            uid if uid.is_empty() => Uuid::new_v4().to_string(),
            uid => uid,
        };

        return Ok((
            uid.clone(),
            vec![single_operation(
                tags,
                replace_existing,
                object,
                request_attributes,
                uid,
            )],
        ))
    }

    // PKCS12  have their own processing
    if key_block.key_format_type == KeyFormatType::PKCS12 {
        //PKCS#12 contain more than just a private key, perform specific processing
        return process_pkcs12(
            request.unique_identifier.as_str().unwrap_or_default(),
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
        &mut request_attributes,
        request.unique_identifier.as_str().unwrap_or_default(),
    )?;
    Ok((
        sk_uid.clone(),
        vec![single_operation(
            sk_tags,
            replace_existing,
            sk,
            request_attributes,
            sk_uid,
        )],
    ))
}

fn private_key_from_openssl(
    sk: PKey<Private>,
    user_tags: Option<HashSet<String>>,
    request_attributes: &mut Attributes,
    request_uid: &str,
) -> KResult<(String, Object, Option<HashSet<String>>)> {
    // convert the private key to PKCS#8
    let mut sk = openssl_private_key_to_kmip(&sk, KeyFormatType::PKCS8)?;

    let sk_uid = if request_uid.is_empty() {
        Uuid::new_v4().to_string()
    } else {
        request_uid.to_string()
    };

    let sk_key_block = sk.key_block_mut()?;

    // add imported links to attributes
    add_imported_links_to_attributes(
        request_attributes,
        sk_key_block
            .key_value
            .attributes
            .get_or_insert(Attributes::default()),
    );

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
    attributes: Attributes,
    uid: String,
) -> AtomicOperation {
    if replace_existing {
        AtomicOperation::Upsert((
            uid,
            object,
            attributes,
            tags.clone(),
            StateEnumeration::Active,
        ))
    } else {
        AtomicOperation::Create((
            uid.clone(),
            object,
            attributes,
            tags.clone().unwrap_or_default(),
        ))
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
    // remove the password from the attributes
    let mut request_attributes = request_attributes;
    request_attributes.remove_link(LinkType::PKCS12PasswordLink);

    // parse the PKCS12
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
            &mut request_attributes,
            private_key_id,
        )?
    };

    //build the leaf certificate
    let (
        leaf_certificate_uid,
        leaf_certificate,
        leaf_certificate_tags,
        leaf_certificate_attributes,
    ) = {
        // Recover the PKCS12 X509 certificate
        let openssl_cert = pkcs12.cert.ok_or_else(|| {
            KmsError::InvalidRequest("X509 certificate not found in PKCS12".to_string())
        })?;

        // insert the tag corresponding to the object type if tags should be updated
        let mut leaf_certificate_tags = user_tags.clone().unwrap_or_default();
        leaf_certificate_tags.insert("_cert".to_string());

        // convert to KMIP
        let (leaf_certificate_uid, leaf_certificate) = openssl_certificate_to_kmip(&openssl_cert)?;

        (
            leaf_certificate_uid,
            leaf_certificate,
            leaf_certificate_tags,
            CertificateAttributes::from(&openssl_cert),
        )
    };

    // build the chain if any  (the chain is optional)
    let mut chain: Vec<(String, Object, HashSet<String>, CertificateAttributes)> = Vec::new();
    if let Some(cas) = pkcs12.ca {
        // import the cas
        for openssl_cert in cas {
            // insert the tag corresponding to the object type if tags should be updated
            let mut chain_certificate_tags = user_tags.clone().unwrap_or_default();
            chain_certificate_tags.insert("_cert".to_string());

            // convert to KMIP
            let (chain_certificate_uid, chain_certificate) =
                openssl_certificate_to_kmip(&openssl_cert)?;

            chain.push((
                chain_certificate_uid,
                chain_certificate,
                chain_certificate_tags,
                CertificateAttributes::from(&openssl_cert),
            ));
        }
    }

    //
    // Stage 2 update the attributes and tags
    // and create the corresponding operations
    //
    let mut operations = Vec::with_capacity(2 + chain.len());

    //add link to certificate in the private key attributes
    private_key
        .key_block_mut()?
        .key_value
        .attributes
        .get_or_insert(Attributes::default())
        .add_link(
            //Note: it is unclear what link type should be used here according to KMIP
            // CertificateLink seems to be for public key only and there is not description
            // for PKCS12CertificateLink
            LinkType::PKCS12CertificateLink,
            LinkedObjectIdentifier::TextString(leaf_certificate_uid.clone()),
        );

    let private_key_attributes = private_key.attributes()?.clone();
    operations.push(single_operation(
        private_key_tags,
        replace_existing,
        private_key,
        private_key_attributes,
        private_key_id.clone(),
    ));
    let request_links = request_attributes.link.unwrap_or_default();
    let mut leaf_certificate_attributes = Attributes {
        certificate_type: Some(CertificateType::X509),
        key_format_type: Some(KeyFormatType::X509),
        link: Some(request_links.clone()),
        object_type: Some(ObjectType::Certificate),
        unique_identifier: Some(UniqueIdentifier::TextString(leaf_certificate_uid.clone())),
        certificate_attributes: Some(leaf_certificate_attributes),
        ..Attributes::default()
    };
    // Add links to the leaf certificate
    // add private key link to certificate
    // (the KMIP spec is unclear whether there should be a LinkType::PrivateKeyLink)
    leaf_certificate_attributes.add_link(
        LinkType::PrivateKeyLink,
        LinkedObjectIdentifier::TextString(private_key_id.clone()),
    );

    // add parent link to certificate
    // (according to the KMIP spec, this would be LinkType::CertificateLink)
    if let Some((parent_id, _, _, _)) = chain.first() {
        leaf_certificate_attributes.add_link(
            LinkType::CertificateLink,
            LinkedObjectIdentifier::TextString(parent_id.clone()),
        );
    }

    operations.push(single_operation(
        Some(leaf_certificate_tags),
        replace_existing,
        leaf_certificate,
        leaf_certificate_attributes,
        leaf_certificate_uid.clone(),
    ));

    let mut parent_certificate_id: Option<String> = None;
    for (
        chain_certificate_uid,
        chain_certificate,
        chain_certificate_tags,
        chain_certificate_attributes,
    ) in chain.into_iter().rev()
    // reverse the chain to have the root first
    {
        // Add links to the chain certificate
        let mut chain_certificate_attributes = Attributes {
            certificate_type: Some(CertificateType::X509),
            key_format_type: Some(KeyFormatType::X509),
            link: Some(request_links.clone()),
            object_type: Some(ObjectType::Certificate),
            unique_identifier: Some(UniqueIdentifier::TextString(chain_certificate_uid.clone())),
            certificate_attributes: Some(chain_certificate_attributes),
            ..Attributes::default()
        };

        if let Some(parent_certificate_id) = parent_certificate_id {
            // add parent link to certificate
            // (according to the KMIP spec, this would be LinkType::CertificateLink)
            chain_certificate_attributes.add_link(
                LinkType::ParentLink,
                LinkedObjectIdentifier::TextString(parent_certificate_id.clone()),
            );
        }
        operations.push(single_operation(
            Some(chain_certificate_tags),
            true,
            chain_certificate,
            chain_certificate_attributes,
            chain_certificate_uid.clone(),
        ));
        parent_certificate_id = Some(chain_certificate_uid);
    }

    //return the private key
    Ok((private_key_id, operations))
}

pub(crate) fn add_imported_links_to_attributes(
    attributes: &mut Attributes,
    links_to_add: &Attributes,
) {
    if let Some(new_links) = links_to_add.link.as_ref() {
        match attributes.link.as_mut() {
            Some(existing_links) => {
                for new_link in new_links {
                    if !existing_links.contains(new_link) {
                        existing_links.push(new_link.clone());
                    }
                }
            }
            None => {
                attributes.link = Some(new_links.clone());
            }
        }
    }
}
