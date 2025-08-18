use std::{collections::HashSet, sync::Arc};

#[cfg(feature = "non-fips")]
use cosmian_kms_server_database::reexport::cosmian_kmip::kmip_0::kmip_types::CryptographicUsageMask;
use cosmian_kms_server_database::reexport::{
    cosmian_kmip::{
        self,
        kmip_0::kmip_types::{CertificateType, KeyWrapType, State},
        kmip_2_1::{
            kmip_attributes::Attributes,
            kmip_data_structures::KeyValue,
            kmip_objects::{Certificate, Object, ObjectType, PrivateKey},
            kmip_operations::{Import, ImportResponse},
            kmip_types::{
                CertificateAttributes, CryptographicAlgorithm, KeyFormatType, LinkType,
                LinkedObjectIdentifier, UniqueIdentifier,
            },
        },
    },
    cosmian_kms_crypto::openssl::{
        kmip_private_key_to_openssl, kmip_public_key_to_openssl, openssl_certificate_to_kmip,
        openssl_private_key_to_kmip, openssl_public_key_to_kmip,
        openssl_x509_to_certificate_attributes,
    },
    cosmian_kms_interfaces::{AtomicOperation, SessionParams},
};
use openssl::x509::X509;
use tracing::{debug, trace};
use uuid::Uuid;

use crate::{
    core::{
        KMS,
        retrieve_object_utils::user_has_permission,
        wrapping::{unwrap_object, wrap_and_cache},
    },
    error::KmsError,
    kms_bail,
    result::KResult,
};

/// Import a new object
pub(crate) async fn import(
    kms: &KMS,
    request: Import,
    owner: &str,
    params: Option<Arc<dyn SessionParams>>,
    privileged_users: Option<Vec<String>>,
) -> KResult<ImportResponse> {
    trace!("Entering import KMIP operation: {}", request);
    // Unique identifiers starting with `[` are reserved for queries on tags
    // see tagging
    // For instance, a request for a unique identifier `[tag1]` will
    // attempt to find a valid single object tagged with `tag1`
    if request
        .unique_identifier
        .as_str()
        .unwrap_or_default()
        .starts_with('[')
    {
        kms_bail!("Importing objects with unique identifiers starting with `[` is not supported");
    }

    // To import an object, ensure the user has the `Create` access right.
    // The `Create` right implicitly grants permission for Create, Import, and Register operations.
    if let Some(users) = privileged_users {
        let has_permission = user_has_permission(
            owner,
            None,
            &cosmian_kmip::kmip_2_1::KmipOperation::Create,
            kms,
            params.clone(),
        )
        .await?;

        if !has_permission && !users.iter().any(|u| u == owner) {
            kms_bail!(KmsError::Unauthorized(
                "User does not have create access-right.".to_owned()
            ))
        }
    }

    // process the request based on the object type,
    let (uid, operations) = match request.object.object_type() {
        ObjectType::SymmetricKey => {
            Box::pin(process_symmetric_key(kms, request, owner, params.clone())).await?
        }
        ObjectType::Certificate => process_certificate(request)?,
        ObjectType::PublicKey => {
            Box::pin(process_public_key(kms, request, owner, params.clone())).await?
        }
        ObjectType::PrivateKey => {
            Box::pin(process_private_key(kms, request, owner, params.clone())).await?
        }
        ObjectType::SecretData => {
            Box::pin(process_secret_data(kms, request, owner, params.clone())).await?
        }
        x => {
            return Err(KmsError::InvalidRequest(format!(
                "Import is not yet supported for objects of type : {x}"
            )))
        }
    };
    // execute the operations
    kms.database.atomic(owner, &operations, params).await?;
    // return the uid
    debug!("Imported object with uid: {}", uid);
    Ok(ImportResponse {
        unique_identifier: UniqueIdentifier::TextString(uid),
    })
}

/// If the user specified tags, we will use these and remove them from the request.
/// else we will use the tags with the object attributes
/// If no tags are found, an empty set is returned
pub(crate) fn recover_tags(request_attributes: &Attributes, object: &Object) -> HashSet<String> {
    // extract the tags from the request attributes
    let mut tags = request_attributes.get_tags();
    if !tags.is_empty() {
        //remove system tags starting with '_'
        tags.retain(|t| !t.starts_with('_'));
        return tags;
    }
    // try extracting the tags from the object attributes
    if let Ok(key_block) = object.key_block() {
        if let Some(KeyValue::Structure {
            attributes: Some(attributes),
            ..
        }) = key_block.key_value.as_ref()
        {
            return attributes.get_tags();
        }
    }
    HashSet::new()
}

pub(crate) async fn process_symmetric_key(
    kms: &KMS,
    request: Import,
    owner: &str,
    params: Option<Arc<dyn SessionParams>>,
) -> Result<(String, Vec<AtomicOperation>), KmsError> {
    // check if the object will be replaced if it already exists
    let replace_existing = request.replace_existing.unwrap_or(false);

    // Generate a new UID if none is provided.
    let uid = match request.unique_identifier.to_string() {
        uid if uid.is_empty() => Uuid::new_v4().to_string(),
        uid => uid,
    };

    let mut object = request.object;
    // Unwrap the Object if required.
    if request.key_wrap_type == Some(KeyWrapType::NotWrapped) {
        unwrap_object(&mut object, kms, owner, params.clone()).await?;
    }

    // Tag the object as a symmetric key
    let mut tags = recover_tags(&request.attributes, &object);
    tags.insert("_kk".to_owned());

    //Request attributes will hold the final attributes of the object.
    let mut attributes = request.attributes;
    // force the object type to be SymmetricKey
    attributes.object_type = Some(ObjectType::SymmetricKey);
    // set the unique identifier
    attributes.unique_identifier = Some(UniqueIdentifier::TextString(uid.clone()));

    // set the tags in the attributes
    attributes.set_tags(tags.clone())?;
    // merge the object attributes with the request attributes without overwriting
    //This will recover existing links, for instance
    if let Ok(object_attributes) = object.key_block()?.attributes() {
        attributes.merge(object_attributes, false);
    }
    // make sure we have a CryptographicAlgorithm set; default to AES
    if attributes.cryptographic_algorithm.is_none() {
        attributes.cryptographic_algorithm = Some(CryptographicAlgorithm::AES);
    }

    // force the usage mask to unrestricted if not in FIPS mode
    #[cfg(feature = "non-fips")]
    // In non-FIPS mode, if no CryptographicUsageMask has been specified,
    // default to Unrestricted.
    if attributes.cryptographic_usage_mask.is_none() {
        attributes.set_cryptographic_usage_mask(Some(CryptographicUsageMask::Unrestricted));
    }

    // Replace updated attributes in the object structure.
    if let Ok(key_block) = object.key_block_mut() {
        if let Some(KeyValue::Structure {
            attributes: attrs, ..
        }) = key_block.key_value.as_mut()
        {
            *attrs = Some(attributes.clone());
        }
    }

    // Wrap the object if requested by the user or on the server params
    wrap_and_cache(
        kms,
        owner,
        params,
        &UniqueIdentifier::TextString(uid.clone()),
        &mut object,
    )
    .await?;

    Ok((
        uid.clone(),
        vec![single_operation(
            tags,
            replace_existing,
            object,
            attributes,
            uid,
        )],
    ))
}

pub(crate) fn process_certificate(
    request: Import,
) -> Result<(String, Vec<AtomicOperation>), KmsError> {
    // check if the object will be replaced if it already exists.
    let replace_existing = request.replace_existing.unwrap_or(false);

    // Tag the object as a certificate
    let mut tags = recover_tags(&request.attributes, &request.object);
    tags.insert("_cert".to_owned());

    // The specification says that this should be DER bytes
    let certificate_der_bytes = match request.object {
        Object::Certificate(Certificate {
            certificate_value, ..
        }) => Ok(certificate_value),
        o => Err(KmsError::Certificate(format!(
            "invalid object type {:?} on import",
            o.object_type()
        ))),
    }?;

    // parse the certificate as an OpenSSL object to convert it to the pivot
    let certificate = X509::from_der(&certificate_der_bytes)?;
    // convert the certificate to a KMIP object
    let object = openssl_certificate_to_kmip(&certificate)?;

    // Set the unique identifier, if not provided, generate a new one
    let uid = match request.unique_identifier.to_string() {
        uid if uid.is_empty() => Uuid::new_v4().to_string(),
        uid => uid,
    };

    // build attributes from the request attributes
    let mut attributes = request.attributes;
    attributes.certificate_type = Some(CertificateType::X509);
    attributes.key_format_type = Some(KeyFormatType::X509);
    attributes.object_type = Some(ObjectType::Certificate);
    attributes.unique_identifier = Some(UniqueIdentifier::TextString(uid.clone()));
    // set the certificate attributes
    attributes.certificate_attributes = Some(openssl_x509_to_certificate_attributes(&certificate));
    // set the tags in the attributes
    attributes.set_tags(tags.clone())?;

    // Merge the object attributes with the request attributes without overwriting
    // Certificates do not hold attributes at this stage
    if let Ok(object_attributes) = object.attributes() {
        attributes.merge(object_attributes, false);
    }

    // if not in FIPS mode, set the CryptographicUsageMask to Unrestricted
    #[cfg(feature = "non-fips")]
    if attributes.cryptographic_usage_mask.is_none() {
        attributes.cryptographic_usage_mask = Some(CryptographicUsageMask::Unrestricted);
    }

    Ok((
        uid.clone(),
        vec![single_operation(
            tags,
            replace_existing,
            object,
            attributes,
            uid,
        )],
    ))
}

pub(crate) async fn process_public_key(
    kms: &KMS,
    request: Import,
    owner: &str,
    params: Option<Arc<dyn SessionParams>>,
) -> Result<(String, Vec<AtomicOperation>), KmsError> {
    // check if the object will be replaced if it already exists
    let replace_existing = request.replace_existing.unwrap_or(false);

    let mut object = request.object;
    // Unwrap the key_block if required.
    {
        if request.key_wrap_type == Some(KeyWrapType::NotWrapped) {
            unwrap_object(&mut object, kms, owner, params.clone()).await?;
        }
    }

    // Tag the object as a public key
    let mut tags = recover_tags(&request.attributes, &object);
    tags.insert("_pk".to_owned());

    // Set the unique identifier, if not provided, generate a new one
    let uid = match request.unique_identifier.to_string() {
        uid if uid.is_empty() => Uuid::new_v4().to_string(),
        uid => uid,
    };

    // build the attributes from the request attributes
    let mut attributes = request.attributes;
    // merge the object attributes with the request attributes without overwriting
    // This will recover existing links, for instance
    if let Ok(object_attributes) = object.attributes() {
        attributes.merge(object_attributes, false);
    }

    // If the key is not wrapped and not a Covercrypt Key, try to parse it as an OpenSSL object and
    // import it as a PKCS8
    // TODO: add Covercrypt keys when support for SPKI is added
    // TODO: https://github.com/Cosmian/cover_crypt/issues/118
    {
        let object_key_block = object.key_block()?;
        if object_key_block.key_wrapping_data.is_none()
            && object_key_block.cryptographic_algorithm != Some(CryptographicAlgorithm::CoverCrypt)
        {
            object = openssl_public_key_to_kmip(
                &kmip_public_key_to_openssl(&object)?,
                KeyFormatType::PKCS8,
                attributes.cryptographic_usage_mask,
            )?;
            // Merge the correct cryptographic attributes in the attributes
            attributes.merge(object.attributes()?, true);
        }
    }

    #[cfg(feature = "non-fips")]
    // In non-FIPS mode, if no CryptographicUsageMask has been specified,
    // default to Unrestricted.
    if attributes.cryptographic_usage_mask.is_none() {
        attributes.cryptographic_usage_mask = Some(CryptographicUsageMask::Unrestricted);
    }
    // set the tags in the attributes
    attributes.set_tags(tags.clone())?;
    // set the unique identifier
    attributes.unique_identifier = Some(UniqueIdentifier::TextString(uid.clone()));

    // Replace updated attributes in the object structure.
    if let Ok(key_block) = object.key_block_mut() {
        if let Some(KeyValue::Structure {
            attributes: attrs, ..
        }) = key_block.key_value.as_mut()
        {
            *attrs = Some(attributes.clone());
        }
    }

    // Wrap the object if requested by the user or on the server params
    wrap_and_cache(
        kms,
        owner,
        params,
        &UniqueIdentifier::TextString(uid.clone()),
        &mut object,
    )
    .await?;

    Ok((
        uid.clone(),
        vec![single_operation(
            tags,
            replace_existing,
            object,
            attributes,
            uid,
        )],
    ))
}

pub(crate) async fn process_private_key(
    kms: &KMS,
    request: Import,
    owner: &str,
    params: Option<Arc<dyn SessionParams>>,
) -> Result<(String, Vec<AtomicOperation>), KmsError> {
    // Whether the object will be replaced if it already exists.
    let replace_existing = request.replace_existing.unwrap_or(false);

    // Process based on the key block type.
    let mut object = request.object;
    if request.key_wrap_type == Some(KeyWrapType::NotWrapped) {
        unwrap_object(&mut object, kms, owner, params.clone()).await?;
    }

    // PKCS12 has its own processing
    if object.key_block()?.key_format_type == KeyFormatType::PKCS12 {
        //PKCS#12 contains more than just a private key, and performs specific processing
        return Box::pin(process_pkcs12(
            kms,
            owner,
            params,
            &request.unique_identifier,
            object,
            request.attributes,
            replace_existing,
        ))
        .await;
    }

    // Tag the object as a private key
    let mut tags = recover_tags(&request.attributes, &object);
    tags.insert("_sk".to_owned());

    // Set the unique identifier, if not provided, generate a new one
    let uid = match request.unique_identifier.to_string() {
        uid if uid.is_empty() => Uuid::new_v4().to_string(),
        uid => uid,
    };

    // Recover user tags.
    let mut attributes = request.attributes;
    // merge the object attributes with the request attributes without overwriting
    // this will recover exiting links for instance
    if let Ok(object_attributes) = object.key_block()?.attributes() {
        attributes.merge(object_attributes, false);
    }

    // If the key is not wrapped and not a Covercrypt Key, try to parse it as an OpenSSL object and
    // import it as a PKCS8
    // TODO: remove Covercrypt keys from this exception when support for PKCS#8 is added
    // TODO: https://github.com/Cosmian/cover_crypt/issues/118
    {
        let object_key_block = object.key_block()?;
        if object_key_block.key_wrapping_data.is_none()
            && object_key_block.cryptographic_algorithm != Some(CryptographicAlgorithm::CoverCrypt)
        {
            object = openssl_private_key_to_kmip(
                &kmip_private_key_to_openssl(&object)?,
                KeyFormatType::PKCS8,
                attributes.cryptographic_usage_mask,
            )?;
            // Merge the correct cryptographic attributes in the attributes
            attributes.merge(object.attributes()?, true);
        }
    }

    #[cfg(feature = "non-fips")]
    // In non-FIPS mode, if no CryptographicUsageMask has been specified,
    // default to Unrestricted.
    if attributes.cryptographic_usage_mask.is_none() {
        attributes.cryptographic_usage_mask = Some(CryptographicUsageMask::Unrestricted);
    }
    // set the tags in the attributes
    attributes.set_tags(tags.clone())?;
    // set the unique identifier
    attributes.unique_identifier = Some(UniqueIdentifier::TextString(uid.clone()));

    // Replace updated attributes in the object structure if the object is not wrapped.
    if let Ok(key_block) = object.key_block_mut() {
        if let Some(KeyValue::Structure {
            attributes: attrs, ..
        }) = key_block.key_value.as_mut()
        {
            *attrs = Some(attributes.clone());
        }
    }

    // Wrap the object if requested by the user or on the server params
    wrap_and_cache(
        kms,
        owner,
        params,
        &UniqueIdentifier::TextString(uid.clone()),
        &mut object,
    )
    .await?;

    Ok((
        uid.clone(),
        vec![single_operation(
            tags,
            replace_existing,
            object,
            attributes,
            uid,
        )],
    ))
}

fn single_operation(
    tags: HashSet<String>,
    replace_existing: bool,
    object: Object,
    attributes: Attributes,
    uid: String,
) -> AtomicOperation {
    // Sync the Object::Attributes with input Attributes
    let mut object = object;
    if let Ok(object_attributes) = object.attributes_mut() {
        object_attributes.clone_from(&attributes);
    }
    if replace_existing {
        AtomicOperation::Upsert((uid, object, attributes, Some(tags), State::Active))
    } else {
        AtomicOperation::Create((uid, object, attributes, tags))
    }
}

#[allow(clippy::ref_option)]
async fn process_pkcs12(
    kms: &KMS,
    owner: &str,
    params: Option<Arc<dyn SessionParams>>,
    unique_identifier: &UniqueIdentifier,
    object: Object,
    request_attributes: Attributes,
    replace_existing: bool,
) -> Result<(String, Vec<AtomicOperation>), KmsError> {
    // recover the PKCS#12 bytes from the object
    let pkcs12_bytes = match object {
        Object::PrivateKey(PrivateKey { key_block }) => key_block.pkcs_der_bytes()?,
        _ => kms_bail!("The PKCS12 object is not correctly formatted"),
    };
    let user_tags = request_attributes.get_tags();

    // recover the password from the attributes
    let password = request_attributes
        .get_link(LinkType::PKCS12PasswordLink)
        .map(|l| l.to_string())
        .unwrap_or_default();
    // remove the password from the attributes
    let mut request_attributes = request_attributes;
    request_attributes.remove_link(LinkType::PKCS12PasswordLink);

    // parse the PKCS12
    let pkcs12_parser = openssl::pkcs12::Pkcs12::from_der(&pkcs12_bytes)?;
    let pkcs12 = pkcs12_parser.parse2(&password).map_err(|e| {
        KmsError::Certificate(format!(
            "Unable to parse PKCS12 file: (bad/missing password?). {e:?}"
        ))
    })?;

    // build the leaf certificate id
    let leaf_certificate_id = match unique_identifier.to_string() {
        uid if uid.is_empty() => Uuid::new_v4().to_string(),
        uid => uid,
    };
    // Build the private key ID
    let private_key_id = format!("{leaf_certificate_id}_sk");

    // First, build the tuples (id, Object) for the private key, the leaf certificate
    // and the chain certificates

    // build the private key
    let mut private_key = {
        let openssl_sk = pkcs12.pkey.ok_or_else(|| {
            KmsError::InvalidRequest("Private key not found in PKCS12".to_owned())
        })?;
        let mut private_key = openssl_private_key_to_kmip(
            &openssl_sk,
            KeyFormatType::PKCS8,
            request_attributes.cryptographic_usage_mask,
        )?;
        let mut attributes = request_attributes.clone();
        // merge the object attributes with the request attributes; overwrite with the correct cryptographic parameters
        if let Ok(object_attributes) = private_key.key_block()?.attributes() {
            attributes.merge(object_attributes, true);
        }
        // create the private key tags
        let mut private_key_tags = user_tags.clone();
        private_key_tags.insert("_sk".to_owned());
        // set tags in the attributes
        attributes.set_tags(private_key_tags.clone())?;
        //set the updated attributes on the key
        if let Some(KeyValue::Structure {
            attributes: attrs, ..
        }) = private_key.key_block_mut()?.key_value.as_mut()
        {
            *attrs = Some(attributes);
        }
        private_key
    };

    // build the leaf certificate
    let (leaf_certificate, leaf_certificate_attributes) = {
        // Recover the PKCS12 X509 certificate
        let openssl_cert = pkcs12.cert.clone().ok_or_else(|| {
            KmsError::InvalidRequest("X509 certificate not found in PKCS12".to_owned())
        })?;

        // convert to KMIP
        let leaf_certificate = openssl_certificate_to_kmip(&openssl_cert)?;

        (
            leaf_certificate,
            openssl_x509_to_certificate_attributes(&openssl_cert),
        )
    };

    // Build the public key ID
    let public_key_id = format!("{leaf_certificate_id}_pk");

    // build the public key from the X509 certificate
    let public_key = {
        // Recover the X509 certificate
        let openssl_cert = pkcs12.cert.ok_or_else(|| {
            KmsError::InvalidRequest("X509 certificate not found in PKCS12".to_owned())
        })?;

        // Get public key from X509 certificate
        let openssl_public_key = openssl_cert.public_key()?;

        // convert to KMIP
        let mut public_key = openssl_public_key_to_kmip(
            &openssl_public_key,
            KeyFormatType::PKCS8,
            request_attributes.cryptographic_usage_mask,
        )?;

        let mut attributes = request_attributes.clone();
        // merge the object attributes with the request attributes; overwrite with the correct cryptographic parameters
        if let Ok(object_attributes) = public_key.key_block()?.attributes() {
            attributes.merge(object_attributes, true);
        }
        attributes.set_link(
            LinkType::PrivateKeyLink,
            LinkedObjectIdentifier::TextString(private_key_id.clone()),
        );

        // create the public key tags
        let mut public_key_tags = user_tags.clone();
        public_key_tags.insert("_pk".to_owned());
        // set tags in the attributes
        attributes.set_tags(public_key_tags.clone())?;
        //set the updated attributes on the key
        if let Some(KeyValue::Structure {
            attributes: attrs, ..
        }) = public_key.key_block_mut()?.key_value.as_mut()
        {
            *attrs = Some(attributes);
        }

        public_key
    };

    // build the chain if any (the chain is optional)
    let mut chain: Vec<(String, Object, CertificateAttributes)> = Vec::new();
    if let Some(cas) = pkcs12.ca {
        // import the cas
        for openssl_cert in cas {
            // convert to KMIP
            let chain_certificate = openssl_certificate_to_kmip(&openssl_cert)?;

            chain.push((
                Uuid::new_v4().to_string(),
                chain_certificate,
                openssl_x509_to_certificate_attributes(&openssl_cert),
            ));
        }
    }

    debug!(
        "Importing PKCS12: private_key_id={:?}, leaf_certificate_id={:?}, chain={:?}",
        private_key_id,
        leaf_certificate_id,
        chain.iter().map(|(id, _, _)| id).collect::<Vec<_>>()
    );

    //
    // Stage 2: update the attributes and tags
    // and create the corresponding operations
    //
    let mut operations = Vec::with_capacity(2 + chain.len());

    //add link to certificate in the private key attributes
    if let Some(KeyValue::Structure { attributes, .. }) =
        private_key.key_block_mut()?.key_value.as_mut()
    {
        let attributes = attributes.get_or_insert(Attributes::default());
        //Note: it is unclear what link type should be used here according to KMIP
        // CertificateLink seems to be for public key only, and there is no description
        // for PKCS12CertificateLink
        attributes.set_link(
            LinkType::PKCS12CertificateLink,
            LinkedObjectIdentifier::TextString(leaf_certificate_id.clone()),
        );
    }
    // Wrap the private key if requested by the user or on the server params
    wrap_and_cache(
        kms,
        owner,
        params,
        &UniqueIdentifier::TextString(private_key_id.clone()),
        &mut private_key,
    )
    .await?;
    // Create an operation to set the private key
    let private_key_attributes = private_key.attributes()?.clone();
    operations.push(single_operation(
        private_key_attributes.get_tags(),
        replace_existing,
        private_key,
        private_key_attributes,
        private_key_id.clone(),
    ));

    // Create an operation to set the public key
    let public_key_attributes = public_key.attributes()?.clone();
    operations.push(single_operation(
        public_key_attributes.get_tags(),
        replace_existing,
        public_key,
        public_key_attributes,
        public_key_id.clone(),
    ));

    let mut leaf_attributes = request_attributes.clone();
    // merge the object attributes with the request attributes; overwrite with the correct cryptographic parameters
    leaf_attributes.merge(
        &Attributes {
            certificate_type: Some(CertificateType::X509),
            key_format_type: Some(KeyFormatType::X509),
            object_type: Some(ObjectType::Certificate),
            unique_identifier: Some(UniqueIdentifier::TextString(leaf_certificate_id.clone())),
            certificate_attributes: Some(leaf_certificate_attributes),
            ..Attributes::default()
        },
        true,
    );
    // certificate tags
    let mut leaf_tags = user_tags.clone();
    leaf_tags.insert("_cert".to_owned());
    leaf_attributes.set_tags(leaf_tags)?;

    // Add links to the leaf certificate
    // add private key link to certificate
    // (the KMIP spec is unclear whether there should be a LinkType::PrivateKeyLink)
    leaf_attributes.set_link(
        LinkType::PrivateKeyLink,
        LinkedObjectIdentifier::TextString(private_key_id.clone()),
    );
    // Add public key link to certificate
    leaf_attributes.set_link(
        LinkType::PublicKeyLink,
        LinkedObjectIdentifier::TextString(public_key_id.clone()),
    );

    // add parent link to certificate
    // (according to the KMIP spec, this would be LinkType::CertificateLink)
    if let Some((parent_id, _, _)) = chain.first() {
        leaf_attributes.set_link(
            LinkType::CertificateLink,
            LinkedObjectIdentifier::TextString(parent_id.clone()),
        );
    }

    debug!(
        "Importing leaf certificate with attributes: {:?}",
        leaf_attributes
    );

    operations.push(single_operation(
        leaf_attributes.get_tags(),
        replace_existing,
        leaf_certificate,
        leaf_attributes,
        leaf_certificate_id,
    ));

    let mut parent_certificate_id: Option<String> = None;
    for (chain_certificate_uid, chain_certificate, chain_certificate_attributes) in
        chain.into_iter().rev()
    // reverse the chain to have the root first
    {
        let mut chain_attributes = request_attributes.clone();
        // Add links to the chain certificate
        chain_attributes.merge(
            &Attributes {
                certificate_type: Some(CertificateType::X509),
                key_format_type: Some(KeyFormatType::X509),
                object_type: Some(ObjectType::Certificate),
                unique_identifier: Some(UniqueIdentifier::TextString(
                    chain_certificate_uid.clone(),
                )),
                certificate_attributes: Some(chain_certificate_attributes),
                ..Attributes::default()
            },
            true,
        );
        // certificate tags
        let mut chain_tags = user_tags.clone();
        chain_tags.insert("_cert".to_owned());
        chain_attributes.set_tags(chain_tags)?;

        if let Some(parent_certificate_id) = parent_certificate_id {
            // add parent link to certificate
            // (according to the KMIP spec, this would be LinkType::CertificateLink)
            chain_attributes.set_link(
                LinkType::CertificateLink,
                LinkedObjectIdentifier::TextString(parent_certificate_id.clone()),
            );
        }
        operations.push(single_operation(
            chain_attributes.get_tags(),
            true,
            chain_certificate,
            chain_attributes,
            chain_certificate_uid.clone(),
        ));
        parent_certificate_id = Some(chain_certificate_uid);
    }

    //return the private key
    Ok((private_key_id, operations))
}

pub(crate) async fn process_secret_data(
    kms: &KMS,
    request: Import,
    owner: &str,
    params: Option<Arc<dyn SessionParams>>,
) -> Result<(String, Vec<AtomicOperation>), KmsError> {
    // check if the object will be replaced if it already exists
    let replace_existing = request.replace_existing.unwrap_or(false);

    // Generate a new UID if none is provided.
    let uid = match request.unique_identifier.to_string() {
        uid if uid.is_empty() => Uuid::new_v4().to_string(),
        uid => uid,
    };

    let mut object = request.object;
    // Unwrap the Object if required.
    if request.key_wrap_type == Some(KeyWrapType::NotWrapped) {
        unwrap_object(&mut object, kms, owner, params.clone()).await?;
    }

    // Tag the object as a secret data
    let mut tags = recover_tags(&request.attributes, &object);
    tags.insert("_sd".to_owned());

    //Request attributes will hold the final attributes of the object.
    let mut attributes = request.attributes;
    // force the object type to be SecretData
    attributes.object_type = Some(ObjectType::SecretData);
    // set the unique identifier
    attributes.unique_identifier = Some(UniqueIdentifier::TextString(uid.clone()));

    // set the tags in the attributes
    attributes.set_tags(tags.clone())?;
    // merge the object attributes with the request attributes without overwriting
    //This will recover existing links, for instance
    if let Ok(object_attributes) = object.key_block()?.attributes() {
        attributes.merge(object_attributes, false);
    }

    // force the usage mask to unrestricted if not in FIPS mode
    #[cfg(feature = "non-fips")]
    // In non-FIPS mode, if no CryptographicUsageMask has been specified,
    // default to Unrestricted.
    if attributes.cryptographic_usage_mask.is_none() {
        attributes.set_cryptographic_usage_mask(Some(CryptographicUsageMask::Unrestricted));
    }

    // Replace updated attributes in the object structure.
    if let Ok(key_block) = object.key_block_mut() {
        if let Some(KeyValue::Structure {
            attributes: attrs, ..
        }) = key_block.key_value.as_mut()
        {
            *attrs = Some(attributes.clone());
        }
    }

    // Wrap the object if requested by the user or on the server params
    wrap_and_cache(
        kms,
        owner,
        params,
        &UniqueIdentifier::TextString(uid.clone()),
        &mut object,
    )
    .await?;

    Ok((
        uid.clone(),
        vec![single_operation(
            tags,
            replace_existing,
            object,
            attributes,
            uid,
        )],
    ))
}
