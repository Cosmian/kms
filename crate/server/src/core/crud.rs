use std::fs;

use async_trait::async_trait;
use cosmian_kmip::kmip::{
    kmip_data_structures::KeyValue,
    kmip_objects::{Object, ObjectType},
    kmip_operations::{
        Create, CreateKeyPair, CreateKeyPairResponse, CreateResponse, Decrypt, DecryptResponse,
        Destroy, DestroyResponse, Encrypt, EncryptResponse, Get, GetAttributes,
        GetAttributesResponse, GetResponse, Import, ImportResponse, Locate, LocateResponse,
        ReKeyKeyPair, ReKeyKeyPairResponse, Revoke, RevokeResponse,
    },
    kmip_types::{
        AttributeReference, Attributes, CryptographicAlgorithm, KeyFormatType, Link, LinkType,
        LinkedObjectIdentifier, RevocationReason, RevocationReasonEnumeration, StateEnumeration,
        Tag, UniqueIdentifier,
    },
};
use cosmian_kms_utils::{
    crypto::{
        abe::locate::compare_abe_attributes, cover_crypt::locate::compare_cover_crypt_attributes,
    },
    types::{
        Access, ObjectOperationTypes, ObjectOwnedResponse, ObjectSharedResponse, UserAccessResponse,
    },
};
use libsgx::quote::{get_quote, hash, prepare_report_data};
use tracing::{debug, trace, warn};
use uuid::Uuid;

use crate::{
    config::{certbot, manifest_path},
    error::KmsError,
    kms_bail,
    result::KResult,
    KMS,
};

#[async_trait]
pub trait KmipServer {
    /// This operation requests the server to Import a Managed Object specified
    /// by its Unique Identifier. The request specifies the object being
    /// imported and all the attributes to be assigned to the object. The
    /// attribute rules for each attribute for “Initially set by” and “When
    /// implicitly set” SHALL NOT be enforced as all attributes MUST be set
    /// to the supplied values rather than any server generated values.
    /// The response contains the Unique Identifier provided in the request or
    /// assigned by the server. The server SHALL copy the Unique Identifier
    /// returned by this operations into the ID Placeholder variable.
    async fn import(&self, request: Import, owner: &str) -> KResult<ImportResponse>;

    /// This operation requests the server to generate a new symmetric key or
    /// generate Secret Data as a Managed Cryptographic Object.
    /// The request contains information about the type of object being created,
    /// and some of the attributes to be assigned to the object (e.g.,
    /// Cryptographic Algorithm, Cryptographic Length, etc.). The response
    /// contains the Unique Identifier of the created object. The server SHALL
    /// copy the Unique Identifier returned by this operation into the ID
    /// Placeholder variable.
    async fn create(&self, request: Create, owner: &str) -> KResult<CreateResponse>;

    /// This operation requests the server to generate a new public/private key
    /// pair and register the two corresponding new Managed Cryptographic Object
    /// The request contains attributes to be assigned to the objects (e.g.,
    /// Cryptographic Algorithm, Cryptographic Length, etc.). Attributes MAY
    /// be specified for both keys at the same time by specifying a Common
    /// Attributes object in the request. Attributes not common to both keys
    /// (e.g., Name, Cryptographic Usage Mask) MAY be specified
    /// using the Private Key Attributes and Public Key Attributes objects in
    /// the request, which take precedence over the Common Attributes object.
    /// For the Private Key, the server SHALL create a Link attribute of Link
    /// Type Public Key pointing to the Public Key. For the Public Key, the
    /// server SHALL create a Link attribute of Link Type Private Key pointing
    /// to the Private Key. The response contains the Unique Identifiers of
    /// both created objects. The ID Placeholder value SHALL be set to the
    /// Unique Identifier of the Private Key
    async fn create_key_pair(
        &self,
        request: CreateKeyPair,
        owner: &str,
    ) -> KResult<CreateKeyPairResponse>;

    /// This operation requests that the server returns the Managed Object
    /// specified by its Unique Identifier. Only a single object is
    /// returned. The response contains the Unique Identifier of the object,
    /// along with the object itself, which MAY be wrapped using a wrapping
    /// key as specified in the request. The following key format
    /// capabilities SHALL be assumed by the client; restrictions apply when the
    /// client requests the server to return an object in a particular
    /// format: • If a client registered a key in a given format, the server
    /// SHALL be able to return the key during the Get operation in the same
    /// format that was used when the key was registered. • Any other format
    /// conversion MAY be supported by the server. If Key Format Type is
    /// specified to be PKCS#12 then the response payload shall be a PKCS#12
    /// container as specified by [RFC7292]. The Unique Identifier shall be
    /// either that of a private key or certificate to be included in the
    /// response. The container shall be protected using the Secret Data object
    /// specified via the private key or certificate’s PKCS#12 Password
    /// Link. The current certificate chain shall also be included
    /// as determined by using the private key’s Public Key link to get the
    /// corresponding public key (where relevant), and then using that
    /// public key’s PKCS#12 Certificate Link to get the base certificate, and
    /// then using each certificate’s Ce
    async fn get(&self, request: Get, owner: &str) -> KResult<GetResponse>;

    /// This operation requests one or more attributes associated with a Managed
    /// Object. The object is specified by its Unique Identifier, and the
    /// attributes are specified by their name in the request. If a specified
    /// attribute has multiple instances, then all instances are returned. If a
    /// specified attribute does not exist (i.e., has no value), then it
    /// SHALL NOT be present in the returned response. If none of the requested
    /// attributes exist, then the response SHALL consist only of the Unique
    /// Identifier. The same Attribute Reference SHALL NOT be present more
    /// than once in a request. If no Attribute Reference is provided, the
    /// server SHALL return all attributes.
    async fn get_attributes(
        &self,
        request: GetAttributes,
        owner: &str,
    ) -> KResult<GetAttributesResponse>;

    /// This operation requests the server to perform an encryption operation on
    /// the provided data using a Managed Cryptographic Object as the key
    /// for the encryption operation.
    ///
    /// The request contains information about the cryptographic parameters
    /// (mode and padding method), the data to be encrypted, and the
    /// IV/Counter/Nonce to use. The cryptographic parameters MAY be omitted
    /// from the request as they can be specified as associated attributes of
    /// the Managed Cryptographic Object.
    ///
    /// The IV/Counter/Nonce MAY also be omitted from the request if the
    /// cryptographic parameters indicate that the server shall generate a
    /// Random IV on behalf of the client or the encryption algorithm does not
    /// need an IV/Counter/Nonce. The server does not store or otherwise
    /// manage the IV/Counter/Nonce.
    ///
    /// If the Managed Cryptographic Object referenced has a Usage Limits
    /// attribute then the server SHALL obtain an allocation from the
    /// current Usage Limits value prior to performing the encryption operation.
    /// If the allocation is unable to be obtained the operation SHALL
    /// return with a result status of Operation Failed and result reason of
    /// Permission Denied.
    ///
    /// The response contains the Unique Identifier of the Managed Cryptographic
    /// Object used as the key and the result of the encryption operation.
    ///
    /// The success or failure of the operation is indicated by the Result
    /// Status (and if failure the Result Reason) in the response header.
    async fn encrypt(&self, request: Encrypt, owner: &str) -> KResult<EncryptResponse>;

    /// This operation requests the server to perform a decryption operation on
    /// the provided data using a Managed Cryptographic Object as the key
    /// for the decryption operation.
    ///
    /// The request contains information about the cryptographic parameters
    /// (mode and padding method), the data to be decrypted, and the
    /// IV/Counter/Nonce to use. The cryptographic parameters MAY be omitted
    /// from the request as they can be specified as associated attributes of
    /// the Managed Cryptographic Object.
    ///
    /// The initialization vector/counter/nonce MAY also be omitted from the
    /// request if the algorithm does not use an IV/Counter/Nonce.
    ///
    /// The response contains the Unique Identifier of the Managed Cryptographic
    /// Object used as the key and the result of the decryption operation.
    ///
    /// The success or failure of the operation is indicated by the Result
    /// Status (and if failure the Result Reason) in the response header.
    async fn decrypt(&self, request: Decrypt, owner: &str) -> KResult<DecryptResponse>;

    /// This operation requests that the server search for one or more Managed
    /// Objects, depending on the attributes specified in the request. All
    /// attributes are allowed to be used. The request MAY contain a Maximum
    /// Items field, which specifies the maximum number of objects to be
    /// returned. If the Maximum Items field is omitted, then the server MAY
    /// return all objects matched, or MAY impose an internal maximum limit due
    /// to resource limitations.
    ///
    /// The request MAY contain an Offset Items field, which specifies the
    /// number of objects to skip that satisfy the identification criteria
    /// specified in the request. An Offset Items field of 0 is the same as
    /// omitting the Offset Items field. If both Offset Items and Maximum Items
    /// are specified in the request, the server skips Offset Items objects and
    /// returns up to Maximum Items objects.
    ///
    /// If more than one object satisfies the identification criteria specified
    /// in the request, then the response MAY contain Unique Identifiers for
    /// multiple Managed Objects. Responses containing Unique Identifiers for
    /// multiple objects SHALL be returned in descending order of object
    /// creation (most recently created object first).  Returned objects SHALL
    /// match all of the attributes in the request. If no objects match, then an
    /// empty response payload is returned. If no attribute is specified in the
    /// request, any object SHALL be deemed to match the Locate request. The
    /// response MAY include Located Items which is the count of all objects
    /// that satisfy the identification criteria.
    ///
    /// The server returns a list of Unique Identifiers of the found objects,
    /// which then MAY be retrieved using the Get operation. If the objects are
    /// archived, then the Recover and Get operations are REQUIRED to be used to
    /// obtain those objects. If a single Unique Identifier is returned to the
    /// client, then the server SHALL copy the Unique Identifier returned by
    /// this operation into the ID Placeholder variable.  If the Locate
    /// operation matches more than one object, and the Maximum Items value is
    /// omitted in the request, or is set to a value larger than one, then the
    /// server SHALL empty the ID Placeholder, causing any subsequent operations
    /// that are batched with the Locate, and which do not specify a Unique
    /// Identifier explicitly, to fail. This ensures that these batched
    /// operations SHALL proceed only if a single object is returned by Locate.
    ///
    /// The Date attributes in the Locate request (e.g., Initial Date,
    /// Activation Date, etc.) are used to specify a time or a time range for
    /// the search. If a single instance of a given Date attribute is used in
    /// the request (e.g., the Activation Date), then objects with the same Date
    /// attribute are considered to be matching candidate objects. If two
    /// instances of the same Date attribute are used (i.e., with two different
    /// values specifying a range), then objects for which the Date attribute is
    /// inside or at a limit of the range are considered to be matching
    /// candidate objects. If a Date attribute is set to its largest possible
    /// value, then it is equivalent to an undefined attribute. The KMIP Usage
    /// Guide [KMIP-UG] provides examples.
    ///
    /// When the Cryptographic Usage Mask attribute is specified in the request,
    /// candidate objects are compared against this field via an operation that
    /// consists of a logical AND of the requested mask with the mask in the
    /// candidate object, and then a comparison of the resulting value with the
    /// requested mask. For example, if the request contains a mask value of
    /// 10001100010000, and a candidate object mask contains 10000100010000,
    /// then the logical AND of the two masks is 10000100010000, which is
    /// compared against the mask value in the request (10001100010000) and the
    /// match fails. This means that a matching candidate object has all of the
    /// bits set in its mask that are set in the requested mask, but MAY have
    /// additional bits set.
    ///
    /// When the Usage Limits attribute is specified in the request, matching
    /// candidate objects SHALL have a Usage Limits Count and Usage Limits Total
    /// equal to or larger than the values specified in the request.
    ///
    /// When an attribute that is defined as a structure is specified, all of
    /// the structure fields are not REQUIRED to be specified. For instance, for
    /// the Link attribute, if the Linked Object Identifier value is specified
    /// without the Link Type value, then matching candidate objects have the
    /// Linked Object Identifier as specified, irrespective of their Link Type.
    ///
    /// When the Object Group attribute and the Object Group Member flag are
    /// specified in the request, and the value specified for Object Group
    /// Member is ‘Group Member Fresh’, matching candidate objects SHALL be
    /// fresh objects from the object group. If there are no more fresh objects
    /// in the group, the server MAY choose to generate a new object on-the-fly,
    /// based on server policy. If the value specified for Object Group Member
    /// is ‘Group Member Default’, the server locates the default object as
    /// defined by server policy.
    ///
    /// The Storage Status Mask field is used to indicate whether on-line
    /// objects (not archived or destroyed), archived objects, destroyed objects
    /// or any combination of the above are to be searched.The server SHALL NOT
    /// return unique identifiers for objects that are destroyed unless the
    /// Storage Status Mask field includes the Destroyed Storage indicator. The
    /// server SHALL NOT return unique identifiers for objects that are archived
    /// unless the Storage Status Mask field includes the Archived Storage
    /// indicator.
    async fn locate(&self, request: Locate, owner: &str) -> KResult<LocateResponse>;

    /// This operation requests the server to revoke a Managed Cryptographic
    /// Object or an Opaque Object. The request contains a reason for the
    /// revocation (e.g., “key compromise”, “cessation of operation”, etc.). The
    /// operation has one of two effects. If the revocation reason is “key
    /// compromise” or “CA compromise”, then the object is placed into the
    /// “compromised” state; the Date is set to the current date and time; and
    /// the Compromise Occurrence Date is set to the value (if provided) in the
    /// Revoke request and if a value is not provided in the Revoke request then
    /// Compromise Occurrence Date SHOULD be set to the Initial Date for the
    /// object. If the revocation reason is neither “key compromise” nor “CA
    /// compromise”, the object is placed into the “deactivated” state, and the
    /// Deactivation Date is set to the current date and time.
    async fn revoke(&self, request: Revoke, owner: &str) -> KResult<RevokeResponse>;

    // This request is used to generate a replacement key pair for an existing
    // public/private key pair.  It is analogous to the Create Key Pair operation,
    // except that attributes of the replacement key pair are copied from the
    // existing key pair, with the exception of the attributes listed in Re-key Key
    // Pair Attribute Requirements tor.
    //
    // As the replacement of the key pair takes over the name attribute for the
    // existing public/private key pair, Re-key Key Pair SHOULD only be performed
    // once on a given key pair.
    //
    // For both the existing public key and private key, the server SHALL create a
    // Link attribute of Link Type Replacement Key pointing to the replacement
    // public and private key, respectively. For both the replacement public and
    // private key, the server SHALL create a Link attribute of Link Type Replaced
    // Key pointing to the existing public and private key, respectively.
    //
    // The server SHALL copy the Private Key Unique Identifier of the replacement
    // private key returned by this operation into the ID Placeholder variable.
    //
    // An Offset MAY be used to indicate the difference between the Initial Date and
    // the Activation Date of the replacement key pair. If no Offset is specified,
    // the Activation Date and Deactivation Date values are copied from the existing
    // key pair. If Offset is set and dates exist for the existing key pair, then
    // the dates of the replacement key pair SHALL be set based on the dates of the
    // existing key pair as follows
    async fn rekey_keypair(
        &self,
        request: ReKeyKeyPair,
        owner: &str,
    ) -> KResult<ReKeyKeyPairResponse>;

    /// This operation is used to indicate to the server that the key material
    /// for the specified Managed Object SHALL be destroyed or rendered
    /// inaccessible. The meta-data for the key material SHALL be retained by
    /// the server.  Objects SHALL only be destroyed if they are in either
    /// Pre-Active or Deactivated state.
    async fn destroy(&self, request: Destroy, owner: &str) -> KResult<DestroyResponse>;

    /// Insert an access authorization for a user (identified by `access.userid`)
    /// to an object (identified by `access.unique_identifier`)
    /// which is owned by `owner` (identified by `access.owner`)
    async fn insert_access(&self, access: &Access, owner: &str) -> KResult<()>;

    /// Remove an access authorization for a user (identified by `access.userid`)
    /// to an object (identified by `access.unique_identifier`)
    /// which is owned by `owner` (identified by `access.owner`)
    async fn delete_access(&self, access: &Access, owner: &str) -> KResult<()>;

    /// Get all the access authorization for a given object
    async fn list_accesses(
        &self,
        object_id: &UniqueIdentifier,
        owner: &str,
    ) -> KResult<Vec<UserAccessResponse>>;

    /// Get all the objects owned by a given user (the owner)
    async fn list_owned_objects(&self, owner: &str) -> KResult<Vec<ObjectOwnedResponse>>;

    /// Get all the objects shared to a given user
    async fn list_shared_objects(&self, owner: &str) -> KResult<Vec<ObjectSharedResponse>>;

    /// Get the SGX quote of a KMS running inside the enclave
    async fn get_quote(&self, nonce: &str) -> KResult<String>;

    /// Get the certificate of a KMS running using HTTPS
    async fn get_certificate(&self) -> KResult<String>;

    /// Get the manifest of the KMS running inside the enclave
    async fn get_manifest(&self) -> KResult<String>;
}

/// Implement the KMIP Server Trait and dispatches the actual actions
/// to the implementation module or ciphers for encryption/decryption
#[async_trait]
impl KmipServer for KMS {
    async fn get_certificate(&self) -> KResult<String> {
        // Get the SSL cert
        let cert = certbot().lock().expect("can't lock certificate mutex");
        let (_, certificate) = cert.get_raw_cert()?;
        Ok(certificate.to_string())
    }

    async fn get_manifest(&self) -> KResult<String> {
        Ok(fs::read_to_string(manifest_path().ok_or_else(|| {
            KmsError::ServerError(
                "`manifest_path` is mandatory when running inside the enclave".to_owned(),
            )
        })?)?)
    }

    async fn get_quote(&self, nonce: &str) -> KResult<String> {
        // Hash the user nonce, the cert and the hash of the manifest
        let data = hash(&prepare_report_data(
            self.get_manifest().await?.as_bytes(),
            self.get_certificate().await?.as_bytes(),
            nonce.as_bytes(),
        ));

        // get the quote
        Ok(get_quote(&data)?)
    }

    async fn import(&self, request: Import, owner: &str) -> KResult<ImportResponse> {
        let mut object = request.object;

        match &mut object {
            Object::PrivateKey { key_block }
            | Object::PublicKey { key_block }
            | Object::SymmetricKey { key_block } => {
                // replace attributes
                key_block.key_value = KeyValue {
                    key_material: key_block.key_value.key_material.clone(),
                    attributes: Some(request.attributes),
                };
            }
            x => {
                //TODO keep attributes as separate column in DB
                warn!("Attributes are not yet supported for objects of type : {x}")
            }
        }

        //TODO no support for wrapped stuff for now
        let wrapped = match &object {
            Object::PrivateKey { key_block } | Object::PublicKey { key_block } => {
                key_block.key_wrapping_data.as_ref()
            }
            _ => None,
        };
        if wrapped.is_some() {
            kms_bail!(KmsError::NotSupported(
                "This server does not yet support wrapped keys".to_owned()
            ));
        }

        let replace_existing = if let Some(v) = request.replace_existing {
            v
        } else {
            false
        };
        let uid = if replace_existing {
            debug!(
                "Upserting object of type: {}, with uid: {}",
                request.object_type, request.unique_identifier
            );
            self.db
                .upsert(
                    &request.unique_identifier,
                    owner,
                    &object,
                    StateEnumeration::Active,
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
            self.db.create(id, owner, &object).await?
        };
        Ok(ImportResponse {
            unique_identifier: uid,
        })
    }

    async fn create(&self, request: Create, owner: &str) -> KResult<CreateResponse> {
        trace!("Create: {}", serde_json::to_string(&request)?);
        if request.protection_storage_masks.is_some() {
            kms_bail!(KmsError::UnsupportedPlaceholder)
        }
        let object = match &request.object_type {
            ObjectType::SymmetricKey => self.create_symmetric_key(&request, owner).await?,
            ObjectType::SecretData => self.create_secret_data(&request, owner).await?,
            &ObjectType::PrivateKey => self.create_private_key(&request, owner).await?,
            _ => {
                kms_bail!(KmsError::NotSupported(format!(
                    "This server does not yet support creation of: {}",
                    request.object_type
                )))
            }
        };
        let uid = self.db.create(None, owner, &object).await?;
        debug!(
            "Created KMS Object of type {:?} with id {uid}",
            &object.object_type(),
        );
        Ok(CreateResponse {
            object_type: request.object_type,
            unique_identifier: uid,
        })
    }

    async fn create_key_pair(
        &self,
        request: CreateKeyPair,
        owner: &str,
    ) -> KResult<CreateKeyPairResponse> {
        trace!("Create key pair: {}", serde_json::to_string(&request)?);
        if request.common_protection_storage_masks.is_some()
            || request.private_protection_storage_masks.is_some()
            || request.public_protection_storage_masks.is_some()
        {
            kms_bail!(KmsError::UnsupportedPlaceholder)
        }
        let sk_uid = Uuid::new_v4().to_string();
        let pk_uid = Uuid::new_v4().to_string();
        let (sk, pk) = self.create_key_pair_(&request, owner).await?.0;

        // start a transaction
        // let mut conn = self.db.get_connection()?;

        // let tx = self.db.transaction(&mut conn)?;
        // let sk_uid = self.db.create_tx(None, &sk, &tx)?;
        // let pk_uid = self.db.create_tx(None, &pk, &tx)?;
        trace!("create_key_pair: sk_uid: {sk_uid}, pk_uid: {pk_uid}");

        //TODO now that the uid is no more generated
        //TODO move the update link code out ard create links before DB inserts
        // now update the public key links
        let mut pk_key_block = match &pk {
            Object::PublicKey { key_block } => key_block.clone(),
            _ => {
                kms_bail!(KmsError::InvalidRequest(
                    "Expected a KMIP Public Key".to_owned(),
                ))
            }
        };
        let mut attr = pk_key_block.key_value.attributes()?.clone();
        attr.link = vec![Link {
            link_type: LinkType::PrivateKeyLink,
            linked_object_identifier: LinkedObjectIdentifier::TextString(sk_uid.clone()),
        }];
        pk_key_block.key_value = KeyValue {
            key_material: pk_key_block.key_value.key_material.clone(),
            attributes: Some(attr),
        };
        let public_key = Object::PublicKey {
            key_block: pk_key_block,
        };
        // self.db.update_tx(
        //     &pk_uid,
        //     &Object::PublicKey {
        //         key_block: pk_key_block,
        //     },
        //     &tx,
        // )?;
        // now update the private key links
        let mut sk_key_block = match &sk {
            Object::PrivateKey { key_block } => key_block.clone(),
            _ => {
                kms_bail!(KmsError::InvalidRequest(
                    "Expected a KMIP Private Key".to_owned(),
                ))
            }
        };
        trace!("Create private key link OK");
        let mut attr = sk_key_block.key_value.attributes()?.clone();
        attr.link = vec![Link {
            link_type: LinkType::PublicKeyLink,
            linked_object_identifier: LinkedObjectIdentifier::TextString(pk_uid.clone()),
        }];
        sk_key_block.key_value = KeyValue {
            key_material: sk_key_block.key_value.key_material.clone(),
            attributes: Some(attr),
        };
        let private_key = Object::PrivateKey {
            key_block: sk_key_block,
        };
        self.db
            .create_objects(
                owner,
                &[
                    (Some(sk_uid.clone()), private_key),
                    (Some(pk_uid.clone()), public_key),
                ],
            )
            .await?;

        // debug!("Created  key pair: {}/{}", &sk_uid, &pk_uid);
        Ok(CreateKeyPairResponse {
            private_key_unique_identifier: sk_uid,
            public_key_unique_identifier: pk_uid,
        })
    }

    async fn get(&self, request: Get, owner: &str) -> KResult<GetResponse> {
        trace!("Get: {}", serde_json::to_string(&request)?);
        let uid = request
            .unique_identifier
            .as_ref()
            .ok_or(KmsError::UnsupportedPlaceholder)?;
        trace!("retrieving KMIP Object with id: {uid}");
        let (object, _state) = self
            .db
            .retrieve(uid, owner, ObjectOperationTypes::Get)
            .await?
            .ok_or_else(|| KmsError::ItemNotFound(format!("Object with uid: {uid} not found")))?;

        debug!("Retrieved Object: {} with id {uid}", &object.object_type());
        Ok(GetResponse {
            object_type: object.object_type(),
            unique_identifier: uid.clone(),
            object,
        })
    }

    async fn get_attributes(
        &self,
        request: GetAttributes,
        owner: &str,
    ) -> KResult<GetAttributesResponse> {
        trace!("Get attributes: {}", serde_json::to_string(&request)?);
        let uid = request
            .unique_identifier
            .as_ref()
            .ok_or(KmsError::UnsupportedPlaceholder)?;

        trace!("retrieving attributes of KMIP Object with id: {uid}");
        let (object, _state) = self
            .db
            .retrieve(uid, owner, ObjectOperationTypes::Get)
            .await?
            .ok_or_else(|| KmsError::ItemNotFound(format!("Object with uid: {uid} not found")))?;

        let object_type = object.object_type();
        let attributes = object.attributes()?;

        let req_attributes = match &request.attribute_references {
            None => {
                return Ok(GetAttributesResponse {
                    unique_identifier: uid.clone(),
                    attributes: attributes.clone(),
                })
            }
            Some(attrs) => attrs,
        };
        let mut res = Attributes::new(object_type);
        for requested in req_attributes {
            match requested {
                AttributeReference::Vendor(req_vdr_attr) => {
                    if let Some(vdr_attrs) = attributes.vendor_attributes.as_ref() {
                        let mut list = res.vendor_attributes.as_ref().unwrap_or(&vec![]).clone();
                        vdr_attrs
                            .iter()
                            .filter(|attr| {
                                attr.vendor_identification == req_vdr_attr.vendor_identification
                                    && attr.attribute_name == req_vdr_attr.attribute_name
                            })
                            .for_each(|vdr_attr| {
                                list.push(vdr_attr.clone());
                            });
                        if !list.is_empty() {
                            res.vendor_attributes = Some(list);
                        }
                    }
                }
                AttributeReference::Standard(tag) => match tag {
                    Tag::ActivationDate => {
                        res.activation_date = attributes.activation_date;
                    }
                    Tag::CryptographicAlgorithm => {
                        res.cryptographic_algorithm = attributes.cryptographic_algorithm;
                    }
                    Tag::CryptographicLength => {
                        res.cryptographic_length = attributes.cryptographic_length;
                    }
                    Tag::CryptographicParameters => {
                        res.cryptographic_parameters = attributes.cryptographic_parameters.clone();
                    }
                    Tag::CryptographicUsageMask => {
                        res.cryptographic_usage_mask = attributes.cryptographic_usage_mask;
                    }
                    Tag::KeyFormatType => {
                        res.key_format_type = attributes.key_format_type;
                    }
                    _ => {}
                },
            }
        }
        debug!("Retrieved Attributes for object {uid}: {res:?}");
        Ok(GetAttributesResponse {
            unique_identifier: uid.clone(),
            attributes: res,
        })
    }

    async fn encrypt(&self, request: Encrypt, owner: &str) -> KResult<EncryptResponse> {
        // 1 - check correlation //TODO
        // 2b - if correlation pull encrypt oracle from cache
        // 2a - if no correlation, create encrypt oracle
        // 3 - call EncryptOracle.encrypt
        trace!("encrypt : {}", serde_json::to_string(&request)?);

        let uid = request
            .unique_identifier
            .as_ref()
            .ok_or(KmsError::UnsupportedPlaceholder)?;
        self.get_encipher(uid, owner)
            .await?
            .encrypt(&request)
            .map_err(Into::into)
    }

    async fn decrypt(&self, request: Decrypt, owner: &str) -> KResult<DecryptResponse> {
        trace!("Decrypt: {:?}", &request.unique_identifier);
        let uid = request
            .unique_identifier
            .as_ref()
            .ok_or(KmsError::UnsupportedPlaceholder)?;
        self.get_decipher(uid, owner)
            .await?
            .decrypt(&request)
            .map_err(Into::into)
    }

    async fn locate(&self, request: Locate, owner: &str) -> KResult<LocateResponse> {
        let uids = match &request.attributes.cryptographic_algorithm {
            Some(CryptographicAlgorithm::ABE) => match request.attributes.key_format_type {
                None => kms_bail!(KmsError::InvalidRequest(
                    "Unable to locate an ABE key, the format type is not specified".to_string()
                )),
                Some(KeyFormatType::AbeUserDecryptionKey) => {
                    let uids_attrs = self
                        .db
                        .find(
                            Some(&request.attributes),
                            Some(StateEnumeration::Active),
                            owner,
                        )
                        .await?;
                    let mut uids = Vec::new();
                    for (uid, _, attributes) in uids_attrs {
                        if compare_abe_attributes(&attributes, &request.attributes)? {
                            uids.push(uid);
                        }
                    }
                    uids
                }
                Some(other) => kms_bail!(KmsError::InvalidRequest(format!(
                    "Unable to locate an ABE keypair for format: {other:?}"
                ))),
            },
            Some(CryptographicAlgorithm::CoverCrypt) => {
                let uids_attrs = self
                    .db
                    .find(
                        Some(&request.attributes),
                        Some(StateEnumeration::Active),
                        owner,
                    )
                    .await?;
                let mut uids = Vec::new();
                for (uid, _, attributes) in uids_attrs {
                    if compare_cover_crypt_attributes(&attributes, &request.attributes)? {
                        uids.push(uid);
                    }
                }
                uids
            }
            Some(other) => kms_bail!(KmsError::NotSupported(format!(
                "The locate of an object for algorithm: {other:?} is not yet supported"
            ))),
            None => kms_bail!(KmsError::InvalidRequest(
                "The cryptographic algorithm must be specified for object location".to_string()
            )),
        };

        let response = LocateResponse {
            located_items: Some(uids.len() as i32),
            unique_identifiers: if uids.is_empty() { None } else { Some(uids) },
        };

        Ok(response)
    }

    async fn revoke(&self, request: Revoke, owner: &str) -> KResult<RevokeResponse> {
        //TODO http://gitlab.cosmian.com/core/cosmian_server/-/issues/131  Reasons should be kept
        let uid = request
            .unique_identifier
            .ok_or(KmsError::UnsupportedPlaceholder)?;
        let state = match request.revocation_reason {
            RevocationReason::Enumeration(e) => match e {
                RevocationReasonEnumeration::Unspecified
                | RevocationReasonEnumeration::AffiliationChanged
                | RevocationReasonEnumeration::Superseded
                | RevocationReasonEnumeration::CessationOfOperation
                | RevocationReasonEnumeration::PrivilegeWithdrawn => StateEnumeration::Deactivated,
                RevocationReasonEnumeration::KeyCompromise
                | RevocationReasonEnumeration::CACompromise => {
                    if request.compromise_occurrence_date.is_none() {
                        kms_bail!(KmsError::InvalidRequest(
                            "A compromise date must be supplied in case of compromised object"
                                .to_owned()
                        ))
                    }
                    StateEnumeration::Compromised
                }
            },
            RevocationReason::TextString(_) => StateEnumeration::Deactivated,
        };
        self.db.update_state(&uid, owner, state).await?;
        Ok(RevokeResponse {
            unique_identifier: uid,
        })
    }

    async fn rekey_keypair(
        &self,
        request: ReKeyKeyPair,
        owner: &str,
    ) -> KResult<ReKeyKeyPairResponse> {
        trace!("Internal rekey key pair");

        let private_key_unique_identifier = request
            .private_key_unique_identifier
            .as_ref()
            .ok_or_else(|| {
                KmsError::NotSupported(
                    "Rekey keypair: ID place holder is not yet supported an a key ID must be \
                     supplied"
                        .to_string(),
                )
            })?;

        let attributes = request.private_key_attributes.as_ref().ok_or_else(|| {
            KmsError::InvalidRequest(
                "Rekey keypair: the private key attributes must be supplied".to_owned(),
            )
        })?;

        match &attributes.cryptographic_algorithm {
            Some(CryptographicAlgorithm::ABE) => {
                super::abe::rekey_keypair_abe(
                    self,
                    private_key_unique_identifier,
                    attributes,
                    owner,
                )
                .await
            }
            Some(CryptographicAlgorithm::CoverCrypt) => {
                super::cover_crypt::rekey_keypair_cover_crypt(
                    self,
                    private_key_unique_identifier,
                    attributes,
                    owner,
                )
                .await
            }
            Some(other) => kms_bail!(KmsError::NotSupported(format!(
                "The rekey of a key pair for algorithm: {:?} is not yet supported",
                other
            ))),
            None => kms_bail!(KmsError::InvalidRequest(
                "The cryptographic algorithm must be specified in the private key attributes for \
                 key pair creation"
                    .to_string()
            )),
        }
    }

    async fn destroy(&self, request: Destroy, owner: &str) -> KResult<DestroyResponse> {
        let uid = request
            .unique_identifier
            .ok_or(KmsError::UnsupportedPlaceholder)?;

        self.db
            .update_state(&uid, owner, StateEnumeration::Destroyed)
            .await?;
        Ok(DestroyResponse {
            unique_identifier: uid,
        })
    }

    async fn list_accesses(
        &self,
        object_id: &UniqueIdentifier,
        owner: &str,
    ) -> KResult<Vec<UserAccessResponse>> {
        // check the object identified by its `uid` is really owned by `owner`
        // only the owner can list the permission of an object
        if !self.db.is_object_owned_by(object_id, owner).await? {
            kms_bail!(KmsError::Unauthorized(format!(
                "Object with uid `{object_id}` is not owned by owner `{owner}`"
            )))
        }

        let list = self.db.list_accesses(object_id).await?;
        let ids = list.into_iter().map(UserAccessResponse::from).collect();

        Ok(ids)
    }

    async fn list_owned_objects(&self, owner: &str) -> KResult<Vec<ObjectOwnedResponse>> {
        let list = self.db.find(None, None, owner).await?;
        let ids = list.into_iter().map(ObjectOwnedResponse::from).collect();
        Ok(ids)
    }

    async fn list_shared_objects(&self, owner: &str) -> KResult<Vec<ObjectSharedResponse>> {
        let list = self.db.list_shared_objects(owner).await?;
        let ids = list.into_iter().map(ObjectSharedResponse::from).collect();
        Ok(ids)
    }

    async fn insert_access(&self, access: &Access, owner: &str) -> KResult<()> {
        let uid = access
            .unique_identifier
            .as_ref()
            .ok_or(KmsError::UnsupportedPlaceholder)?;

        // check the object identified by its `uid` is really owned by `owner`
        if !self.db.is_object_owned_by(uid, owner).await? {
            kms_bail!(KmsError::Unauthorized(format!(
                "Object with uid `{uid}` is not owned by owner `{owner}`"
            )))
        }

        // check if owner is trying to grant themself
        if owner == access.user_id {
            kms_bail!(KmsError::Unauthorized(
                "You can't grant yourself, you have already all rights on your own objects"
                    .to_string()
            ))
        }

        self.db
            .insert_access(uid, &access.user_id, access.operation_type)
            .await?;
        Ok(())
    }

    async fn delete_access(&self, access: &Access, owner: &str) -> KResult<()> {
        let uid = access
            .unique_identifier
            .as_ref()
            .ok_or(KmsError::UnsupportedPlaceholder)?;

        // check the object identified by its `uid` is really owned by `owner`
        if !self.db.is_object_owned_by(uid, owner).await? {
            kms_bail!(KmsError::Unauthorized(format!(
                "Object with uid `{uid}` is not owned by owner `{owner}`"
            )))
        }

        // check if owner is trying to grant themself
        if owner == access.user_id {
            kms_bail!(KmsError::Unauthorized(
                "You can't revoke yourself, you shoud keep all rights on your own objects"
                    .to_string()
            ))
        }

        self.db
            .delete_access(uid, &access.user_id, access.operation_type)
            .await?;
        Ok(())
    }
}
