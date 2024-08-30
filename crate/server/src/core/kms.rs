use std::{
    collections::{BTreeSet, HashSet},
    fs,
};

use actix_web::{HttpMessage, HttpRequest};
use base64::{
    engine::general_purpose::{self, STANDARD as b64},
    Engine as _,
};
use cosmian_kmip::{
    crypto::secret::Secret,
    kmip::{
        kmip_messages::{Message, MessageResponse},
        kmip_operations::{
            Certify, CertifyResponse, Create, CreateKeyPair, CreateKeyPairResponse, CreateResponse,
            Decrypt, DecryptResponse, Destroy, DestroyResponse, Encrypt, EncryptResponse, Export,
            ExportResponse, Get, GetAttributes, GetAttributesResponse, GetResponse, Import,
            ImportResponse, Locate, LocateResponse, ReKey, ReKeyKeyPair, ReKeyKeyPairResponse,
            ReKeyResponse, Revoke, RevokeResponse, Validate, ValidateResponse,
        },
        kmip_types::{StateEnumeration, UniqueIdentifier},
    },
};
use cosmian_kms_client::access::{
    Access, AccessRightsObtainedResponse, ObjectOwnedResponse, UserAccessResponse,
};
use tracing::debug;
use uuid::Uuid;

use crate::{
    config::{DbParams, ServerParams},
    core::{extra_database_params::ExtraDatabaseParams, operations},
    database::Database,
    error::KmsError,
    kms_bail, kms_error,
    middlewares::{ssl_auth::PeerCommonName, JwtAuthClaim},
    result::{KResult, KResultHelper},
};

/// A Simple Key Management System that partially implements KMIP 2.1:
/// `https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=kmip`
pub struct KMS {
    pub(crate) params: ServerParams,
    pub(crate) db: Box<dyn Database + Sync + Send>,
}

/// Implement the KMIP Server operations and dispatches the actual actions
/// to the implementation module or ciphers for encryption/decryption
impl KMS {
    /// Adds a new encrypted `SQLite` database to the KMS server.
    ///
    /// # Returns
    ///
    /// Returns a base64-encoded string that represents the token associated with the new database.
    ///
    /// # Errors
    ///
    /// Returns an error if the KMS server does not allow this operation or if an error occurs while
    /// generating the new database or key.
    pub(crate) async fn add_new_database(&self) -> KResult<String> {
        if let DbParams::SqliteEnc(_) = self.params.db_params.as_ref().ok_or_else(|| {
            kms_error!("Unexpected fatal error: no database configured on the KMS server")
        })? {
            // Generate a new group id
            let uid: u128 = loop {
                let uid = Uuid::new_v4().to_u128_le();
                if let Some(database) = self.db.filename(uid) {
                    if !database.exists() {
                        // Create an empty file (to book the group id)
                        fs::File::create(database)?;
                        break uid
                    }
                }
            };

            // Encode ExtraDatabaseParams
            let params = ExtraDatabaseParams {
                group_id: uid,
                key: Secret::new_random()?,
            };

            let token = b64.encode(serde_json::to_vec(&params)?);

            // Create a dummy query to initialize the database
            // Note: if we don't proceed like that, the password will be set at the first query of the user
            // which let him put the password he wants.
            self.db.find(None, None, "", true, Some(&params)).await?;

            return Ok(token)
        }

        kms_bail!(KmsError::InvalidRequest(
            "add_new_database: not an encrypted sqlite: this server does not allow this operation"
                .to_owned()
        ));
    }

    /// This operation requests the server to Import a Managed Object specified
    /// by its Unique Identifier. The request specifies the object being
    /// imported and all the attributes to be assigned to the object. The
    /// attribute rules for each attribute for "Initially set by" and "When
    /// implicitly set" SHALL NOT be enforced as all attributes MUST be set
    /// to the supplied values rather than any server generated values.
    /// The response contains the Unique Identifier provided in the request or
    /// assigned by the server. The server SHALL copy the Unique Identifier
    /// returned by this operations into the ID Placeholder variable.
    ///
    /// Cosmian specific: unique identifiers starting with `[` are reserved
    /// for queries on tags. See tagging.
    /// For instance, a request for unique identifier `[tag1]` will
    /// attempt to find a valid single object tagged with `tag1`
    pub(crate) async fn import(
        &self,
        request: Import,
        user: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<ImportResponse> {
        operations::import(self, request, user, params).await
    }

    /// This request is used to generate a Certificate object for a public key.
    /// This request supports the certification of a new public key, as well as
    /// the certification of a public key that has already been certified (i.e.,
    /// certificate update). Only a single certificate SHALL be requested at a
    /// time. The Certificate Request object MAY be omitted, in which case
    /// the public key for which a Certificate object is generated SHALL be
    /// specified by its Unique Identifier only. If the Certificate Request Type
    /// and the Certificate Request objects are omitted from the request, then
    /// the Certificate Type SHALL be specified using the Attributes object.
    /// The Certificate Request is passed as a Byte String, which allows
    /// multiple certificate request types for X.509 certificates (e.g.,
    /// PKCS#10, PEM, etc.) to be submitted to the server. The generated
    /// Certificate object whose Unique Identifier is returned MAY be obtained
    /// by the client via a Get operation in the same batch, using the ID
    /// Placeholder mechanism. For the public key, the server SHALL create a
    /// Link attribute of Link Type Certificate pointing to the generated
    /// certificate. For the generated certificate, the server SHALL create a
    /// Link attribute of Link Type Public Key pointing to the Public Key.
    /// The server SHALL copy the Unique Identifier of the generated certificate
    /// returned by this operation into the ID Placeholder variable.
    /// If the information in the Certificate Request conflicts with the
    /// attributes specified in the Attributes, then the information in the
    /// Certificate Request takes precedence.
    pub(crate) async fn certify(
        &self,
        request: Certify,
        user: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<CertifyResponse> {
        operations::certify(self, request, user, params).await
    }

    /// This operation requests the server to generate a new symmetric key or
    /// generate Secret Data as a Managed Cryptographic Object.
    /// The request contains information about the type of object being created,
    /// and some of the attributes to be assigned to the object (e.g.,
    /// Cryptographic Algorithm, Cryptographic Length, etc.). The response
    /// contains the Unique Identifier of the created object. The server SHALL
    /// copy the Unique Identifier returned by this operation into the ID
    /// Placeholder variable.
    pub(crate) async fn create(
        &self,
        request: Create,
        user: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<CreateResponse> {
        operations::create(self, request, user, params).await
    }

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
    pub(crate) async fn create_key_pair(
        &self,
        request: CreateKeyPair,
        user: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<CreateKeyPairResponse> {
        operations::create_key_pair(self, request, user, params).await
    }

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
    pub(crate) async fn decrypt(
        &self,
        request: Decrypt,
        user: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<DecryptResponse> {
        operations::decrypt(self, request, user, params).await
    }

    /// This operation is used to indicate to the server that the key material
    /// for the specified Managed Object SHALL be destroyed or rendered
    /// inaccessible. The meta-data for the key material SHALL be retained by
    /// the server.  Objects SHALL only be destroyed if they are in either
    /// Pre-Active or Deactivated state.
    pub(crate) async fn destroy(
        &self,
        request: Destroy,
        user: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<DestroyResponse> {
        operations::destroy_operation(self, request, user, params).await
    }

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
    pub(crate) async fn encrypt(
        &self,
        request: Encrypt,
        user: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<EncryptResponse> {
        operations::encrypt(self, request, user, params).await
    }

    /// This operation requests that the server returns a Managed Object specified by its Unique Identifier,
    /// together with its attributes.
    /// The Key Format Type, Key Wrap Type, Key Compression Type and Key Wrapping Specification
    /// SHALL have the same semantics as for the Get operation.
    /// If the Managed Object has been Destroyed then the key material for the specified managed object
    /// SHALL not be returned in the response.
    /// The server SHALL copy the Unique Identifier returned by this operations
    /// into the ID Placeholder variable.
    pub(crate) async fn export(
        &self,
        request: Export,
        user: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<ExportResponse> {
        operations::export(self, request, user, params).await
    }

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
    /// container as specified by RFC7292. The Unique Identifier shall be
    /// either that of a private key or certificate to be included in the
    /// response. The container shall be protected using the Secret Data object
    /// specified via the private key or certificate's PKCS#12 Password
    /// Link. The current certificate chain shall also be included
    /// as determined by using the private key's Public Key link to get the
    /// corresponding public key (where relevant), and then using that
    /// public key's PKCS#12 Certificate Link to get the base certificate, and
    /// then using each certificate's Ce
    pub(crate) async fn get(
        &self,
        request: Get,
        user: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<GetResponse> {
        operations::get(self, request, user, params).await
    }

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
    pub(crate) async fn get_attributes(
        &self,
        request: GetAttributes,
        user: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<GetAttributesResponse> {
        operations::get_attributes(self, request, user, params).await
    }

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
    /// Member is 'Group Member Fresh', matching candidate objects SHALL be
    /// fresh objects from the object group. If there are no more fresh objects
    /// in the group, the server MAY choose to generate a new object on-the-fly,
    /// based on server policy. If the value specified for Object Group Member
    /// is 'Group Member Default', the server locates the default object as
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
    pub(crate) async fn locate(
        &self,
        request: Locate,
        user: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<LocateResponse> {
        operations::locate(self, request, Some(StateEnumeration::Active), user, params).await
    }

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
    pub(crate) async fn rekey_keypair(
        &self,
        request: ReKeyKeyPair,
        user: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<ReKeyKeyPairResponse> {
        operations::rekey_keypair(self, request, user, params).await
    }

    /// This request is used to generate a replacement key for an existing symmetric key. It is analogous to the Create operation, except that attributes of the replacement key are copied from the existing key, with the exception of the attributes listed in Re-key Attribute Requirements.
    ///
    /// As the replacement key takes over the name attribute of the existing key, Re-key SHOULD only be performed once on a given key.
    ///
    /// The server SHALL copy the Unique Identifier of the replacement key returned by this operation into the ID Placeholder variable.
    ///
    /// For the existing key, the server SHALL create a Link attribute of Link Type Replacement Object pointing to the replacement key. For the replacement key, the server SHALL create a Link attribute of Link Type Replaced Key pointing to the existing key.
    ///
    /// An Offset MAY be used to indicate the difference between the Initial Date and the Activation Date of the replacement key. If no Offset is specified, the Activation Date, Process Start Date, Protect Stop Date and Deactivation Date values are copied from the existing key.
    pub(crate) async fn rekey(
        &self,
        request: ReKey,
        user: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<ReKeyResponse> {
        operations::rekey(self, request, user, params).await
    }

    pub(crate) async fn message(
        &self,
        request: Message,
        user: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<MessageResponse> {
        operations::message(self, request, user, params).await
    }

    pub(crate) async fn validate(
        &self,
        request: Validate,
        user: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<ValidateResponse> {
        operations::validate_operation(self, request, user, params).await
    }

    /// This operation requests the server to revoke a Managed Cryptographic
    /// Object or an Opaque Object. The request contains a reason for the
    /// revocation (e.g., "key compromise", "cessation of operation", etc.). The
    /// operation has one of two effects. If the revocation reason is "key
    /// compromise" or "CA compromise", then the object is placed into the
    /// "compromised" state; the Date is set to the current date and time; and
    /// the Compromise Occurrence Date is set to the value (if provided) in the
    /// Revoke request and if a value is not provided in the Revoke request then
    /// Compromise Occurrence Date SHOULD be set to the Initial Date for the
    /// object. If the revocation reason is neither "key compromise" nor "CA
    /// compromise", the object is placed into the "deactivated" state, and the
    /// Deactivation Date is set to the current date and time.
    pub(crate) async fn revoke(
        &self,
        request: Revoke,
        user: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<RevokeResponse> {
        operations::revoke_operation(self, request, user, params).await
    }

    /// Grant an access to a user (identified by `access.userid`)
    /// to an object (identified by `access.unique_identifier`)
    /// which is owned by `owner` (identified by `access.owner`)
    pub(crate) async fn grant_access(
        &self,
        access: &Access,
        owner: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        let uid = access
            .unique_identifier
            .as_ref()
            .ok_or(KmsError::UnsupportedPlaceholder)?
            .as_str()
            .context("unique_identifier is not a string")?;

        // check the object identified by its `uid` is really owned by `owner`
        if !self.db.is_object_owned_by(uid, owner, params).await? {
            kms_bail!(KmsError::Unauthorized(format!(
                "Object with uid `{uid}` is not owned by owner `{owner}`"
            )))
        }

        // check if owner is trying to grant them self
        if owner == access.user_id {
            kms_bail!(KmsError::Unauthorized(
                "You can't grant yourself, you have already all rights on your own objects"
                    .to_string()
            ))
        }

        self.db
            .grant_access(
                uid,
                &access.user_id,
                HashSet::from_iter(access.operation_types.clone()),
                params,
            )
            .await?;
        Ok(())
    }

    /// Remove an access authorization for a user (identified by `access.userid`)
    /// to an object (identified by `access.unique_identifier`)
    /// which is owned by `owner` (identified by `access.owner`)
    pub(crate) async fn revoke_access(
        &self,
        access: &Access,
        owner: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<()> {
        let uid = access
            .unique_identifier
            .as_ref()
            .ok_or(KmsError::UnsupportedPlaceholder)?
            .as_str()
            .context("unique_identifier is not a string")?;

        // check the object identified by its `uid` is really owned by `owner`
        if !self.db.is_object_owned_by(uid, owner, params).await? {
            kms_bail!(KmsError::Unauthorized(format!(
                "Object with uid `{uid}` is not owned by owner `{owner}`"
            )))
        }

        // check if owner is trying to revoke itself
        if owner == access.user_id {
            kms_bail!(KmsError::Unauthorized(
                "You can't revoke yourself, you should keep all rights on your own objects"
                    .to_string()
            ))
        }

        self.db
            .remove_access(
                uid,
                &access.user_id,
                HashSet::from_iter(access.operation_types.clone()),
                params,
            )
            .await?;
        Ok(())
    }

    /// Get all the access granted for a given object
    /// per user
    pub(crate) async fn list_accesses(
        &self,
        object_id: &UniqueIdentifier,
        owner: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<UserAccessResponse>> {
        let object_id = object_id
            .as_str()
            .context("unique_identifier is not a string")?;
        // check the object identified by its `uid` is really owned by `owner`
        // only the owner can list the permission of an object
        if !self.db.is_object_owned_by(object_id, owner, params).await? {
            kms_bail!(KmsError::Unauthorized(format!(
                "Object with uid `{object_id}` is not owned by owner `{owner}`"
            )))
        }

        let list = self
            .db
            .list_object_accesses_granted(object_id, params)
            .await?;
        let ids = list
            .into_iter()
            .map(|(user_id, operations)| UserAccessResponse {
                user_id,
                operations: operations.into_iter().collect::<BTreeSet<_>>(),
            })
            .collect();

        Ok(ids)
    }

    /// Get all the objects owned by a given user (the owner)
    pub(crate) async fn list_owned_objects(
        &self,
        owner: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<ObjectOwnedResponse>> {
        let list = self.db.find(None, None, owner, true, params).await?;
        let ids = list.into_iter().map(ObjectOwnedResponse::from).collect();
        Ok(ids)
    }

    /// Get all the access rights granted to a given user
    pub(crate) async fn list_access_rights_obtained(
        &self,
        user: &str,
        params: Option<&ExtraDatabaseParams>,
    ) -> KResult<Vec<AccessRightsObtainedResponse>> {
        let list = self
            .db
            .list_user_granted_access_rights(user, params)
            .await?;
        let ids = list
            .into_iter()
            .map(AccessRightsObtainedResponse::from)
            .collect();
        Ok(ids)
    }

    /// Get the user from the request depending on the authentication method
    /// The user is encoded in the JWT `Authorization` header
    /// If the header is not present, the user is extracted from the client certificate
    /// If the client certificate is not present, the user is extracted from the configuration file
    pub(crate) fn get_user(&self, req_http: &HttpRequest) -> String {
        let default_username = self.params.default_username.clone();

        if self.params.force_default_username {
            debug!(
                "Authenticated using forced default user: {}",
                default_username
            );
            return default_username
        }
        // if there is a JWT token, use it in priority
        let user = match req_http.extensions().get::<JwtAuthClaim>() {
            Some(claim) => claim.email.clone(),
            None => {
                // check for client certificate authentication
                match req_http.extensions().get::<PeerCommonName>() {
                    Some(claim) => claim.common_name.clone(),
                    // if no client certificate, use the default username
                    None => default_username,
                }
            }
        };
        debug!("Authenticated user: {}", user);
        user
    }

    /// Get the `SqliteEnc` database secrets from the request
    /// The secrets are encoded in the `KmsDatabaseSecret` header
    pub(crate) fn get_sqlite_enc_secrets(
        &self,
        req_http: &HttpRequest,
    ) -> KResult<Option<ExtraDatabaseParams>> {
        Ok(
            match self.params.db_params.as_ref().ok_or_else(|| {
                kms_error!("Unexpected fatal error: no database configured on the KMS server")
            })? {
                DbParams::SqliteEnc(_) => {
                    let secrets = req_http
                        .headers()
                        .get("KmsDatabaseSecret")
                        .and_then(|h| h.to_str().ok().map(std::string::ToString::to_string))
                        .ok_or_else(|| {
                            KmsError::Unauthorized(
                                "Missing KmsDatabaseSecret header in the query".to_owned(),
                            )
                        })?;

                    let secrets = general_purpose::STANDARD.decode(secrets).map_err(|e| {
                        KmsError::Unauthorized(format!(
                            "KmsDatabaseSecret header cannot be decoded: {e}"
                        ))
                    })?;

                    Some(
                        serde_json::from_slice::<ExtraDatabaseParams>(&secrets).map_err(|e| {
                            KmsError::Unauthorized(format!(
                                "KmsDatabaseSecret header cannot be read: {e}"
                            ))
                        })?,
                    )
                }
                _ => None,
            },
        )
    }
}
